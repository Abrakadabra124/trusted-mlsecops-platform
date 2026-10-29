import asyncio
import io
import tempfile
import threading
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from starlette.requests import Request

from mlsecops import advisory, serving_http
from mlsecops import kube_candidate_probe as probe
from mlsecops.contracts import Rejected, canonical
from mlsecops.signing import encode64
from scripts import kube_candidate_native as native


class CandidateInferenceContracts(unittest.TestCase):
    def test_candidate_reader_pins_selected_authority_without_forwarding_selector(self):
        for target in probe.Target:
            config = {
                "context": {"policy": {"environment": "lab"}},
                "permit_public": encode64(b"r" * 32),
                "trust_target": target.value,
                "kubernetes_worker": {},
            }
            with (
                patch.object(probe, "CandidateReader") as reader,
                patch.object(probe.trust_authority, "read", return_value="response") as read,
            ):
                probe.candidate(config)
                options = reader.call_args.kwargs
                self.assertNotIn("trust_target", options)
                self.assertNotIn("kubernetes_worker", options)
                lease = options["trust_lease"]
                self.assertEqual(lease.reader(), "response")
                read.assert_called_once_with(
                    "/trust-client", "lab", config["permit_public"], expected_host=target.host
                )

    def test_replay_matrix_uses_separate_denied_and_recovered_engines(self):
        engines = [Mock(), Mock()]
        client = Mock()
        client.request.return_value = {"items": []}
        check = Mock()
        with (
            patch.object(probe, "candidate"),
            patch.object(probe.serving, "Engine", side_effect=engines),
            patch.object(probe, "site", side_effect=lambda engine: nullcontext(Mock())),
            patch.object(
                probe.kube_candidate_clock,
                "exercise",
                return_value={"cause": "trust_version_replay"},
            ) as exercise,
            patch.object(probe, "matrix", return_value=({}, 0.0)) as matrix,
        ):
            result = probe.replay_matrix(
                {}, {"fault": "policy-change"}, {}, b"saved", check, client, Mock()
            )
            self.assertEqual(result["recovery_max_golden_error"], 0.0)
            self.assertIs(exercise.call_args.args[0], engines[0])
            self.assertEqual(exercise.call_args.kwargs["replayed"], b"saved")
            exercise.call_args.kwargs["reader_factory"]()
            self.assertIs(matrix.call_args.args[1], engines[1])
            matrix.call_args.args[-1]("golden-status", 200, 200)
            check.assert_any_call("replay-recovery-golden-status", 200, 200)
            self.assertEqual(client.request.call_count, 3)

    def test_replay_matrix_does_not_run_without_capture_or_for_another_fault(self):
        with patch.object(probe.serving, "Engine") as construct:
            self.assertIsNone(probe.replay_matrix({}, {}, {}, None, Mock(), Mock(), Mock()))
            with self.assertRaisesRegex(Rejected, "candidate_replay_fault"):
                probe.replay_matrix({}, {"fault": "outage"}, {}, b"saved", Mock(), Mock(), Mock())
            construct.assert_not_called()

    def test_clock_matrix_uses_new_engine_per_fault_and_checks_cleanup(self):
        expected = {"clock_cache": True, "features": [[0.5] * len(probe.FEATURES)]}
        client = Mock()
        client.request.return_value = {"items": []}
        engines = [Mock() for _ in probe.kube_candidate_clock.FAULTS]
        checks = []

        def check(label, actual, wanted):
            self.assertEqual(actual, wanted, label)
            checks.append(label)

        with (
            patch.object(probe, "candidate") as reader,
            patch.object(probe.serving, "Engine", side_effect=engines) as construct,
            patch.object(probe, "site", side_effect=lambda engine: nullcontext(Mock())),
            patch.object(
                probe.kube_candidate_clock, "exercise", return_value={"pass": True}
            ) as exercise,
        ):
            result = probe.clock_matrix({}, expected, check, client, Mock())
            self.assertEqual(len(result), 5)
            self.assertEqual(construct.call_count, 5)
            self.assertEqual([call.args[0] for call in exercise.call_args_list], engines)
            self.assertEqual(
                [call.kwargs["fault"] for call in exercise.call_args_list],
                list(probe.kube_candidate_clock.FAULTS),
            )
            exercise.call_args.kwargs["reader_factory"]()
            self.assertEqual(reader.call_count, 6)
        self.assertEqual(len(checks), 5)

    def test_clock_matrix_never_repeats_in_authority_fault_jobs_or_implicit_opt_in(self):
        with patch.object(probe.serving, "Engine") as construct:
            for expected in ({}, {"clock_cache": 1}, {"clock_cache": True, "fault": "outage"}):
                self.assertEqual(probe.clock_matrix({}, expected, Mock(), Mock(), Mock()), [])
            construct.assert_not_called()

    def test_matrix_uses_actual_parser_and_advisory_and_rejects_wrong_status(self):
        engine = SimpleNamespace(lock=threading.Lock())
        expected = {
            "model": "a" * 64,
            "bundle": "b" * 64,
            "features": [[0.5] * 6],
            "scores": [0.75],
        }
        observed = []

        def request(path, body=None, authorized=True):
            if not authorized:
                return 401, {}
            if path == "/readyz":
                return 200, {"model_sha256": expected["model"], "bundle_sha256": expected["bundle"]}
            if engine.lock.locked():
                return 429, {}
            raw = canonical(body) if isinstance(body, dict) else body

            async def receive():
                return {"type": "http.request", "body": raw, "more_body": False}

            scope = {
                "type": "http",
                "path": path,
                "query_string": b"",
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(raw)).encode()),
                ],
            }
            try:
                rows = asyncio.run(serving_http.read_body(Request(scope, receive)))
                return 200, {
                    "model_sha256": expected["model"],
                    "bundle_sha256": expected["bundle"],
                    "predictions": advisory.decide(rows, lambda x: [0.75] * len(x)),
                }
            except serving_http.BodyLimit:
                return 413, {}
            except Rejected:
                return 422, {}

        def check(label, actual, wanted):
            self.assertIs(type(actual), type(wanted), label)
            self.assertEqual(actual, wanted, label)
            observed.append(label)

        _, error = probe.matrix(request, engine, expected, check)
        self.assertEqual(error, 0)
        self.assertTrue(
            {
                "422-nan",
                "422-inf",
                "422-negative-inf",
                "422-101-rows",
                "100-rows-count",
                "429-busy",
                "413-over-64KiB",
            }.issubset(observed)
        )
        self.assertEqual(len(observed), len(set(observed)))

        def bypass(path, body=None, **kwargs):
            status, value = request(path, body, **kwargs)
            return (200 if status == 422 else status), value

        with self.assertRaises(AssertionError):
            probe.matrix(bypass, engine, expected, check)

    def test_site_thread_start_failure_closes_engine_and_listener(self):
        temporary = tempfile.TemporaryDirectory
        listener, engine, server = Mock(), Mock(), Mock(started=False)
        listener.getsockname.return_value = ("127.0.0.1", 12345)
        with (
            patch.object(
                probe.tempfile, "TemporaryDirectory", side_effect=lambda **kw: temporary()
            ),
            patch.object(probe.serving_http, "create_app"),
            patch.object(probe.socket, "socket", return_value=listener),
            patch.object(probe.uvicorn, "Config"),
            patch.object(probe.uvicorn, "Server", return_value=server),
            patch.object(probe.threading, "Thread") as thread,
        ):
            thread.return_value.start.side_effect = RuntimeError("cannot start")
            with self.assertRaises(RuntimeError):
                with probe.site(engine):
                    self.fail("must not enter")
            thread.return_value.join.assert_not_called()
        listener.close.assert_called_once()
        engine.close.assert_called_once()

    def test_native_refuses_dirty_checkout_before_any_infrastructure_mutation(self):
        with (
            patch.object(native, "hosted"),
            patch.object(native, "command", return_value=" M file.py"),
            patch.object(native.kube_trust, "bootstrap") as bootstrap,
        ):
            with self.assertRaisesRegex(Rejected, "dirty_source"):
                native.qualify(Path.cwd(), Path.cwd() / ".runtime", "image")
            bootstrap.assert_not_called()

    def test_probe_failure_never_echoes_private_exception(self):
        with (
            patch.object(probe, "enforce", side_effect=Rejected("PRIVATE-SENTINEL")),
            patch("sys.stdout", io.StringIO()) as output,
        ):
            self.assertEqual(probe.main(), 1)
            self.assertNotIn("PRIVATE-SENTINEL", output.getvalue())
            self.assertIn("candidate_inference_rejected", output.getvalue())


if __name__ == "__main__":
    unittest.main()
