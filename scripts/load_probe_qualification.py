import asyncio
import io
import runpy
import sys
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from mlsecops import load_probe as probe
from mlsecops.contracts import Rejected, canonical, digest, write_json
from mlsecops.load_golden import Golden
from mlsecops.serving_access import Access
from scripts.load_diagnostics_qualification import audit_fixture
from scripts.load_golden_qualification import expected, response
from scripts.load_measurement_qualification import rows


class ProbeContracts(unittest.TestCase):
    def test_real_listener_closes_and_failed_thread_start_does_not_leak_socket(self):
        app = probe.serving_http.FastAPI()

        @app.post("/v1/predict")
        async def predict():
            return response()

        with probe.listen(app) as port:
            status, body = asyncio.run(probe.load_measurement.request(port, "a" * 64, b"{}"))
            self.assertEqual(status, 200)
            self.assertTrue(Golden.from_expected(expected()).valid(body))
        with self.assertRaises(OSError):
            probe.socket.create_connection(("127.0.0.1", port), timeout=0.2)
        listener = Mock()
        listener.getsockname.return_value = ("127.0.0.1", 1234)
        with (
            patch.object(probe.socket, "socket", return_value=listener),
            patch.object(probe.uvicorn, "Server"),
            patch.object(probe.threading, "Thread") as thread,
        ):
            thread.return_value.start.side_effect = RuntimeError("start-failed")
            with self.assertRaises(RuntimeError), probe.listen(app):
                pass
        listener.close.assert_called_once()

    def test_startup_and_shutdown_deadlines_are_fail_closed(self):
        for mode in ("dead", "deadline", "shutdown"):
            listener, server, thread = Mock(), Mock(), Mock()
            listener.getsockname.return_value = ("127.0.0.1", 1234)
            server.started = mode == "shutdown"
            thread.is_alive.side_effect = (
                [False, False]
                if mode == "dead"
                else [True, False]
                if mode == "deadline"
                else [True]
            )
            with (
                patch.object(probe.socket, "socket", return_value=listener),
                patch.object(probe.uvicorn, "Server", return_value=server),
                patch.object(probe.threading, "Thread", return_value=thread),
                patch.object(probe.time, "monotonic", side_effect=[0, 101]),
            ):
                with self.subTest(mode=mode), self.assertRaises(Rejected), probe.listen(None):
                    pass
            listener.close.assert_called_once()

    def test_completed_run_and_all_binding_failure_paths_close_engine(self):
        for fault in (None, "identity", "permit", "release", "prediction", "receipt", "cleanup"):
            with self.subTest(fault=fault):
                self.scenario(fault)

    def scenario(self, fault):
        config = {
            "expected_permit": "d" * 64,
            "expected_campaign": "e" * 32,
            "kubernetes_worker": {},
        }
        engine = Mock()
        engine.check.return_value = {
            "ready": True,
            "model_sha256": "a" * 64,
            "bundle_sha256": "b" * 64,
        }
        engine.loaded.permit_sha256 = config["expected_permit"]
        engine.loaded.release_ready = False
        engine.worker.binding = {"session_id": "f" * 32}
        engine.worker.name, engine.worker.job_uid, engine.worker.pod_uid = (
            "worker-owned",
            "job-uid",
            "pod-uid",
        )
        if fault == "identity":
            engine.check.return_value = {}
        if fault == "permit":
            engine.loaded.permit_sha256 = "wrong"
        if fault == "release":
            engine.loaded.release_ready = True
        observation = {"records": rows(), "elapsed_ns": 130_000_000_000, "exhausted": False}
        summary = probe.load_measurement.summarize(**observation)
        receipt = {"summary_sha256": "wrong" if fault == "receipt" else digest(canonical(summary))}
        limited = probe.load_diagnostics.reasons()
        receipt["diagnostics_sha256"] = digest(
            canonical(
                probe.load_diagnostics.result(
                    probe.load_diagnostics.Timings(), limited, audit_fixture()
                )
            )
        )

        def listen(app):
            self.assertTrue((probe.DIRECTORY / "audit").is_dir())
            self.assertFalse((probe.DIRECTORY / "audit").is_symlink())
            return nullcontext(1234)

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(probe, "DIRECTORY", Path(temporary) / "load"),
            patch.object(probe, "Client") as client,
            patch.object(probe, "candidate"),
            patch.object(probe.load_diagnostics, "audit_status", return_value=audit_fixture()),
            patch.object(probe, "Worker") as worker,
            patch.object(probe.serving, "Engine", return_value=engine) as construct,
            patch.object(probe, "listen", side_effect=listen),
            patch.object(
                probe.load_measurement,
                "request",
                new=AsyncMock(
                    return_value=(503, {}) if fault == "prediction" else (200, response())
                ),
            ),
            patch.object(
                probe,
                "exercise",
                new=AsyncMock(return_value=(observation, {"profile_met": True}, limited)),
            ),
            patch.object(probe, "send", side_effect=[{}, receipt]) as send,
        ):
            client.return_value.request.side_effect = [
                {"items": []},
                {"items": ["leftover"] if fault == "cleanup" else []},
            ]
            if fault is None:
                report = probe.qualify(config, expected())
                self.assertTrue(report["profile_met"])
                self.assertFalse(report["release_ready"])
                self.assertEqual(
                    [call.args[1] for call in send.call_args_list], ["start", "finish"]
                )
                construct.call_args.kwargs["worker_factory"](b"model", "image")
                worker.assert_called_once_with(b"model", "image", {})
            else:
                with self.assertRaises(Rejected):
                    probe.qualify(config, expected())
        engine.close.assert_called()

    def test_main_success_error_and_module_entrypoint_do_not_print_private_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            write_json(path, {})
            for failure in (False, True):
                output = io.StringIO()
                with (
                    patch.object(probe, "enforce"),
                    patch.object(
                        sys, "argv", ["load", "--config", str(path), "--request", str(path)]
                    ),
                    patch.object(sys, "stdout", output),
                    patch.object(
                        probe,
                        "qualify",
                        side_effect=RuntimeError("PRIVATE") if failure else None,
                        return_value={"status": "pass"},
                    ),
                ):
                    self.assertEqual(probe.main(), 1 if failure else 0)
                self.assertNotIn("PRIVATE", output.getvalue())
        with (
            patch("mlsecops.process_privacy.enforce"),
            patch.object(sys, "argv", ["load"]),
            patch.object(sys, "stdout", io.StringIO()),
            self.assertRaises(SystemExit) as stop,
        ):
            runpy.run_path(probe.__file__, run_name="__main__")
        self.assertEqual(stop.exception.code, 1)

    def test_ten_distinct_identities_use_existing_bounded_access(self):
        value = probe.credentials()
        self.assertEqual(len(value["clients"]), 10)
        self.assertEqual(len({c["token"] for c in value["clients"]}), 10)
        access = Access(value)
        for client in value["clients"]:
            self.assertEqual(
                access.authenticate(["Bearer " + client["token"]]), client["principal_id"]
            )
            self.assertEqual(
                (client["requests_per_second"], client["burst"], client["max_in_flight"]),
                (20, 40, 4),
            )

    def test_bounded_overload_is_separate_and_recovery_is_verified(self):
        golden = Golden.from_expected(expected())
        observation = {"records": [], "elapsed_ns": 1, "exhausted": False, "clock": {}}
        replies = [(429, {})] * 39 + [(200, response()), (200, response())]
        with (
            patch.object(
                probe.load_measurement, "collect", new=AsyncMock(return_value=observation)
            ),
            patch.object(probe.load_measurement, "request", new=AsyncMock(side_effect=replies)),
            patch.object(probe.asyncio, "sleep", new=AsyncMock()),
        ):
            value, overload, limited = asyncio.run(probe.exercise(1234, ["a" * 64] * 10, golden))
        self.assertIs(value, observation)
        self.assertEqual(overload["attempts"], 40)
        self.assertEqual(overload["limited"], 39)
        self.assertEqual(overload["correct"], 1)
        self.assertEqual(overload["errors"], 0)
        self.assertEqual(limited["overload"]["unrecognized"], 39)
        self.assertTrue(overload["recovered"])
        self.assertTrue(overload["profile_met"])

    def test_overload_timeout_and_invalid_recovery_cannot_pass(self):
        golden = Golden.from_expected(expected())
        with (
            patch.object(probe.load_measurement, "collect", new=AsyncMock(return_value={})),
            patch.object(
                probe.load_measurement,
                "request",
                new=AsyncMock(side_effect=TimeoutError("private")),
            ),
            patch.object(probe.asyncio, "sleep", new=AsyncMock()),
        ):
            _, overload, _ = asyncio.run(probe.exercise(1234, ["a" * 64] * 10, golden))
        self.assertEqual(overload["errors"], 40)
        self.assertFalse(overload["profile_met"])
        self.assertNotIn("private", str(overload))

    def test_reason_counts_separate_normal_burst_and_recovery(self):
        golden = Golden.from_expected(expected())
        limited = {
            "schema_version": 1,
            "request_id": "a" * 32,
            "error": {"code": "client_limited"},
        }

        async def collect(request, valid):
            await request(0)
            return {"controlled": True}

        with (
            patch.object(probe.load_measurement, "collect", side_effect=collect),
            patch.object(
                probe.load_measurement, "request", new=AsyncMock(return_value=(429, limited))
            ),
            patch.object(probe.asyncio, "sleep", new=AsyncMock()),
        ):
            _, _, reasons = asyncio.run(probe.exercise(1234, ["a" * 64] * 10, golden))
        self.assertEqual(
            [reasons[p]["client_limited"] for p in ("normal", "overload", "recovery")], [1, 40, 1]
        )

    def test_initial_foreign_worker_refused_before_engine(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(probe, "DIRECTORY", Path(temporary) / "load"),
            patch.object(probe, "Client") as client,
            patch.object(probe.serving, "Engine") as construct,
        ):
            client.return_value.request.return_value = {"items": [{"foreign": True}]}
            with self.assertRaisesRegex(Rejected, "load_initial_worker_present"):
                probe.qualify({}, expected())
            construct.assert_not_called()

    def test_failed_operator_handoff_always_closes_owned_engine(self):
        config = {
            "expected_permit": "d" * 64,
            "expected_campaign": "e" * 32,
            "kubernetes_worker": {},
        }
        engine = Mock()
        engine.check.return_value = {
            "ready": True,
            "model_sha256": "a" * 64,
            "bundle_sha256": "b" * 64,
        }
        engine.loaded.permit_sha256 = config["expected_permit"]
        engine.loaded.release_ready = False
        engine.worker.binding = {"session_id": "f" * 32}
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(probe, "DIRECTORY", Path(temporary) / "load"),
            patch.object(probe, "Client") as client,
            patch.object(probe, "candidate"),
            patch.object(probe.serving, "Engine", return_value=engine),
            patch.object(probe, "listen", return_value=nullcontext(1234)),
            patch.object(
                probe.load_measurement, "request", new=AsyncMock(return_value=(200, response()))
            ),
            patch.object(probe, "send", side_effect=Rejected("operator-refused")),
        ):
            client.return_value.request.return_value = {"items": []}
            with self.assertRaisesRegex(Rejected, "operator-refused"):
                probe.qualify(config, expected())
        engine.close.assert_called()


if __name__ == "__main__":
    unittest.main()
