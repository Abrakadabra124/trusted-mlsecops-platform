import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import kube_serving_lifecycle as lifecycle
from mlsecops.contracts import Rejected, canonical


class LifecycleContracts(unittest.TestCase):
    def exercise(self, fault, *, late=False, resurrect=False, invalid=False, fail_signal=False):
        clock = [100.0]
        phase = [None]
        checks = []
        process = Mock()
        expected = {"fault": fault, "model": "a" * 64, "bundle": "b" * 64, "scores": [0.7]}

        def check(label, condition):
            if not condition:
                raise Rejected(label)
            checks.append(label)

        def checkpoint(name, fault):
            if fail_signal:
                raise Rejected("coordinator_failed")
            phase[0] = name

        def request(path, body=None):
            if phase[0] == "denied" and resurrect:
                code = 200
            elif phase[0] == "denied" or path == "/readyz":
                code = 503
            elif phase[0] is None:
                code = 200
            elif fault != "outage":
                code = 503
            else:
                code = 503 if clock[0] >= (160.2 if late else 159.7) else 200
            clock[0] += 0.001
            return code, (
                {
                    "model_sha256": expected["model"],
                    "bundle_sha256": expected["bundle"],
                    "predictions": [{"decision": "score", "score": 0.1 if invalid else 0.7}],
                }
                if code == 200
                else {
                    "schema_version": 1,
                    "request_id": "c" * 32,
                    "error": {"code": "model_unavailable"},
                }
            )

        with (
            patch.object(lifecycle.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(lifecycle.time, "time", side_effect=lambda: 1700000000 + clock[0]),
            patch.object(
                lifecycle.time,
                "sleep",
                side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay),
            ),
            patch.object(lifecycle, "checkpoint", side_effect=checkpoint),
            patch.object(lifecycle.socket, "gethostbyname", return_value="10.0.0.2"),
            patch.object(lifecycle, "tcp_state", return_value=True),
            patch.object(lifecycle.signal, "SIGSTOP", 19, create=True),
            patch.object(lifecycle.signal, "SIGCONT", 18, create=True),
        ):
            result = lifecycle.exercise(process, request, b"{}", expected, check)
        return result, process, checks

    def test_outage_bounds_client_completed_503_from_lower_bound_and_stays_fenced(self):
        result, process, checks = self.exercise("outage")
        self.assertLessEqual(result["first_503_seconds"], 60)
        self.assertGreater(result["observations"], 3)
        self.assertIn("no-automatic-reactivation", checks)
        self.assertEqual(process.send_signal.call_count, 2)

    def test_live_policy_change_and_revocation_are_not_cached_or_auto_restored(self):
        for fault in ["policy-change", "revocation"]:
            with self.subTest(fault=fault):
                result, process, checks = self.exercise(fault)
                self.assertLess(result["first_503_seconds"], 60)
                process.send_signal.assert_not_called()
                self.assertIn("trust-fault-readiness-503", checks)

    def test_blackhole_requires_drop_recovery_and_denial_past_original_lease(self):
        result, process, checks = self.exercise("blackhole")
        self.assertLessEqual(result["first_503_seconds"], 60)
        self.assertGreaterEqual(result["trace"][-1]["start_seconds"], 60)
        self.assertIn("trust-blackhole-TCP-blocked", checks)
        self.assertIn("trust-blackhole-TCP-restored", checks)
        self.assertEqual(process.send_signal.call_count, 2)

    def test_tcp_timeout_is_distinguished_from_refused_and_restored_connections(self):
        for blocked, replies, expected in (
            (True, [TimeoutError()], True),
            (False, [TimeoutError(), Mock()], True),
            (True, [Mock(), TimeoutError()], True),
            (True, [ConnectionRefusedError()], False),
        ):
            clock = [0.0]

            def connect(*args, **kwargs):
                self.assertEqual(args, (("10.0.0.2", 5432),))
                self.assertEqual(kwargs, {"timeout": 1})
                clock[0] += 1
                reply = replies.pop(0) if len(replies) > 1 else replies[0]
                if isinstance(reply, Exception):
                    raise reply
                return reply

            with (
                patch.object(lifecycle.socket, "create_connection", side_effect=connect),
                patch.object(lifecycle.time, "monotonic", side_effect=lambda: clock[0]),
                patch.object(lifecycle.time, "sleep"),
            ):
                self.assertIs(lifecycle.tcp_state("10.0.0.2", blocked=blocked), expected)

    def test_late_denial_resurrection_and_invalid_scores_cannot_pass(self):
        for options in [{"late": True}, {"resurrect": True}, {"invalid": True}]:
            with self.subTest(options=options), self.assertRaises(Rejected):
                self.exercise("outage", **options)

    def test_stopped_child_is_continued_even_when_coordinator_fails(self):
        process = Mock()
        with (
            patch.object(lifecycle, "checkpoint", side_effect=Rejected("failure")),
            patch.object(lifecycle.signal, "SIGSTOP", 19, create=True),
            patch.object(lifecycle.signal, "SIGCONT", 18, create=True),
            patch.object(lifecycle, "valid", return_value=True),
            self.assertRaises(Rejected),
        ):
            lifecycle.exercise(
                process, lambda *args: (200, {}), b"{}", {"fault": "outage"}, lambda *args: None
            )
        self.assertEqual([c.args[0] for c in process.send_signal.call_args_list], [19, 18])

    def test_checkpoint_accepts_only_exact_ack_and_has_bounded_wait(self):
        import io

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with (
                patch.object(lifecycle, "DIRECTORY", directory),
                patch("sys.stdout", io.StringIO()),
            ):
                path = directory / "mlsecops-trust-ready.json"
                path.write_bytes(canonical({"phase": "ready", "fault": "outage"}))
                lifecycle.checkpoint("ready", "outage")
                path.write_bytes(canonical({"phase": "denied", "fault": "outage"}))
                with self.assertRaises(Rejected):
                    lifecycle.checkpoint("ready", "outage")
                path.unlink()
                with patch.object(lifecycle.time, "monotonic", side_effect=[0, 91]):
                    with self.assertRaises(Rejected):
                        lifecycle.checkpoint("ready", "outage")
                with patch.object(
                    lifecycle.time,
                    "sleep",
                    side_effect=lambda delay: path.write_bytes(
                        canonical({"phase": "ready", "fault": "outage"})
                    ),
                ):
                    lifecycle.checkpoint("ready", "outage")

    def test_missing_trace_after_delayed_operator_does_not_pass(self):
        clock = [0]

        def check(label, condition):
            if not condition:
                raise Rejected(label)

        with (
            patch.object(lifecycle.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(lifecycle, "valid", return_value=True),
            patch.object(lifecycle, "checkpoint", side_effect=lambda *a: clock.__setitem__(0, 66)),
            self.assertRaisesRegex(Rejected, "complete-trace"),
        ):
            lifecycle.exercise(
                Mock(), lambda *a: (200, {}), b"{}", {"fault": "policy-change"}, check
            )

    def test_response_validation_rejects_invalid_contracts(self):
        expected = {"model": "a" * 64, "bundle": "b" * 64, "scores": [0.7]}
        good = {
            "model_sha256": expected["model"],
            "bundle_sha256": expected["bundle"],
            "predictions": [{"decision": "score", "score": 0.7}],
        }
        self.assertTrue(lifecycle.valid(200, good, expected))
        for field, value in [
            ("model_sha256", "c" * 64),
            ("predictions", []),
            ("predictions", [{"decision": "score", "score": float("nan")}]),
            ("predictions", [{"decision": "score", "score": True}]),
        ]:
            changed = copy.deepcopy(good)
            changed[field] = value
            self.assertFalse(lifecycle.valid(200, changed, expected))
        self.assertFalse(lifecycle.valid(429, {}, expected))
        self.assertFalse(lifecycle.valid(503, None, expected))
        self.assertFalse(lifecycle.valid(503, {"error": "private"}, expected))


if __name__ == "__main__":
    unittest.main()
