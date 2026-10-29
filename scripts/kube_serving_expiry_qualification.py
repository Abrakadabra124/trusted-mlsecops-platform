import unittest
from unittest.mock import patch

from mlsecops import kube_serving_expiry as expiry
from mlsecops.contracts import Rejected


class ExpiryContracts(unittest.TestCase):
    def exercise(self, *, late=False, early=False, resurrect=False, skew=False, invalid=False):
        clock, checks = [100.0], []
        expected = {"expires_at": 110, "model": "a" * 64, "bundle": "b" * 64, "scores": [0.7]}

        def check(label, condition):
            if not condition:
                raise Rejected(label)
            checks.append(label)

        def request(path, body=None):
            code = 200 if clock[0] < (110.5 if late else 109.1) else 503
            if early and clock[0] >= 102:
                code = 503
            if resurrect and clock[0] >= 110:
                code = 200
            if path == "/readyz":
                code = 503
            clock[0] += 0.001
            if skew:
                clock[0] -= 1
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
            patch.object(expiry.time, "time", side_effect=lambda: clock[0]),
            patch.object(expiry.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(
                expiry.time, "sleep", side_effect=lambda d: clock.__setitem__(0, clock[0] + d)
            ),
        ):
            result = expiry.exercise(request, b"{}", expected, check)
        return result, checks

    def test_real_expiry_trace_requires_positive_then_bounded_denial_and_no_reactivation(self):
        result, checks = self.exercise()
        self.assertLessEqual(result["first_503_seconds_from_expiry"], 0)
        self.assertGreaterEqual(result["first_503_seconds_from_expiry"], -2)
        self.assertGreaterEqual(result["trace"][-1]["start_epoch"], 111)
        self.assertIn("approval-expiry-no-reactivation", checks)

    def test_late_early_resurrected_clock_reversed_or_wrong_prediction_cannot_pass(self):
        for option in ("late", "early", "resurrect", "skew", "invalid"):
            with self.subTest(option=option), self.assertRaises(Rejected):
                self.exercise(**{option: True})

    def test_missing_or_unbounded_window_is_rejected_before_http(self):
        from unittest.mock import Mock

        for value in (None, True, 100, 99, 221):
            request = Mock()

            def check(label, condition):
                if not condition:
                    raise Rejected(label)

            with patch.object(expiry.time, "time", return_value=100), self.assertRaises(Rejected):
                expiry.exercise(request, b"{}", {"expires_at": value}, check)
            request.assert_not_called()

    def test_scheduler_delay_past_window_cannot_pass_without_observations(self):
        from unittest.mock import Mock

        request = Mock()

        def check(label, condition):
            if not condition:
                raise Rejected(label)

        with (
            patch.object(expiry.time, "time", return_value=100),
            patch.object(expiry.time, "monotonic", side_effect=[0, 200]),
            self.assertRaisesRegex(Rejected, "complete-trace"),
        ):
            expiry.exercise(request, b"{}", {"expires_at": 110}, check)
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
