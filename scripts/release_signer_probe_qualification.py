import unittest
from unittest.mock import Mock

from mlsecops.contracts import Rejected
from scripts import release_signer_probe as probe


class SignerTraceContracts(unittest.TestCase):
    def trace(self, statuses, times, mutation=None):
        return probe.observe_refusal(
            Mock(side_effect=[(s, {}) for s in statuses]),
            {},
            mutation or Mock(return_value={"version": 2}),
            clock=Mock(side_effect=times),
            pause=Mock(),
        )

    def test_trace_anchors_before_success_and_requires_two_denials(self):
        result = self.trace([200, 200, 503, 503], [10, 11, 11.1, 12, 12.1, 13, 13.1])
        self.assertAlmostEqual(result["first_503_seconds"], 2.1)
        self.assertEqual(result["observations"], 3)
        self.assertEqual([row["http_status"] for row in result["trace"]], [200, 503, 503])
        self.assertEqual(result["trust_receipt"], {"version": 2})

    def test_failed_initial_request_never_mutates_trust(self):
        mutation = Mock()
        with self.assertRaisesRegex(Rejected, "signer_trace_initial_prediction"):
            self.trace([503], [10], mutation)
        mutation.assert_not_called()

    def test_late_ml_reactivation_or_unexpected_http_fails(self):
        for statuses, times in (
            ([200, 200], [10, 70, 70.1]),
            ([200, 503, 200], [10, 11, 12, 13, 14]),
            ([200, 429], [10, 11, 12]),
            ([200, 503], [10, 70, 70.1]),
            ([200, 503], [10, 11, 10.5]),
            ([200, 503], [10, float("nan"), 12]),
            ([200, 503.0], [10, 11, 12]),
            ([200, 503], [10, 76, 77]),
        ):
            with self.subTest(statuses=statuses, times=times), self.assertRaises(Rejected):
                self.trace(statuses, times)

    def test_stalled_observer_cannot_loop_forever_or_report_success(self):
        with self.assertRaisesRegex(Rejected, "signer_trace_refusal_missing"):
            probe.observe_refusal(
                Mock(return_value=(200, {})), {}, Mock(), clock=Mock(return_value=10), pause=Mock()
            )

    def test_mutation_failure_is_not_a_successful_revocation_trace(self):
        with self.assertRaisesRegex(Rejected, "update-unconfirmed"):
            self.trace([200], [10], Mock(side_effect=Rejected("update-unconfirmed")))


if __name__ == "__main__":
    unittest.main()
