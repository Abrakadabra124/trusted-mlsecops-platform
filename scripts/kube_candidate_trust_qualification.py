import unittest
from unittest.mock import Mock, patch

from mlsecops import kube_candidate_trust as probe
from mlsecops.contracts import Rejected


class CandidateTrustContracts(unittest.TestCase):
    def test_key_probe_requires_live_fault_trace_and_exact_cold_reader_refusal(self):
        for cause in ("trust_key_revoked", "trust_artifact_revoked", "PRIVATE", None):
            reader = Mock()
            if cause is not None:
                reader.load.side_effect = Rejected(cause)
            checks = []

            def check(label, actual, expected):
                checks.append(label)
                if type(actual) is not type(expected) or actual != expected:
                    raise Rejected(label)

            with patch.object(
                probe.lifecycle, "exercise", return_value={"verified": True}
            ) as exercise:
                if cause == "trust_key_revoked":
                    result = probe.exercise(
                        lambda: reader, Mock(), b"{}", {"fault": "key-revocation"}, check
                    )
                    self.assertEqual(result, {"verified": True})
                    self.assertIn("cold-reader-key-revocation", checks)
                    # The lifecycle checker remains fail-closed after adapting
                    # its boolean assertions to the typed candidate reports.
                    with self.assertRaises(Rejected):
                        exercise.call_args.args[-1]("late-ML", False)
                else:
                    with self.assertRaises(Rejected):
                        probe.exercise(
                            lambda: reader, Mock(), b"{}", {"fault": "key-revocation"}, check
                        )
            reader.load.assert_called_once()

    def test_unknown_fault_is_not_silently_treated_as_a_key_revocation(self):
        with patch.object(probe.lifecycle, "exercise") as exercise, self.assertRaises(Rejected):
            probe.exercise(Mock(), Mock(), b"{}", {"fault": "revocation"}, Mock())
        exercise.assert_not_called()


if __name__ == "__main__":
    unittest.main()
