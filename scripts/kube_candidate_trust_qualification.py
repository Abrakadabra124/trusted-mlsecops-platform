import unittest
from unittest.mock import Mock, patch

from mlsecops import kube_candidate_trust as probe
from mlsecops import trust
from mlsecops.contracts import Rejected


class CandidateTrustContracts(unittest.TestCase):
    def test_actual_model_revoke_requires_exact_artifact_denial(self):
        def check(label, actual, expected):
            if type(actual) is not type(expected) or actual != expected:
                raise Rejected(label)

        for cause in ("trust_artifact_revoked", "trust_key_revoked", None):
            reader = Mock()
            if cause:
                reader.load.side_effect = Rejected(cause)
            with patch.object(probe.lifecycle, "exercise", return_value={"fault": "revocation"}):
                if cause == "trust_artifact_revoked":
                    self.assertEqual(
                        probe.exercise(lambda: reader, Mock(), {}, {"fault": "revocation"}, check),
                        {"fault": "revocation"},
                    )
                else:
                    with self.assertRaises(Rejected):
                        probe.exercise(lambda: reader, Mock(), {}, {"fault": "revocation"}, check)

    def test_outage_cannot_start_without_refresh_pause(self):
        with (
            patch.object(probe.lifecycle, "exercise") as exercise,
            self.assertRaisesRegex(Rejected, "candidate_trust_pause_required"),
        ):
            probe.exercise(Mock(), Mock(), b"{}", {"fault": "outage"}, Mock())
        exercise.assert_not_called()

    def test_wrong_cold_cause_acceptance_or_recovered_identity_reject(self):
        def check(label, actual, expected):
            if type(actual) is not type(expected) or actual != expected:
                raise Rejected(label)

        for fault, cause, model in (
            ("outage", Rejected("trust_service_unavailable"), "a" * 64),
            ("blackhole", trust.Unavailable("PRIVATE"), "a" * 64),
            ("policy-change", Rejected("trust_key_revoked"), "a" * 64),
            ("policy-change", None, "a" * 64),
            ("policy-change", Rejected("trust_policy_changed"), "c" * 64),
        ):
            cold, restored = Mock(), Mock()
            cold.load.side_effect = cause
            restored.load.return_value.model_sha256 = model
            restored.load.return_value.subject_sha256 = "b" * 64

            def lifecycle(*args, on_denied, **kwargs):
                on_denied()
                return {"fault": fault}

            with (
                self.subTest(fault=fault, cause=type(cause).__name__, model=model[0]),
                patch.object(probe.lifecycle, "exercise", side_effect=lifecycle),
                self.assertRaises(Rejected),
            ):
                probe.exercise(
                    Mock(side_effect=[cold, restored]),
                    Mock(),
                    b"{}",
                    {"fault": fault, "model": "a" * 64, "bundle": "b" * 64},
                    check,
                    pause=Mock(),
                )

    def test_nonterminal_fault_requires_exact_cold_denial_then_same_candidate_recovery(self):
        for fault, cause in (
            ("outage", trust.Unavailable("trust_service_unavailable")),
            ("blackhole", trust.Unavailable("trust_service_unavailable")),
            ("policy-change", Rejected("trust_policy_changed")),
        ):
            readers = [Mock(), Mock()]
            readers[0].load.side_effect = cause
            readers[1].load.return_value.model_sha256 = "a" * 64
            readers[1].load.return_value.subject_sha256 = "b" * 64
            events = []

            def exercise(*args, on_denied, **kwargs):
                events.append("authority-unavailable-or-incompatible")
                on_denied()
                events.append("restored-and-fenced")
                return {"fault": fault}

            def check(label, actual, expected):
                self.assertIs(type(actual), type(expected), label)
                self.assertEqual(actual, expected, label)

            with patch.object(probe.lifecycle, "exercise", side_effect=exercise):
                result = probe.exercise(
                    Mock(side_effect=readers),
                    Mock(),
                    b"{}",
                    {"fault": fault, "model": "a" * 64, "bundle": "b" * 64},
                    check,
                    pause=Mock(),
                )
            self.assertEqual(result["fault"], fault)
            self.assertEqual(
                events, ["authority-unavailable-or-incompatible", "restored-and-fenced"]
            )
            for reader in readers:
                reader.load.assert_called_once()

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
            probe.exercise(Mock(), Mock(), b"{}", {"fault": "unknown-revocation"}, Mock())
        exercise.assert_not_called()


if __name__ == "__main__":
    unittest.main()
