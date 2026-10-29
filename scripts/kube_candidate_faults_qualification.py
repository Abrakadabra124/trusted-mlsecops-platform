import copy
import io
import unittest
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected
from mlsecops.trust_targets import Target
from scripts import kube_candidate_faults as target


class CandidateFaultCoordinatorTests(unittest.TestCase):
    def run_faults(
        self,
        *,
        faults=None,
        mutate=None,
        changed=False,
        fail=False,
        expires_at=1600,
        authority=Target.PRIMARY,
    ):
        expected = {"model": "a" * 64, "bundle": "b" * 64}
        states = [{"promotion": 1}, {"promotion": 2 if changed else 1}] * 4
        observed = []

        def invoke(state, profile, config, request, **kwargs):
            observed.append(request["fault"])
            self.assertTrue(kwargs["candidate_probe"])
            self.assertIs(kwargs["trust_target"], authority)
            if fail:
                raise Rejected("controlled_probe_failure")
            result = {
                "status": "pass",
                "release_ready": False,
                "model_sha256": expected["model"],
                "subject_sha256": expected["bundle"],
                "authority_target": authority.value,
                "lifecycle": {"fault": request["fault"]},
            }
            return {**result, **(mutate or {})}

        coordinator = Mock(
            __enter__=Mock(return_value="coordinator"), __exit__=Mock(return_value=False)
        )
        self.last_coordinator = coordinator
        with (
            patch.object(target, "snapshot", side_effect=states),
            patch.object(target.time, "time", return_value=1000),
            patch.object(target, "Coordinator", return_value=coordinator),
            patch.object(target, "invoke", side_effect=invoke),
            patch("sys.stdout", new_callable=io.StringIO),
        ):
            result = target.exercise(
                "state",
                {},
                {"trust_target": authority.value},
                expected,
                key="key",
                policy="c" * 64,
                revoked_key="d" * 64,
                faults=faults or (*target.NONTERMINAL, "key-revocation"),
                expires_at=expires_at,
                target=authority,
            )
        return result, observed, coordinator

    def test_real_faults_are_ordered_before_irreversible_revoke_and_bind_journal(self):
        for faults in (
            target.NONTERMINAL,
            ("key-revocation",),
            (*target.NONTERMINAL, "key-revocation"),
        ):
            result, observed, coordinator = self.run_faults(faults=faults)
            self.assertEqual(tuple(observed), faults)
            self.assertEqual(tuple(result), faults)
            self.assertEqual(coordinator.__exit__.call_count, len(faults))
            self.assertTrue(all(len(v["snapshot_sha256"]) == 64 for v in result.values()))

    def test_wrong_identity_fault_scope_or_journal_cannot_pass(self):
        for mutation in (
            {"status": "fail"},
            {"release_ready": True},
            {"model_sha256": "c" * 64},
            {"subject_sha256": "c" * 64},
            {"lifecycle": {"fault": "foreign"}},
            {"authority_target": "model-revocation"},
        ):
            with (
                self.subTest(mutation=mutation),
                self.assertRaisesRegex(Rejected, "binding_changed"),
            ):
                self.run_faults(mutate=copy.deepcopy(mutation))
        with self.assertRaisesRegex(Rejected, "binding_changed"):
            self.run_faults(changed=True)

    def test_invalid_order_and_expiring_permit_refuse_before_fault_mutation(self):
        with patch.object(target, "Coordinator") as coordinator:
            with self.assertRaisesRegex(Rejected, "fault_order"):
                target.exercise(
                    None,
                    None,
                    None,
                    {},
                    key=None,
                    policy=None,
                    revoked_key=None,
                    faults=("key-revocation", "outage"),
                    expires_at=1600,
                )
            coordinator.assert_not_called()
        with self.assertRaisesRegex(Rejected, "candidate_trust_window"):
            self.run_faults(expires_at=1179)

    def test_probe_error_is_not_converted_into_success(self):
        with self.assertRaisesRegex(Rejected, "controlled_probe_failure"):
            self.run_faults(fail=True)
        self.last_coordinator.__exit__.assert_called_once()

    def test_model_revoke_uses_selected_target_and_rejects_other_faults(self):
        result, observed, _ = self.run_faults(
            faults=("revocation",), authority=Target.MODEL_REVOCATION
        )
        self.assertEqual(observed, ["revocation"])
        self.assertEqual(result["revocation"]["probe"]["authority_target"], "model-revocation")
        for faults in (target.NONTERMINAL, ("key-revocation",)):
            with self.assertRaisesRegex(Rejected, "candidate_trust_fault_order"):
                self.run_faults(faults=faults, authority=Target.MODEL_REVOCATION)

    def test_mismatched_selected_config_refuses_before_mutation(self):
        with patch.object(target, "Coordinator") as coordinator:
            with self.assertRaisesRegex(Rejected, "candidate_trust_fault_order"):
                target.exercise(
                    None,
                    None,
                    {},
                    {},
                    key=None,
                    policy=None,
                    revoked_key=None,
                    faults=("revocation",),
                    expires_at=1600,
                    target=Target.MODEL_REVOCATION,
                )
            coordinator.assert_not_called()
