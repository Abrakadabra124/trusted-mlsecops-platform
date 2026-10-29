import copy
import unittest
from unittest.mock import patch

from mlsecops.contracts import Rejected
from scripts import kube_promotion_replay as replay


class ReplayContracts(unittest.TestCase):
    def setUp(self):
        self.previous = dict.fromkeys(
            ("package", "policy_envelope", "assurance_envelope", "approval_envelope", "reports")
        )
        self.previous["context"] = {"candidate_reference": "old"}
        self.decision = {"sequence": 1, "environment": "local-cpu", "expires_at": 1000}
        self.receipt = {
            "state": "recorded-not-activated",
            "environment": "local-cpu",
            "sequence": 2,
            "request_sha256": "a" * 64,
            "proposal_reference": "b" * 64,
            "subject_sha256": "c" * 64,
            "release_ready": False,
            "trust": {"checked_at": 1},
        }
        self.before = {"objects": {"unselected": 0}, "promotion": {"sequence": 2}}
        self.after = {"objects": {"unselected": 3}, "promotion": {"sequence": 2}}
        self.snapshots = self.enterContext(
            patch.object(replay, "snapshot", side_effect=[self.before, self.after, self.after])
        )
        self.verify = self.enterContext(
            patch.object(replay.release_authorization, "verify", return_value=self.decision)
        )
        self.enterContext(patch.object(replay.time, "time", return_value=500))
        self.stage = self.enterContext(patch.object(replay, "stage", return_value={"old": True}))
        self.refusal = {"status": "rejected", "reason": "promotion_sequence_conflict"}
        self.retried = {"status": "recorded-not-activated", "receipt": copy.deepcopy(self.receipt)}
        self.retried["receipt"]["trust"] = {"checked_at": 2}
        self.invoke = self.enterContext(
            patch.object(replay.kube_promotion, "invoke", side_effect=[self.refusal, self.retried])
        )

    def exercise(self):
        return replay.exercise(
            "root", "state", "image", {}, self.previous, {"current": True}, self.receipt
        )

    def test_unselected_cas_writes_are_allowed_but_journal_and_current_retry_stay_unchanged(self):
        result = self.exercise()
        self.assertTrue(result["journal_unchanged"])
        self.assertEqual(result["prior_sequence"], 1)
        self.assertEqual(result["current_sequence"], 2)
        self.assertEqual(result["prior_valid_at_epoch"], 500)
        self.assertEqual(self.verify.call_count, 2)
        self.assertEqual(self.invoke.call_args_list[-1].args[3], {"current": True})

    def test_unknown_refusal_or_silent_success_does_not_prove_replay_protection(self):
        for outcome in ({"status": "rejected"}, {"status": "recorded-not-activated"}):
            self.invoke.side_effect = [outcome]
            self.snapshots.side_effect = [self.before]
            with self.assertRaisesRegex(Rejected, "replay_reason"):
                self.exercise()

    def test_rejected_request_that_changes_selected_journal_is_not_accepted(self):
        self.snapshots.side_effect = [self.before, {**self.after, "promotion": {"sequence": 1}}]
        with self.assertRaisesRegex(Rejected, "replay_journal"):
            self.exercise()

    def test_expiry_cannot_be_mistaken_for_sequence_refusal(self):
        self.verify.side_effect = [self.decision, Rejected("release_expired_or_future_document")]
        with self.assertRaisesRegex(Rejected, "expired"):
            self.exercise()
        self.assertEqual(self.invoke.call_count, 1)

    def test_wrong_prior_sequence_is_rejected_before_storage_mutation(self):
        self.decision["sequence"] = 2
        with self.assertRaisesRegex(Rejected, "replay_sequence"):
            self.exercise()
        self.stage.assert_not_called()
        self.invoke.assert_not_called()

    def test_retry_cannot_select_different_subject_or_write_again(self):
        for changed_receipt, changed_snapshot in ((True, False), (False, True)):
            retry = copy.deepcopy(self.retried)
            if changed_receipt:
                retry["receipt"]["subject_sha256"] = "d" * 64
            self.invoke.side_effect = [self.refusal, retry]
            self.snapshots.side_effect = [
                self.before,
                self.after,
                self.before if changed_snapshot else self.after,
            ]
            with self.assertRaisesRegex(Rejected, "replay_current_retry"):
                self.exercise()
