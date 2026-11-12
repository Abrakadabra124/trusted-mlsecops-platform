"""Reject incomplete hosted handoff evidence without starting infrastructure."""

import copy
import unittest
from contextlib import ExitStack, contextmanager
from unittest.mock import patch

from mlsecops.contracts import Rejected
from scripts import kube_serving_native as probe
from scripts import kube_serving_service_native as subject


class HandoffEvidence(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.order = []
        record = {"id": "first", "kind": "identity.denied", "receipt": "signed-first"}
        added = {"id": "second", "kind": "identity.denied", "receipt": "signed-second"}
        self.before = {"pin": "a", "permissions": {"mode": 384}, "records": [record]}
        self.after = copy.deepcopy(self.before)
        self.after["records"].append(added)
        self.inbox = {"heartbeats": {"serving": 5}, "records": [record, added]}

        @contextmanager
        def transfer(state):
            self.order.append("old-owner-removed")
            result = {"before": "old"}
            try:
                yield result
            finally:
                self.order.append("original-owner-restored")
                result.update(after="new", release_ready=False)

        self.stack.enter_context(patch.object(subject, "hosted"))
        self.stack.enter_context(
            patch.object(
                subject.kube_security_events, "validate", return_value={"pins": {"serving": "a"}}
            )
        )
        self.stack.enter_context(patch.object(subject.kube_serving_handoff, "transfer", transfer))
        self.stack.enter_context(patch.object(probe, "serving_configuration", return_value={}))
        self.invoke = self.stack.enter_context(
            patch.object(probe, "invoke", side_effect=lambda *a: self.order.append("real-probe"))
        )
        self.snapshot = self.stack.enter_context(
            patch.object(subject, "snapshot", side_effect=[self.before, self.after])
        )
        self.observe = self.stack.enter_context(
            patch.object(subject, "observe", return_value={"pod_uid": "new"})
        )
        self.collector = self.stack.enter_context(
            patch.object(
                subject.audit,
                "collector",
                side_effect=[{"heartbeats": {"serving": 4}}, self.inbox],
            )
        )
        self.clock = self.stack.enter_context(
            patch.object(subject.time, "monotonic", side_effect=[0, 1])
        )
        self.sleep = self.stack.enter_context(patch.object(subject.time, "sleep"))

    def run_handoff(self, **expected):
        return subject.handoff("state", "profile", "promotion", {"ready": True, **expected})

    def test_return_needs_new_owner_counter_and_retained_receipted_events(self):
        self.collector.side_effect = [
            {"heartbeats": {"serving": 4}},
            {"heartbeats": {"serving": 4}},
            self.inbox,
        ]
        self.clock.side_effect = [0, 0.5, 1]
        report = self.run_handoff()
        self.assertEqual(self.order, ["old-owner-removed", "real-probe", "original-owner-restored"])
        self.assertEqual(report["return_heartbeat_before"], 4)
        self.assertEqual(report["return_heartbeat_after"], 5)
        self.assertEqual(report["identity_events_delivered"], 1)
        self.assertFalse(report["release_ready"])
        self.sleep.assert_called_once_with(0.5)
        self.assertEqual(self.invoke.call_args.args[2]["kubernetes_worker"], "profile")

    def test_unready_expectation_cannot_run_or_claim_transfer(self):
        with self.assertRaisesRegex(Rejected, "expected_active"):
            self.run_handoff(ready=False)
        self.invoke.assert_not_called()
        self.snapshot.assert_not_called()

    def test_missing_probe_heartbeat_stays_failed_after_owner_return(self):
        self.collector.side_effect = [{"heartbeats": {}}]
        with self.assertRaisesRegex(Rejected, "heartbeat_missing"):
            self.run_handoff()
        self.assertEqual(self.order[-1], "original-owner-restored")
        self.observe.assert_not_called()

    def test_stale_counter_cannot_satisfy_return_deadline(self):
        self.collector.side_effect = [{"heartbeats": {"serving": 4}}] * 2
        self.clock.side_effect = [0, 120]
        with self.assertRaisesRegex(Rejected, "heartbeat_deadline"):
            self.run_handoff()

    def test_late_counter_or_replaced_pod_is_not_accepted(self):
        self.clock.side_effect = [0, 121]
        with self.assertRaisesRegex(Rejected, "return_changed"):
            self.run_handoff()

    def test_probe_of_another_pod_is_not_proof_of_returned_owner(self):
        self.observe.return_value = {"pod_uid": "unexpected"}
        with self.assertRaisesRegex(Rejected, "return_changed"):
            self.run_handoff()

    def test_changed_permissions_are_rejected(self):
        self.after["permissions"] = {"mode": 511}
        with self.assertRaisesRegex(Rejected, "identity_changed"):
            self.run_handoff()

    def test_wrong_registered_identity_is_rejected(self):
        self.before["pin"] = "foreign"
        with self.assertRaisesRegex(Rejected, "identity_changed"):
            self.run_handoff()

    def test_returned_identity_cannot_change_pin_or_drop_receipts(self):
        self.after["pin"] = "foreign"
        with self.assertRaisesRegex(Rejected, "http_receipt"):
            self.run_handoff()

    def test_outbox_success_without_independent_receipt_is_rejected(self):
        self.inbox["records"] = self.before["records"]
        with self.assertRaisesRegex(Rejected, "http_receipt"):
            self.run_handoff()

    def test_failed_actual_probe_is_not_hidden_by_owner_return(self):
        self.invoke.side_effect = Rejected("actual_probe_failed")
        with self.assertRaisesRegex(Rejected, "actual_probe_failed"):
            self.run_handoff()
        self.assertEqual(self.order[-1], "original-owner-restored")
        self.observe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
