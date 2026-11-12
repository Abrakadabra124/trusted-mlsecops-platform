"""A failed probe cannot claim success or return a second serving identity owner."""

import copy
import importlib.util
import unittest
from contextlib import contextmanager
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected


class OwnedProbe(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("scripts.kube_owned_probe"))
        from scripts import kube_owned_probe

        self.subject = kube_owned_probe
        self.order = []
        self.marker = {"pins": {"serving": "owned"}}
        self.before = {"pin": "owned", "permissions": {"private": True}, "records": []}
        self.after = copy.deepcopy(self.before)
        self.inbox = {"heartbeats": {"serving": 6}, "records": []}

        @contextmanager
        def transfer(state):
            self.order.append("old-owner-absent")
            report = {"before": "old"}
            try:
                yield report
            finally:
                self.order.append("resume")
                report.update(after="new", release_ready=False)

        self.enterContext(patch.object(self.subject, "hosted"))
        self.enterContext(
            patch.object(self.subject.audit_state, "validate", return_value=self.marker)
        )
        self.enterContext(patch.object(self.subject.handoff, "transfer", transfer))
        self.enterContext(
            patch.object(
                self.subject.observations, "snapshot", side_effect=[self.before, self.after]
            )
        )
        self.collector = self.enterContext(
            patch.object(
                self.subject.audit,
                "collector",
                side_effect=[{"heartbeats": {"serving": 5}}, self.inbox],
            )
        )
        self.enterContext(patch.object(self.subject.service, "validate", return_value={}))
        self.pod = self.enterContext(
            patch.object(self.subject.service, "pod", return_value={"metadata": {"uid": "new"}})
        )
        self.clock = self.enterContext(
            patch.object(self.subject.time, "monotonic", side_effect=[0, 1])
        )
        self.enterContext(patch.object(self.subject.time, "sleep"))

    def operation(self):
        self.order.append("probe-cleaned")
        return {"status": "pass", "release_ready": False}

    def test_probe_cleanup_then_independent_counter_then_resume_and_new_heartbeat(self):
        def collector(*args):
            self.order.append("collector")
            return {"heartbeats": {"serving": 5}} if self.collector.call_count == 1 else self.inbox

        self.collector.side_effect = collector
        result = self.subject.run("state", "profile", self.operation)
        self.assertEqual(
            self.order, ["old-owner-absent", "probe-cleaned", "collector", "resume", "collector"]
        )
        self.assertEqual(result["value"]["status"], "pass")
        self.assertEqual(result["ownership"]["heartbeat_before"], 5)
        self.assertEqual(result["ownership"]["heartbeat_after"], 6)
        self.assertFalse(result["ownership"]["release_ready"])

    def test_failed_probe_restores_fault_and_owner_but_remains_failed(self):
        def failed():
            self.order.append("probe-cleaned")
            raise Rejected("original-probe-failure")

        with self.assertRaisesRegex(Rejected, "original-probe-failure"):
            self.subject.run(
                "state",
                "profile",
                failed,
                restore_failure=lambda: self.order.append("fault-restored"),
            )
        self.assertEqual(
            self.order, ["old-owner-absent", "probe-cleaned", "fault-restored", "resume"]
        )
        self.assertEqual(self.collector.call_count, 2)

    def test_success_does_not_execute_failure_restore_and_observes_returned_owner(self):
        restore = Mock()
        observed = Mock(return_value={"pod_uid": "new"})
        result = self.subject.run(
            "state", "profile", self.operation, restore_failure=restore, after_return=observed
        )
        restore.assert_not_called()
        observed.assert_called_once_with()
        self.assertEqual(result["ownership"]["observation"], {"pod_uid": "new"})

    def test_stale_heartbeat_or_late_return_is_rejected(self):
        self.inbox["heartbeats"]["serving"] = 5
        self.clock.side_effect = [0, 121]
        with self.assertRaises(Rejected):
            self.subject.run("state", "profile", self.operation)

    def test_other_pod_cannot_claim_the_returned_owners_heartbeat(self):
        self.pod.return_value = {"metadata": {"uid": "foreign"}}
        with self.assertRaises(Rejected):
            self.subject.run("state", "profile", self.operation)

    def test_mutated_identity_or_history_is_not_retention(self):
        self.after["records"] = [{"id": "unconfirmed", "receipt": None, "kind": "identity.denied"}]
        with self.assertRaises(Rejected):
            self.subject.run("state", "profile", self.operation)

    def test_failed_probe_without_restore_still_returns_owner_and_reraises(self):
        operation = Mock(side_effect=Rejected("original"))
        observed = Mock()
        with self.assertRaisesRegex(Rejected, "original"):
            self.subject.run("state", "profile", operation, after_return=observed)
        observed.assert_not_called()
        self.assertEqual(self.order, ["old-owner-absent", "resume"])

    def test_uncertain_resume_blocks_readback_and_acceptance(self):
        @contextmanager
        def refused(state):
            yield {"before": "old"}
            raise Rejected("jobs-remain")

        observed = Mock()
        with (
            patch.object(self.subject.handoff, "transfer", refused),
            self.assertRaisesRegex(Rejected, "jobs-remain"),
        ):
            self.subject.run("state", "profile", self.operation, after_return=observed)
        observed.assert_not_called()
        self.assertEqual(self.collector.call_count, 1)


class InvokeRouting(unittest.TestCase):
    def test_existing_marker_requires_owner_and_failure_never_falls_back(self):
        from scripts import kube_owned_probe as subject
        from scripts import kube_serving_native as probe

        for exists in (False, True):
            result = {"status": "pass", "release_ready": False}
            restoration = Mock()

            def owned(state, profile, operation, **kwargs):
                self.assertIs(kwargs["restore_failure"], restoration)
                return {"value": operation(), "ownership": {"verified": True}}

            with (
                self.subTest(exists=exists),
                patch.object(subject, "hosted"),
                patch.object(
                    subject.service,
                    "directory",
                    return_value=Mock(exists=Mock(return_value=exists)),
                ),
                patch.object(probe, "invoke", return_value=result) as call,
                patch.object(subject, "run", side_effect=owned) as run,
            ):
                observed = subject.invoke(
                    "state",
                    "profile",
                    "config",
                    "expected",
                    restore_failure=restoration,
                    candidate_probe=True,
                )
                call.assert_called_once_with(
                    "state", "profile", "config", "expected", candidate_probe=True
                )
                self.assertEqual("ownership_return" in observed, exists)
                if exists:
                    call.reset_mock()
                    run.side_effect = Rejected("suspended-or-invalid")
                    with self.assertRaisesRegex(Rejected, "suspended-or-invalid"):
                        subject.invoke("state", "profile", "config", "expected")
                    call.assert_not_called()
                else:
                    run.assert_not_called()

    def test_hosted_guard_precedes_all_owned_and_legacy_paths(self):
        from scripts import kube_owned_probe as subject

        with (
            patch.object(subject, "hosted", side_effect=Rejected("hosted-only")),
            patch.object(subject.service, "directory") as directory,
        ):
            with self.assertRaisesRegex(Rejected, "hosted-only"):
                subject.invoke("state", "profile", {}, {})
            with self.assertRaisesRegex(Rejected, "hosted-only"):
                subject.run("state", "profile", Mock())
        directory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
