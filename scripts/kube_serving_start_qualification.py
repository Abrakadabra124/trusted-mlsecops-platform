"""An actual HTTP owner and its fresh signed heartbeat must precede admission."""

import importlib.util
import unittest
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected


class ServingStart(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("scripts.kube_serving_start_native"))
        from scripts import kube_serving_start_native

        self.subject = kube_serving_start_native
        self.order = []
        self.enterContext(patch.object(self.subject, "hosted"))
        self.enterContext(
            patch.object(
                self.subject.audit_state, "validate", return_value={"pins": {"serving": "identity"}}
            )
        )
        self.bootstrap = self.enterContext(
            patch.object(
                self.subject.service,
                "bootstrap",
                side_effect=lambda *args: self.order.append("bootstrap") or {"ready": True},
            )
        )
        self.pod = self.enterContext(
            patch.object(self.subject.service, "pod", return_value={"metadata": {"uid": "owned"}})
        )
        self.observe = self.enterContext(
            patch.object(
                self.subject.observations,
                "observe",
                side_effect=lambda *args: self.order.append("HTTP") or {"pod_uid": "owned"},
            )
        )
        self.snapshot = self.enterContext(
            patch.object(self.subject.observations, "snapshot", return_value={"pin": "identity"})
        )
        self.collector = self.enterContext(
            patch.object(
                self.subject.audit,
                "collector",
                side_effect=[{"heartbeats": {"serving": 7}}, {"heartbeats": {"serving": 8}}],
            )
        )
        self.clock = self.enterContext(
            patch.object(self.subject.time, "monotonic", side_effect=[0, 1, 2])
        )
        self.enterContext(patch.object(self.subject.time, "sleep"))

    def test_fresh_heartbeat_and_actual_unready_http_precede_return(self):
        result = self.subject.start("state", "profile", "promotion")
        self.assertEqual(self.order, ["bootstrap", "HTTP"])
        self.assertEqual(result["pod_uid"], "owned")
        self.assertEqual((result["heartbeat_before"], result["heartbeat_after"]), (7, 8))
        self.assertFalse(self.observe.call_args.args[1]["ready"])
        self.assertFalse(result["release_ready"])

    def test_old_counter_cannot_prove_new_owner(self):
        self.collector.side_effect = [{"heartbeats": {"serving": 7}}] * 2
        self.clock.side_effect = [0, 120]
        with self.assertRaisesRegex(Rejected, "heartbeat_deadline"):
            self.subject.start("state", "profile", "promotion")

    def test_late_heartbeat_is_not_accepted(self):
        self.clock.side_effect = [0, 121]
        with self.assertRaises(Rejected):
            self.subject.start("state", "profile", "promotion")

    def test_final_identity_readback_is_inside_deadline(self):
        self.clock.side_effect = [0, 1, 121]
        with self.assertRaisesRegex(Rejected, "heartbeat_deadline"):
            self.subject.start("state", "profile", "promotion")

    def test_changed_pod_or_identity_cannot_prove_startup(self):
        self.pod.side_effect = [{"metadata": {"uid": "owned"}}, {"metadata": {"uid": "other"}}]
        with self.assertRaises(Rejected):
            self.subject.start("state", "profile", "promotion")

    def test_bootstrap_or_http_failure_is_not_a_ready_service(self):
        self.bootstrap.side_effect = Rejected("incomplete-bootstrap")
        with self.assertRaisesRegex(Rejected, "incomplete-bootstrap"):
            self.subject.start("state", "profile", "promotion")
        self.observe.assert_not_called()

    def test_waits_for_a_new_signed_heartbeat(self):
        self.collector.side_effect = [{"heartbeats": {"serving": n}} for n in (7, 7, 8)]
        self.clock.side_effect = [0, 1, 2, 3]
        self.assertEqual(self.subject.start("state", "profile", "promotion")["heartbeat_after"], 8)
        self.subject.time.sleep.assert_called_once_with(0.5)

    def test_actual_observation_and_snapshot_bind_to_the_same_identity(self):
        for changed in ("http", "pin"):
            with self.subTest(changed=changed):
                self.clock.side_effect = [0, 1]
                self.collector.side_effect = [{"heartbeats": {"serving": n}} for n in (0, 1)]
                self.observe.side_effect = None
                self.observe.return_value = {"pod_uid": "other" if changed == "http" else "owned"}
                self.snapshot.return_value = {"pin": "other" if changed == "pin" else "identity"}
                with self.assertRaisesRegex(Rejected, "identity_binding"):
                    self.subject.start("state", "profile", "promotion")

    def test_hosted_guard_and_http_failure_propagate_before_success(self):
        self.subject.hosted.side_effect = Rejected("hosted_only")
        with self.assertRaisesRegex(Rejected, "hosted_only"):
            self.subject.start("state", "profile", "promotion")
        self.bootstrap.assert_not_called()
        self.subject.hosted.side_effect = None
        self.observe.side_effect = Rejected("HTTP_rejected")
        with self.assertRaisesRegex(Rejected, "HTTP_rejected"):
            self.subject.start("state", "profile", "promotion")

    def test_selection_starts_absent_or_matching_context_and_explicitly_changes_other(self):
        expected = {"ready": False}
        directory = Mock()
        with (
            patch.object(self.subject.service, "directory", return_value=directory),
            patch.object(
                self.subject.service,
                "validate",
                return_value={"profile": "profile", "config": "old"},
            ) as validate,
            patch.object(
                self.subject.service, "configuration", return_value="old"
            ) as configuration,
            patch.object(self.subject, "start", return_value="started") as start,
            patch.object(
                self.subject.observations, "change_configuration", return_value="changed"
            ) as change,
        ):
            directory.exists.return_value = False
            self.assertEqual(
                self.subject.select("state", "profile", "promotion", expected=expected), "started"
            )
            validate.assert_not_called()
            directory.exists.return_value = True
            self.assertEqual(
                self.subject.select("state", "profile", "promotion", expected=expected), "started"
            )
            configuration.return_value = "new"
            self.assertEqual(
                self.subject.select("state", "profile", "promotion", expected=expected), "changed"
            )
            change.assert_called_once_with("state", "promotion", expected)
            self.assertEqual(start.call_count, 2)
            validate.return_value = {"profile": "other", "config": "old"}
            with self.assertRaisesRegex(Rejected, "profile_changed"):
                self.subject.select("state", "profile", "promotion", expected=expected)
            validate.side_effect = Rejected("incomplete_marker")
            with self.assertRaisesRegex(Rejected, "incomplete_marker"):
                self.subject.select("state", "profile", "promotion", expected=expected)
            self.assertEqual(start.call_count, 2)


if __name__ == "__main__":
    unittest.main()
