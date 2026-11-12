"""Immutable serving configuration changes while the verified owner is suspended."""

import copy
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import kube_serving_handoff as handoff
from mlsecops.contracts import Rejected, canonical, digest
from scripts.kube_promotion_native import configuration
from scripts.kube_serving_runtime_qualification import PROFILE


class ReconfigureServing(unittest.TestCase):
    def setUp(self):
        self.assertTrue(
            hasattr(handoff, "reconfigure"), "explicit configuration transition missing"
        )
        self.service = handoff.service
        self.promotion = configuration(
            "/client",
            "/trust-client",
            dict(
                context={"policy": {"environment": "local-cpu"}},
                trusted_root="root",
                expected_policy="a" * 64,
                expected_serving_image=PROFILE["image_id"],
            ),
            "authority",
        )
        config = self.service.configuration(self.promotion, PROFILE)
        self.documents = self.service.documents("a" * 32, PROFILE, config)
        self.mapping_key = self.service.kube_storage.reference(self.documents[0])
        self.deployment_key = self.service.kube_storage.reference(self.documents[1])
        self.marker = dict(
            schema_version=1,
            workspace_id="a" * 32,
            ready=False,
            handoff="b" * 32,
            profile=PROFILE,
            config=config,
            config_sha256=digest(canonical(config)),
            audit_pin="c" * 64,
            resources={self.mapping_key: "old-map", self.deployment_key: "deployment"},
        )
        self.ticket = dict(
            nonce=self.marker["handoff"],
            previous="old-http",
            marker_sha256=digest(canonical(self.marker)),
        )
        self.live = copy.deepcopy(self.documents[0])
        self.live["metadata"].update(uid="old-map", resourceVersion="17")
        self.audit = {
            "pins": {"serving": self.marker["audit_pin"]},
            "observer": None,
            "context": {"initial_root": "authority"},
        }
        self.events = []
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(
            patch.object(self.service, "validate", side_effect=lambda *a, **k: self.marker)
        )
        self.stack.enter_context(patch.object(self.service, "directory", return_value="private"))
        self.stack.enter_context(
            patch.object(
                self.service.kube_storage, "get", side_effect=lambda *a: copy.deepcopy(self.live)
            )
        )
        self.audit_reader = self.stack.enter_context(
            patch.object(self.service.kube_security_events, "validate", return_value=self.audit)
        )
        self.stack.enter_context(
            patch.object(
                self.service.kube_security_events.kube_observer_profile,
                "current_root",
                side_effect=lambda *a: self.audit["context"]["initial_root"],
            )
        )
        self.stack.enter_context(
            patch.object(
                self.service.kube_security_events,
                "save",
                side_effect=lambda *a: self.events.append("save"),
            )
        )
        self.empty = self.stack.enter_context(
            patch.object(
                self.service, "wait_empty", side_effect=lambda *a: self.events.append("empty")
            )
        )
        self.jobs = self.stack.enter_context(
            patch.object(handoff, "jobs_empty", side_effect=lambda *a: self.events.append("jobs"))
        )
        self.pods = self.stack.enter_context(
            patch.object(
                handoff, "wait_pods_absent", side_effect=lambda *a: self.events.append("pods")
            )
        )
        self.command = self.stack.enter_context(
            patch.object(handoff, "kubectl", side_effect=self.delete)
        )
        self.create = self.stack.enter_context(
            patch.object(self.service.kube_security_events, "create", side_effect=self.install)
        )

    def delete(self, state, arguments, options):
        self.assertEqual(self.events[:3], ["empty", "jobs", "pods"])
        self.assertEqual(
            arguments,
            [
                "delete",
                "--raw=/api/v1/namespaces/ml-serving/configmaps/release-risk-advisor",
                "-f",
                "-",
            ],
        )
        self.assertEqual(options["preconditions"], {"uid": "old-map", "resourceVersion": "17"})
        self.events.append("delete")
        self.live = None
        return SimpleNamespace(stdout=b"{}")

    def install(self, state, local, marker, document):
        self.assertIsNone(self.live)
        self.assertNotIn(self.mapping_key, marker["resources"])
        self.assertFalse(marker["ready"])
        self.events.append("create")
        self.live = copy.deepcopy(document)
        self.live["metadata"].update(uid="new-map", resourceVersion="19")
        marker["resources"][self.mapping_key] = "new-map"

    def change(self, **updates):
        return handoff.reconfigure(
            "state", self.ticket, {**self.promotion, "expected_policy": "d" * 64, **updates}
        )

    def test_new_map_rebinds_ticket_and_preserves_deployment_identity_and_suspension(self):
        returned = self.change()
        self.assertFalse(self.marker["ready"])
        self.assertEqual(
            self.marker["resources"],
            {self.mapping_key: "new-map", self.deployment_key: "deployment"},
        )
        self.assertEqual(self.marker["audit_pin"], "c" * 64)
        self.assertEqual(returned["nonce"], self.ticket["nonce"])
        self.assertEqual(returned["previous"], self.ticket["previous"])
        self.assertEqual(returned["marker_sha256"], digest(canonical(self.marker)))
        with self.assertRaisesRegex(Rejected, "marker_changed"):
            handoff.resume("state", self.ticket)

    def test_exact_config_retry_does_not_replace_owned_map(self):
        returned = handoff.reconfigure("state", self.ticket, self.promotion)
        self.assertEqual(returned, self.ticket)
        self.command.assert_not_called()
        self.create.assert_not_called()

    def test_unproven_root_or_changed_identity_refuses_before_delete(self):
        self.audit_reader.side_effect = Rejected("unproven-root")
        with self.assertRaises(Rejected):
            self.change(trust_root="new")
        self.audit_reader.side_effect = None
        self.audit["pins"]["serving"] = "f" * 64
        with self.assertRaises(Rejected):
            self.change()
        self.command.assert_not_called()

    def test_historical_root_is_not_a_target_for_new_configuration(self):
        self.audit["context"]["initial_root"] = "rotated-root"
        with self.assertRaises(Rejected):
            self.change()
        self.command.assert_not_called()
        self.change(trust_root="rotated-root")
        self.audit_reader.assert_called_with(
            "state", profile=PROFILE, environment="local-cpu", authority_root="rotated-root"
        )

    def test_credentials_environment_or_image_change_is_not_configuration_only(self):
        for change in (
            {"storage_client": "/foreign"},
            {"trust_client": "/foreign"},
            {"context": {"policy": {"environment": "foreign"}}},
            {"expected_serving_image": "sha256:" + "f" * 64},
        ):
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.change(**change)
        self.command.assert_not_called()

    def test_foreign_jobs_or_unconfirmed_old_processes_prevent_delete(self):
        for check in (self.empty, self.jobs, self.pods):
            check.side_effect = Rejected("unconfirmed")
            with self.assertRaises(Rejected):
                self.change()
            check.side_effect = None
        self.command.assert_not_called()

    def test_foreign_map_or_missing_resource_version_prevents_delete(self):
        for metadata in (
            {"uid": "foreign", "resourceVersion": "17"},
            {"uid": "old-map", "resourceVersion": ""},
        ):
            self.live["metadata"].update(metadata)
            with self.assertRaises(Rejected):
                self.change()
        self.command.assert_not_called()

    def test_failed_deletion_never_creates_replacement(self):
        self.command.side_effect = Rejected("delete-failed")
        with self.assertRaises(Rejected):
            self.change()
        self.create.assert_not_called()
        self.assertFalse(self.marker["ready"])
        with self.assertRaises(Rejected):
            handoff.resume("state", self.ticket)
        rebound = {**self.ticket, "marker_sha256": digest(canonical(self.marker))}
        with self.assertRaises(Rejected):
            handoff.resume("state", rebound)

    def test_unconfirmed_map_disappearance_blocks_creation(self):
        self.command.side_effect = None
        with (
            patch.object(handoff.time, "monotonic", side_effect=[0, 46]),
            self.assertRaisesRegex(Rejected, "configuration_cleanup"),
        ):
            self.change()
        self.create.assert_not_called()
        self.assertIn("configuration_change", self.marker)

    def test_map_deletion_waits_for_readback_before_replacement(self):
        old = copy.deepcopy(self.live)

        def delayed_delete(*_):
            self.events.append("delete")
            self.live = None

        self.command.side_effect = delayed_delete
        with (
            patch.object(self.service.kube_storage, "get", side_effect=[old, old, None]),
            patch.object(handoff.time, "monotonic", return_value=0),
            patch.object(handoff.time, "sleep") as sleep,
        ):
            self.change()
        sleep.assert_called_once_with(0.5)
        self.assertNotIn("configuration_change", self.marker)

    def test_configuration_cannot_change_deployment_spec(self):
        documents = self.service.documents

        def changed(workspace, profile, config):
            mapping, deployment = documents(workspace, profile, config)
            if config["expected_policy"] != self.promotion["expected_policy"]:
                deployment["spec"]["replicas"] = 2
            return mapping, deployment

        with (
            patch.object(self.service, "documents", side_effect=changed),
            self.assertRaises(Rejected),
        ):
            self.change()
        self.command.assert_not_called()

    def test_changed_final_marker_never_gets_a_resumable_ticket(self):
        # Use a separate persisted marker so a final readback cannot be silently
        # accepted merely because the caller's in-memory request still looks valid.
        with (
            patch.object(
                self.service,
                "validate",
                side_effect=[self.marker, {**self.marker, "audit_pin": "f" * 64}],
            ),
            self.assertRaisesRegex(Rejected, "configuration_readback"),
        ):
            self.change()
        self.assertIn("configuration_change", self.marker)

    def test_failed_creation_keeps_suspended_state_and_invalidates_old_ticket(self):
        self.create.side_effect = Rejected("unowned-map-present")
        with self.assertRaises(Rejected):
            self.change()
        self.assertFalse(self.marker["ready"])
        self.assertNotIn(self.mapping_key, self.marker["resources"])
        with self.assertRaises(Rejected):
            handoff.resume("state", self.ticket)


if __name__ == "__main__":
    unittest.main()
