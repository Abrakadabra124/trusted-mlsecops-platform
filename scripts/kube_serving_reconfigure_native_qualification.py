"""Native configuration evidence must bind new ownership, state and fresh heartbeat."""

import copy
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from mlsecops import kube_serving_probe
from mlsecops.contracts import Rejected, canonical, digest
from scripts import kube_serving_service_native as subject
from scripts.kube_promotion_native import configuration
from scripts.kube_serving_runtime_qualification import PROFILE


class ConfigurationEvidence(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
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
        config = subject.service.configuration(self.promotion, PROFILE)
        mapping, deployment = subject.service.documents("a" * 32, PROFILE, config)
        self.mapping_key = subject.service.kube_storage.reference(mapping)
        self.deployment_key = subject.service.kube_storage.reference(deployment)
        self.prior = dict(
            workspace_id="a" * 32,
            profile=PROFILE,
            config=config,
            config_sha256=digest(canonical(config)),
            resources={self.mapping_key: "old-map", self.deployment_key: "deployment"},
        )
        self.promotion["expected_policy"] = "d" * 64
        config = subject.service.configuration(self.promotion, PROFILE)
        self.current = {
            **copy.deepcopy(self.prior),
            "config": config,
            "config_sha256": digest(canonical(config)),
        }
        self.current["resources"][self.mapping_key] = "new-map"
        record = {"id": "first", "kind": "identity.denied", "receipt": "signed-first"}
        added = {"id": "second", "kind": "identity.denied", "receipt": "signed-second"}
        self.before = {"pin": "a" * 64, "permissions": {"mode": 384}, "records": [record]}
        self.after = copy.deepcopy(self.before)
        self.after["records"].append(added)
        self.inbox = {"heartbeats": {"serving": 6}, "records": [record, added]}
        self.order = []
        self.stack.enter_context(patch.object(subject, "hosted"))
        self.stack.enter_context(
            patch.object(
                subject.service,
                "validate",
                side_effect=lambda *_: self.prior if not self.order else self.current,
            )
        )
        self.stack.enter_context(
            patch.object(
                subject.kube_security_events,
                "validate",
                return_value={"pins": {"serving": "a" * 64}},
            )
        )
        self.stack.enter_context(
            patch.object(
                subject,
                "snapshot",
                side_effect=lambda *_: self.before if not self.order else self.after,
            )
        )
        self.stack.enter_context(
            patch.object(
                subject.kube_serving_handoff,
                "suspend",
                side_effect=lambda *_: self.order.append("suspend"),
            )
        )
        self.stack.enter_context(
            patch.object(
                subject.kube_serving_handoff,
                "reconfigure",
                side_effect=lambda *_: self.order.append("reconfigure"),
            )
        )

        def resume(*_):
            self.order.append("resume")
            return {"before": "old-http", "after": "new-http", "release_ready": False}

        self.resume = self.stack.enter_context(
            patch.object(subject.kube_serving_handoff, "resume", side_effect=resume)
        )
        self.observe = self.stack.enter_context(
            patch.object(subject, "observe", return_value={"pod_uid": "new-http"})
        )
        self.pod = self.stack.enter_context(
            patch.object(subject.service, "pod", return_value={"metadata": {"uid": "new-http"}})
        )

        def collect(*_):
            self.order.append("collect")
            return (
                {"heartbeats": {"serving": 5}} if self.order.count("collect") == 1 else self.inbox
            )

        self.collector = self.stack.enter_context(
            patch.object(subject.audit, "collector", side_effect=collect)
        )
        self.clock = self.stack.enter_context(
            patch.object(subject.time, "monotonic", side_effect=[0, 1, 1])
        )
        self.sleep = self.stack.enter_context(patch.object(subject.time, "sleep"))

    def run_change(self, ready=True):
        return subject.change_configuration("state", self.promotion, {"ready": ready})

    def test_receipt_counter_and_new_map_are_read_after_serialized_replacement(self):
        result = self.run_change()
        self.assertEqual(self.order, ["suspend", "reconfigure", "collect", "resume", "collect"])
        self.assertEqual((result["heartbeat_before"], result["heartbeat_after"]), (5, 6))
        self.assertEqual(result["identity_events_delivered"], 1)
        self.assertFalse(result["release_ready"])
        self.assertNotEqual(result["configmap_before"], result["configmap_after"])

    def test_unready_configuration_keeps_journal_and_reports_no_fake_receipt(self):
        self.after = copy.deepcopy(self.before)
        result = self.run_change(ready=False)
        self.assertEqual(result["identity_events_delivered"], 0)

    def test_unready_configuration_cannot_change_retained_history(self):
        with self.assertRaisesRegex(Rejected, "refusal_state_changed"):
            self.run_change(ready=False)

    def test_old_map_foreign_deployment_or_changed_identity_cannot_pass(self):
        for target, key, bad in (
            (self.current["resources"], self.mapping_key, "old-map"),
            (self.current["resources"], self.deployment_key, "foreign"),
            (self.current, "config_sha256", self.prior["config_sha256"]),
            (self.after, "pin", "foreign"),
            (self.after, "permissions", {}),
        ):
            original = target[key]
            target[key] = bad
            self.order.clear()
            self.clock.side_effect = [0, 1]
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.run_change()
            target[key] = original

    def test_changed_pod_cannot_claim_restoration(self):
        self.observe.return_value = {"pod_uid": "foreign"}
        with self.assertRaises(Rejected):
            self.run_change()

    def test_old_owner_heartbeat_cannot_satisfy_new_owner_deadline(self):
        self.inbox["heartbeats"]["serving"] = 5
        self.clock.side_effect = [0, 121]
        with self.assertRaisesRegex(Rejected, "heartbeat_deadline"):
            self.run_change()

    def test_replaced_pod_after_observation_cannot_claim_final_state(self):
        self.pod.return_value = {"metadata": {"uid": "unexpected-replacement"}}
        with self.assertRaisesRegex(Rejected, "configuration_binding"):
            self.run_change()

    def test_late_fresh_heartbeat_still_fails_total_budget(self):
        self.clock.side_effect = [0, 121]
        with self.assertRaisesRegex(Rejected, "configuration_binding"):
            self.run_change()

    def test_final_binding_and_receipt_checks_are_inside_total_deadline(self):
        for boundary in ("pod", "receipt"):
            elapsed = [0]
            self.order.clear()
            self.clock.side_effect = lambda: elapsed[0]

            def finish(*args):
                elapsed[0] = 121
                return {"metadata": {"uid": "new-http"}} if boundary == "pod" else 1

            target = subject.service if boundary == "pod" else subject.audit
            name = "pod" if boundary == "pod" else "identity_receipts"
            with (
                self.subTest(boundary=boundary),
                patch.object(target, name, side_effect=finish),
                self.assertRaisesRegex(Rejected, "configuration_binding"),
            ):
                self.run_change()

    def test_exact_deadline_after_receipt_is_measured_and_accepted(self):
        elapsed = [0]
        self.clock.side_effect = lambda: elapsed[0]

        def receipt(*args):
            elapsed[0] = 120
            return 1

        with patch.object(subject.audit, "identity_receipts", side_effect=receipt):
            self.assertEqual(self.run_change()["elapsed_seconds"], 120)

    def test_missing_original_heartbeat_stops_before_new_owner(self):
        self.collector.side_effect = None
        self.collector.return_value = {"heartbeats": {}}
        with self.assertRaisesRegex(Rejected, "heartbeat_missing"):
            self.run_change()
        self.resume.assert_not_called()

    def test_missing_independent_receipt_stays_failed(self):
        self.inbox["records"] = []
        with self.assertRaisesRegex(Rejected, "http_receipt"):
            self.run_change()

    def test_policy_binding_diagnostic_is_finite_and_does_not_disclose_unknown_error(self):
        config = self.prior["config"]
        with (
            patch.object(kube_serving_probe.trust, "Lease"),
            patch.object(kube_serving_probe.release_reader, "Reader") as reader,
        ):
            reader.return_value.load.side_effect = Rejected("serving_head_binding")
            self.assertEqual(kube_serving_probe.diagnose(config), "reader-serving_head_binding")
            reader.return_value.load.side_effect = Rejected("private-canary")
            self.assertEqual(kube_serving_probe.diagnose(config), "reader-other-refusal")


if __name__ == "__main__":
    unittest.main()
