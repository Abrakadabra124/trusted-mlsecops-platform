"""Each controlled trust Job stays separate inside one explicit owner window."""

import copy
import importlib.util
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from mlsecops.contracts import Rejected


class ControlledTrustCampaign(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("scripts.kube_controlled_trust_campaign"))
        from scripts import kube_controlled_trust_campaign

        self.subject = kube_controlled_trust_campaign
        self.order = []
        self.inputs = []
        self.fail_at = None
        self.config = {"trust_root": "old", "minimum_trust_version": 2}
        self.rollback = copy.deepcopy(self.config)
        self.expected = {"ready": True, "model": "model", "bundle": "bundle"}
        self.rotation = {"next_public": "new", "receipt": {"version": 3}}
        self.enterContext(patch.object(self.subject, "hosted"))

        def owner(state, profile, operation):
            self.order.append("suspend")
            try:
                value = operation()
                return {"value": value, "ownership": {"verified": True}}
            finally:
                self.order.append("resume")

        @contextmanager
        def coordinator(state, fault, policy, key, model):
            self.order.append("start-" + fault)
            try:
                yield fault
            finally:
                self.order.append("restore-" + fault)

        def probe(state, profile, config, expected, **options):
            self.inputs.append(copy.deepcopy((config, expected, options)))
            index = len(self.inputs)
            self.order.append("probe-" + str(index))
            try:
                if self.fail_at == index:
                    raise Rejected("probe-failed-" + str(index))
                return {"probe": index, "status": "pass"}
            finally:
                self.order.append("cleanup-" + str(index))

        self.owner = self.enterContext(
            patch.object(self.subject.ownership, "run", side_effect=owner)
        )
        self.enterContext(patch.object(self.subject, "Coordinator", side_effect=coordinator))
        self.probe = self.enterContext(
            patch.object(self.subject.probes, "invoke", side_effect=probe)
        )

    def run_campaign(self):
        return self.subject.qualify(
            "state",
            "profile",
            self.config,
            self.rollback,
            self.expected,
            self.rotation,
            "policy",
            "new-key",
            "model",
        )

    def test_seven_jobs_keep_order_and_explicit_root_change_with_one_return(self):
        result = self.run_campaign()
        self.owner.assert_called_once()
        self.assertEqual(self.probe.call_count, 7)
        self.assertEqual(self.order[0], "suspend")
        self.assertEqual(self.order[-2:], ["cleanup-7", "resume"])
        self.assertEqual(self.inputs[0][0]["trust_root"], "old")
        self.assertEqual(self.inputs[0][1]["reader_refusal"], "trust_authority_missing_or_foreign")
        self.assertFalse(self.inputs[0][1]["ready"])
        self.assertTrue(all(config["trust_root"] == "new" for config, _, _ in self.inputs[1:]))
        self.assertEqual(self.config, {"trust_root": "new", "minimum_trust_version": 3})
        self.assertEqual(self.rollback, self.config)
        self.assertEqual(
            [request.get("fault") for _, request, _ in self.inputs[2:6]],
            ["outage", "blackhole", "policy-change", "revocation"],
        )
        self.assertFalse(self.inputs[-1][1]["ready"])
        self.assertEqual(result["value"]["old_config_refusal"]["probe"], 1)
        self.assertEqual(result["value"]["serving"]["probe"], 2)
        self.assertEqual(result["value"]["revoked"]["probe"], 7)
        self.assertEqual(len(result["value"]["live_trust"]), 4)
        self.assertNotIn("ownership", result["value"])
        self.assertEqual(result["ownership"], {"verified": True})
        self.assertEqual(self.expected, {"ready": True, "model": "model", "bundle": "bundle"})

    def test_each_failed_job_stops_following_jobs_and_restores_before_owner_return(self):
        faults = {3: "outage", 4: "blackhole", 5: "policy-change", 6: "revocation"}
        for index in range(1, 8):
            with self.subTest(index=index):
                self.order.clear()
                self.inputs.clear()
                self.config.update(trust_root="old", minimum_trust_version=2)
                self.rollback.update(self.config)
                self.fail_at = index
                with self.assertRaisesRegex(Rejected, "probe-failed-" + str(index)):
                    self.run_campaign()
                self.assertEqual(len(self.inputs), index)
                tail = ["cleanup-" + str(index)]
                if index in faults:
                    tail.append("restore-" + faults[index])
                self.assertEqual(self.order[-len(tail) - 1 :], tail + ["resume"])
                if index == 1:
                    self.assertEqual(self.config["trust_root"], "old")

    def test_return_failure_never_becomes_success(self):
        def owner(state, profile, operation):
            operation()
            raise Rejected("owned_probe_return_binding")

        self.owner.side_effect = owner
        with self.assertRaisesRegex(Rejected, "owned_probe_return_binding"):
            self.run_campaign()
        self.assertEqual(len(self.inputs), 7)

    def test_hosted_guard_rejects_before_owner_or_probe(self):
        self.subject.hosted.side_effect = Rejected("hosted_only")
        with self.assertRaisesRegex(Rejected, "hosted_only"):
            self.run_campaign()
        self.owner.assert_not_called()
        self.probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
