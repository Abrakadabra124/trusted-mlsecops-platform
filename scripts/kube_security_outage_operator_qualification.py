"""Failure and identity boundaries of the hosted outage coordinator."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from mlsecops.contracts import Rejected, canonical
from scripts import kube_security_outage_operator as module
from scripts.kube_serving_runtime_qualification import PROFILE
from scripts.security_outage_packet_qualification import fixture


class OperatorContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.packet, reference, context, golden = fixture()
        self.op = module.Coordinator(self.root, PROFILE, "1" * 32, reference, context, golden)
        self.pod = {"metadata": {"name": "probe", "uid": "owned"}}

    def observe(self, value):
        output = SimpleNamespace(returncode=0, stdout=canonical(value), stderr=b"")
        with patch.object(module, "kubectl", return_value=output) as api:
            self.op.observe(self.pod)
        return api

    def test_order_campaign_and_phase_payload_are_checked_before_fault_action(self):
        for request in (
            {"phase": "outage", "campaign": "1" * 32, "payload": {}},
            {"phase": "ready", "campaign": "2" * 32, "payload": {}},
            {"phase": "ready", "campaign": "1" * 32, "payload": {"unexpected": True}},
        ):
            with patch.object(self.op, "act") as act, self.assertRaises(Rejected):
                self.observe(request)
            act.assert_not_called()

    def test_exact_retry_reacks_without_repeating_mutation_and_changed_body_rejected(self):
        request = {"phase": "ready", "campaign": "1" * 32, "payload": {}}
        with patch.object(self.op, "act", return_value={}) as act:
            self.observe(request)
            self.observe(request)
            self.assertEqual(act.call_count, 1)
            with self.assertRaises(Rejected):
                self.observe({**request, "payload": {"changed": True}})

    def test_replaced_pod_refused_and_close_is_idempotent(self):
        self.observe(None)
        self.pod["metadata"]["uid"] = "foreign"
        with self.assertRaises(Rejected):
            self.observe(None)
        fault = MagicMock()
        self.op.fault = fault
        self.op.close()
        self.op.close()
        fault.__exit__.assert_called_once_with(None, None, None)

    def test_final_packet_requires_completed_actions_and_exact_model_binding(self):
        with self.assertRaises(Rejected):
            self.op.act("finish", {"packet": self.packet, "summary": {}})
        self.assertFalse((self.op.destination / "packet.json").exists())

    def test_failed_generator_cleanup_keeps_owned_descriptor_for_real_retry(self):
        self.op.marker = {"workspace_id": "1" * 32}
        self.op.before = {}
        created = SimpleNamespace(stdout=canonical({"metadata": {"uid": "owned-fault"}}))
        with (
            patch.object(module.audit, "kubectl", return_value=created),
            patch.object(module.audit.kube_storage, "verify_resource"),
            patch.object(module.audit, "health"),
            patch.object(
                module.audit.kube_promotion, "cleanup", side_effect=[Rejected("temporary"), None]
            ) as cleanup,
        ):
            self.op.act("outage", {})
            with self.assertRaises(Rejected):
                self.op.close()
            self.assertIsNotNone(self.op.fault)
            self.op.close()
            self.assertEqual(cleanup.call_count, 2)
            self.assertIsNone(self.op.fault)


if __name__ == "__main__":
    unittest.main()
