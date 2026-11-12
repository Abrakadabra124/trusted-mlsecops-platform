"""Failure and identity boundaries of the hosted outage coordinator."""

import io
import json
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
        with (
            patch.object(module, "kubectl", return_value=output) as api,
            patch("sys.stdout", io.StringIO()),
        ):
            self.op.observe(self.pod)
        return api

    def test_operator_failure_is_reported_before_cleanup_without_raw_child_output(self):
        for raw in (
            b"PRIVATE-marker",
            canonical(
                {
                    "status": "fail",
                    "release_ready": False,
                    "code": "security_green_probe_rejected",
                    "locations": [
                        {
                            "exception": "KeyError",
                            "source_file": "mlsecops/security_outage_probe.py",
                            "source_line": 10,
                        }
                    ],
                }
            ),
        ):
            self.op.pod = self.pod
            self.op.phases = ["ready"]
            response = SimpleNamespace(stdout=raw, returncode=0)
            with (
                patch.object(
                    self.op, "_observe", create=True, side_effect=Rejected("PRIVATE-marker")
                ),
                patch.object(module, "kubectl", return_value=response),
                patch("sys.stdout", io.StringIO()) as output,
            ):
                with self.assertRaises(Rejected):
                    self.op.observe(self.pod)
            value = json.loads(output.getvalue())
            self.assertEqual(value["code"], "security_outage_operator_rejected")
            self.assertEqual(value["completed_phases"], ["ready"])
            self.assertNotIn("PRIVATE-marker", output.getvalue())
            self.assertEqual("probe" in value, raw != b"PRIVATE-marker")

    def test_order_campaign_and_phase_payload_are_checked_before_fault_action(self):
        for request in (
            {"phase": "outage", "campaign": "1" * 32, "payload": {}},
            {"phase": "ready", "campaign": "2" * 32, "payload": {}},
            {"phase": "ready", "campaign": "1" * 32, "payload": {"unexpected": True}},
        ):
            with patch.object(self.op, "act") as act, self.assertRaises(Rejected):
                self.observe(request)
            act.assert_not_called()

    def test_diagnostic_read_failure_does_not_replace_original_failure(self):
        self.op.pod = self.pod
        original = Rejected("PRIVATE-original")
        with (
            patch.object(self.op, "_observe", side_effect=original),
            patch.object(module, "kubectl", side_effect=OSError("PRIVATE-read")),
            patch("sys.stdout", io.StringIO()) as output,
        ):
            with self.assertRaises(Rejected) as failure:
                self.op.observe(self.pod)
        self.assertIs(failure.exception, original)
        self.assertNotIn("PRIVATE", output.getvalue())
        self.assertNotIn("probe", json.loads(output.getvalue()))

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
