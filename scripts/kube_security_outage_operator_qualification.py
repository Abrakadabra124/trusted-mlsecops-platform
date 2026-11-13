"""Failure and identity boundaries of the hosted outage coordinator."""

import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from mlsecops.contracts import Rejected, canonical, read_json, write_json
from mlsecops.security_event_ledger import Ledger
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

    def test_failed_exec_has_bounded_container_exit_grace_and_other_errors_fail_immediately(self):
        for stderr in (b"container not found", b"PRIVATE-unclassified"):
            response = SimpleNamespace(stdout=b"", stderr=stderr, returncode=1)
            with (
                patch.object(module, "kubectl", return_value=response),
                patch.object(module.time, "monotonic", return_value=10),
            ):
                if stderr == b"container not found":
                    self.op._observe(self.pod)
                    self.assertEqual(self.op.exit_deadline, 15)
                    self.op._observe(self.pod)
                    self.op.exit_deadline = 9
                with self.assertRaises(Rejected):
                    self.op._observe(self.pod)

    def test_retry_of_nonlast_phase_cannot_repeat_earlier_fault(self):
        with patch.object(self.op, "act", return_value={}):
            self.observe({"phase": "ready", "campaign": "1" * 32, "payload": {}})
            self.observe({"phase": "outage", "campaign": "1" * 32, "payload": {}})
            with self.assertRaises(Rejected):
                self.observe({"phase": "ready", "campaign": "1" * 32, "payload": {}})

    def test_finish_ack_has_no_private_payload_and_diagnostic_limit_is_enforced(self):
        self.op.phases = list(module.exchange.PHASES[:-1])
        with patch.object(self.op, "act", return_value={"packet_sha256": "a" * 64}):
            self.observe(
                {
                    "phase": "finish",
                    "campaign": "1" * 32,
                    "payload": {"packet": self.packet, "summary": {}},
                }
            )
        retained = read_json(self.op.destination / "operator.json")
        self.assertEqual(retained["results"]["finish"], {"packet_sha256": "a" * 64})
        self.assertNotIn("finished_at_ms", retained["timeline"]["finish"])
        with (
            patch.object(self.op, "_observe", side_effect=Rejected("PRIVATE")),
            patch.object(module, "kubectl", return_value=SimpleNamespace(stdout=b"x" * 65537)),
            patch("sys.stdout", io.StringIO()) as output,
        ):
            with self.assertRaises(Rejected):
                self.op.observe(self.pod)
        self.assertNotIn("probe", json.loads(output.getvalue()))
        self.assertFalse((self.op.destination / "failed-child-private.log").exists())


class RecoveryRetentionContracts(unittest.TestCase):
    def setUp(self):
        from scripts.kube_security_outage_native_qualification import RetentionContracts

        self.fx = RetentionContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        _, reference, context, golden = fixture()
        self.op = module.Coordinator(
            self.fx.state, self.fx.marker["profile"], "2" * 32, reference, context, golden
        )
        self.op.marker = self.fx.marker
        self.op.before = {}
        self.op.boundary = self.fx.binding["boundary"]
        self.op.fault = MagicMock()

    def recover(self, *, failure=None, marker=None, records=None, steps=None):
        packet = copy.deepcopy(self.fx.binding["recovery"]["signed_evidence"])
        projection = self.fx.binding["recovery"]["original_denial"]
        steps = [] if steps is None else steps

        def clock():
            steps.append("timestamp")
            return 4025_999999

        with (
            patch.object(module.time, "time_ns", side_effect=clock),
            patch.object(module.audit, "health", side_effect=lambda *args: steps.append("health")),
            patch.object(
                module.audit.kube_security_events,
                "validate",
                return_value=self.fx.marker if marker is None else marker,
            ),
            patch.object(module, "snapshot", return_value={}),
            patch.object(
                module.audit,
                "job",
                return_value={
                    "pin": "2" * 64,
                    "records": [projection] if records is None else records,
                },
            ),
            patch.object(module.audit, "collector", return_value={"records": [projection]}),
            patch.object(
                module.audit,
                "private_outbox",
                create=True,
                return_value=packet["outbox"],
                side_effect=failure,
            ),
            patch.object(
                module.audit, "private_collector", create=True, return_value=packet["collector"]
            ),
        ):
            return self.op.act("recover", {})

    def test_recover_retains_full_signed_packet_before_worker_cleanup(self):
        self.recover()
        self.assertIn("signed_evidence", self.op.recovery)
        self.assertEqual(
            self.op.recovery["signed_evidence"], self.fx.binding["recovery"]["signed_evidence"]
        )
        self.assertEqual(read_json(self.op.destination / "recovery.json"), self.op.recovery)

    def test_fault_removal_is_timestamped_after_verified_close_before_health(self):
        steps = []
        self.op.fault.__exit__.side_effect = lambda *args: steps.append("closed")
        # recover has started, but its completion clocks do not exist during capture.
        self.op.timeline = {"recover": {"started_at_ms": 4020, "started_ns": 4020_000000}}
        self.recover(steps=steps)
        self.assertEqual(steps, ["closed", "timestamp", "health"])
        self.assertEqual(self.op.recovery.get("fault_removed_at_ms"), 4025)
        self.assertNotIn("finished_at_ms", self.op.timeline["recover"])

    def test_failed_close_never_records_fault_removal_or_runs_drain(self):
        steps = []
        self.op.fault.__exit__.side_effect = Rejected("cleanup_unverified")
        with self.assertRaisesRegex(Rejected, "cleanup_unverified"):
            self.recover(steps=steps)
        self.assertEqual(steps, [])
        self.assertIsNone(self.op.recovery)
        self.assertFalse((self.op.destination / "recovery.json").exists())

    def test_failed_private_readback_cannot_fall_back_to_hash_only_success(self):
        with self.assertRaises(Rejected):
            self.recover(failure=Rejected("private_read_failed"))
        self.assertIsNone(self.op.recovery)
        self.assertIsNone(self.op.fault)

    def test_start_and_attempt_require_validated_owner_and_unchanged_snapshot(self):
        with (
            patch.object(module, "hosted"),
            patch.object(
                module.audit.kube_security_events, "validate", return_value=self.fx.marker
            ),
            patch.object(module, "snapshot", return_value={}),
        ):
            self.op.start()
        with patch.object(module.audit, "health"):
            self.assertEqual(self.op.act("ready", {}), {})
        with (
            patch.object(
                module.kube_security_boundary, "invoke", return_value=self.fx.binding["boundary"]
            ),
            patch.object(module, "snapshot", return_value={}),
        ):
            self.assertEqual(self.op.act("attempt", {}), {})
        with (
            patch.object(
                module.kube_security_boundary, "invoke", return_value=self.fx.binding["boundary"]
            ),
            patch.object(module, "snapshot", return_value={"changed": True}),
            self.assertRaises(Rejected),
        ):
            self.op.act("attempt", {})

    def test_phase_preconditions_refuse_missing_fault_missing_denial_and_active_fault(self):
        for phase, fault, boundary, payload in (
            ("outage", self.op.fault, self.op.boundary, {}),
            ("attempt", None, self.op.boundary, {}),
            ("recover", None, self.op.boundary, {}),
            ("recover", self.op.fault, None, {}),
            ("wrong", None, None, {}),
            ("ready", None, None, {"foreign": True}),
        ):
            self.op.fault, self.op.boundary = fault, boundary
            with self.subTest(phase=phase), self.assertRaises(Rejected):
                self.op.act(phase, payload)

    def test_recover_rejects_changed_owner_and_missing_original_delivery(self):
        with self.assertRaisesRegex(Rejected, "identity_changed"):
            self.recover(marker={**self.fx.marker, "ready": False})
        self.op.fault = MagicMock()
        with self.assertRaisesRegex(Rejected, "recovery_binding"):
            self.recover(records=[])
        self.assertIsNone(self.op.recovery)

    def complete(self):
        self.recover()
        # The controlled packet uses campaign 1; its independent test directory
        # uses campaign 2 to avoid adopting the retention fixture's directory.
        self.op.campaign = "1" * 32
        self.op.phases = list(module.exchange.PHASES[:-1])
        self.op.timeline = copy.deepcopy(self.fx.operator["timeline"])
        result = self.op.act("finish", {"packet": self.fx.packet, "summary": self.fx.summary})
        self.op.phases.append("finish")
        return result

    def test_complete_recovery_replays_after_worker_cleanup_and_keeps_private_binding(self):
        self.assertEqual(self.complete(), {"packet_sha256": self.fx.summary["packet_sha256"]})
        with patch.object(module, "kubectl", side_effect=AssertionError("no cluster replay")):
            self.assertEqual(self.op.reverify(), self.fx.summary)
            report = {**self.fx.summary, "worker_cleanup_verified": True}
            result = self.op.finish(report, canonical(report) + b"\n")
        self.assertIn("signed_evidence", result["recovery"])
        self.assertEqual(
            read_json(self.op.destination / "binding.json")["recovery"], result["recovery"]
        )
        for raw, value in ((b"PRIVATE", report), (canonical({}) + b"\n", {})):
            with self.assertRaises(Rejected):
                self.op.finish(value, raw)

    def test_finish_rejects_wrong_summary_before_retaining_packet(self):
        self.recover()
        self.op.campaign = "1" * 32
        self.op.phases = list(module.exchange.PHASES[:-1])
        with self.assertRaisesRegex(Rejected, "summary"):
            self.op.act("finish", {"packet": self.fx.packet, "summary": {}})
        self.assertFalse((self.op.destination / "packet.json").exists())

    def test_finish_and_post_cleanup_replay_reject_historical_signed_recovery(self):
        self.complete()
        self.fx.signed_recovery(
            queued_at_ms=1200, ingested_at_ms=1300, routed_at_ms=1400, acknowledged_at_ms=1500
        )
        self.op.recovery = copy.deepcopy(self.fx.binding["recovery"])
        write_json(self.op.destination / "recovery.json", self.op.recovery)
        with self.assertRaisesRegex(Rejected, "recovery_timeline"):
            self.op.reverify()
        self.op.phases = list(module.exchange.PHASES[:-1])
        with self.assertRaisesRegex(Rejected, "recovery_timeline"):
            self.op.act("finish", {"packet": self.fx.packet, "summary": self.fx.summary})

    def test_outbox_acknowledgement_must_fit_between_route_and_recover_finish(self):
        # The signed receipt is routed at 4035 and the operator finishes recover at 4040.
        for acknowledged in (3040, 5000):
            self.fx.signed_recovery(acknowledged_at_ms=acknowledged)
            self.fx.publish()
            with (
                self.subTest(acknowledged=acknowledged),
                self.assertRaisesRegex(Rejected, "recovery_timeline"),
            ):
                self.fx.verify()

    def test_collector_snapshot_updated_after_recover_cannot_replay(self):
        collector = self.fx.binding["recovery"]["signed_evidence"]["collector"]
        book = Ledger(self.fx.fx.registry, collector["snapshot"])
        book.poll(clock_ms=5000)
        collector["snapshot"] = book.document()
        self.fx.publish()
        with self.assertRaisesRegex(Rejected, "recovery_timeline"):
            self.fx.verify()

    def test_post_cleanup_replay_rejects_missing_lifecycle_changed_packet_summary_and_recovery(
        self,
    ):
        with self.assertRaises(Rejected):
            self.op.reverify()
        self.complete()
        self.op.summary = {}
        with self.assertRaisesRegex(Rejected, "summary_changed"):
            self.op.reverify()
        self.op.summary = self.fx.summary
        original = (self.op.destination / "packet.json").read_bytes()
        write_json(self.op.destination / "packet.json", {})
        with self.assertRaisesRegex(Rejected, "packet_changed"):
            self.op.reverify()
        (self.op.destination / "packet.json").write_bytes(original)
        recovery = copy.deepcopy(self.op.recovery)
        recovery["fault_removed"] = False
        write_json(self.op.destination / "recovery.json", recovery)
        with self.assertRaisesRegex(Rejected, "recovery_changed"):
            self.op.reverify()
        self.op.recovery = recovery
        with self.assertRaisesRegex(Rejected, "refusal_or_recovery_changed"):
            self.op.reverify()


if __name__ == "__main__":
    unittest.main()
