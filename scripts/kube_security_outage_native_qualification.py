"""Mode conflicts must reject before touching the hosted infrastructure."""

import copy
import dataclasses
import io
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import security_outage_packet
from mlsecops.contracts import Rejected, canonical, digest, write_json
from mlsecops.security_outage_exchange import PHASES
from scripts import kube_candidate_native as candidate
from scripts import kube_serving_native as serving
from scripts.kube_serving_runtime_qualification import PROFILE
from scripts.security_outage_packet_qualification import fixture, timeline


class OutageCompositionContracts(unittest.TestCase):
    def test_native_entrypoint_rejects_unowned_host_without_disclosing_exception(self):
        from scripts import kube_security_outage_native as native

        with (
            patch("scripts.kube_trust_native.hosted", side_effect=Rejected("PRIVATE")),
            patch.object(sys, "argv", ["security-outage"]),
            patch.object(sys, "stdout", io.StringIO()) as output,
            self.assertRaises(SystemExit) as stopped,
        ):
            runpy.run_path(native.__file__, run_name="__main__")
        self.assertEqual(stopped.exception.code, 1)
        self.assertNotIn("PRIVATE", output.getvalue())

    def test_candidate_conflicts_reject_before_source_and_cluster_reads(self):
        for other in (
            "privacy",
            "load",
            "monitoring",
            "include_key_revocation",
            "include_trust_lifecycle",
        ):
            with patch.object(candidate, "hosted"), patch.object(candidate, "command") as command:
                with self.assertRaises(Rejected):
                    candidate.qualify("unused", "unused", "unused", security=True, **{other: True})
            command.assert_not_called()
        with patch.object(candidate, "hosted"), self.assertRaises(Rejected):
            candidate.qualify("unused", "unused", "unused", security=1)

    def test_probe_conflicts_reject_before_resource_creation(self):
        for options in (
            {},
            {"candidate_probe": True, "privacy_operator": Mock()},
            {"candidate_probe": True, "load_operator": Mock()},
            {"candidate_probe": True, "monitoring_operator": Mock()},
            {"candidate_probe": True, "coordinator": Mock()},
            {"candidate_probe": True, "cli_privacy": True},
            {"candidate_probe": True, "trust_target": serving.Target.MODEL_REVOCATION},
        ):
            with patch.object(serving, "kubectl") as api, self.assertRaises(Rejected):
                serving.invoke(Path("unused"), PROFILE, {}, {}, security_operator=Mock(), **options)
            api.assert_not_called()


class RetentionContracts(unittest.TestCase):
    def setUp(self):
        from scripts import kube_security_outage_native as native

        self.native = native
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "state"
        self.directory = self.state / ("evidence/security-outage/" + "1" * 32)
        self.directory.mkdir(parents=True)
        self.packet, ref, trace, golden = fixture()
        self.summary = security_outage_packet.verify(
            self.packet, reference=ref, context=trace, golden=golden, campaign="1" * 32
        )
        boundary = {
            "status": "pass",
            "release_ready": False,
            "scope": "controlled-authorization-and-trust-real-sql-audit-boundary",
            "audit_checks": 1,
            "audit_denials": 1,
            "audit_check_error": "promotion_audit_unavailable",
            "promotion_error": "promotion_denial_audit_unconfirmed",
            "pending": {
                "event_id": "a" * 64,
                "envelope_sha256": "b" * 64,
                "reason": "audit_unavailable",
                "receipt": None,
                "kind": "promotion.denied",
            },
        }
        recovery = {
            "original_denial": {
                "id": "a" * 64,
                "envelope": "b" * 64,
                "kind": "promotion.denied",
                "receipt": "c" * 64,
            },
            "fault_removed": True,
            "SQL_and_CAS_unchanged": True,
        }
        self.binding = {
            "context": dataclasses.asdict(trace),
            "campaign": "1" * 32,
            "reference": ref,
            "golden": {
                "body": golden.body.decode(),
                "model": golden.model,
                "bundle": golden.bundle,
                "score": golden.score,
            },
            "summary": self.summary,
            "boundary": boundary,
            "recovery": recovery,
            "base_snapshot_sha256": "d" * 64,
        }
        source = {
            "source_revision": "f" * 40,
            "source_fingerprint": "e" * 64,
            "image_id": "sha256:" + "d" * 64,
        }
        self.primary = {
            "source": source,
            "source_dirty": False,
            "release_ready": False,
            "full_M23": "inconclusive",
            "security_campaign_id": "1" * 32,
            "qualification_permit_sha256": trace.permit_sha256,
            "proposal_reference": trace.proposal_sha256,
            "subject_sha256": trace.bundle_sha256,
            "model_sha256": trace.model_sha256,
            "base_snapshot_sha256": "d" * 64,
            "native": {
                **self.summary,
                "operator_retained_reverified": self.summary,
                "worker_cleanup_verified": True,
                "audit_boundary": boundary,
                "recovery": recovery,
            },
        }
        self.operator = {
            "campaign": "1" * 32,
            "phases": list(PHASES),
            "requests": {},
            "results": {},
            "timeline": timeline(),
        }
        for phase in PHASES:
            payload = {"packet": self.packet, "summary": self.summary} if phase == "finish" else {}
            self.operator["requests"][phase] = digest(
                canonical({"phase": phase, "campaign": "1" * 32, "payload": payload})
            )
            self.operator["results"][phase] = (
                {"packet_sha256": self.summary["packet_sha256"]} if phase == "finish" else {}
            )
        self.public = {"source": source, "method_materials": {"method": "f" * 64}}
        self.publish()

    def publish(self):
        write_json(self.directory / "packet.json", self.packet)
        self.binding["packet_hash"] = digest((self.directory / "packet.json").read_bytes())
        write_json(self.directory / "binding.json", self.binding)
        write_json(self.directory / "operator.json", self.operator)
        write_json(self.state / self.native.PRIVATE, self.primary)
        self.public["primary_sha256"] = digest((self.state / self.native.PRIVATE).read_bytes())
        self.public["retained_sha256"] = {
            name: digest((self.directory / name).read_bytes())
            for name in ("binding.json", "packet.json", "operator.json")
        }
        write_json(self.state / self.native.PUBLIC, self.public)

    def verify(self):
        with (
            patch.object(self.native, "command", return_value="f" * 40),
            patch.object(self.native, "source_fingerprint", return_value="e" * 64),
            patch.object(self.native, "materials", return_value={"method": "f" * 64}),
        ):
            return self.native.reverify(self.root, self.state)

    def test_primary_replay_uses_retained_files_without_infrastructure(self):
        with patch.object(self.native.kube_storage, "admin") as sql:
            self.assertTrue(self.verify()["retained_primary_reverified"])
        sql.assert_not_called()

    def test_changed_packet_rejected_before_acceptance(self):
        (self.directory / "packet.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(Rejected):
            self.verify()

    def test_precollected_green_windows_do_not_prove_later_operator_outage(self):
        self.operator["timeline"] = {
            phase: {
                "started_at_ms": 10000 + index * 1000,
                "finished_at_ms": 10500 + index * 1000,
                "started_ns": (10000 + index * 1000) * 1000000,
                "finished_ns": (10500 + index * 1000) * 1000000,
            }
            for index, phase in enumerate(PHASES[:-1])
        }
        self.operator["timeline"]["finish"] = {"started_at_ms": 15000, "started_ns": 15000000000}
        self.publish()
        with self.assertRaises(Rejected):
            self.verify()

    def test_rehashed_lineage_from_foreign_commit_is_not_current_source(self):
        from mlsecops.audit_lineage import checked
        from mlsecops.load_golden import Golden
        from mlsecops.serving_context import QualificationTrace

        context = self.binding["context"]
        context["lineage"]["source_revision"] = "0" * 40
        self.packet["context"] = copy.deepcopy(context)
        trace = QualificationTrace(
            *(
                context[name]
                for name in ("permit_sha256", "proposal_sha256", "bundle_sha256", "model_sha256")
            ),
            checked(context["lineage"]),
        )
        # Closed windows carry the same lineage. Rebuild their derived hashes,
        # not a trivially inconsistent tamper that the existing verifier catches.
        from mlsecops import monitoring, monitoring_stream

        reference = self.binding["reference"]
        evaluator = monitoring.Evaluator(reference, digest(canonical(reference)))
        for item in self.packet["windows"]:
            old = item["document"]
            stream = monitoring_stream.Accumulator(
                reference, digest(canonical(reference)), started_at_ms=old["started_at_ms"]
            )
            for record in item["http"]:
                stream.add(
                    trace,
                    record["features"],
                    record["response"]["predictions"],
                    record["response"]["request_id"],
                )
            closed = stream.close(sequence=old["sequence"], ended_at_ms=old["ended_at_ms"])
            item["document"] = closed.document()
            item["monitor"]["reports"] = [evaluator.evaluate(closed.document())]
        golden = self.binding["golden"]
        self.summary = security_outage_packet.verify(
            self.packet,
            reference=reference,
            context=trace,
            golden=Golden(
                golden["body"].encode(), golden["model"], golden["bundle"], golden["score"]
            ),
            campaign="1" * 32,
        )
        self.binding["summary"] = self.summary
        self.primary["native"].update(self.summary)
        self.primary["native"]["operator_retained_reverified"] = self.summary
        self.operator["requests"]["finish"] = digest(
            canonical(
                {
                    "phase": "finish",
                    "campaign": "1" * 32,
                    "payload": {"packet": self.packet, "summary": self.summary},
                }
            )
        )
        self.operator["results"]["finish"] = {"packet_sha256": self.summary["packet_sha256"]}
        self.publish()
        with self.assertRaises(Rejected):
            self.verify()

    def test_rehashed_semantic_tampering_of_fault_cleanup_and_binding_rejected(self):
        for target, field, value in (
            (self.binding["recovery"], "fault_removed", False),
            (self.binding["recovery"], "SQL_and_CAS_unchanged", False),
            (self.binding["boundary"], "audit_checks", 0),
            (self.binding["boundary"], "audit_check_error", "release_assurance_required"),
            (self.primary, "proposal_reference", "1" * 64),
            (self.operator["requests"], "attempt", "0" * 64),
        ):
            original = copy.deepcopy(target[field])
            target[field] = value
            self.publish()
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.verify()
            target[field] = original
        self.publish()


if __name__ == "__main__":
    unittest.main()
