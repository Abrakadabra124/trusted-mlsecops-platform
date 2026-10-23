import base64
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import audit_evidence, audit_snapshot, release_bundle, signing
from mlsecops.contracts import Rejected, canonical, decode, digest, write_json
from scripts import audit_correlation_probe, release_bundle_qualification
from scripts import serving_output_native as native
from scripts.audit_evidence_qualification import fixture
from scripts.audit_export_qualification import encoded, records
from scripts.candidate_serving_reader import KIND


class ParentPacketContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        release_bundle_qualification.ReleaseBundleContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        release_bundle_qualification.ReleaseBundleContracts.tearDownClass()

    def setUp(self):
        self.bundle = release_bundle_qualification.ReleaseBundleContracts()
        self.bundle.setUp()
        self.addCleanup(self.bundle.doCleanups)
        self.package = self.bundle.create()
        self.verified = self.bundle.check(self.package)
        self.context = self.bundle.materials.context
        self.source = self.context["expected"]
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.state = self.root / "state"
        self.campaign = "d" * 32
        self.destination = self.state / "serving-qualifications" / self.campaign
        self.key = self.root / "qualification.pem"
        self.public = signing.create_key(self.key)
        self.subject = {
            "proposal_reference": digest(canonical(self.package["envelope"])),
            "subject_sha256": self.verified["subject_sha256"],
            "model_sha256": digest(self.verified["model"]),
            "candidate_reference": self.context["candidate_reference"],
            "evaluation_reference": self.context["evaluation_reference"],
        }
        write_json(self.root / "policies/local-cpu.json", self.context["policy"])
        write_json(self.state / "storage-trust.json", self.context["trust"])
        write_json(self.state / "trusted-keys.json", {"approver": self.bundle.materials.public})
        write_json(
            self.state / "evidence/release-native.json",
            {
                "scope": "release-proposal-and-authorization-denial-not-full-M10",
                "status": "pass",
                "source_dirty": False,
                "release_ready": False,
                "source": self.source,
                **self.subject,
            },
        )
        self.permit = {
            "schema_version": 1,
            "purpose": KIND,
            "campaign_id": self.campaign,
            "environment": self.context["policy"]["environment"],
            "proposal_sha256": self.subject["proposal_reference"],
            "subject_sha256": self.subject["subject_sha256"],
            "model_sha256": self.subject["model_sha256"],
            **self.source,
            "issued_at": self.bundle.clock,
            "expires_at": self.bundle.clock + 600,
        }
        self.envelope = signing.sign(self.permit, KIND, self.key)
        self.expected = audit_correlation_probe.candidate(
            self.package, self.context, self.envelope, self.public, self.bundle.materials.public
        )
        manifest, _, outcomes, _ = fixture()
        chunks = [encoded(records(bound=self.expected))]
        saved = decode(manifest)
        saved["segments"][0].update(size=len(chunks[0]), sha256=digest(chunks[0]))
        from mlsecops import audit_export

        self.content = audit_evidence.create(
            canonical(saved),
            chunks,
            outcomes,
            canonical(audit_export.project(chunks)) + b"\n",
            binding={"campaign_id": self.campaign, "source": self.source},
        )
        self.summary = audit_evidence.verify(
            self.content,
            binding={"campaign_id": self.campaign, "source": self.source},
            expected_context=self.expected,
        )
        self.report = {
            **self.subject,
            "campaign_id": self.campaign,
            "qualification_permit_sha256": digest(canonical(self.permit)),
            "runtime": {
                "audit_evidence": self.summary,
                "http_correlation": self.summary["correlation"],
                "public_audit_window": self.summary["public"],
            },
        }

    def run_check(self, report=None, envelope=None, public=None, content=None):
        write_json(self.destination / "permit.json", envelope or self.envelope)
        write_json(self.destination / "public.json", {"qualification": public or self.public})
        with (
            patch.object(release_bundle, "load", return_value=self.package),
            patch.object(
                audit_snapshot, "load_packet", return_value=content or self.content
            ) as read,
            patch("time.time", return_value=self.bundle.clock + 10),
        ):
            result = native.verify_packet(
                self.root, self.state, self.source, self.campaign, report or self.report
            )
        read.assert_called_once_with(self.destination / "audit-evidence")
        return result

    def test_parent_reloads_real_signed_primary_and_exact_private_packet(self):
        self.assertEqual(self.run_check(), self.summary)
        self.assertFalse(self.summary["release_ready"])

    def test_replayed_campaign_expired_and_invalid_signed_permit_reject(self):
        for fault in ("campaign", "expiry", "signature", "purpose", "image", "publisher-key"):
            permit = copy.deepcopy(self.permit)
            report = copy.deepcopy(self.report)
            if fault == "campaign":
                permit["campaign_id"] = "f" * 32
            if fault == "expiry":
                permit.update(issued_at=self.bundle.clock - 600, expires_at=self.bundle.clock - 1)
            if fault == "purpose":
                permit["purpose"] = "release-approval"
            if fault == "image":
                permit["image_id"] = "sha256:" + "f" * 64
            key = self.bundle.materials.key if fault == "publisher-key" else self.key
            public = self.bundle.materials.public if fault == "publisher-key" else self.public
            envelope = signing.sign(permit, KIND, key)
            if fault == "signature":
                signature = envelope["signatures"][0]
                value = bytearray(base64.b64decode(signature["sig"], validate=True))
                value[0] ^= 1
                signature["sig"] = base64.b64encode(value).decode()
            report["qualification_permit_sha256"] = digest(canonical(permit))
            with self.subTest(fault=fault), self.assertRaises(Rejected):
                self.run_check(report=report, envelope=envelope, public=public)

    def test_agreeing_denial_counts_cannot_replace_the_primary_http_outcome(self):
        report = copy.deepcopy(self.report)
        for correlation in (
            report["runtime"]["http_correlation"],
            report["runtime"]["audit_evidence"]["correlation"],
        ):
            correlation.update(completed_200=0, failed_after_intent=1)
        with self.assertRaisesRegex(Rejected, "serving_output_packet_binding"):
            self.run_check(report=report)

    def test_mismatched_receipt_and_tampered_retained_bytes_reject(self):
        for field in (*self.subject, "qualification_permit_sha256"):
            report = {**self.report, field: "f" * 64}
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.run_check(report=report)
        for section in ("audit_evidence", "http_correlation", "public_audit_window"):
            report = copy.deepcopy(self.report)
            report["runtime"][section] = {}
            with self.subTest(section=section), self.assertRaises(Rejected):
                self.run_check(report=report)
        with self.assertRaises(Rejected):
            self.run_check(content=b"tampered")
        with self.assertRaises(Rejected):
            self.run_check(report={**self.report, "campaign_id": "f" * 32})


if __name__ == "__main__":
    unittest.main()
