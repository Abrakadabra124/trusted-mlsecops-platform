import copy
import tempfile
import unittest
from dataclasses import FrozenInstanceError, asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import release_bundle, release_policy, signing, storage, trust
from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts import candidate_serving_reader as qualification
from scripts import release_bundle_qualification as fixtures
from scripts.candidate_lineage_qualification import alternate_public_encoding


class CandidateReaderContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.ReleaseBundleContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.ReleaseBundleContracts.tearDownClass()

    def setUp(self):
        self.bundle = fixtures.ReleaseBundleContracts()
        self.bundle.setUp()
        self.addCleanup(self.bundle.doCleanups)
        self.package = self.bundle.create()
        self.verified = self.bundle.check(self.package)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.key = Path(temporary.name) / "qualification.pem"
        self.public = signing.create_key(self.key)
        self.wall = float(self.bundle.clock)
        self.monotonic = 100.0
        self.failure = None
        self.role = "ml_serving"
        self.permit = {
            "schema_version": 1,
            "purpose": "candidate-serving-qualification",
            "campaign_id": "a" * 32,
            "environment": "local-cpu",
            "proposal_sha256": digest(canonical(self.package["envelope"])),
            "subject_sha256": self.verified["subject_sha256"],
            "model_sha256": digest(self.verified["model"]),
            **self.bundle.materials.context["expected"],
            "issued_at": int(self.wall),
            "expires_at": int(self.wall) + 600,
        }
        self.policy = {
            "schema_version": 1,
            "environment": "local-cpu",
            "version": 1,
            "promotion_policy_sha256": digest(canonical(self.permit)),
            "issued_at": int(self.wall),
            "expires_at": int(self.wall) + 1200,
            "revoked_artifacts": [],
            "revoked_keys": [],
        }
        self.lease = trust.Lease(
            self.read_trust,
            trusted_root=self.public,
            environment="local-cpu",
            minimum_version=1,
            wall_clock=lambda: self.wall,
            monotonic_clock=lambda: self.monotonic,
        )
        for target, field, values in (
            (storage, "connection_parameters", {"side_effect": lambda client: {"user": self.role}}),
            (
                release_bundle,
                "load",
                {"side_effect": lambda *args, **kwargs: copy.deepcopy(self.package)},
            ),
        ):
            patcher = patch.object(target, field, **values)
            patcher.start()
            self.addCleanup(patcher.stop)

    def read_trust(self):
        if self.failure:
            raise self.failure
        return signing.sign(self.policy, "trust-policy", self.key), int(self.wall)

    def reader(self, **changes):
        return qualification.CandidateReader(
            "serving",
            **{
                "context": self.bundle.materials.context,
                "publisher_public": self.bundle.materials.public,
                "proposal_reference": self.permit["proposal_sha256"],
                "permit_envelope": signing.sign(self.permit, qualification.KIND, self.key),
                "permit_public": self.public,
                "expected_permit": digest(canonical(self.permit)),
                "expected_campaign": "a" * 32,
                "trust_lease": self.lease,
                **changes,
            },
        )

    def test_actual_signed_bundle_is_immutable_but_not_release_approved(self):
        before = copy.deepcopy(self.package)
        reader = self.reader()
        loaded = reader.load()
        self.assertEqual(loaded.model, self.verified["model"])
        self.assertEqual(loaded.subject_sha256, self.verified["subject_sha256"])
        self.assertFalse(loaded.release_ready)
        context = loaded.audit_context
        self.assertEqual(context.kind, "candidate-qualification")
        self.assertEqual(context.permit_sha256, digest(canonical(self.permit)))
        self.assertEqual(context.proposal_sha256, self.permit["proposal_sha256"])
        self.assertEqual(context.bundle_sha256, loaded.subject_sha256)
        self.assertEqual(context.model_sha256, loaded.model_sha256)
        self.assertFalse(context.release_ready)
        self.assertFalse(hasattr(context, "selection_sha256"))
        self.assertEqual(loaded.scope, qualification.KIND)
        self.assertEqual(self.package, before)
        self.assertEqual(reader.check(loaded)["version"], 1)
        with self.assertRaises(FrozenInstanceError):
            loaded.model = b"changed"
        self.assertNotIn("reports", self.permit)
        self.assertNotIn("required_gates", self.permit)
        reader.reference = "f" * 64
        reader.policy = "e" * 64
        reader.permit.clear()
        self.assertEqual(loaded.audit_context, context)
        with self.assertRaises(Rejected):
            reader.check(loaded)

    def test_explicit_authority_rotation_preserves_permit_but_not_retired_root(self):
        root_key = self.key.with_name("authority.pem")
        root_public = signing.create_key(root_key)
        lease = trust.Lease(
            lambda: (signing.sign(self.policy, "trust-policy", root_key), int(self.wall)),
            trusted_root=root_public,
            environment="local-cpu",
            minimum_version=1,
            wall_clock=lambda: self.wall,
            monotonic_clock=lambda: self.monotonic,
        )
        loaded = self.reader(trust_lease=lease, trust_root_public=root_public).load()
        self.assertEqual(loaded.permit_sha256, digest(canonical(self.permit)))
        self.assertEqual(loaded.model, self.verified["model"])
        self.assertFalse(loaded.release_ready)
        # A different pinned root never exempts the unchanged permit signer from revocation.
        self.policy["revoked_keys"] = [digest(signing.decode64(self.public))]
        self.policy["version"] += 1
        with self.assertRaisesRegex(Rejected, "trust_key_revoked"):
            self.reader(trust_lease=lease, trust_root_public=root_public).load()
        with self.assertRaisesRegex(Rejected, "qualification_trust_binding"):
            self.reader(trust_lease=lease)
        with self.assertRaisesRegex(Rejected, "qualification_trust_binding"):
            self.reader(trust_lease=lease, trust_root_public=self.public)

    def test_private_trace_matches_primary_sources_without_inventing_release_approval(self):
        context = self.bundle.materials.context
        objects = self.package["capsule"]["objects"]
        record = decode(objects[("candidates", context["candidate_reference"])])
        metadata = decode(objects[("candidates", record["metadata_object"])])
        statement = signing.verify(
            decode(objects[("manifests", record["dataset_reference"])]),
            "stored-dataset",
            context["trust"]["curator"],
        )
        provenance = signing.verify(
            decode(objects[("lineage", statement["lineage_object"])]),
            "data-lineage",
            context["trust"]["curator"],
        )
        loaded = self.reader().load()
        trace = loaded.audit_context
        self.assertEqual(trace.schema_version, 2)
        self.assertEqual(
            asdict(trace.lineage),
            {
                "source_revision": metadata["source_revision"],
                "source_fingerprint": metadata["source_fingerprint"],
                "source_sha256": provenance["source_sha256"],
                "source_approval_sha256": statement["source_approval_digest"],
                "dataset_sha256": record["dataset_reference"],
                "lineage_sha256": statement["lineage_object"],
                "run_sha256": record["metadata_object"],
                "evaluation_sha256": context["evaluation_reference"],
            },
        )
        for forbidden in ("authorization_sha256", "assurance_sha256", "approval_sha256"):
            self.assertFalse(hasattr(trace, forbidden))
        self.assertEqual(trace.permit_sha256, digest(canonical(self.permit)))
        self.assertFalse(trace.release_ready)

    def test_source_report_binds_unchanged_signed_proposal_not_latest_alias(self):
        report = {
            "scope": "release-proposal-and-authorization-denial-not-full-M10",
            "status": "pass",
            "source_dirty": False,
            "release_ready": False,
            "source": self.bundle.materials.context["expected"],
            "proposal_reference": self.permit["proposal_sha256"],
            "subject_sha256": self.permit["subject_sha256"],
            "model_sha256": self.permit["model_sha256"],
        }
        arguments = {
            "policy": self.bundle.materials.context["policy"],
            "source_trust": self.bundle.materials.context["trust"],
            "publisher_public": self.bundle.materials.public,
            "expected": self.bundle.materials.context["expected"],
            "clock": int(self.wall),
        }
        context, verified = qualification.bind_proposal(report, self.package, **arguments)
        self.assertEqual(context, self.bundle.materials.context)
        self.assertEqual(verified, self.verified)
        for field, value in (
            ("source_dirty", True),
            ("source_dirty", 0),
            ("release_ready", True),
            ("status", "inconclusive"),
            ("source", {}),
            ("proposal_reference", "0" * 64),
            ("subject_sha256", "0" * 64),
            ("model_sha256", "0" * 64),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                qualification.bind_proposal({**report, field: value}, self.package, **arguments)

    def test_permit_cannot_be_used_as_production_approval(self):
        envelope = signing.sign(self.permit, qualification.KIND, self.key)
        with self.assertRaisesRegex(Rejected, "wrong_payload_type"):
            release_policy.checked(envelope, "release-approval", self.public)
        with self.assertRaises(Rejected):
            self.reader(
                permit_envelope=signing.sign(self.permit, "release-approval", self.key)
            ).load()
        with self.assertRaises(Rejected):
            self.reader(permit_envelope=None).load()

    def test_each_signed_binding_and_unknown_fields_are_enforced(self):
        original = copy.deepcopy(self.permit)
        changes = (
            ("schema_version", True),
            ("purpose", "release"),
            ("campaign_id", "b" * 32),
            ("environment", "other"),
            ("proposal_sha256", "0" * 64),
            ("subject_sha256", "0" * 64),
            ("model_sha256", "0" * 64),
            ("source_revision", "0" * 40),
            ("source_fingerprint", "0" * 64),
            ("image_id", "sha256:" + "0" * 64),
            ("required_gates", []),
            ("expires_at", int(self.wall)),
            ("issued_at", int(self.wall) + 1),
            ("expires_at", int(self.wall) + 601),
        )
        for field, value in changes:
            with self.subTest(field=field, value=value):
                self.permit = {**original, field: value}
                self.policy["promotion_policy_sha256"] = digest(canonical(self.permit))
                with self.assertRaises(Rejected):
                    self.reader(proposal_reference=original["proposal_sha256"]).load()
        self.permit = original

    def test_wrong_root_role_pin_or_trust_service_fail_closed(self):
        with self.assertRaises(Rejected):
            self.reader(expected_permit="0" * 64).load()
        with self.assertRaises(Rejected):
            self.reader(permit_public=self.bundle.materials.public).load()
        self.role = "ml_promoter"
        with self.assertRaisesRegex(Rejected, "qualification_storage_identity"):
            self.reader().load()
        self.role = "ml_serving"
        self.failure = trust.Unavailable("unavailable")
        with self.assertRaises(trust.Unavailable):
            self.reader().load()

    def test_qualification_key_is_separate_from_publisher(self):
        public = self.bundle.materials.public
        with self.assertRaisesRegex(Rejected, "qualification_key_separation"):
            self.reader(
                permit_public=public,
                trust_lease=SimpleNamespace(root=public, environment="local-cpu"),
            )

    def test_alternate_encodings_cannot_reuse_any_source_signer(self):
        for public in (
            self.bundle.materials.public,
            *(self.bundle.materials.context["trust"][role] for role in ("curator", "evaluator")),
        ):
            alternate = alternate_public_encoding(public)
            self.assertNotEqual(public, alternate)
            self.assertEqual(signing.decode64(public), signing.decode64(alternate))
            with (
                self.subTest(public=public),
                self.assertRaisesRegex(Rejected, "qualification_key_separation"),
            ):
                self.reader(
                    permit_public=alternate,
                    trust_lease=SimpleNamespace(root=alternate, environment="local-cpu"),
                )

    def test_campaign_rejects_wrong_type_and_format(self):
        for invalid in (None, 1, True, [], "../outside", "A" * 32):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(Rejected, "qualification_campaign"),
            ):
                self.reader(expected_campaign=invalid)

    def expiry_during_refresh(self, proposal, unavailable):
        if proposal:
            self.bundle.attributes["expires_at"] = int(self.wall) + 120
            self.package = self.bundle.create()
            self.verified = self.bundle.check(self.package)
            self.permit.update(
                proposal_sha256=digest(canonical(self.package["envelope"])),
                subject_sha256=self.verified["subject_sha256"],
            )
            self.policy["promotion_policy_sha256"] = digest(canonical(self.permit))
        reader = self.reader()
        loaded = reader.load()
        elapsed = loaded.expires_at - self.wall - 10
        self.wall += elapsed
        self.monotonic += elapsed
        reader.check(loaded)
        self.wall += 9
        self.monotonic += 9

        def delayed():
            self.wall += 2
            self.monotonic += 2
            if unavailable:
                raise trust.Unavailable("controlled outage")
            return self.read_trust()

        self.lease.reader = delayed
        with self.assertRaises(Rejected):
            reader.check(loaded)
        self.assertIsNone(reader.current)

    def test_permit_expiry_during_successful_refresh_denies(self):
        self.expiry_during_refresh(proposal=False, unavailable=False)

    def test_permit_expiry_during_unavailable_refresh_denies(self):
        self.expiry_during_refresh(proposal=False, unavailable=True)

    def test_proposal_expiry_during_successful_refresh_denies(self):
        self.expiry_during_refresh(proposal=True, unavailable=False)

    def test_proposal_expiry_during_unavailable_refresh_denies(self):
        self.expiry_during_refresh(proposal=True, unavailable=True)

    def test_tampered_proposal_materials_are_not_loaded(self):
        self.package["documents"]["model-card"] += b" "
        reader = self.reader()
        with self.assertRaises(Rejected):
            reader.load()
        self.assertIsNone(reader.current)

    def revoke(self, field, reference):
        reader = self.reader()
        loaded = reader.load()
        self.policy["version"] += 1
        self.policy[field] = [reference]
        with self.assertRaises(Rejected):
            reader.check(loaded)
        self.assertIsNone(reader.current)

    def test_revoked_model_invalidates_existing_handoff(self):
        self.revoke("revoked_artifacts", self.permit["model_sha256"])

    def test_revoked_publisher_invalidates_existing_handoff(self):
        self.revoke("revoked_keys", digest(signing.decode64(self.bundle.materials.public)))

    def test_old_handoff_and_expired_permit_are_denied(self):
        reader = self.reader()
        loaded = reader.load()
        reader.load()
        with self.assertRaisesRegex(Rejected, "qualification_not_current"):
            reader.check(loaded)
        reader = self.reader()
        loaded = reader.load()
        self.wall += 600
        self.monotonic += 600
        with self.assertRaises(Rejected):
            reader.check(loaded)
        self.assertIsNone(reader.current)

    def test_outage_cannot_extend_original_sixty_second_lease(self):
        reader = self.reader()
        loaded = reader.load()
        deadline = self.lease.deadline
        self.failure = trust.Unavailable("unavailable")
        self.wall += 59
        self.monotonic += 59
        reader.check(loaded)
        self.assertEqual(self.lease.deadline, deadline)
        self.wall += 1
        self.monotonic += 1
        with self.assertRaises(Rejected):
            reader.check(loaded)
        self.assertIsNone(reader.current)


if __name__ == "__main__":
    unittest.main()
