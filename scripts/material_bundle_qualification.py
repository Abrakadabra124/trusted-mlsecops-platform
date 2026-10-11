import copy
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from mlsecops import candidate_lineage, evaluation_quality, material_bundle, storage
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.signing import create_key, sign, verify
from scripts import candidate_lineage_qualification as fixtures


class MaterialBundleContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.CandidateLineageContracts.setUpClass()
        cls.key = fixtures.CandidateLineageContracts.directory / "approver.pem"
        cls.public = create_key(cls.key)

    @classmethod
    def tearDownClass(cls):
        fixtures.CandidateLineageContracts.tearDownClass()

    def setUp(self):
        self.fixture = fixtures.CandidateLineageContracts()
        self.fixture.setUp()
        self.context = {
            "candidate_reference": self.fixture.candidate_ref,
            "evaluation_reference": self.fixture.evaluation_ref,
            "policy": self.fixture.policy,
            "trust": self.fixture.trust,
            "expected": self.fixture.expected,
            "owners": fixtures.OWNERS,
            "known_owners": fixtures.KNOWN_OWNERS,
        }
        self.reads = set()
        self.published = {}

    def get(self, client, table, reference):
        self.reads.add((client, table, reference))
        self.assertIn(
            (client, table),
            {
                ("publisher", "manifests"),
                ("publisher", "lineage"),
                ("promoter", "candidates"),
                ("promoter", "evaluations"),
            },
        )
        content = self.fixture.objects[(table, reference)]
        self.assertEqual(digest(content), reference)
        return content

    def create(self, **changes):
        arguments = {"context": self.context, "signing_key": self.key, "signer_public": self.public}
        arguments.update(changes)
        with (
            patch.object(storage, "get", side_effect=self.get),
            patch.object(
                storage,
                "connection_parameters",
                side_effect=lambda client: {"user": "ml_" + client},
            ),
        ):
            return material_bundle.create("publisher", "promoter", **arguments)

    def check(self, bundle, **changes):
        arguments = {"context": self.context, "signer_public": self.public}
        arguments.update(changes)
        with patch.object(
            storage, "get", side_effect=AssertionError("Offline verifier must not read SQL")
        ):
            return material_bundle.verify_bundle(bundle, **arguments)

    def test_signed_closed_bundle_replays_without_sql_or_labels(self):
        bundle = self.create()
        result = self.check(bundle)
        self.assertEqual(result["model"], self.fixture.model)
        self.assertFalse(result["release_ready"])
        self.assertEqual(result["full_M10"], "inconclusive")
        self.assertEqual(result["projection"]["assessment"]["asset_count"], 5)
        self.assertEqual(len(bundle["objects"]), 9)
        self.assertEqual(bundle, self.create())

    def test_foreign_signer_and_wrong_payload_type_rejected(self):
        bundle = self.create()
        with self.assertRaises(Rejected):
            self.check(bundle, signer_public=self.fixture.public["curator"])
        manifest = verify(bundle["envelope"], "candidate-materials", self.public)
        bundle["envelope"] = sign(manifest, "release-approval", self.key)
        with self.assertRaises(Rejected):
            self.check(bundle)

    def test_model_tampering_and_missing_materials_rejected(self):
        bundle = self.create()
        model_key = ("candidates", digest(self.fixture.model))
        for change in ("tamper", "missing"):
            invalid = copy.deepcopy(bundle)
            if change == "tamper":
                invalid["objects"][model_key] = b"changed"
            else:
                del invalid["objects"][model_key]
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.check(invalid)

    def test_extraneous_materials_and_duplicate_manifest_entries_rejected(self):
        bundle = self.create()
        bundle["objects"][("holdout", digest(b"forbidden"))] = b"forbidden"
        with self.assertRaises(Rejected):
            self.check(bundle)
        bundle = self.create()
        manifest = verify(bundle["envelope"], "candidate-materials", self.public)
        manifest["objects"].append(copy.deepcopy(manifest["objects"][0]))
        bundle["envelope"] = sign(manifest, "candidate-materials", self.key)
        with self.assertRaises(Rejected):
            self.check(bundle)

    def test_signed_manifest_change_cannot_rebind_context(self):
        bundle = self.create()
        manifest = verify(bundle["envelope"], "candidate-materials", self.public)
        for field, value in (
            ("schema_version", True),
            ("environment", "production"),
            ("projection_sha256", "0" * 64),
        ):
            altered = {**manifest, field: value}
            invalid = {**bundle, "envelope": sign(altered, "candidate-materials", self.key)}
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.check(invalid)

    def test_approver_must_not_be_curator_or_evaluator(self):
        for role in ("curator", "evaluator"):
            with self.subTest(role=role), self.assertRaises(Rejected):
                self.create(
                    signing_key=self.fixture.directory / f"{role}.pem",
                    signer_public=self.fixture.public[role],
                )

    def test_equivalent_key_encodings_cannot_turn_curator_into_approver(self):
        for role in ("curator", "evaluator"):
            with (
                self.subTest(role=role),
                self.assertRaisesRegex(Rejected, "signer_roles_not_separated"),
            ):
                self.create(
                    signing_key=self.fixture.directory / f"{role}.pem",
                    signer_public=fixtures.alternate_public_encoding(self.fixture.public[role]),
                )

    def test_wrong_signing_key_rejected_before_publication(self):
        with self.assertRaises(Rejected):
            self.create(signing_key=self.fixture.directory / "curator.pem")

    def test_independent_expected_build_and_policy_are_not_read_from_bundle(self):
        bundle = self.create()
        invalid_context = {
            **self.context,
            "expected": {**self.context["expected"], "source_revision": "0" * 40},
        }
        with self.assertRaises(Rejected):
            self.check(bundle, context=invalid_context)

    def resign(self, bundle, manifest):
        return {**bundle, "envelope": sign(manifest, "candidate-materials", self.key)}

    @contextmanager
    def sql(self):
        def put(client, table, content):
            self.assertEqual((client, table), ("promoter", "releases"))
            reference = digest(content)
            self.published.setdefault(reference, content)
            return reference

        def get(client, table, reference):
            self.assertIn(client, ("promoter", "serving"))
            self.assertEqual(table, "releases")
            if reference not in self.published:
                raise Rejected("storage_object_missing")
            return self.published[reference]

        with (
            patch.object(storage, "put", side_effect=put),
            patch.object(storage, "get", side_effect=get),
            patch.object(
                storage,
                "connection_parameters",
                side_effect=lambda client: {"user": "ml_" + client},
            ),
        ):
            yield

    def test_publish_idempotency_and_serving_readback(self):
        bundle = self.create()
        arguments = {"context": self.context, "signer_public": self.public}
        with self.sql():
            first = material_bundle.publish("promoter", bundle, **arguments)
            self.assertEqual(first, digest(canonical(bundle["envelope"])))
            self.assertEqual(len(self.published), 10)
            snapshot = dict(self.published)
            self.assertEqual(material_bundle.publish("promoter", bundle, **arguments), first)
            self.assertEqual(self.published, snapshot)
            result = material_bundle.read("serving", first, **arguments)
            self.assertEqual(result["model"], self.fixture.model)
            self.assertFalse(result["release_ready"])

    def test_publication_rejects_unverified_bundle_before_writes(self):
        bundle = self.create()
        bundle["envelope"]["signatures"][0]["sig"] = "A" * 88
        with self.sql(), self.assertRaises(Rejected):
            material_bundle.publish(
                "promoter", bundle, context=self.context, signer_public=self.public
            )
        self.assertEqual(self.published, {})

    def test_partial_publication_retries_without_alias_or_false_success(self):
        bundle = self.create()
        arguments = {"context": self.context, "signer_public": self.public}
        with self.sql():
            original = storage.put
            calls = []

            def interrupted(client, table, content):
                calls.append(content)
                if len(calls) == 2:
                    raise Rejected("interrupted-write")
                return original(client, table, content)

            with patch.object(storage, "put", side_effect=interrupted):
                with self.assertRaisesRegex(Rejected, "interrupted-write"):
                    material_bundle.publish("promoter", bundle, **arguments)
            self.assertEqual(len(self.published), 1)
            self.assertNotIn(digest(canonical(bundle["envelope"])), self.published)
            reference = material_bundle.publish("promoter", bundle, **arguments)
            self.assertEqual(len(self.published), 10)
            self.assertFalse(
                material_bundle.read("serving", reference, **arguments)["release_ready"]
            )

    def test_sql_role_guards_reject_before_any_access(self):
        bundle = self.create()
        with self.sql():
            for role in ("serving", "publisher", "scorer"):
                with (
                    self.subTest(role=role),
                    self.assertRaisesRegex(Rejected, "publisher_identity"),
                ):
                    material_bundle.publish(
                        role, bundle, context=self.context, signer_public=self.public
                    )
            with self.assertRaisesRegex(Rejected, "reader_identity"):
                material_bundle.read(
                    "scorer", "0" * 64, context=self.context, signer_public=self.public
                )
        self.assertEqual(self.published, {})

    def test_wrong_storage_receipt_and_failed_readback_cannot_report_success(self):
        bundle = self.create()
        arguments = {"context": self.context, "signer_public": self.public}
        for position in (0, len(bundle["objects"])):
            calls = []

            def put(client, table, content):
                calls.append(content)
                return "0" * 64 if len(calls) == position + 1 else digest(content)

            with self.sql(), patch.object(storage, "put", side_effect=put):
                with (
                    self.subTest(position=position),
                    self.assertRaisesRegex(Rejected, "storage_integrity"),
                ):
                    material_bundle.publish("promoter", bundle, **arguments)
        with self.sql(), patch.object(storage, "get", side_effect=Rejected("readback_failed")):
            with self.assertRaisesRegex(Rejected, "readback_failed"):
                material_bundle.publish("promoter", bundle, **arguments)

    def test_signed_malformed_index_and_size_limits_rejected(self):
        bundle = self.create()
        manifest = verify(bundle["envelope"], "candidate-materials", self.public)
        variants = [
            {**manifest, field: value}
            for field, value in (
                ("schema_version", 2),
                ("kind", "release"),
                ("state", "approved"),
                ("objects", {}),
                ("objects", []),
                ("objects", manifest["objects"] * 2),
            )
        ]
        for field, value in (
            ("namespace", "holdout"),
            ("namespace", []),
            ("sha256", "not-a-digest"),
            ("bytes", True),
            ("bytes", 0),
            ("bytes", material_bundle.MAX_OBJECT_BYTES + 1),
        ):
            descriptors = copy.deepcopy(manifest["objects"])
            descriptors[0][field] = value
            variants.append({**manifest, "objects": descriptors})
        descriptors = copy.deepcopy(manifest["objects"])
        for descriptor in descriptors[:2]:
            descriptor["bytes"] = material_bundle.MAX_OBJECT_BYTES
        variants.append({**manifest, "objects": descriptors})
        for index, altered in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(Rejected):
                self.check(self.resign(bundle, altered))

    def test_envelope_bounds_and_recursive_input_rejected(self):
        bundle = self.create()
        with self.assertRaisesRegex(Rejected, "envelope_too_large"):
            self.check(
                {**bundle, "envelope": {"payload": "A" * material_bundle.MAX_ENVELOPE_BYTES}}
            )
        recursive = {}
        recursive["payload"] = recursive
        with self.assertRaises(Rejected):
            self.check({**bundle, "envelope": recursive})
        nested = {}
        for _ in range(12000):
            nested = {"payload": nested}
        with self.assertRaisesRegex(Rejected, "invalid_envelope"):
            self.check({**bundle, "envelope": nested})

    def test_signed_missing_dependency_and_unused_material_rejected(self):
        bundle = self.create()
        manifest = verify(bundle["envelope"], "candidate-materials", self.public)
        model_key = ("candidates", digest(self.fixture.model))
        incomplete = copy.deepcopy(bundle)
        del incomplete["objects"][model_key]
        reduced = {
            **manifest,
            "objects": [item for item in manifest["objects"] if item["sha256"] != model_key[1]],
        }
        with self.assertRaisesRegex(Rejected, "dependency_missing"):
            self.check(self.resign(incomplete, reduced))
        extra = b"unreferenced"
        bundle["objects"][("candidates", digest(extra))] = extra
        manifest["objects"].append(
            {"namespace": "candidates", "sha256": digest(extra), "bytes": len(extra)}
        )
        with self.assertRaisesRegex(Rejected, "unreferenced_material"):
            self.check(self.resign(bundle, manifest))

    def test_wrong_object_container_type_and_length_rejected(self):
        bundle = self.create()
        with self.assertRaisesRegex(Rejected, "objects_invalid"):
            self.check({**bundle, "objects": []})
        model_key = ("candidates", digest(self.fixture.model))
        for content in (bytearray(self.fixture.model), b"x" * len(self.fixture.model), b""):
            changed = {**bundle, "objects": {**bundle["objects"], model_key: content}}
            with (
                self.subTest(content_type=type(content)),
                self.assertRaisesRegex(Rejected, "material_integrity"),
            ):
                self.check(changed)

    def test_reader_callbacks_cannot_access_labels_or_unknown_role(self):
        bundle = self.create()
        for role, table in (("metadata", "holdout"), ("scorer", "evaluations")):

            def access(read, **context):
                return read(role, table, "0" * 64)

            with patch.object(candidate_lineage, "reconcile", side_effect=access):
                with (
                    self.subTest(role=role),
                    self.assertRaisesRegex(Rejected, "bundle_reader_scope"),
                ):
                    self.check(bundle)
                with self.assertRaisesRegex(Rejected, "inventory_reader_scope"):
                    self.create()

    def test_rehashed_inner_signature_still_rejected_with_valid_outer_signature(self):
        bundle = self.create()
        manifest = verify(bundle["envelope"], "candidate-materials", self.public)
        envelope = decode(self.fixture.objects[("evaluations", self.fixture.evaluation_ref)])
        envelope["signatures"][0]["sig"] = "A" * 88
        content = canonical(envelope)
        reference = digest(content)
        del bundle["objects"][("evaluations", self.fixture.evaluation_ref)]
        bundle["objects"][("evaluations", reference)] = content
        for descriptor in manifest["objects"]:
            if descriptor["sha256"] == self.fixture.evaluation_ref:
                descriptor.update(sha256=reference, bytes=len(content))
        manifest["evaluation_reference"] = reference
        with self.assertRaisesRegex(Rejected, "signature"):
            self.check(
                self.resign(bundle, manifest),
                context={**self.context, "evaluation_reference": reference},
            )

    def test_quality_failure_remains_failure_in_signed_capsule(self):
        rows, _ = fixtures.examples()
        self.fixture.bound["report"].update(
            evaluation_quality.summarize(
                rows, [0.5] * 400, evaluation_quality.freeze(self.fixture.policy)
            )
        )
        self.context["evaluation_reference"] = self.fixture.signed(
            "evaluations", self.fixture.bound, "stored-evaluation", "evaluator"
        )
        result = self.check(self.create())
        self.assertEqual(result["projection"]["quality_component"], "fail")
        self.assertFalse(result["release_ready"])


if __name__ == "__main__":
    unittest.main()
