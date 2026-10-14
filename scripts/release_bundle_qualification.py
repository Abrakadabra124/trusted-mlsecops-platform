import copy
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from mlsecops import release_bundle, storage
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.signing import sign, verify
from scripts import material_bundle_qualification as fixtures


class ReleaseBundleContracts(unittest.TestCase):
    @contextmanager
    def memory_storage(self, values, fail_at=None, wrong_receipt=False):
        writes = []

        def put(client, table, content):
            self.assertEqual((client, table), ("promoter", "releases"))
            writes.append(digest(content))
            if len(writes) == fail_at:
                raise OSError("controlled storage outage")
            values[digest(content)] = content
            return "0" * 64 if wrong_receipt else digest(content)

        def get(client, table, reference):
            self.assertIn(client, ("promoter", "serving"))
            self.assertEqual(table, "releases")
            if reference not in values:
                raise Rejected("storage_object_missing")
            content = values[reference]
            if digest(content) != reference:
                raise Rejected("storage_object_integrity_failed")
            return content

        with (
            patch.object(
                storage,
                "connection_parameters",
                side_effect=lambda client: {"user": "ml_" + client},
            ),
            patch.object(storage, "put", side_effect=put),
            patch.object(storage, "get", side_effect=get),
        ):
            yield writes

    @classmethod
    def setUpClass(cls):
        fixtures.MaterialBundleContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.MaterialBundleContracts.tearDownClass()

    def setUp(self):
        self.materials = fixtures.MaterialBundleContracts()
        self.materials.setUp()
        self.lock = (Path(__file__).resolve().parents[1] / "uv.lock").read_bytes()
        fixture = self.materials.fixture
        fixture.lineage["inputs"]["uv.lock"] = {
            "sha256": digest(self.lock),
            "bytes": len(self.lock),
        }
        fixture.lineage_id = digest(canonical(fixture.lineage))
        fixture.statement.update(
            lineage_id=fixture.lineage_id,
            lineage_object=fixture.signed("lineage", fixture.lineage, "data-lineage", "curator"),
        )
        fixture.dataset_ref = fixture.signed(
            "manifests", fixture.statement, "stored-dataset", "curator"
        )
        fixture.record["dataset_reference"] = fixture.dataset_ref
        fixture.metadata["lineage_id"] = fixture.lineage_id
        fixture.bound.update(dataset_reference=fixture.dataset_ref, lineage_id=fixture.lineage_id)
        fixture.rebound_candidate()
        self.materials.context.update(
            candidate_reference=fixture.candidate_ref, evaluation_reference=fixture.evaluation_ref
        )
        self.capsule = self.materials.create()
        self.clock = int(time.time())
        self.attributes = {
            "release_id": "1" * 32,
            "sequence": 1,
            "owner": "platform-owner",
            "issued_at": self.clock,
            "expires_at": self.clock + 1800,
            "issuer": "lab-publisher",
        }
        self.arguments = {
            "context": self.materials.context,
            "publisher_public": self.materials.public,
            "expected_serving_image": fixture.expected["image_id"],
            "clock": self.clock,
        }

    def create(self):
        return release_bundle.create(
            self.capsule,
            self.lock,
            self.attributes,
            signing_key=self.materials.key,
            **self.arguments,
        )

    def check(self, package, **changes):
        return release_bundle.verify(package, **{**self.arguments, **changes})

    def test_complete_release_materials_are_bound_but_not_approved(self):
        package = self.create()
        result = self.check(package)
        self.assertEqual(result["model"], self.materials.fixture.model)
        self.assertEqual(result["subject_sha256"], digest(canonical(result["manifest"])))
        self.assertFalse(result["release_ready"])
        self.assertEqual(package, self.create())
        self.assertEqual(set(package["documents"]), set(release_bundle.DOCUMENTS))

    def test_runtime_pin_id_and_material_size_fail_closed(self):
        package = self.create()
        with self.assertRaisesRegex(Rejected, "runtime_pin"):
            self.check(package, expected_serving_image="latest")
        payload = verify(package["envelope"], "model-release", self.materials.public)
        invalid = copy.deepcopy(package)
        invalid["envelope"] = sign(
            {**payload, "release_id": "latest"}, "model-release", self.materials.key
        )
        with self.assertRaisesRegex(Rejected, "invalid_id"):
            self.check(invalid)
        for value in (b"", "not-bytes", b"x" * (1024 * 1024 + 1)):
            invalid = copy.deepcopy(package)
            invalid["documents"]["model-card"] = value
            with self.assertRaisesRegex(Rejected, "material_size"):
                self.check(invalid)

    def test_proposal_publication_is_idempotent_and_serving_readback_matches(self):
        package = self.create()
        values = {}
        with self.memory_storage(values):
            reference = release_bundle.publish("promoter", package, **self.arguments)
            before = dict(values)
            self.assertEqual(
                release_bundle.publish("promoter", package, **self.arguments), reference
            )
            self.assertEqual(values, before)
            self.assertEqual(
                release_bundle.read("serving", reference, **self.arguments), self.check(package)
            )
            for client in ("publisher", "scorer", "serving"):
                with self.assertRaisesRegex(Rejected, "publisher_storage_identity"):
                    release_bundle.publish(client, package, **self.arguments)
            with self.assertRaisesRegex(Rejected, "reader_storage_identity"):
                release_bundle.read("publisher", reference, **self.arguments)

    def test_interrupted_publication_has_no_release_index_and_retry_is_safe(self):
        package = self.create()
        reference = digest(canonical(package["envelope"]))
        values = {}
        with self.memory_storage(values, fail_at=12), self.assertRaises(OSError):
            release_bundle.publish("promoter", package, **self.arguments)
        self.assertNotIn(reference, values)
        with self.memory_storage(values):
            self.assertEqual(
                release_bundle.publish("promoter", package, **self.arguments), reference
            )
            self.assertFalse(
                release_bundle.read("serving", reference, **self.arguments)["release_ready"]
            )

    def test_storage_missing_or_replaced_model_card_is_rejected(self):
        package = self.create()
        values = {}
        with self.memory_storage(values):
            reference = release_bundle.publish("promoter", package, **self.arguments)
            card = digest(package["documents"]["model-card"])
            del values[card]
            with self.assertRaisesRegex(Rejected, "object_missing"):
                release_bundle.read("serving", reference, **self.arguments)
            values[card] = b"swapped"
            with self.assertRaisesRegex(Rejected, "integrity_failed"):
                release_bundle.read("serving", reference, **self.arguments)

    def test_signed_document_digest_cannot_override_material_semantics(self):
        package = self.create()
        manifest = verify(package["envelope"], "model-release", self.materials.public)
        for name in ("model-card", "parameters", "runtime-profile"):
            content = canonical({"claimed": "pass"})
            altered = {
                **package,
                "documents": {**package["documents"], name: content},
                "envelope": sign(
                    {**manifest, "materials": {**manifest["materials"], name: digest(content)}},
                    "model-release",
                    self.materials.key,
                ),
            }
            with (
                self.subTest(document=name),
                self.assertRaisesRegex(Rejected, "material_semantics"),
            ):
                self.check(altered)

    def test_storage_receipts_and_post_write_readback_cannot_be_trusted_blindly(self):
        package = self.create()
        with (
            self.memory_storage({}),
            patch.object(release_bundle, "read", return_value={}),
            self.assertRaisesRegex(Rejected, "readback_mismatch"),
        ):
            release_bundle.publish("promoter", package, **self.arguments)
        with (
            self.memory_storage({}),
            patch.object(release_bundle.material_bundle, "publish", return_value="0" * 64),
            patch.object(storage, "put", return_value="0" * 64),
            self.assertRaisesRegex(Rejected, "receipt_mismatch"),
        ):
            release_bundle.publish("promoter", package, **self.arguments)

    def test_signed_alias_swap_wrong_model_document_and_unknown_schema_rejected(self):
        package = self.create()
        for name in release_bundle.DOCUMENTS:
            invalid = copy.deepcopy(package)
            invalid["documents"][name] += b"changed"
            with self.subTest(name=name), self.assertRaises(Rejected):
                self.check(invalid)
        manifest = verify(package["envelope"], "model-release", self.materials.public)
        for field, value in (
            ("schema_version", True),
            ("environment", "production"),
            ("owner", "unknown"),
            ("sequence", 0),
            ("expires_at", self.clock),
            ("serving_image", "sha256:" + "0" * 64),
        ):
            invalid = copy.deepcopy(package)
            invalid["envelope"] = sign(
                {**manifest, field: value}, "model-release", self.materials.key
            )
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.check(invalid)


if __name__ == "__main__":
    unittest.main()
