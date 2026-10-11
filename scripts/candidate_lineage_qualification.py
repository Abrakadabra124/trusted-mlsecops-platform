import copy
import importlib.metadata
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from mlsecops import (
    asset_graph,
    candidate_lineage,
    data_source,
    evaluation_quality,
    holdout_budget,
    storage,
)
from mlsecops.contracts import Rejected, canonical, decode, digest, now, read_json
from mlsecops.datasets import FEATURES
from mlsecops.signing import create_key, sign
from scripts.evaluation_quality_qualification import examples

ROOT = Path(__file__).resolve().parents[1]
OWNERS = {
    "dataset": "data-owner",
    "run": "ml-owner",
    "model": "ml-owner",
    "runtime": "platform-owner",
    "policy": "platform-owner",
}
KNOWN_OWNERS = ["data-owner", "ml-owner", "platform-owner"]


class CandidateLineageContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name)
        cls.public = {
            role: create_key(cls.directory / f"{role}.pem") for role in ("curator", "evaluator")
        }
        cls.policy = {
            **read_json(ROOT / "policies/local-cpu.json"),
            "rows": 496,
            "split_counts": [64, 32, 400],
        }
        rows, scores = examples()
        cls.summary = evaluation_quality.summarize(
            rows, scores, evaluation_quality.freeze(cls.policy)
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.objects = {}
        self.reads = []
        self.approval = {
            "schema_version": 1,
            "source": self.policy["source"],
            "purpose": "synthetic-lab",
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            "owner": "lab-curator",
        }
        self.trust = {**self.public, "source_approval_digest": digest(canonical(self.approval))}
        self.manifest = {
            "schema_version": 1,
            "source": self.policy["source"],
            "seed": self.policy["data_seed"],
            "policy_digest": digest(canonical(self.policy)),
            "features": list(FEATURES),
            "source_approval_digest": self.trust["source_approval_digest"],
            "objects": {
                f"{name}.json": {"sha256": digest(name.encode()), "bytes": 100, "rows": count}
                for name, count in zip(
                    ("train", "validation", "holdout"), (64, 32, 400), strict=True
                )
            },
        }
        self.dataset_id = digest(canonical(self.manifest))
        self.lineage = {
            "schema_version": 1,
            "dataset_id": self.dataset_id,
            "source_sha256": "a" * 64,
            "policy_digest": self.manifest["policy_digest"],
            "lock_sha256": "b" * 64,
            "inputs": {name: {"sha256": "c" * 64, "bytes": 10} for name in data_source.INPUTS},
            "classification": "synthetic-only",
            "curator": "lab-curator",
        }
        self.lineage_id = digest(canonical(self.lineage))
        self.statement = {
            "schema_version": 1,
            "dataset_id": self.dataset_id,
            "lineage_id": self.lineage_id,
            "policy_digest": self.manifest["policy_digest"],
            "source_approval_digest": self.trust["source_approval_digest"],
            "manifest_object": self.signed("manifests", self.manifest, "dataset", "curator"),
            "approval_object": self.signed("manifests", self.approval, "source", "curator"),
            "lineage_object": self.signed("lineage", self.lineage, "data-lineage", "curator"),
            "quarantine_object": "a" * 64,
        }
        self.dataset_ref = self.signed("manifests", self.statement, "stored-dataset", "curator")
        self.expected = {
            "image_id": "sha256:" + "d" * 64,
            "source_fingerprint": "e" * 64,
            "source_revision": "f" * 40,
        }
        self.model = b"controlled-no-model-parser"
        self.metadata = {
            "schema_version": 1,
            "run_id": "1" * 32,
            "created_at": now(),
            "dataset_id": self.dataset_id,
            "lineage_id": self.lineage_id,
            "model_digest": digest(self.model),
            "policy_digest": self.manifest["policy_digest"],
            "input_digest": "2" * 64,
            "execution": {"image_id": self.expected["image_id"]},
            "versions": {},
            "validation_parity_max_error": 0.0,
            "validation_probability_digest": "3" * 64,
            "materials": self.manifest["objects"],
            "status": "unapproved-candidate",
            **self.expected,
        }
        self.record = {
            "schema_version": 1,
            "dataset_reference": self.dataset_ref,
            "model_object": self.put("candidates", self.model),
            "metadata_object": self.put("candidates", canonical(self.metadata)),
            "scores_object": "4" * 64,
        }
        self.candidate_ref = self.put("candidates", canonical(self.record))
        holdout = self.manifest["objects"]["holdout.json"]["sha256"]
        receipt = holdout_budget.reservation(holdout, 1)
        self.receipt_ref = self.put("evaluations", receipt)
        self.bound = {
            "schema_version": 1,
            "candidate_reference": self.candidate_ref,
            "dataset_reference": self.dataset_ref,
            "lineage_id": self.lineage_id,
            "holdout_access": {
                "holdout_digest": holdout,
                "slot": 1,
                "reservation": self.receipt_ref,
                "policy_digest": digest(canonical(holdout_budget.policy())),
            },
            "report": {
                "schema_version": 1,
                "created_at": now(),
                "holdout_digest": holdout,
                **{
                    name: self.metadata[name]
                    for name in (
                        "run_id",
                        "model_digest",
                        "dataset_id",
                        "policy_digest",
                        "image_id",
                        "validation_parity_max_error",
                    )
                },
                **self.summary,
                "release_status": "unapproved",
                "limitations": ["controlled fixture"],
                "scan": {
                    "format": "onnx",
                    "policy_version": "linear-onnx-v1",
                    "onnx_version": importlib.metadata.version("onnx"),
                    "inspected_nodes": 1,
                    "unsupported": 0,
                    "skipped": 0,
                    "errors": 0,
                },
                "prediction_protocol": {
                    "schema_version": 2,
                    "model_digest": digest(self.model),
                    "rows": 400,
                    "batch_id": "5" * 32,
                    "request_digest": "6" * 64,
                    "response_digest": "7" * 64,
                },
                "prediction_execution": {"image_id": self.expected["image_id"]},
            },
        }
        self.evaluation_ref = self.signed(
            "evaluations", self.bound, "stored-evaluation", "evaluator"
        )

    def put(self, table, content):
        identifier = digest(content)
        self.objects[(table, identifier)] = content
        return identifier

    def signed(self, table, payload, kind, role):
        return self.put(table, canonical(sign(payload, kind, self.directory / f"{role}.pem")))

    def rebound_candidate(self):
        self.record["metadata_object"] = self.put("candidates", canonical(self.metadata))
        self.candidate_ref = self.put("candidates", canonical(self.record))
        self.bound["candidate_reference"] = self.candidate_ref
        self.evaluation_ref = self.signed(
            "evaluations", self.bound, "stored-evaluation", "evaluator"
        )

    def collect(self, **changes):
        identities = changes.pop(
            "identities", {"publisher": "ml_publisher", "promoter": "ml_promoter"}
        )

        def get(client, table, identifier):
            self.reads.append((client, table))
            allowed = {
                "publisher": {"manifests", "lineage"},
                "promoter": {"candidates", "evaluations"},
            }
            if table not in allowed[client]:
                raise AssertionError("unexpected data or write access")
            try:
                content = self.objects[(table, identifier)]
            except KeyError:
                raise Rejected("storage_object_missing") from None
            if digest(content) != identifier:
                raise Rejected("storage_object_integrity_failed")
            return content

        arguments = dict(
            candidate_reference=self.candidate_ref,
            evaluation_reference=self.evaluation_ref,
            policy=self.policy,
            trust=self.trust,
            expected=self.expected,
            owners=OWNERS,
            known_owners=KNOWN_OWNERS,
        )
        arguments.update(changes)
        with (
            patch.object(storage, "get", side_effect=get),
            patch.object(
                storage,
                "connection_parameters",
                side_effect=lambda client: {"user": identities[client]},
            ),
        ):
            return candidate_lineage.collect("publisher", "promoter", **arguments)

    def test_signed_materials_build_exact_graph_without_reading_labels(self):
        original = copy.deepcopy(self.objects)
        result = self.collect()
        self.assertEqual(result["assessment"]["asset_count"], 5)
        self.assertFalse(result["release_ready"])
        self.assertEqual(result["full_M19"], "inconclusive")
        self.assertEqual(result["quality_component"], "pass")
        self.assertEqual(self.objects, original)
        self.assertEqual(
            set(self.reads),
            {
                ("publisher", "manifests"),
                ("publisher", "lineage"),
                ("promoter", "candidates"),
                ("promoter", "evaluations"),
            },
        )
        assets = {asset["kind"]: asset for asset in result["graph"]["assets"]}
        self.assertEqual(assets["dataset"]["sha256"], self.dataset_id)
        self.assertEqual(assets["run"]["sha256"], self.record["metadata_object"])
        self.assertEqual(assets["model"]["sha256"], digest(self.model))
        self.assertEqual(assets["runtime"]["sha256"], "d" * 64)
        self.assertEqual(result, self.collect())

    def test_foreign_curator_or_evaluator_rejected(self):
        for role in ("curator", "evaluator"):
            with self.subTest(role=role), self.assertRaises(Rejected):
                self.collect(
                    trust={**self.trust, role: create_key(self.directory / f"foreign-{role}.pem")}
                )

    def test_tampered_model_or_signed_envelope_rejected(self):
        for table, reference in (
            ("candidates", self.record["model_object"]),
            ("evaluations", self.evaluation_ref),
            ("manifests", self.dataset_ref),
        ):
            original = self.objects[(table, reference)]
            self.objects[(table, reference)] = b"tampered"
            with self.subTest(table=table), self.assertRaises(Rejected):
                self.collect()
            self.objects[(table, reference)] = original

    def test_unknown_source_approval_or_missing_budget_receipt_rejected(self):
        with self.assertRaises(Rejected):
            self.collect(trust={**self.trust, "source_approval_digest": "0" * 64})
        del self.objects[("evaluations", self.receipt_ref)]
        with self.assertRaises(Rejected):
            self.collect()

    def test_candidate_manifest_lineage_and_materials_must_match(self):
        original = copy.deepcopy(self.metadata)
        for key, value in (("dataset_id", "0" * 64), ("lineage_id", "0" * 64), ("materials", {})):
            self.metadata = {**original, key: value}
            self.rebound_candidate()
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.collect()

    def test_expected_build_bindings_cannot_be_taken_from_candidate(self):
        for key, value in (
            ("image_id", "sha256:" + "0" * 64),
            ("source_fingerprint", "0" * 64),
            ("source_revision", "0" * 40),
        ):
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.collect(expected={**self.expected, key: value})

    def test_evaluation_from_other_candidate_rejected(self):
        self.bound["candidate_reference"] = "0" * 64
        self.evaluation_ref = self.signed(
            "evaluations", self.bound, "stored-evaluation", "evaluator"
        )
        with self.assertRaises(Rejected):
            self.collect()

    def test_holdout_digest_and_row_count_match_curator_manifest(self):
        self.manifest["objects"]["holdout.json"]["sha256"] = "0" * 64
        self.rebound_candidate()
        with patch(
            "mlsecops.storage_dataset.read_manifest", return_value=(self.manifest, self.statement)
        ):
            with self.assertRaisesRegex(Rejected, "holdout_binding"):
                self.collect()

    def test_owner_configuration_and_metadata_identity_rejected(self):
        with self.assertRaises(Rejected):
            self.collect(owners={**OWNERS, "dataset": "attacker"})
        with self.assertRaises(Rejected):
            self.collect(owners={})

    def test_metadata_execution_image_mismatch_rejected(self):
        self.metadata["execution"] = {"image_id": "sha256:" + "0" * 64}
        self.rebound_candidate()
        with self.assertRaisesRegex(Rejected, "execution"):
            self.collect()

    def test_expected_build_schema_and_identifiers_are_strict(self):
        for key, values in {
            "image_id": [None, "latest", "sha256:" + "0" * 63],
            "source_revision": [None, "main", "a" * 64],
            "source_fingerprint": [None, "a" * 63],
        }.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(Rejected):
                    self.collect(expected={**self.expected, key: value})
        with self.assertRaises(Rejected):
            self.collect(expected={**self.expected, "alias": "champion"})
        with self.assertRaises(Rejected):
            self.collect(candidate_reference="latest")
        with self.assertRaises(Rejected):
            self.collect(evaluation_reference=None)

    def test_signer_separation_and_scoped_reader_identities(self):
        with self.assertRaisesRegex(Rejected, "signer_roles"):
            self.collect(trust={**self.trust, "evaluator": self.trust["curator"]})
        for role in ("publisher", "promoter"):
            identities = {"publisher": "ml_publisher", "promoter": "ml_promoter", role: "ml_scorer"}
            with self.subTest(role=role), self.assertRaisesRegex(Rejected, "reader_identity"):
                self.collect(identities=identities)

    def test_invalid_training_time_and_evaluation_before_training(self):
        for value in (None, "not-a-time", "2026-10-11T00:00:00", "2999-01-01T00:00:00+00:00"):
            self.metadata["created_at"] = value
            self.rebound_candidate()
            with self.subTest(value=value), self.assertRaisesRegex(Rejected, "time_binding"):
                self.collect()

    def test_rehashed_invalid_signature_cannot_become_trusted_evidence(self):
        envelope = decode(self.objects[("evaluations", self.evaluation_ref)])
        envelope["signatures"][0]["sig"] = "A" * 88
        self.evaluation_ref = self.put("evaluations", canonical(envelope))
        with self.assertRaisesRegex(Rejected, "signature"):
            self.collect()

    def test_quality_failure_is_preserved_not_converted_to_approval(self):
        rows, _ = examples()
        self.bound["report"].update(
            evaluation_quality.summarize(rows, [0.5] * 400, evaluation_quality.freeze(self.policy))
        )
        self.evaluation_ref = self.signed(
            "evaluations", self.bound, "stored-evaluation", "evaluator"
        )
        result = self.collect()
        self.assertEqual(result["quality_component"], "fail")
        self.assertEqual(result["candidate_state"], "unapproved-candidate")
        self.assertFalse(result["release_ready"])

    def test_signed_but_expired_source_approval_is_rejected(self):
        self.approval["expires_at"] = "2000-01-01T00:00:00+00:00"
        self.statement["approval_object"] = self.signed(
            "manifests", self.approval, "source", "curator"
        )
        self.dataset_ref = self.signed("manifests", self.statement, "stored-dataset", "curator")
        self.record["dataset_reference"] = self.dataset_ref
        self.bound["dataset_reference"] = self.dataset_ref
        self.rebound_candidate()
        with self.assertRaisesRegex(Rejected, "expired_source_approval"):
            self.collect()

    def test_rehashed_holdout_row_count_mismatch_is_rejected(self):
        self.manifest["objects"]["holdout.json"]["rows"] = 401
        self.rebound_candidate()
        with patch(
            "mlsecops.storage_dataset.read_manifest", return_value=(self.manifest, self.statement)
        ):
            with self.assertRaisesRegex(Rejected, "holdout_binding"):
                self.collect()

    def test_same_model_bytes_keep_both_run_dependencies_when_projected(self):
        first = self.collect()["graph"]
        self.metadata["run_id"] = "9" * 32
        self.bound["report"]["run_id"] = self.metadata["run_id"]
        self.rebound_candidate()
        second = self.collect()["graph"]
        first_model = next(asset for asset in first["assets"] if asset["kind"] == "model")
        second_model = next(asset for asset in second["assets"] if asset["kind"] == "model")
        self.assertEqual(first_model["sha256"], second_model["sha256"])
        self.assertNotEqual(first_model["asset_id"], second_model["asset_id"])
        merged = {
            asset["asset_id"]: asset for graph in (first, second) for asset in graph["assets"]
        }
        graph = {"schema_version": 1, "assets": list(merged.values())}
        snapshot = {
            "schema_version": 1,
            "environment": "local-cpu",
            "graph_sha256": digest(canonical(graph)),
            "deployments": [],
        }
        result = asset_graph.assess(
            graph,
            KNOWN_OWNERS,
            "local-cpu",
            snapshot,
            [{key: first_model[key] for key in ("asset_id", "sha256")}],
        )
        self.assertEqual(
            result["impacted_assets"], sorted([first_model["asset_id"], second_model["asset_id"]])
        )


if __name__ == "__main__":
    unittest.main()
