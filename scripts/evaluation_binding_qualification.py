import copy
import importlib.metadata
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import evaluation_quality, holdout_budget, storage, storage_pipeline
from mlsecops.contracts import Rejected, canonical, digest, now, read_json
from mlsecops.signing import create_key, sign
from scripts.evaluation_quality_qualification import examples


class BindingContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.key = Path(cls.directory.name) / "evaluator.pem"
        cls.public = create_key(cls.key)
        cls.profile = read_json(Path(__file__).resolve().parents[1] / "policies/local-cpu.json")
        rows, scores = examples()
        cls.summary = evaluation_quality.summarize(
            rows, scores, evaluation_quality.freeze(cls.profile)
        )
        cls.metadata = {
            "run_id": "1" * 32,
            "model_digest": "2" * 64,
            "dataset_id": "3" * 64,
            "lineage_id": "4" * 64,
            "image_id": "sha256:" + "5" * 64,
            "policy_digest": digest(canonical(cls.profile)),
            "validation_parity_max_error": 0.0,
        }
        cls.candidate = "6" * 64
        cls.record = {"dataset_reference": "7" * 64}
        cls.reservation = holdout_budget.reservation("8" * 64, 1)
        cls.bound = {
            "schema_version": 1,
            "candidate_reference": cls.candidate,
            "dataset_reference": cls.record["dataset_reference"],
            "lineage_id": cls.metadata["lineage_id"],
            "holdout_access": {
                "holdout_digest": "8" * 64,
                "slot": 1,
                "reservation": digest(cls.reservation),
                "policy_digest": digest(canonical(holdout_budget.policy())),
            },
            "report": {
                "schema_version": 1,
                "created_at": now(),
                "holdout_digest": "8" * 64,
                **{name: value for name, value in cls.metadata.items() if name != "lineage_id"},
                **cls.summary,
                "release_status": "unapproved",
                "limitations": ["controlled fixture"],
                "scan": {
                    "format": "onnx",
                    "policy_version": "linear-onnx-v2",
                    "onnx_version": importlib.metadata.version("onnx"),
                    "inspected_nodes": 2,
                    "unsupported": 0,
                    "skipped": 0,
                    "errors": 0,
                },
                "prediction_protocol": {
                    "schema_version": 2,
                    "model_digest": cls.metadata["model_digest"],
                    "rows": 400,
                    "batch_id": "a" * 32,
                    "request_digest": "b" * 64,
                    "response_digest": "c" * 64,
                },
                "prediction_execution": {"image_id": cls.metadata["image_id"]},
            },
        }

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def read(
        self,
        bound=None,
        *,
        key=None,
        kind="stored-evaluation",
        missing_reservation=False,
        candidate=None,
    ):
        envelope = sign(bound if bound is not None else self.bound, kind, key or self.key)
        report_id = digest(canonical(envelope))

        def get(client, table, identifier):
            self.assertEqual(table, "evaluations")
            if identifier == report_id:
                return canonical(envelope)
            if not missing_reservation and identifier == digest(self.reservation):
                return self.reservation
            raise Rejected("storage_object_missing")

        with (
            patch.object(
                storage_pipeline,
                "load_candidate",
                return_value=(self.record, self.metadata, b"controlled-model"),
            ),
            patch.object(storage, "get", side_effect=get),
        ):
            return storage_pipeline.read_evaluation(
                "client",
                report_id,
                candidate or self.candidate,
                self.profile,
                {"evaluator": self.public},
            )

    def test_real_signature_and_expected_subject(self):
        self.assertEqual(self.read(), self.bound)

    def test_different_candidate_cannot_replay_valid_report(self):
        with self.assertRaisesRegex(Rejected, "stored_evaluation_subject_mismatch"):
            self.read(candidate="9" * 64)

    def test_subject_swaps_rejected_even_with_valid_signature(self):
        for field in ("run_id", "model_digest", "dataset_id", "image_id", "policy_digest"):
            bound = copy.deepcopy(self.bound)
            bound["report"][field] = "0" * 64
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.read(bound)
        for field in ("candidate_reference", "dataset_reference", "lineage_id"):
            bound = copy.deepcopy(self.bound)
            bound[field] = "0" * 64
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.read(bound)

    def test_missing_metric_is_not_success(self):
        for field in evaluation_quality.SUMMARY_FIELDS:
            bound = copy.deepcopy(self.bound)
            bound["report"].pop(field)
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.read(bound)

    def test_self_approval_and_wrong_payload_kind(self):
        foreign = Path(self.directory.name) / "publisher.pem"
        create_key(foreign)
        with self.assertRaises(Rejected):
            self.read(key=foreign)
        with self.assertRaises(Rejected):
            self.read(kind="evaluation")

    def test_missing_reservation_cannot_authorize_report(self):
        with self.assertRaisesRegex(Rejected, "storage_object_missing"):
            self.read(missing_reservation=True)

    def test_reservation_and_budget_policy_bound(self):
        for field, value in (
            ("slot", 2),
            ("slot", True),
            ("holdout_digest", "9" * 64),
            ("reservation", "0" * 64),
            ("policy_digest", "0" * 64),
        ):
            bound = copy.deepcopy(self.bound)
            bound["holdout_access"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(Rejected):
                self.read(bound)

    def test_insufficient_data_cannot_be_declared_pass(self):
        bound = copy.deepcopy(self.bound)
        rows, scores = examples(398)
        bound["report"].update(
            evaluation_quality.summarize(rows, scores, evaluation_quality.freeze(self.profile))
        )
        bound["report"]["prediction_protocol"]["rows"] = 398
        self.assertEqual(self.read(bound)["report"]["quality_component"], "inconclusive")
        bound["report"]["quality_component"] = "pass"
        with self.assertRaisesRegex(Rejected, "evaluation_decision_mismatch"):
            self.read(bound)

    def test_corrupt_summary_rejected(self):
        mutations = (
            lambda value: value.update(rows=True),
            lambda value: value.update(positives=999),
            lambda value: value.update(dummy_auprc=0.1),
            lambda value: value.update(auprc_gain=1),
            lambda value: value.update(evaluation_policy_digest="0" * 64),
            lambda value: value["evaluation_policy"].update(threshold=0.1),
            lambda value: value["slices"]["low-change"].update(rows=-1),
            lambda value: value["slices"]["low-change"].update(rows=199),
            lambda value: value["slices"]["low-change"].update(recall=True),
            lambda value: value["slices"]["low-change"].update(recall=0.5),
            lambda value: value["confidence_intervals"].update(seed=0),
            lambda value: value["confidence_intervals"].update(valid_resamples=0),
            lambda value: value["confidence_intervals"].update(status="pass"),
            lambda value: value["confidence_intervals"].update(auprc=[1.0, 0.9]),
            lambda value: value["confidence_intervals"].update(auprc_gain=[False, 0.9]),
        )
        for index, mutate in enumerate(mutations):
            bound = copy.deepcopy(self.bound)
            mutate(bound["report"])
            with self.subTest(mutation=index), self.assertRaises(Rejected):
                self.read(bound)

    def test_report_metadata_protocol_and_execution_fail_closed(self):
        mutations = (
            lambda value: value.update(schema_version=True),
            lambda value: value["report"].update(schema_version=True),
            lambda value: value["report"].update(validation_parity_max_error=True),
            lambda value: value["report"].update(release_status="approved"),
            lambda value: value["report"].update(created_at="2026-10-11"),
            lambda value: value["report"].update(created_at=None),
            lambda value: value["report"]["prediction_protocol"].update(rows=401),
            lambda value: value["report"]["prediction_protocol"].update(batch_id="invalid"),
            lambda value: value["report"]["prediction_protocol"].update(request_digest="invalid"),
            lambda value: value["report"]["prediction_execution"].update(image_id="foreign"),
            lambda value: value["report"]["prediction_execution"].update(input_digest="0" * 64),
        )
        for index, mutate in enumerate(mutations):
            bound = copy.deepcopy(self.bound)
            mutate(bound)
            with self.subTest(mutation=index), self.assertRaises(Rejected):
                self.read(bound)


if __name__ == "__main__":
    unittest.main()
