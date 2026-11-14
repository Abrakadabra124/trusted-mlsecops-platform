"""Regressions for the signed-candidate M06 join. No database, network or worker is started."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mlsecops import reproducibility_candidate as gate
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from mlsecops.prediction_protocol import PredictionBatch, response
from scripts.reproducibility_native import record_from


class SignedRepeat(unittest.TestCase):
    def setUp(self):
        self.state = Path(self.enterContext(TemporaryDirectory()))
        self.rows = [dict(features=[float(i)] * 6, label=i) for i in (0, 1)]
        self.vector = [0.1, 0.9]
        model = b"controlled-model"
        self.scan = {}
        request = PredictionBatch(model, [r["features"] for r in self.rows]).request
        self.output = response(request, self.vector, self.scan)
        h = "a" * 64
        self.metadata = dict(
            run_id="a" * 32,
            input_digest=h,
            dataset_id=h,
            policy_digest=h,
            source_fingerprint=h,
            source_revision="c" * 40,
            image_id="sha256:" + h,
            versions={"runtime": "controlled"},
            model_digest=digest(model),
            materials={"holdout.json": {"sha256": digest(canonical(self.rows))}},
        )
        self.proof = dict(
            batch_id=request["batch_id"],
            request_digest=digest(canonical(request)),
            response_digest=digest(canonical(self.output)),
        )
        self.signed = dict(
            prediction_protocol=self.proof,
            scan=self.scan,
            auprc=1.0,
            holdout_digest=digest(canonical(self.rows)),
        )
        self.candidate = dict(
            metadata=self.metadata,
            model=model,
            bindings=dict(candidate_reference=h, evaluation_reference=h, dataset_reference=h),
            policy={},
            files={"storage-demo.json": h},
        )
        boundary = dict(
            image_id=self.metadata["image_id"],
            network="none",
            memory_limit_bytes=4 * 1024**3,
            cpu_limit=2,
            deadline_seconds=600,
            elapsed_seconds=0.1,
        )
        self.worker = self.enterContext(
            patch.object(gate, "run_worker", return_value=(self.output, boundary))
        )
        self.enterContext(patch.object(gate, "subject", return_value=self.candidate))
        self.enterContext(
            patch.object(
                gate.storage_pipeline, "read_evaluation", return_value=dict(report=self.signed)
            )
        )
        self.enterContext(
            patch.object(
                gate,
                "verify_dataset",
                return_value=(dict(holdout=self.rows), dict(objects=self.metadata["materials"])),
            )
        )
        write_json(self.state / "storage-trust.json", {})
        env = {"OMP_NUM_THREADS": "1"}
        self.records = []
        self.campaign = self.state / "reproducibility" / ("b" * 32)
        for index in range(3):
            record = record_from(
                {**self.metadata, "run_id": f"{index:032x}", "dataset_id": "f" * 64},
                self.rows,
                self.vector,
                env,
            )
            self.records.append(record)
            write_json(self.vector_path(record), self.vector)
        self.evidence = dict(
            image_id=self.metadata["image_id"],
            campaign_id=self.campaign.name,
            records=self.records,
            baseline_environment=env,
        )

    def vector_path(self, record):
        return self.campaign / "candidates" / record["run_id"] / "golden-scores.json"

    def bind(self):
        result = dict(cases=[], input_digests={}, metrics={}, artifact_hashes={})
        gate.bind(self.state, self.state, self.evidence, result, "a" * 64)
        return result

    def test_actual_predictions_are_replayed_and_compared_to_three_runs(self):
        result = self.bind()
        self.assertEqual(result["checks"], 1)
        self.assertEqual(
            result["metrics"],
            dict(candidate_probability_difference=0.0, candidate_auprc_difference=0.0),
        )
        doc = read_json(self.campaign / "candidate-replay.json")
        self.assertEqual(doc["reference_runs"], [r["run_id"] for r in self.records])
        self.assertEqual(doc["protocol"]["response_digest"], self.proof["response_digest"])

    def test_foreign_subject_or_replayed_materials_rejected(self):
        ref = self.records[-1]
        for target, change, code in (
            (self.candidate["files"], {"storage-demo.json": "foreign"}, "frozen_demo"),
            (self.metadata, dict(materials={}), "split_mismatch"),
            (self.signed, dict(holdout_digest="different"), "split_mismatch"),
            (self.proof, dict(request_digest="foreign"), "request_mismatch"),
            (self.proof, dict(response_digest="foreign"), "response_mismatch"),
            (self.signed, dict(scan={"unseen": True}), "rows_mismatch"),
            (self.signed, dict(auprc=0.4), "reference_or_evaluation"),
            (self.metadata, dict(run_id=ref["run_id"]), "reference_or_evaluation"),
            (ref["inputs"], dict(request="foreign"), "training_inputs"),
            (ref, dict(vector_digest="foreign"), "vector_changed"),
            (ref, dict(auprc=0.4), "repeat_tolerance"),
        ):
            with (
                self.subTest(change=change),
                patch.dict(target, change),
                self.assertRaisesRegex(Rejected, code),
            ):
                self.bind()
        vector = [0.11, 0.9]
        write_json(self.vector_path(ref), vector)
        with (
            patch.dict(ref, vector_digest=digest(canonical(vector))),
            self.assertRaisesRegex(Rejected, "repeat_tolerance"),
        ):
            self.bind()
