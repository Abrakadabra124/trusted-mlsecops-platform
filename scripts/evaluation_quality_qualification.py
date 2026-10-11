import importlib.metadata
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.metrics import average_precision_score

from mlsecops import evaluation_quality, pipeline, storage_pipeline
from mlsecops.contracts import Rejected, canonical, digest, read_json
from mlsecops.prediction_protocol import response

ROOT = Path(__file__).resolve().parents[1]


def profile():
    return read_json(ROOT / "policies/local-cpu.json")


def examples(count=400):
    rows = [
        {
            "entity_id": index,
            "features": [0.25 if index < count // 2 else 0.75] + [0.5] * 5,
            "label": index % 2,
        }
        for index in range(count)
    ]
    return rows, [float(row["label"]) for row in rows]


class QualityContracts(unittest.TestCase):
    def test_paired_baseline_bootstrap_has_exactly_zero_gain(self):
        rows, _ = examples()
        report = evaluation_quality.summarize(
            rows, [0.5] * len(rows), evaluation_quality.freeze(profile())
        )
        self.assertEqual(report["confidence_intervals"]["auprc_gain"], [0.0, 0.0])
        self.assertEqual(report["quality_component"], "fail")

    def test_validator_preserves_degenerate_and_insufficient_states(self):
        for count, single_class in ((398, False), (400, True)):
            rows, scores = examples(count)
            if single_class:
                for row in rows:
                    row["label"] = 1
            report = evaluation_quality.summarize(
                rows, scores, evaluation_quality.freeze(profile())
            )
            evaluation_quality.validate_summary(report)
            report["confidence_intervals"]["status"] = "computed"
            with self.assertRaisesRegex(Rejected, "evaluation_insufficient_confidence"):
                evaluation_quality.validate_summary(report)
            if single_class:
                report["auprc"] = 1.0
                with self.assertRaisesRegex(Rejected, "evaluation_undefined_metric"):
                    evaluation_quality.validate_summary(report)

    def test_validator_handles_undefined_intervals_without_false_bounds(self):
        rows, scores = examples()
        for index, row in enumerate(rows):
            row["label"] = int(index != 0)
        report = evaluation_quality.summarize(rows, scores, evaluation_quality.freeze(profile()))
        self.assertEqual(report["confidence_intervals"]["status"], "inconclusive")
        evaluation_quality.validate_summary(report)
        report["confidence_intervals"]["auprc"] = [0.5, 1.0]
        with self.assertRaisesRegex(Rejected, "evaluation_undefined_confidence"):
            evaluation_quality.validate_summary(report)

    def test_slice_boundary_uses_validated_json_not_float32_rounding(self):
        rows, scores = examples(398)
        rows[0]["features"][0] = 0.499999999
        rows[1]["features"][0] = 0.5
        report = evaluation_quality.summarize(rows, scores, evaluation_quality.freeze(profile()))
        self.assertEqual(report["slices"]["low-change"]["rows"], 198)
        self.assertEqual(report["slices"]["high-change"]["rows"], 200)

    def test_input_rows_and_rules_are_not_mutated(self):
        rows, scores = examples(398)
        rules = evaluation_quality.freeze(profile())
        original = canonical([rows, scores, rules])
        report = evaluation_quality.summarize(rows, scores, rules)
        self.assertEqual(canonical([rows, scores, rules]), original)
        rules["slices"].clear()
        self.assertEqual(report["evaluation_policy"]["slices"], ["low-change", "high-change"])

    def test_undefined_recall_with_enough_slice_rows(self):
        rows, scores = examples()
        for index, row in enumerate(rows):
            row["label"] = int(index >= 200)
        report = evaluation_quality.summarize(rows, scores, evaluation_quality.freeze(profile()))
        self.assertEqual(report["quality_component"], "inconclusive")
        self.assertIn("undefined_slice_recall:low-change", report["quality_reasons"])

    def test_invalid_rows_and_empty_dataset_rejected(self):
        for rows in (None, {}, [], [None], [{}], [{"features": [0.5] * 6}]):
            with self.subTest(rows=rows), self.assertRaises(Rejected):
                evaluation_quality.summarize(rows, [], evaluation_quality.freeze(profile()))

    def test_insufficient_sample_is_inconclusive_not_failure(self):
        rows, scores = examples(398)
        report = evaluation_quality.summarize(rows, scores, evaluation_quality.freeze(profile()))
        self.assertEqual(report["quality_component"], "inconclusive")
        self.assertIn("insufficient_positive_labels", report["quality_reasons"])
        self.assertEqual(report["positives"], 199)

    def test_empty_slice_is_not_silently_zero_recall(self):
        rows, scores = examples()
        for row in rows:
            row["features"][0] = 0.25
        report = evaluation_quality.summarize(rows, scores, evaluation_quality.freeze(profile()))
        self.assertEqual(report["quality_component"], "inconclusive")
        self.assertIsNone(report["slices"]["high-change"]["recall"])
        self.assertIn("insufficient_slice_rows:high-change", report["quality_reasons"])

    def test_both_degenerate_classes_are_inconclusive(self):
        for label in (0, 1):
            rows, scores = examples()
            for row in rows:
                row["label"] = label
            with self.subTest(label=label):
                report = evaluation_quality.summarize(
                    rows, scores, evaluation_quality.freeze(profile())
                )
                self.assertEqual(report["quality_component"], "inconclusive")
                self.assertIn("single_class_holdout", report["quality_reasons"])
                self.assertIsNone(report["auprc"])
                canonical(report)

    def test_exact_minimum_counts_are_accepted(self):
        rows, scores = examples()
        rules = evaluation_quality.freeze(profile())
        report = evaluation_quality.summarize(rows, scores, rules)
        self.assertEqual(report["quality_component"], "pass")
        self.assertEqual(report["quality_reasons"], [])
        self.assertEqual(report["auprc"], 1.0)
        self.assertEqual(report["dummy_auprc"], 0.5)
        self.assertEqual(report["evaluation_policy_digest"], digest(canonical(rules)))
        self.assertEqual(report["confidence_intervals"]["auprc"], [1.0, 1.0])
        self.assertEqual(report["confidence_intervals"]["valid_resamples"], 1000)

    def test_poor_model_fails_not_inconclusive(self):
        rows, scores = examples()
        report = evaluation_quality.summarize(
            rows, [1 - score for score in scores], evaluation_quality.freeze(profile())
        )
        self.assertEqual(report["quality_component"], "fail")
        self.assertIn("auprc_below_minimum", report["quality_reasons"])
        self.assertIn("baseline_gain_below_minimum", report["quality_reasons"])

    def test_constant_score_matches_train_fitted_dummy_prior(self):
        rows, scores = examples()
        labels = [row["label"] for row in rows]
        observed = evaluation_quality.summarize(rows, scores, evaluation_quality.freeze(profile()))
        for training_labels in ([0, 0, 0, 1], [0, 1, 1, 1]):
            dummy = DummyClassifier(strategy="prior").fit([[0]] * 4, training_labels)
            expected = average_precision_score(labels, dummy.predict_proba([[0]] * len(rows))[:, 1])
            self.assertEqual(observed["dummy_auprc"], expected)

    def test_resampling_is_paired_deterministic_and_not_global_rng(self):
        rows, _ = examples()
        scores = [0.9 if index % 7 else 0.1 for index in range(len(rows))]
        rules = evaluation_quality.freeze(profile())
        first = evaluation_quality.summarize(rows, scores, rules)
        np.random.seed(991)
        second = evaluation_quality.summarize(rows, scores, rules)
        self.assertEqual(first, second)
        interval = first["confidence_intervals"]["auprc_gain"]
        self.assertLessEqual(interval[0], interval[1])
        self.assertTrue(-1 <= interval[0] <= interval[1] <= 1)

    def test_undefined_bootstrap_replicates_are_not_dropped(self):
        labels = np.array([0, 1])
        rules = evaluation_quality.freeze(profile())
        observed = evaluation_quality.intervals(labels, np.array([0.0, 1.0]), rules)
        self.assertEqual(observed["status"], "inconclusive")
        self.assertGreater(observed["undefined_resamples"], 0)
        self.assertIsNone(observed["auprc_gain"])
        self.assertEqual(observed["valid_resamples"] + observed["undefined_resamples"], 1000)

    def test_probability_and_label_validation(self):
        for invalid in (True, float("nan"), float("inf"), -0.1, 1.1, "0.5"):
            rows, scores = examples()
            scores[0] = invalid
            with self.subTest(score=invalid), self.assertRaises(Rejected):
                evaluation_quality.summarize(rows, scores, evaluation_quality.freeze(profile()))
        for invalid in (True, None, "1", 2, 1.0):
            rows, scores = examples()
            rows[0]["label"] = invalid
            with self.subTest(label=invalid), self.assertRaises(Rejected):
                evaluation_quality.summarize(rows, scores, evaluation_quality.freeze(profile()))

    def test_wrong_score_count_and_invalid_features(self):
        rows, scores = examples()
        with self.assertRaises(Rejected):
            evaluation_quality.summarize(rows, scores[:-1], evaluation_quality.freeze(profile()))
        rows[0]["features"][0] = float("nan")
        with self.assertRaises(Rejected):
            evaluation_quality.summarize(rows, scores, evaluation_quality.freeze(profile()))

    def test_profile_cannot_weaken_frozen_policy(self):
        for field, value in (
            ("minimum_positives", 1),
            ("minimum_auprc", 0.1),
            ("minimum_auprc_gain", 0),
            ("minimum_slice_rows", 1),
            ("environment", "production"),
            ("source", "private-business"),
            ("label_horizon", "unmatured"),
        ):
            invalid = profile()
            invalid[field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(Rejected, "evaluation_profile_not_frozen_lab"),
            ):
                evaluation_quality.freeze(invalid)

    def test_rules_cannot_be_changed_after_freeze(self):
        rows, scores = examples()
        for field in ("threshold", "resamples", "seed"):
            invalid = evaluation_quality.freeze(profile())
            invalid[field] = 0
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(Rejected, "evaluation_rules_changed"),
            ):
                evaluation_quality.summarize(rows, scores, invalid)


class IntegrationContracts(unittest.TestCase):
    def test_actual_preprocessor_fits_only_training_rows(self):
        from sklearn.preprocessing import StandardScaler

        from mlsecops.worker import train

        rows, _ = examples()
        captured = []
        original = StandardScaler.fit

        def fit(instance, features, labels=None, **keywords):
            captured.append(features.copy())
            return original(instance, features, labels, **keywords)

        with patch.object(StandardScaler, "fit", fit):
            for value in (0.0, 1.0):
                train(
                    {"action": "train", "train": rows, "features": [[value] * 6] * 10, "seed": 17}
                )
        self.assertEqual(len(captured), 2)
        expected = np.array([row["features"] for row in rows], dtype=np.float32)
        for observed in captured:
            np.testing.assert_array_equal(observed, expected)
        with self.assertRaisesRegex(Rejected, "unexpected_fields"):
            train(
                {
                    "action": "train",
                    "train": rows,
                    "features": [[1.0] * 6],
                    "seed": 17,
                    "validation_labels": [1],
                }
            )

    def test_sql_rejects_unfrozen_policy_before_storage_access(self):
        invalid = profile()
        invalid["minimum_auprc"] = 0
        with patch.object(storage_pipeline, "load_candidate") as loader:
            with self.assertRaisesRegex(Rejected, "evaluation_profile_not_frozen_lab"):
                storage_pipeline.evaluate("client", "candidate", invalid, "image", {}, "key")
            loader.assert_not_called()

    def test_worker_is_not_authority_for_quality(self):
        rows, scores = examples(398)
        scan = {
            "format": "onnx",
            "policy_version": "linear-onnx-v1",
            "onnx_version": importlib.metadata.version("onnx"),
            "inspected_nodes": 1,
            "unsupported": 0,
            "skipped": 0,
            "errors": 0,
        }
        metadata = {
            "image_id": "image",
            "run_id": "1" * 32,
            "dataset_id": "a" * 64,
            "validation_parity_max_error": 0.0,
        }
        manifest = {"objects": {"holdout.json": {"sha256": "b" * 64}}}

        def executor(image, request):
            return response(request, scores, scan), {"image_id": image}

        result = pipeline.evaluate_verified_candidate(
            metadata, b"controlled-model", rows, manifest, profile(), "image", executor
        )
        self.assertEqual(result["quality_component"], "inconclusive")
        self.assertEqual(result["release_status"], "unapproved")
        self.assertEqual(result["evaluation_policy"], evaluation_quality.freeze(profile()))


if __name__ == "__main__":
    unittest.main()
