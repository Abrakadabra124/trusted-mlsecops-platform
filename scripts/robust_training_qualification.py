import copy
import itertools
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np
from scipy.optimize import check_grad
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from mlsecops import controller_worker, robust_training, worker
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.datasets import arrays, generate


class RobustTrainingTests(unittest.TestCase):
    def fixture(self):
        features, labels = arrays(generate(rows=500))
        fitted = make_pipeline(StandardScaler(), LogisticRegression(random_state=17, max_iter=300))
        fitted.fit(features, labels)
        return fitted, features, labels

    def test_gradient_matches_finite_differences_away_from_bounds(self):
        fitted, features, labels = self.fixture()
        design = robust_training.design(features, labels, fitted.steps[0][1])
        parameters = np.linspace(0.1, 0.7, 13)
        error = check_grad(
            lambda values: robust_training.objective(values, design)[0],
            lambda values: robust_training.objective(values, design)[1],
            parameters,
        )
        self.assertLess(error, 1e-6)

    def test_margin_matches_explicit_clipped_corners_for_both_labels(self):
        fitted, _, _ = self.fixture()
        scaler = fitted.steps[0][1]
        features = np.asarray(
            [[0.0, 0.2, 0.3, 0.4, 1.0, 0.6], [0.02, 0.7, 0.6, 0.5, 0.98, 0.3], [0.5] * 6]
        )
        for labels in (np.array([0, 1, 0]), np.array([1, 0, 1])):
            for direction in (-1, 1):
                weights = direction * np.array([2.0, -1.0, 0.5, -0.8, -1.5, 0.2])
                bias = 0.3
                parameters = np.r_[np.maximum(weights, 0), np.maximum(-weights, 0), bias]
                margin = robust_training.design(features, labels, scaler) @ parameters
                observed = []
                for row, label in zip(features, labels, strict=True):
                    values = []
                    for changes in itertools.product((-0.05, 0.05), repeat=2):
                        changed = row.copy()
                        changed[[0, 4]] = np.clip(changed[[0, 4]] + changes, 0, 1)
                        values.append(
                            (2 * label - 1) * (scaler.transform([changed])[0] @ weights + bias)
                        )
                    observed.append(min(values))
                np.testing.assert_allclose(margin, observed, rtol=0, atol=1e-12)

    def test_simultaneous_split_parts_are_not_a_false_exact_margin(self):
        fitted, features, labels = self.fixture()
        design = robust_training.design(features, labels, fitted.steps[0][1])
        parameters = np.r_[np.ones(12), 0.0]
        canonical_parameters = robust_training.collapse(parameters)
        self.assertTrue(np.all(design @ canonical_parameters >= design @ parameters))
        self.assertGreater(
            robust_training.objective(parameters, design)[0],
            robust_training.objective(canonical_parameters, design)[0],
        )

    def test_refit_recomputes_convergence_and_preserves_scaler(self):
        fitted, features, labels = self.fixture()
        before = copy.deepcopy(fitted.steps[0][1].__dict__)
        result = robust_training.refit(fitted, features, labels)
        self.assertEqual(result["algorithm"], "clipped-box-logistic-v1")
        self.assertLessEqual(result["final_objective"], result["initial_objective"])
        self.assertLessEqual(result["projected_gradient_inf"], 1e-5)
        for name in ("mean_", "scale_", "var_"):
            np.testing.assert_array_equal(before[name], fitted.steps[0][1].__dict__[name])

    def test_solver_failure_nonfinite_and_forged_convergence_rejected(self):
        for invalid in (
            SimpleNamespace(success=False, x=np.zeros(13), nit=1),
            SimpleNamespace(success=True, x=np.full(13, np.nan), nit=1),
            SimpleNamespace(success=True, x=np.zeros(12), nit=1),
            SimpleNamespace(success=True, x=-np.ones(13), nit=1),
            SimpleNamespace(success=True, x=np.zeros(13), nit=1),
        ):
            fitted, features, labels = self.fixture()
            with (
                patch.object(robust_training, "minimize", return_value=invalid),
                self.assertRaises(Rejected),
            ):
                robust_training.refit(fitted, features, labels)

    def test_worker_variant_is_explicit_bound_and_has_real_onnx_parity(self):
        request = {
            "action": "research-robust-train",
            "train": generate(rows=1000),
            "seed": 17,
            "features": [row["features"] for row in generate(seed=881, rows=1000)],
        }
        output = worker.execute(request)
        self.assertEqual(output["action"], request["action"])
        self.assertEqual(output["input_digest"], digest(canonical(request)))
        self.assertEqual(output["optimization"]["training_rows"], 1000)
        expected, actual = np.asarray(output["python_scores"]), np.asarray(output["onnx_scores"])
        self.assertLessEqual(float(abs(expected - actual).max()), 1e-5)
        outside = abs(expected - 0.5) > 1e-5
        np.testing.assert_array_equal(expected[outside] >= 0.5, actual[outside] >= 0.5)
        with self.assertRaises(Rejected):
            worker.execute({**request, "budget": 0.01})

    def test_existing_training_does_not_silently_use_new_algorithm(self):
        request = {
            "action": "train",
            "train": generate(rows=100),
            "seed": 17,
            "features": [[0.5] * 6],
        }
        with patch.object(robust_training, "refit", side_effect=AssertionError("unexpected")):
            output = worker.execute(request)
        self.assertNotIn("optimization", output)
        self.assertEqual(output["action"], "train")

    def test_research_action_has_no_scoped_controller_authority(self):
        profile = {
            "image": "lab/worker@sha256:" + "1" * 64,
            "image_id": "sha256:" + "2" * 64,
            "config_id": "sha256:" + "2" * 64,
            "manifest_id": "sha256:" + "1" * 64,
            "source_fingerprint": "3" * 64,
            "source_revision": "4" * 40,
        }
        for role in ("publisher", "scorer"):
            with self.assertRaisesRegex(Rejected, "controller_worker_action_mismatch"):
                controller_worker.documents(profile, role, {"action": "research-robust-train"})
        for action in ([], {}, None, "unknown"):
            with self.assertRaises(Rejected):
                worker.execute({"action": action})

    def test_invalid_geometry_scaler_and_single_class_cannot_train(self):
        fitted, features, labels = self.fixture()
        with self.assertRaisesRegex(Rejected, "requires_two_classes"):
            robust_training.refit(fitted, features, np.ones_like(labels))
        fitted.steps[-1][1].C = 2.0
        with self.assertRaisesRegex(Rejected, "estimator_profile"):
            robust_training.refit(fitted, features, labels)
        scaler = fitted.steps[0][1]
        for invalid in (features[:, :5], np.full_like(features, np.nan), features + 2):
            with self.assertRaises(Rejected):
                robust_training.design(invalid, labels, scaler)
        for invalid in (labels[:1], np.full_like(labels, 2), labels.astype(bool)):
            with self.assertRaises(Rejected):
                robust_training.design(features, invalid, scaler)
        for value in (0, -1, np.nan):
            invalid = copy.deepcopy(scaler)
            invalid.scale_[0] = value
            with self.assertRaises(Rejected):
                robust_training.design(features, labels, invalid)
        rows = generate(rows=100)
        for row in rows:
            row["label"] = 1
        with self.assertRaisesRegex(Rejected, "requires_two_classes"):
            worker.execute(
                {
                    "action": "research-robust-train",
                    "train": rows,
                    "seed": 17,
                    "features": [[0.5] * 6],
                }
            )

    def test_large_margins_remain_finite_and_immutable_split_direction_is_flat(self):
        fitted, features, labels = self.fixture()
        design = robust_training.design(features, labels, fitted.steps[0][1])
        for bias in (-1000.0, 1000.0):
            parameters = np.r_[np.ones(12), bias]
            loss, gradient = robust_training.objective(parameters, design)
            self.assertTrue(np.isfinite(loss))
            self.assertTrue(np.isfinite(gradient).all())
            for index in (1, 2, 3, 5):
                self.assertAlmostEqual(gradient[index] + gradient[index + 6], 0, places=12)


if __name__ == "__main__":
    unittest.main()
