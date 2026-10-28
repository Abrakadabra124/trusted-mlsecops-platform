import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np
from scipy.optimize import check_grad
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from mlsecops import noise_training, robust_training
from mlsecops.contracts import Rejected
from mlsecops.datasets import arrays, generate


class NoiseTrainingTests(unittest.TestCase):
    def fixture(self):
        features, labels = arrays(generate(rows=500))
        model = make_pipeline(StandardScaler(), LogisticRegression(random_state=17, max_iter=300))
        model.fit(features, labels)
        return model, features, labels

    def test_generalized_gradient_and_bounded_loss(self):
        model, features, labels = self.fixture()
        design = robust_training.design(features, labels, model.steps[0][1], linf_budget=0.10)
        parameters = np.linspace(0.1, 0.7, 13)
        self.assertLess(
            check_grad(
                lambda p: noise_training.objective(p, design)[0],
                lambda p: noise_training.objective(p, design)[1],
                parameters,
            ),
            1e-6,
        )
        for margin in (-10000.0, 10000.0):
            inputs = np.zeros((20, 13))
            inputs[:, -1] = 1
            parameters = np.zeros(13)
            parameters[-1] = margin
            loss, gradient = noise_training.objective(parameters, inputs)
            self.assertTrue(np.isfinite(gradient).all())
            self.assertGreaterEqual(loss, 0)
            self.assertLessEqual(loss, 1 / 0.7)

    def test_balanced_gradient_and_weights_use_only_observed_train_labels(self):
        model, features, labels = self.fixture()
        matrix = robust_training.design(features, labels, model.steps[0][1], linf_budget=0.10)
        weights = noise_training.weights(labels, balanced=True)
        self.assertAlmostEqual(float(weights[labels == 0].sum()), len(labels) / 2)
        self.assertAlmostEqual(float(weights[labels == 1].sum()), len(labels) / 2)
        parameters = np.linspace(0.1, 0.7, 13)
        self.assertLess(
            check_grad(
                lambda p: noise_training.objective(p, matrix, weights)[0],
                lambda p: noise_training.objective(p, matrix, weights)[1],
                parameters,
            ),
            1e-6,
        )
        receipt = noise_training.refit(model, features, labels, balanced=True)
        self.assertLessEqual(receipt["projected_gradient_inf"], 1e-5)
        self.assertNotEqual(noise_training.definition(True), noise_training.definition(False))
        for invalid in (1, None, "balanced"):
            with self.assertRaises(Rejected):
                noise_training.definition(invalid)
        for labels in (np.ones(3, dtype=int), np.array([[0, 1]]), np.array([0.0, 1.0])):
            with self.assertRaises(Rejected):
                noise_training.weights(labels, True)

    def test_refit_is_deterministic_train_only_and_preserves_scaler(self):
        model, features, labels = self.fixture()
        original = copy.deepcopy(model)
        twin = copy.deepcopy(model)
        receipt = noise_training.refit(model, features, labels)
        self.assertLessEqual(receipt["final_objective"], receipt["initial_objective"])
        self.assertLessEqual(receipt["projected_gradient_inf"], 1e-5)
        self.assertEqual(receipt, noise_training.refit(twin, features, labels))
        np.testing.assert_array_equal(model.predict_proba(features), twin.predict_proba(features))
        for name in ("mean_", "scale_", "var_"):
            np.testing.assert_array_equal(
                getattr(model.steps[0][1], name), getattr(original.steps[0][1], name)
            )

    def test_fake_convergence_invalid_state_and_single_class_rejected(self):
        for result in (
            SimpleNamespace(success=False, x=np.zeros(13), nit=1),
            SimpleNamespace(success=True, x=np.zeros(13), nit=1),
            SimpleNamespace(success=True, x=np.full(13, np.nan), nit=1),
            SimpleNamespace(success=True, x=-np.ones(13), nit=1),
            SimpleNamespace(success=True, x=np.zeros(12), nit=1),
            SimpleNamespace(success=True, x=np.zeros(13), nit=501),
        ):
            model, features, labels = self.fixture()
            before = model.predict_proba(features)
            with patch.object(noise_training, "minimize", return_value=result):
                with self.assertRaises(Rejected):
                    noise_training.refit(model, features, labels)
            np.testing.assert_array_equal(before, model.predict_proba(features))
        model, features, labels = self.fixture()
        with self.assertRaises(Rejected):
            noise_training.refit(model, features, np.ones_like(labels))
        model.steps[-1][1].C = 2
        with self.assertRaises(Rejected):
            noise_training.refit(model, features, labels)

    def test_training_box_is_clipped_and_does_not_change_evaluation_policy(self):
        from scripts import robustness

        model, features, labels = self.fixture()
        scaler = model.steps[0][1]
        values = np.array([[0.02, 0.2, 0.3, 0.4, 0.98, 0.6]])
        weights = np.array([2.0, 1.0, 1.0, 1.0, -2.0, 1.0])
        params = np.r_[np.maximum(weights, 0), np.maximum(-weights, 0), 0.3]
        matrix = robust_training.design(values, np.array([1]), scaler, linf_budget=0.10)
        changed = values.copy()
        changed[0, [0, 4]] = [0.0, 1.0]
        np.testing.assert_allclose(matrix @ params, scaler.transform(changed) @ weights + 0.3)
        self.assertEqual(robustness.policy()["linf_budget"], 0.05)
        for invalid in (-1, 2, True, float("nan"), "0.1"):
            with self.assertRaises(Rejected):
                robust_training.design(features, labels, scaler, linf_budget=invalid)

    def test_development_decision_retains_failure_and_inconclusive(self):
        from scripts.noise_training_validation import decide

        baseline = {"auprc": 0.90}
        clean = {"auprc": 0.87, "auprc_gain": 0.2, "positives": 1200}
        evasion = {"status": "pass"}
        poisoned = [{"status": "pass"}] * 4
        self.assertEqual(decide(baseline, clean, evasion, poisoned), "pass")
        for altered in (
            {**clean, "auprc": 0.869999},
            {**clean, "positives": 199},
            {**clean, "auprc_gain": 0.09},
        ):
            self.assertNotEqual(decide(baseline, altered, evasion, poisoned), "pass")
        for status in ("fail", "inconclusive"):
            self.assertNotEqual(decide(baseline, clean, evasion, [{"status": status}] * 4), "pass")
        self.assertEqual(decide(baseline, clean, {"status": "fail"}, poisoned), "fail")
        for invalid in ([], [{"status": "unknown"}] * 4):
            with self.assertRaises(Rejected):
                decide(baseline, clean, evasion, invalid)

    def test_default_worker_uses_balanced_fit_and_reference_stays_distinct(self):
        from mlsecops import worker

        rows = generate(rows=1000)
        x, y = arrays(rows)
        expected = make_pipeline(
            StandardScaler(), LogisticRegression(random_state=17, max_iter=300)
        )
        expected.fit(x, y)
        reference = expected.predict_proba(x)[:, 1]
        noise_training.refit(expected, x, y, balanced=True)
        request = {
            "action": "train",
            "train": rows,
            "seed": 17,
            "features": [r["features"] for r in rows],
        }
        output = worker.execute(request)
        np.testing.assert_allclose(
            output["python_scores"], expected.predict_proba(x)[:, 1], atol=1e-12
        )
        np.testing.assert_allclose(
            output["onnx_scores"], output["python_scores"], atol=1e-5, rtol=0
        )
        self.assertNotIn("optimization", output)
        previous = worker.execute({**request, "action": "reference-logistic-train"})
        np.testing.assert_allclose(previous["python_scores"], reference, atol=1e-12)
        self.assertGreater(float(np.max(np.abs(reference - output["python_scores"]))), 0.01)
        with patch.object(
            noise_training, "refit", side_effect=Rejected("test-convergence-failure")
        ):
            with self.assertRaisesRegex(Rejected, "convergence"):
                worker.execute(request)


if __name__ == "__main__":
    unittest.main()
