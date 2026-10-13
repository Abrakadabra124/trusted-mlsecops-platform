import copy
import unittest
from unittest.mock import Mock

from mlsecops import advisory
from mlsecops.contracts import Rejected
from mlsecops.datasets import FEATURES, generate
from scripts import robustness


class AdvisoryTests(unittest.TestCase):
    def test_outside_support_abstains_without_calling_predictor(self):
        predictor = Mock(side_effect=AssertionError("must not execute"))
        rows = robustness.outside_support()
        result = advisory.decide(rows, predictor)
        self.assertEqual(len(result), 12)
        self.assertTrue(
            all(
                item == {"decision": "abstain", "reason": "outside-support", "score": None}
                for item in result
            )
        )
        predictor.assert_not_called()

    def test_mixed_batch_preserves_positions_and_only_scores_supported_rows(self):
        predictor = Mock(return_value=[0.25, 0.75])
        rows = [[0.0] * 6, [-0.01] + [0.5] * 5, [1.0] * 6]
        before = copy.deepcopy(rows)
        result = advisory.decide(rows, predictor)
        predictor.assert_called_once_with([rows[0], rows[2]])
        self.assertEqual([item["score"] for item in result], [0.25, None, 0.75])
        self.assertEqual([item["decision"] for item in result], ["score", "abstain", "score"])
        self.assertEqual(rows, before)

    def test_malformed_batch_fails_before_any_prediction(self):
        for rows in (
            None,
            [],
            [[0.5] * 6] * 101,
            [[0.5] * 5],
            [[True] * 6],
            [["0.5"] * 6],
            [[float("nan")] * 6],
            [[float("inf")] * 6],
            [[10**400] * 6],
        ):
            with self.subTest(rows=str(rows)[:30]):
                predictor = Mock()
                with self.assertRaises(Rejected):
                    advisory.decide(rows, predictor)
                predictor.assert_not_called()
        predictor = Mock()
        with self.assertRaises(Rejected):
            advisory.decide([[0.5] * 6, [None] * 6], predictor)
        predictor.assert_not_called()

    def test_bad_runtime_result_is_not_an_ood_abstention(self):
        for scores in ([], [0.1, 0.2], [True], [-0.01], [1.01], [float("nan")], [None]):
            with self.subTest(scores=scores), self.assertRaises(Rejected):
                advisory.decide([[0.5] * 6], Mock(return_value=scores))
        with self.assertRaisesRegex(Rejected, "runtime-unavailable"):
            advisory.decide([[0.5] * 6], Mock(side_effect=Rejected("runtime-unavailable")))


class EvasionTests(unittest.TestCase):
    def setUp(self):
        self.rows = generate(seed=73041, rows=100)
        self.features = [row["features"] for row in self.rows]

    def test_frozen_scope_and_four_bounded_corners(self):
        rules = robustness.policy()
        self.assertEqual(rules["mutable_features"], ["change_size", "change_entropy"])
        self.assertEqual(rules["linf_budget"], 0.05)
        self.assertEqual(rules["maximum_recall_drop"], 0.05)
        before = copy.deepcopy(self.features)
        corners = robustness.corners(self.features)
        self.assertEqual(len(corners), 4)
        self.assertEqual(before, self.features)
        for rows in corners:
            robustness.verify_changes(self.features, rows)
            for original, changed in zip(self.features, rows, strict=True):
                for index, name in enumerate(FEATURES):
                    if name not in rules["mutable_features"]:
                        self.assertEqual(changed[index], original[index])

    def test_outside_support_immutable_changes_and_excess_budget_rejected(self):
        source = [[0.5] * 6]
        for index, value in ((0, 0.56), (1, 0.49), (0, 1.1)):
            changed = copy.deepcopy(source)
            changed[0][index] = value
            with self.assertRaises(Rejected):
                robustness.verify_changes(source, changed)
        with self.assertRaises(Rejected):
            robustness.verify_changes(source, source * 2)

    def test_attack_uses_only_four_queries_and_never_increases_score(self):
        def predict(rows):
            return [row[0] * 0.7 + row[4] * 0.3 for row in rows]

        predictor = Mock(side_effect=predict)
        clean = predict(self.features)
        result = robustness.attack(self.features, clean, predictor)
        self.assertEqual(predictor.call_count, 4)
        self.assertTrue(
            all(after <= before for before, after in zip(clean, result["scores"], strict=True))
        )
        self.assertEqual(result["scores"], predict(result["features"]))
        robustness.verify_changes(self.features, result["features"])
        self.assertEqual(len(result["corner_scores"]), 4)

    def test_attack_validates_each_response(self):
        with self.assertRaises(Rejected):
            robustness.attack(self.features, [0.5] * 100, Mock(return_value=[]))
        with self.assertRaises(Rejected):
            robustness.attack(self.features, [0.5], Mock())

    def test_selection_retains_clean_noop_and_rejects_partial_matrix(self):
        clean = [0.1] * 100
        score_sets = [[0.2] * 100] * 4
        result = robustness.select(self.features, clean, score_sets)
        self.assertEqual(result["features"], self.features)
        self.assertEqual(result["scores"], clean)
        for partial in ([], score_sets[:3], score_sets + score_sets[:1]):
            with self.assertRaises(Rejected):
                robustness.select(self.features, clean, partial)

    def test_metrics_use_all_positive_rows_and_do_not_hide_failures(self):
        rows = [{"entity_id": index, "features": [0.5] * 6, "label": 1} for index in range(3000)]
        clean, attacked = [0.8] * 3000, [0.8] * 2700 + [0.2] * 300
        report = robustness.compare(rows, clean, attacked)
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["positives"], 3000)
        self.assertEqual(report["lost_true_positives"], 300)
        self.assertAlmostEqual(report["recall_drop"], 0.1)
        self.assertEqual(robustness.compare(rows, clean, clean)["status"], "pass")
        with self.assertRaises(Rejected):
            robustness.compare(rows, attacked, clean)

    def test_insufficient_probes_or_positives_are_inconclusive(self):
        result = robustness.compare(self.rows, [0.5] * 100, [0.4] * 100)
        self.assertEqual(result["status"], "inconclusive")
        rows = [{"entity_id": index, "features": [0.5] * 6, "label": 0} for index in range(3000)]
        result = robustness.compare(rows, [0.1] * 3000, [0.1] * 3000)
        self.assertEqual(result["status"], "inconclusive")
        self.assertIsNone(result["recall_drop"])


if __name__ == "__main__":
    unittest.main()
