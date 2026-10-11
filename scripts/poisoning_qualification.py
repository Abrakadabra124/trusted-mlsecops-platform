import copy
import unittest

from mlsecops.contracts import Rejected, canonical
from scripts import poisoning


def rows(count=1000):
    return [
        {
            "entity_id": index,
            "features": [0.2 if index % 2 else 0.8] + [0.5] * 5,
            "label": index % 2,
        }
        for index in range(count)
    ]


class PoisoningContracts(unittest.TestCase):
    def test_full_frozen_matrix_and_no_mutable_policy_escape(self):
        policy = poisoning.policy()
        matrix = poisoning.matrix()
        self.assertEqual(len(matrix), 35)
        self.assertEqual(sum(case["family"] == "clean" for case in matrix), 5)
        self.assertEqual(len({case["id"] for case in matrix}), 35)
        for family in ("label-flip", "backdoor"):
            self.assertEqual(sum(case["family"] == family for case in matrix), 15)
        policy["seeds"].clear()
        self.assertEqual(len(poisoning.policy()["seeds"]), 5)

    def test_mutation_count_repeatability_and_train_only(self):
        original = rows(14000)
        before = canonical(original)
        for family in ("label-flip", "backdoor"):
            for count in (70, 140, 700):
                changed, receipt = poisoning.poison(original, family, count, 17)
                again, repeated = poisoning.poison(original, family, count, 17)
                self.assertEqual((changed, receipt), (again, repeated))
                self.assertEqual(
                    sum(left != right for left, right in zip(original, changed, strict=True)), count
                )
                self.assertEqual(receipt["changed_rows"], count)
                for left, right in zip(original, changed, strict=True):
                    self.assertEqual(left["entity_id"], right["entity_id"])
                    if left != right:
                        self.assertEqual((left["label"], right["label"]), (1, 0))
                        if family == "label-flip":
                            self.assertEqual(left["features"], right["features"])
                        else:
                            self.assertEqual(right["features"][4], 1.0)
                            self.assertEqual(
                                left["features"][:4] + left["features"][5:],
                                right["features"][:4] + right["features"][5:],
                            )
        self.assertEqual(canonical(original), before)

    def test_unsupported_family_count_seed_and_exhausted_selection_rejected(self):
        for family, count, seed in (
            ("other", 1, 17),
            ("clean", 1, 17),
            ("label-flip", True, 17),
            ("label-flip", -1, 17),
            ("label-flip", 501, 17),
            ("label-flip", 1, True),
            ("label-flip", 1, -1),
        ):
            with self.subTest(family=family, count=count, seed=seed), self.assertRaises(Rejected):
                poisoning.poison(rows(), family, count, seed)

    def test_trigger_is_bounded_and_does_not_change_labels_or_input(self):
        original = rows()
        before = canonical(original)
        triggered = poisoning.trigger(original)
        self.assertEqual(canonical(original), before)
        self.assertTrue(all(row["features"][4] == 1.0 for row in triggered))
        self.assertEqual([row["label"] for row in original], [row["label"] for row in triggered])

    def test_self_control_and_known_threshold_violations(self):
        samples = rows(2000)
        correct = [0.9 if row["label"] else 0.1 for row in samples]
        self.assertEqual(
            poisoning.compare(samples, correct, correct, correct, correct)["status"], "pass"
        )
        attacked = [0.1] * len(samples)
        result = poisoning.compare(samples, correct, attacked, correct, attacked)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["asr_delta"], 1.0)
        self.assertGreater(result["auprc_drop"], 0.03)
        self.assertGreater(result["asr_delta_ci"][1], 0.10)

    def test_insufficient_eligible_probes_is_inconclusive(self):
        samples = rows(998)
        correct = [float(row["label"]) for row in samples]
        result = poisoning.compare(samples, correct, correct, correct, correct)
        self.assertEqual(result["eligible_rows"], 499)
        self.assertEqual(result["status"], "inconclusive")
        self.assertIsNone(result["asr_delta_ci"])
        samples = rows(1000)
        correct = [float(row["label"]) for row in samples]
        self.assertEqual(
            poisoning.compare(samples, correct, correct, correct, correct)["status"], "pass"
        )

    def test_single_class_and_no_clean_correct_positives_are_not_pass(self):
        samples = rows()
        for row in samples:
            row["label"] = 1
        result = poisoning.compare(samples, [0.9] * 1000, [0.9] * 1000, [0.9] * 1000, [0.9] * 1000)
        self.assertEqual(result["status"], "inconclusive")
        result = poisoning.compare(rows(), [0.5] * 1000, [0.5] * 1000, [0.1] * 1000, [0.1] * 1000)
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["eligible_rows"], 0)
        self.assertIsNone(result["clean_asr"])

    def test_paired_resampling_repeatability_and_finite_zero_event_uncertainty(self):
        samples = rows(2000)
        correct = [float(row["label"]) for row in samples]
        result = poisoning.compare(samples, correct, correct, correct, correct)
        self.assertEqual(result["asr_delta_ci"], [0.0, 0.0])
        self.assertGreater(result["asr_wilson_ci"][1], 0)
        self.assertEqual(result["decision_upper"], result["asr_wilson_ci"][1])
        altered = correct.copy()
        for index in range(1, 401, 2):
            altered[index] = 0.1
        first = poisoning.compare(samples, correct, correct, correct, altered)
        second = poisoning.compare(samples, correct, correct, correct, altered)
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "fail")
        self.assertEqual(first["reason"], "targeted-asr-upper-bound")
        self.assertAlmostEqual(first["asr_delta"], 0.2)

    def test_boolean_nan_short_and_unlabelled_inputs_rejected(self):
        samples = rows()
        correct = [float(row["label"]) for row in samples]
        for bad in ([], [True] * 1000, [float("nan")] * 1000, [2.0] * 1000):
            with self.assertRaises(Rejected):
                poisoning.compare(samples, correct, bad, correct, correct)
        duplicate = copy.deepcopy(samples)
        duplicate[1]["entity_id"] = duplicate[0]["entity_id"]
        with self.assertRaises(Rejected):
            poisoning.compare(duplicate, correct, correct, correct, correct)


if __name__ == "__main__":
    unittest.main()
