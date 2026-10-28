import copy
import unittest

from mlsecops.contracts import Rejected
from scripts import absolute_poisoning
from scripts.poisoning import policy as original_policy


class AbsoluteProtocolTests(unittest.TestCase):
    def records(self):
        return [
            {
                **case,
                "run_id": f"{i:032x}",
                "mutation_count": case["count"],
                "metrics": {"status": "pass"},
            }
            for i, case in enumerate(absolute_poisoning.matrix(), 1)
        ]

    def test_exact_cartesian_matrix_and_existing_thresholds(self):
        cases = absolute_poisoning.matrix()
        self.assertEqual(len(cases), 42)
        self.assertEqual(len({c["id"] for c in cases}), 42)
        self.assertEqual(sum(c["family"] == "clean" for c in cases), 6)
        self.assertEqual(
            {(c["train_rows"], c["seed"]) for c in cases},
            {(n, s) for n in (2000, 14000) for s in (17, 29, 43)},
        )
        for key in (
            "maximum_auprc_drop",
            "maximum_asr_increase_upper",
            "minimum_eligible",
            "bootstrap",
        ):
            self.assertEqual(absolute_poisoning.policy()[key], original_policy()[key])
        summary = absolute_poisoning.summarize(self.records())
        self.assertEqual(
            (summary["training_runs"], summary["poisoned_runs"], summary["clean_controls"]),
            (42, 36, 6),
        )
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(absolute_poisoning.full_status(summary), "inconclusive")

    def test_partial_duplicate_reordered_and_false_counts_are_rejected(self):
        original = self.records()
        invalid = [original[:-1], original[::-1], original + [original[0]]]
        for field, value in (
            ("train_rows", 2001),
            ("train_rows", True),
            ("count", 24),
            ("seed", 18),
            ("mutation_count", False),
            ("metrics", {"status": "skipped"}),
            ("run_id", original[1]["run_id"]),
        ):
            changed = copy.deepcopy(original)
            changed[0][field] = value
            invalid.append(changed)
        for rows in invalid:
            with self.assertRaises(Rejected):
                absolute_poisoning.summarize(rows)

    def test_failure_preserved_even_without_challenges(self):
        rows = self.records()
        rows[1]["metrics"]["status"] = "inconclusive"
        summary = absolute_poisoning.summarize(rows)
        self.assertEqual(absolute_poisoning.full_status(summary), "inconclusive")
        rows[2]["metrics"]["status"] = "fail"
        summary = absolute_poisoning.summarize(rows)
        self.assertEqual(summary["status"], "fail")
        self.assertEqual(absolute_poisoning.full_status(summary), "fail")


if __name__ == "__main__":
    unittest.main()
