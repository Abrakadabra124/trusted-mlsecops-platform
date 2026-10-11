import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected
from scripts import poisoning_native
from scripts.poisoning import matrix


def results():
    return [
        {
            **case,
            "run_id": f"{index:032x}",
            "mutation_count": case["count"],
            "metrics": {"status": "pass"},
        }
        for index, case in enumerate(matrix(), 1)
    ]


class NativeContracts(unittest.TestCase):
    def test_full_matrix_aggregate_and_mixed_outcomes(self):
        records = results()
        report = poisoning_native.summarize(records)
        self.assertEqual(
            (report["training_runs"], report["poisoned_runs"], report["clean_controls"]),
            (35, 30, 5),
        )
        self.assertEqual(report["status"], "pass")
        records[1]["metrics"]["status"] = "inconclusive"
        self.assertEqual(poisoning_native.summarize(records)["status"], "inconclusive")
        records[2]["metrics"]["status"] = "fail"
        self.assertEqual(poisoning_native.summarize(records)["status"], "fail")

    def test_partial_reordered_duplicate_and_malformed_matrix_rejected(self):
        original = results()
        fixtures = [original[:-1], original[::-1], [], [{}] * 35]
        for field, value in (
            ("count", False),
            ("mutation_count", False),
            ("run_id", "invalid"),
            ("run_id", original[1]["run_id"]),
            ("family", "other"),
            ("seed", 18),
            ("metrics", {"status": "skipped"}),
        ):
            changed = copy.deepcopy(original)
            changed[0][field] = value
            fixtures.append(changed)
        for records in fixtures:
            with self.subTest(records=records[:1]), self.assertRaises(Rejected):
                poisoning_native.summarize(records)

    def test_pinned_materials_and_disjoint_frozen_probes(self):
        root = Path(__file__).resolve().parents[1]
        _, train, validation, probes, triggered = poisoning_native.materials(root)
        self.assertEqual(
            [len(rows) for rows in (train, validation, probes, triggered)],
            [14000, 3000, 3000, 3000],
        )
        self.assertFalse(
            {row["entity_id"] for row in train + validation}.intersection(
                row["entity_id"] for row in probes
            )
        )
        self.assertEqual([row["label"] for row in probes], [row["label"] for row in triggered])
        self.assertTrue(all(row["features"][4] == 1.0 for row in triggered))
        with (
            patch.object(poisoning_native, "generated", return_value=b"[]"),
            self.assertRaisesRegex(Rejected, "poisoning_source_lock_mismatch"),
        ):
            poisoning_native.materials(root)


if __name__ == "__main__":
    unittest.main()
