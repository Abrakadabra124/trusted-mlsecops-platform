import copy
import unittest
from unittest.mock import patch

from mlsecops import promotion_recovery, storage_snapshot
from mlsecops.contracts import Rejected, canonical
from scripts import kube_promotion_snapshot as snapshot


class SnapshotContracts(unittest.TestCase):
    def fixture(self):
        def tables(names):
            return {
                name: {"rows": 0, "bytes": 0, "sha256": "a" * 64, "invalid": 0} for name in names
            }

        return {
            "objects": tables(storage_snapshot.TABLES),
            "promotion": {
                "migration": promotion_recovery.migration(),
                "tables": tables(promotion_recovery.TABLES),
            },
        }

    def test_single_statement_reads_artifacts_and_selected_journal_from_owned_database(self):
        expected = self.fixture()
        with patch.object(
            snapshot.kube_storage, "admin", return_value=canonical(expected).decode()
        ) as admin:
            self.assertEqual(snapshot.read("owned-state"), expected)
        admin.assert_called_once()
        self.assertEqual(admin.call_args.args[0], "owned-state")
        sql = admin.call_args.args[1]
        self.assertTrue(sql.startswith("SELECT jsonb_build_object("))
        self.assertEqual(sql.count(";"), 1)
        for table in ("heads", "events", "authorities"):
            self.assertIn("ml_promotion." + table, sql)
        self.assertIn("ml.releases", sql)

    def test_missing_journal_or_corrupted_migration_and_rows_cannot_pass(self):
        changed = copy.deepcopy(self.fixture())
        changed["promotion"]["tables"]["heads"]["invalid"] = 1
        migration = copy.deepcopy(self.fixture())
        migration["promotion"]["migration"]["sha256"] = "b" * 64
        for value in (
            {"objects": self.fixture()["objects"]},
            {**self.fixture(), "extra": True},
            changed,
            migration,
        ):
            with (
                patch.object(
                    snapshot.kube_storage, "admin", return_value=canonical(value).decode()
                ),
                self.assertRaises(Rejected),
            ):
                snapshot.read("owned-state")


if __name__ == "__main__":
    unittest.main()
