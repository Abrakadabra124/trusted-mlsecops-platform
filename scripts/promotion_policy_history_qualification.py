"""Recovery must retain signer transitions without invalidating historical releases."""

import copy
import unittest
from contextlib import contextmanager
from unittest.mock import Mock, patch

from mlsecops import (
    promotion_recovery,
    promotion_state,
    release_key_rotation,
    storage_restore,
    storage_snapshot,
)
from mlsecops.contracts import Rejected, canonical, digest
from scripts import kube_promotion_snapshot, promotion_recovery_qualification


class PolicyHistoryContracts(unittest.TestCase):
    def test_unsupported_schema_numbers_are_not_silently_downgraded(self):
        for value in (None, True, 0, 3, "2"):
            for operation in (promotion_recovery.migration, promotion_recovery.ledger_sql):
                with self.assertRaisesRegex(Rejected, "promotion_backup_migration_mismatch"):
                    operation(value)

    def fixture(self, version=2):
        history = {"version": 1, "sha256": digest(promotion_state.migration_sql().encode())}
        names = (
            (*promotion_recovery.TABLES, "policy_rotations")
            if version == 2
            else promotion_recovery.TABLES
        )
        if version == 2:
            history = [
                history,
                {"version": 2, "sha256": digest(release_key_rotation.migration_sql().encode())},
            ]
        return {
            "migration": history,
            "tables": {
                name: {"rows": 0, "bytes": 0, "sha256": "a" * 64, "invalid": 0} for name in names
            },
        }

    def test_v1_checksum_is_frozen_and_only_exact_ordered_histories_are_accepted(self):
        self.assertEqual(
            self.fixture(1)["migration"]["sha256"],
            "d6378c6fbf34cbe6fe527f7ea87499bb205309654a3acb3b1e3ff2d3161e7304",
        )
        for version in (1, 2):
            history = self.fixture(version)["migration"]
            entries = [history] if version == 1 else history
            text = "\n".join(f"{item['version']}:{item['sha256']}" for item in entries)
            execute = Mock(return_value=text)
            self.assertEqual(promotion_state.migration_version("owned", execute), version)
            self.assertEqual(
                promotion_recovery.validate_ledger(self.fixture(version)), self.fixture(version)
            )
        for value in (
            "",
            "1:latest",
            text.splitlines()[1],
            text + "\n3:" + "b" * 64,
            "\n".join(reversed(text.splitlines())),
        ):
            with self.assertRaises(Rejected):
                promotion_state.migration_version("owned", Mock(return_value=value))

    def test_missing_rotation_table_and_corrupt_history_are_rejected(self):
        base = self.fixture()
        invalid = []
        for history in (
            None,
            [],
            base["migration"][:1],
            list(reversed(base["migration"])),
            {"version": 2, "sha256": "a" * 64},
        ):
            invalid.append({**base, "migration": history})
        for index, field, value in (
            (0, "version", True),
            (1, "sha256", "b" * 64),
            (1, "version", 2.0),
        ):
            changed = copy.deepcopy(base)
            changed["migration"][index][field] = value
            invalid.append(changed)
        invalid.append({**base, "tables": self.fixture(1)["tables"]})
        invalid.append({**base, "migration": self.fixture(1)["migration"]})
        changed = copy.deepcopy(base)
        changed["tables"]["policy_rotations"]["invalid"] = 1
        invalid.append(changed)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(Rejected):
                promotion_recovery.validate_ledger(value)

    def test_restore_toc_requires_rotations_only_for_v2_history(self):
        entries = [("ml", name) for name in storage_snapshot.TABLES]
        entries += [("ml_promotion", name) for name in self.fixture()["tables"]]
        toc = "\n".join(
            f"{i}; 0 {i} TABLE DATA {schema} {name} ml_owner"
            for i, (schema, name) in enumerate(entries, 1)
        ).encode()
        storage_restore.validate_toc(
            toc, include_promotion=True, promotion_migration=self.fixture()["migration"]
        )
        for content, history in (
            (toc.rsplit(b"\n", 1)[0], self.fixture()["migration"]),
            (toc, self.fixture(1)["migration"]),
            (toc + b"\n" + toc.splitlines()[-1], self.fixture()["migration"]),
        ):
            with self.assertRaises(Rejected):
                storage_restore.validate_toc(
                    content, include_promotion=True, promotion_migration=history
                )

    def test_rotation_rows_share_combined_database_bounds(self):
        cas = {
            name: {"rows": 0, "bytes": 0, "sha256": "a" * 64, "invalid": 0}
            for name in storage_snapshot.TABLES
        }
        base = self.fixture()
        promotion_recovery.validate_combined(cas, base)
        cas["releases"].update(rows=6000, bytes=6000)
        base["tables"]["policy_rotations"].update(rows=5000, bytes=5000)
        with self.assertRaisesRegex(Rejected, "backup_database_limit"):
            promotion_recovery.validate_combined(cas, base)

    def test_snapshot_detects_concurrent_schema_change_before_dump(self):
        @contextmanager
        def session(arguments, query):
            self.assertIn("ml_promotion.policy_rotations", query)
            self.assertEqual(query.count("pg_export_snapshot()"), 1)
            yield result, None

        result = {
            "snapshot": "00000001-00000002-1",
            "promotion": self.fixture(),
            "tables": {
                name: {"rows": 0, "bytes": 0, "sha256": "a" * 64, "invalid": 0}
                for name in storage_snapshot.TABLES
            },
        }
        with (
            patch.object(promotion_state, "migration_version", return_value=2),
            patch.object(storage_snapshot, "json_session", side_effect=session),
        ):
            with storage_snapshot.snapshot("owned", include_promotion=True) as observed:
                self.assertEqual(observed, result)
            result["promotion"] = self.fixture(1)
            with self.assertRaisesRegex(Rejected, "promotion_backup_migration_changed"):
                with storage_snapshot.snapshot("owned", include_promotion=True):
                    self.fail("Schema changed before export")

    def test_kubernetes_and_plain_readback_validate_selected_schema(self):
        result = {
            "objects": {
                name: {"rows": 0, "bytes": 0, "sha256": "a" * 64, "invalid": 0}
                for name in storage_snapshot.TABLES
            },
            "promotion": self.fixture(),
        }
        with (
            patch.object(promotion_state, "migration_version", return_value=2),
            patch.object(
                kube_promotion_snapshot.kube_storage,
                "admin",
                return_value=canonical(result).decode(),
            ) as execute,
        ):
            self.assertEqual(kube_promotion_snapshot.read("owned"), result)
            self.assertIn("ml_promotion.policy_rotations", execute.call_args.args[1])
            result["promotion"] = self.fixture(1)
            execute.return_value = canonical(result).decode()
            with self.assertRaisesRegex(Rejected, "promotion_backup_migration_changed"):
                kube_promotion_snapshot.read("owned")
        with (
            patch.object(promotion_state, "migration_version", return_value=2),
            patch.object(
                promotion_recovery, "admin", return_value=canonical(self.fixture()).decode()
            ),
        ):
            self.assertEqual(promotion_recovery.read("owned"), self.fixture())

    def test_new_restore_installs_rotation_schema_before_import_and_readback(self):
        from mlsecops import release_key_store

        case = promotion_recovery_qualification.PromotionRestoreContracts()
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.promotion = self.fixture()
        case.statement["promotion"] = case.promotion
        case.pin = digest(canonical(case.statement))
        case.patches["read"].return_value = case.promotion
        tables = [("ml", name) for name in case.tables] + [
            ("ml_promotion", name) for name in case.promotion["tables"]
        ]
        toc = "\n".join(
            f"{i}; 0 {i} TABLE DATA {schema} {name} ml_owner"
            for i, (schema, name) in enumerate(tables, 1)
        ).encode()

        def command(arguments, *args, **kwargs):
            migrate.assert_called_once_with(case.target.resolve())
            return toc if "--list" in arguments else b""

        case.patches["binary_command"].side_effect = command
        with patch.object(release_key_store, "migrate") as migrate:
            self.assertEqual(case.restore()["promotion"], case.promotion)
            self.assertTrue(case.restore()["reused"])
            migrate.assert_called_once_with(case.target.resolve())

    def test_migration_requires_exact_history_and_checks_committed_state(self):
        from mlsecops import release_key_store

        checksum = digest(release_key_rotation.migration_sql().encode())
        for versions, success, writes in (([2], True, 0), ([1, 2], True, 1), ([1, 1], False, 1)):
            execute = Mock()
            with patch.object(promotion_state, "migration_version", side_effect=versions):
                if success:
                    self.assertEqual(
                        release_key_store.migrate("owned", backend=lambda _: ("owned", execute)),
                        checksum,
                    )
                else:
                    with self.assertRaisesRegex(Rejected, "release_rotation_migration_readback"):
                        release_key_store.migrate("owned", backend=lambda _: ("owned", execute))
            self.assertEqual(execute.call_count, writes)
            if writes:
                sql = execute.call_args.args[1]
                self.assertIn("pg_advisory_xact_lock", sql)
                self.assertIn("SET LOCAL ROLE ml_owner", sql)
                self.assertIn("promotion_migration_history_mismatch", sql)
                self.assertIn(release_key_rotation.migration_sql(), sql)
        with patch.object(promotion_state, "migration_version", side_effect=Rejected("unknown")):
            execute = Mock()
            with self.assertRaisesRegex(Rejected, "unknown"):
                release_key_store.migrate("owned", backend=lambda _: ("owned", execute))
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
