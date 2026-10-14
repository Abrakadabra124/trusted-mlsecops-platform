import copy
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from mlsecops import promotion_recovery, storage_backup, storage_restore, storage_snapshot
from mlsecops.contracts import Rejected, canonical, digest, now, write_json
from mlsecops.signing import ROLES, create_key, sign


class PromotionRecoveryContracts(unittest.TestCase):
    def fixture(self):
        return {
            "migration": promotion_recovery.migration(),
            "tables": {
                name: {"rows": 0, "bytes": 0, "sha256": "a" * 64, "invalid": 0}
                for name in promotion_recovery.TABLES
            },
        }

    def test_exact_ledger_contract_and_unknown_history_fail_closed(self):
        expected = self.fixture()
        self.assertEqual(promotion_recovery.validate_ledger(expected), expected)
        mutations = []
        for value in (None, {}, {**expected, "extra": True}):
            mutations.append(value)
        for version in (True, 0, 2):
            mutations.append(
                {**expected, "migration": {**expected["migration"], "version": version}}
            )
        mutations.append({**expected, "migration": {"version": 1, "sha256": "b" * 64}})
        mutations.append({**expected, "tables": {}})
        for field, value in (("invalid", 1), ("rows", -1), ("bytes", True), ("sha256", "latest")):
            changed = copy.deepcopy(expected)
            changed["tables"]["heads"][field] = value
            mutations.append(changed)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(Rejected):
                promotion_recovery.validate_ledger(value)

    def test_readback_validates_database_not_only_a_saved_manifest(self):
        with patch.object(
            promotion_recovery, "admin", return_value=canonical(self.fixture()).decode()
        ):
            self.assertEqual(promotion_recovery.read("owned"), self.fixture())
        with patch.object(promotion_recovery, "admin", return_value="{}"):
            with self.assertRaises(Rejected):
                promotion_recovery.read("owned")

    def test_fencing_requires_termination_and_zero_remaining_sessions(self):
        for responses, success in (
            (["", "t\nt", "0", "0"], True),
            (["", "f"], False),
            (["", "", "-1"], False),
            (["", "", "0", "1"], False),
        ):
            with patch.object(promotion_recovery, "admin", side_effect=responses):
                if success:
                    promotion_recovery.freeze("owned")
                else:
                    with self.assertRaisesRegex(Rejected, "sessions_not_fenced"):
                        promotion_recovery.freeze("owned")
        with patch.object(promotion_recovery, "admin", side_effect=["", "-1"]):
            promotion_recovery.thaw("owned")
        with patch.object(promotion_recovery, "admin", side_effect=["", "0"]):
            with self.assertRaisesRegex(Rejected, "maintenance_not_released"):
                promotion_recovery.thaw("owned")

    def test_extended_toc_is_exact_data_only_scope(self):
        tables = [("ml", name) for name in storage_snapshot.TABLES]
        tables += [("ml_promotion", name) for name in promotion_recovery.TABLES]
        content = "\n".join(
            f"{index}; 0 {index} TABLE DATA {schema} {name} ml_owner"
            for index, (schema, name) in enumerate(tables, 1)
        ).encode()
        storage_restore.validate_toc(content, include_promotion=True)
        with self.assertRaises(Rejected):
            storage_restore.validate_toc(content)
        for invalid in (
            b"",
            content.split(b"\n", 1)[1],
            content + b"\n" + content.split(b"\n", 1)[0],
            content + b"\n99; 0 99 FUNCTION ml_promotion unsafe ml_owner",
            content.replace(b"ml_promotion heads", b"public heads"),
        ):
            with self.assertRaises(Rejected):
                storage_restore.validate_toc(invalid, include_promotion=True)

    def test_extended_snapshot_reads_both_ledgers_in_one_export(self):
        result = {
            "snapshot": "00000001-00000002-1",
            "tables": self.cas(),
            "promotion": self.fixture(),
        }

        @contextmanager
        def session(arguments, query):
            self.assertIn("REPEATABLE READ READ ONLY", query)
            self.assertIn("ml_promotion.events", query)
            self.assertEqual(query.count("pg_export_snapshot()"), 1)
            yield result, None

        with patch.object(storage_snapshot, "json_session", side_effect=session):
            with storage_snapshot.snapshot("owned", include_promotion=True) as observed:
                self.assertEqual(observed, result)
            result["promotion"]["tables"]["heads"]["invalid"] = 1
            with self.assertRaises(Rejected):
                with storage_snapshot.snapshot("owned", include_promotion=True):
                    self.fail("Invalid journal cannot reach pg_dump")

    def cas(self):
        return {
            name: {"rows": 0, "bytes": 0, "sha256": "a" * 64, "invalid": 0}
            for name in storage_snapshot.TABLES
        }

    def test_manifest_v2_requires_exact_promotion_schema_and_combined_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            public = {role: create_key(state / f"keys/{role}.pem") for role in ROLES}
            policy = {"scope": "controlled"}
            statement = {
                "schema_version": 2,
                "format": "postgres-custom-data-only",
                "started_at": now(),
                "completed_at": now(),
                "source_workspace": "a" * 32,
                "image": storage_backup.IMAGE,
                "migration": storage_backup.migration(),
                "policy_digest": digest(canonical(policy)),
                "trusted_keys_digest": digest(canonical(public)),
                "archive": {"name": "data.dump", "sha256": digest(b"PGDMP"), "bytes": 5},
                "tables": self.cas(),
                "promotion": self.fixture(),
            }

            def envelope(value):
                return sign(value, "storage-backup", state / "keys/trust.pem")

            self.assertEqual(
                storage_backup.verify_manifest(envelope(statement), public, policy), statement
            )
            invalid = [
                {**statement, "schema_version": True},
                {**statement, "schema_version": 1},
                {key: value for key, value in statement.items() if key != "promotion"},
                {**statement, "promotion": None},
            ]
            oversized = copy.deepcopy(statement)
            oversized["tables"]["releases"].update(rows=6000, bytes=6000)
            oversized["promotion"]["tables"]["events"].update(rows=6000, bytes=6000)
            invalid.append(oversized)
            for value in invalid:
                with self.assertRaises(Rejected):
                    storage_backup.verify_manifest(envelope(value), public, policy)
            root = state / "root"
            write_json(root / "policies/local-cpu.json", policy)
            for pin in (None, "0" * 64):
                with patch.object(
                    storage_restore, "read_backup", return_value=(statement, b"PGDMP")
                ):
                    with self.assertRaisesRegex(Rejected, "restore_backup_pin"):
                        storage_restore.restore(
                            root, state, state / "target", public, expected_backup_id=pin
                        )
                self.assertFalse((state / "target").exists())


class PromotionRestoreContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = self.root / "restored"
        self.public = {role: create_key(self.root / f"keys/{role}.pem") for role in ROLES}
        write_json(self.root / "policies/local-cpu.json", {"scope": "controlled"})
        fixture = PromotionRecoveryContracts()
        self.promotion = fixture.fixture()
        self.tables = fixture.cas()
        self.statement = {
            "schema_version": 2,
            "source_workspace": "a" * 32,
            "tables": self.tables,
            "promotion": self.promotion,
        }
        self.pin = digest(canonical(self.statement))
        self.marker = {
            "name": "owned",
            "workspace_id": "b" * 32,
            "container_id": "controlled",
            "port": 15442,
        }
        self.patches = {}

        def replace(module, name, **arguments):
            patcher = patch.object(module, name, **arguments)
            self.patches[name] = patcher.start()
            self.addCleanup(patcher.stop)

        replace(storage_restore, "read_backup", return_value=(self.statement, b"PGDMP"))
        replace(
            storage_restore,
            "initialize",
            side_effect=lambda root, target: write_json(target / "workspace.json", {}),
        )
        replace(storage_restore, "bootstrap")
        replace(storage_restore, "validate", return_value=self.marker)
        replace(storage_restore, "verify_configuration")
        replace(storage_restore, "ledger", return_value=self.tables)
        replace(storage_restore.promotion_state, "install")
        replace(promotion_recovery, "read", return_value=self.promotion)
        replace(promotion_recovery, "freeze")
        replace(promotion_recovery, "thaw")
        tables = [("ml", name) for name in self.tables] + [
            ("ml_promotion", name) for name in promotion_recovery.TABLES
        ]
        toc = "\n".join(
            f"{index}; 0 {index} TABLE DATA {schema} {name} ml_owner"
            for index, (schema, name) in enumerate(tables, 1)
        ).encode()
        replace(
            storage_restore,
            "binary_command",
            side_effect=lambda arguments, *args, **kwargs: toc if "--list" in arguments else b"",
        )

    def restore(self, **keywords):
        return storage_restore.restore(
            self.root,
            self.root / "backup",
            self.target,
            self.public,
            15442,
            expected_backup_id=self.pin,
            **keywords,
        )

    def test_new_target_receipt_then_idempotent_readback_no_reimport(self):
        receipt = self.restore()
        self.assertFalse(receipt["release_ready"])
        self.assertFalse(receipt["reused"])
        self.assertEqual(receipt["promotion"], self.promotion)
        self.patches["freeze"].assert_called_once_with("owned")
        self.patches["thaw"].assert_called_once_with("owned")
        self.assertTrue(self.restore()["reused"])
        self.assertEqual(self.patches["binary_command"].call_count, 2)
        changed = copy.deepcopy(self.promotion)
        changed["tables"]["heads"]["sha256"] = "b" * 64
        self.patches["read"].return_value = changed
        with self.assertRaisesRegex(Rejected, "restore_existing_promotion_changed"):
            self.restore()
        self.assertEqual(self.patches["thaw"].call_count, 2)

    def test_concurrent_restore_is_rejected_before_bootstrap_or_fencing(self):
        entered, proceed = threading.Event(), threading.Event()

        def initialize(root, target):
            entered.set()
            if not proceed.wait(5):
                raise AssertionError("Controlled first restore did not resume")
            write_json(target / "workspace.json", {})

        self.patches["initialize"].side_effect = initialize
        with ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(self.restore)
            try:
                self.assertTrue(entered.wait(5))
                with self.assertRaisesRegex(Rejected, "restore_target_busy"):
                    self.restore()
                self.patches["freeze"].assert_not_called()
            finally:
                proceed.set()
            self.assertFalse(first.result(timeout=5)["release_ready"])
        self.patches["freeze"].assert_called_once_with("owned")
        self.patches["thaw"].assert_called_once_with("owned")

    def test_interrupted_or_mismatched_import_does_not_open_clients(self):
        self.patches["binary_command"].side_effect = Rejected("controlled-import-failure")
        with self.assertRaisesRegex(Rejected, "controlled-import-failure"):
            self.restore()
        self.patches["thaw"].assert_not_called()
        self.assertFalse((self.target / "recovery.json").exists())
        with self.assertRaisesRegex(Rejected, "restore_requires_new_target"):
            self.restore()

    def test_post_import_journal_mismatch_stays_fenced(self):
        changed = copy.deepcopy(self.promotion)
        changed["tables"]["heads"]["sha256"] = "b" * 64
        self.patches["read"].side_effect = [self.promotion, changed]
        with self.assertRaisesRegex(Rejected, "restore_promotion_ledger_mismatch"):
            self.restore()
        self.patches["thaw"].assert_not_called()

    def test_nonempty_promotion_target_and_changed_receipt_are_not_repaired(self):
        changed = copy.deepcopy(self.promotion)
        changed["tables"]["heads"].update(rows=1, bytes=1)
        self.patches["read"].return_value = changed
        with self.assertRaisesRegex(Rejected, "restore_promotion_target_not_empty"):
            self.restore()
        self.patches["binary_command"].assert_not_called()

    def test_experimental_image_is_not_implicitly_adopted_for_promotion_recovery(self):
        with patch.object(storage_restore, "image_reference"):
            with self.assertRaisesRegex(Rejected, "experimental_image_not_qualified"):
                self.restore(experimental_image_id="sha256:" + "a" * 64)
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    unittest.main()
