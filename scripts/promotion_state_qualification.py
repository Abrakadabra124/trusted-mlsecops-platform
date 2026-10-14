import unittest
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import psycopg

from mlsecops import promotion_state, storage_snapshot
from mlsecops.contracts import Rejected, canonical, digest


class PromotionStateContracts(unittest.TestCase):
    def setUp(self):
        owned = patch.object(promotion_state, "validate", return_value={"name": "owned"})
        owned.start()
        self.addCleanup(owned.stop)
        self.request = {
            "schema_version": 1,
            "kind": "promotion-selection",
            "environment": "local-cpu",
            "policy_sha256": "a" * 64,
            "sequence": 1,
            "subject_sha256": "b" * 64,
            "proposal_reference": "c" * 64,
            "authorization_reference": "d" * 64,
            "issued_at": 2000000000,
            "expires_at": 2000000060,
        }

    def test_request_is_bounded_canonical_and_not_authorization(self):
        content = canonical(self.request)
        self.assertEqual(promotion_state.request(content), self.request)
        self.assertNotIn("release_ready", self.request)

    def test_invalid_schema_identity_sequence_and_window_are_rejected(self):
        for field, value in (
            ("schema_version", True),
            ("kind", "approved"),
            ("environment", "';DROP SCHEMA ml;"),
            ("sequence", True),
            ("sequence", 0),
            ("sequence", 2**53),
            ("subject_sha256", "latest"),
            ("issued_at", 0),
            ("expires_at", 2000000000),
            ("expires_at", 2000003601),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(Rejected):
                promotion_state.request(canonical({**self.request, field: value}))
        for content in (b"", b"x" * 65537, b" " + canonical(self.request)):
            with self.assertRaises(Rejected):
                promotion_state.request(content)
        with self.assertRaises(Rejected):
            promotion_state.request("not-bytes")

    def test_initialization_refuses_to_reset_existing_head_or_policy(self):
        with patch.object(promotion_state, "admin", return_value="different"):
            with self.assertRaisesRegex(Rejected, "configuration_conflict"):
                promotion_state.configure("owned", "local-cpu", "a" * 64)

    def test_migration_never_rewrites_existing_history(self):
        expected = digest(promotion_state.migration_sql().encode())
        with patch.object(
            promotion_state, "admin", side_effect=["ml_promotion.migrations", f"1:{expected}"]
        ):
            self.assertEqual(promotion_state.install("owned"), expected)
        with patch.object(
            promotion_state, "admin", side_effect=["ml_promotion.migrations", "wrong"]
        ):
            with self.assertRaisesRegex(Rejected, "migration_history"):
                promotion_state.install("owned")

    def test_legacy_backup_cannot_omit_promotion_ledger_silently(self):
        with patch.object(promotion_state, "admin", return_value=""):
            promotion_state.require_legacy_backup_scope("owned")
        with patch.object(promotion_state, "admin", return_value="ml_promotion"):
            with self.assertRaisesRegex(Rejected, "backup_promotion_ledger_not_supported"):
                promotion_state.require_legacy_backup_scope("owned")

    def test_backup_scope_is_rechecked_inside_exported_snapshot_not_only_preflight(self):
        result = {
            "snapshot": "00000001-00000002-1",
            "promotion_absent": True,
            "tables": {
                name: {"rows": 0, "bytes": 0, "sha256": "a" * 64, "invalid": 0}
                for name in storage_snapshot.TABLES
            },
        }

        @contextmanager
        def session(arguments, query):
            self.assertIn("REPEATABLE READ READ ONLY", query)
            self.assertIn("pg_catalog.pg_namespace", query)
            self.assertIn("pg_export_snapshot()", query)
            yield result, None

        with patch.object(storage_snapshot, "json_session", side_effect=session):
            with storage_snapshot.snapshot("owned") as observed:
                self.assertEqual(observed, result)
            for value in (False, None, 0, 1, "true"):
                result["promotion_absent"] = value
                with (
                    self.subTest(value=value),
                    self.assertRaisesRegex(Rejected, "backup_promotion_ledger_not_supported"),
                ):
                    with storage_snapshot.snapshot("owned"):
                        self.fail("An unsupported ledger must not reach pg_dump")

    def test_explicit_install_and_configuration_are_idempotent_not_reset_operations(self):
        checksum = digest(promotion_state.migration_sql().encode())
        with patch.object(
            promotion_state, "admin", side_effect=["", "", f"1:{checksum}"]
        ) as execute:
            self.assertEqual(promotion_state.install("owned"), checksum)
            self.assertIn("BEGIN;", execute.call_args_list[1].args[1])
        for existing in ("", "a" * 64):
            with patch.object(
                promotion_state, "admin", side_effect=[existing, "", "a" * 64]
            ) as execute:
                promotion_state.configure("owned", "local-cpu", "a" * 64)
                self.assertNotIn("UPDATE", execute.call_args_list[1].args[1])
        with patch.object(promotion_state, "admin", side_effect=["", "", "b" * 64]):
            with self.assertRaisesRegex(Rejected, "configuration_conflict"):
                promotion_state.configure("owned", "local-cpu", "a" * 64)

    def test_state_read_is_not_readiness_and_errors_are_sanitized(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.execute.return_value.fetchone.return_value = (1, "a" * 64)
        with patch.object(promotion_state.storage, "connect", return_value=connection):
            self.assertFalse(promotion_state.state("serving", "local-cpu")["release_ready"])
            connection.execute.return_value.fetchone.return_value = None
            with self.assertRaisesRegex(Rejected, "state_missing"):
                promotion_state.state("serving", "local-cpu")
        with patch.object(
            promotion_state.storage,
            "connect",
            side_effect=psycopg.OperationalError("private endpoint"),
        ):
            with self.assertRaisesRegex(Rejected, "state_rejected:unavailable"):
                promotion_state.state("serving", "local-cpu")


if __name__ == "__main__":
    unittest.main()
