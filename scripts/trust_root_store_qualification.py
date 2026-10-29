"""Controlled operator transport; live SQL is exercised only in hosted CI."""

import io
import runpy
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import MagicMock, patch

from mlsecops import trust_authority, trust_root_store, trust_rotation
from mlsecops.contracts import Rejected, canonical, digest
from scripts import trust_rotation_qualification as fixtures


class RotationStore(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RotationContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.package = self.fixture.package()
        self.before = {
            "environment": "local-cpu",
            "root_public": self.fixture.old_public,
            "version": 1,
            "sha256": digest(canonical(self.fixture.previous)),
            "envelope": self.fixture.previous,
            "clock": self.fixture.clock,
        }
        self.after = {
            **self.before,
            "root_public": self.fixture.new_public,
            "version": 2,
            "sha256": digest(canonical(self.package["document"])),
            "envelope": self.package["document"],
        }
        self.migrations = "1:" + digest(trust_authority.migration_sql().encode())
        self.migrations += "\n2:" + digest(trust_rotation.migration_sql().encode())
        self.execute = MagicMock(side_effect=self.query)
        self.backend = lambda state: ("owned", self.execute)
        self.addCleanup(patch.stopall)
        self.current = patch.object(
            trust_authority, "current", side_effect=[("owned", self.before), ("owned", self.after)]
        ).start()

    def query(self, container, sql):
        self.assertEqual(container, "owned")
        if "SELECT version || ':' || sha256" in sql:
            return self.migrations
        if sql.startswith("SELECT encode(envelope"):
            return canonical(self.fixture.previous).hex()
        if sql.startswith("SELECT encode(package"):
            return canonical(self.package).hex()
        if sql.startswith("BEGIN;"):
            return ""
        raise AssertionError("Unexpected controlled SQL")

    def rotate(self, **changes):
        return trust_root_store.rotate(
            "state",
            self.package,
            **{
                "current_root": self.fixture.old_public,
                "next_root": self.fixture.new_public,
                "backend": self.backend,
                **changes,
            },
        )

    def writes(self):
        return [
            call.args[1]
            for call in self.execute.call_args_list
            if call.args[1].startswith("BEGIN;")
        ]

    def test_atomic_transition_and_readback_do_not_reset_documents(self):
        result = self.rotate()
        self.assertEqual(result["state"], "rotated-not-activated")
        self.assertEqual(result["version"], 2)
        self.assertEqual(result["document_sha256"], self.after["sha256"])
        self.assertFalse(result["release_ready"])
        self.assertFalse(result["reused"])
        self.assertEqual(len(self.writes()), 1)
        sql = self.writes()[0]
        for expected in (
            "pg_advisory_xact_lock",
            "rotation_concurrent_update_conflict",
            "rotation_expired_or_future",
            "INSERT INTO ml_trust.documents",
            "INSERT INTO ml_trust.root_rotations",
            "UPDATE ml_trust.settings",
        ):
            self.assertIn(expected, sql)
        for forbidden in ("DELETE", "TRUNCATE", "DROP"):
            self.assertNotIn(forbidden, sql)

    def test_exact_current_retry_revalidates_both_signatures_and_receipt_without_writes(self):
        self.current.side_effect = [("owned", self.after)]
        result = self.rotate()
        self.assertTrue(result["reused"])
        self.assertEqual(self.writes(), [])
        self.current.side_effect = [("owned", self.after)]
        self.package["acceptance"]["signatures"] = []
        with self.assertRaises(Rejected):
            self.rotate()
        self.assertEqual(self.writes(), [])

    def test_foreign_pins_changed_head_and_missing_migration_do_not_write(self):
        for field, value in (
            ("root_public", self.fixture.new_public),
            ("sha256", "0" * 64),
            ("version", 3),
        ):
            self.current.side_effect = [("owned", {**self.before, field: value})]
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.rotate()
        self.current.side_effect = [("owned", self.before)]
        with self.assertRaises(Rejected):
            self.rotate(next_root=self.fixture.old_public)
        self.current.side_effect = [("owned", self.before)]
        self.migrations = self.migrations.splitlines()[0]
        with self.assertRaisesRegex(Rejected, "rotation_migration_required"):
            self.rotate()
        self.assertEqual(self.writes(), [])

    def test_retry_rejects_missing_or_changed_receipt_and_previous_document(self):
        for prefix in ("SELECT encode(package", "SELECT encode(envelope"):
            for raw in ("", b"changed".hex()):
                self.current.side_effect = [("owned", self.after)]
                self.execute.side_effect = lambda c, s: (
                    raw if s.startswith(prefix) else self.query(c, s)
                )
                with self.subTest(prefix=prefix, raw=raw), self.assertRaises(Rejected):
                    self.rotate()
        self.assertEqual(self.writes(), [])

    def test_unconfirmed_commit_is_not_reported_as_rotation_success(self):
        for field, value in (
            ("root_public", self.fixture.old_public),
            ("sha256", "0" * 64),
            ("version", 3),
        ):
            self.current.side_effect = [
                ("owned", self.before),
                ("owned", {**self.after, field: value}),
            ]
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(Rejected, "rotation_commit_unconfirmed"),
            ):
                self.rotate()
        self.current.side_effect = [("owned", self.before), ("owned", self.after)]
        self.execute.side_effect = lambda c, s: (
            "" if s.startswith("SELECT encode(package") else self.query(c, s)
        )
        with self.assertRaisesRegex(Rejected, "rotation_receipt_unconfirmed"):
            self.rotate()

    def test_additive_migration_is_explicit_idempotent_and_checksum_checked(self):
        self.current.side_effect = [("owned", self.before)]
        result = trust_root_store.migrate("state", backend=self.backend)
        self.assertTrue(result["reused"])
        self.assertEqual(self.writes(), [])
        self.current.side_effect = [("owned", self.before)]
        v1 = self.migrations.splitlines()[0]
        self.execute.side_effect = [v1, "", self.migrations]
        result = trust_root_store.migrate("state", backend=self.backend)
        self.assertFalse(result["reused"])
        self.assertEqual(len(self.writes()), 1)
        self.current.side_effect = [("owned", self.before)]
        self.execute.side_effect = [v1, "", v1]
        with self.assertRaises(Rejected):
            trust_root_store.migrate("state", backend=self.backend)

    def test_cli_confirmation_required_and_errors_are_redacted(self):
        for args in (
            ["migrate", "--state", "private"],
            ["rotate", "--state", "private", "--confirm-authority"],
        ):
            output = io.StringIO()
            with redirect_stderr(output):
                self.assertEqual(trust_root_store.main(args), 1)
            self.assertNotIn("private", output.getvalue())
        for action, target, extra in (
            ("migrate", "migrate", []),
            (
                "rotate",
                "rotate",
                [
                    "--document",
                    "signed.json",
                    "--current-root",
                    self.fixture.old_public,
                    "--next-root",
                    self.fixture.new_public,
                ],
            ),
        ):
            with (
                patch.object(
                    trust_root_store, target, return_value={"release_ready": False}
                ) as invoked,
                patch.object(trust_root_store, "read_json", return_value=self.package),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    trust_root_store.main(
                        [action, "--state", "state", "--confirm-authority", *extra]
                    ),
                    0,
                )
                invoked.assert_called_once()

    def test_kubernetes_cli_routes_only_to_explicit_owned_backend(self):
        from mlsecops.kube_trust import binding

        with (
            patch.object(trust_root_store, "migrate", return_value={}) as migrate,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                trust_root_store.main(
                    [
                        "migrate",
                        "--state",
                        "state",
                        "--backend",
                        "kubernetes",
                        "--confirm-authority",
                    ]
                ),
                0,
            )
        migrate.assert_called_once_with("state", backend=binding)
        with (
            patch.object(trust_authority, "install", return_value="a" * 64) as install,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                trust_authority.main(
                    [
                        "install",
                        "--state",
                        "state",
                        "--backend",
                        "kubernetes",
                        "--confirm-authority",
                        "--root-public",
                        self.fixture.new_public,
                    ]
                ),
                0,
            )
        self.assertIs(install.call_args.kwargs["backend"], binding)
        with (
            patch("sys.argv", ["trust_root_store", "migrate", "--state", "private"]),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as result,
        ):
            runpy.run_module("mlsecops.trust_root_store", run_name="__main__")
        self.assertEqual(result.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
