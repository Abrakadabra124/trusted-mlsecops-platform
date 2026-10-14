import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import psycopg

from mlsecops.contracts import Rejected, read_json, write_json
from scripts import promotion_native as native


class PromotionNativeCliContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name)
        self.argv = ["native", "--state", str(self.state), "--confirm-disposable"]

    def test_explicit_disposable_confirmation_is_required_before_mutation(self):
        with (
            patch.object(native.sys, "argv", self.argv[:-1]),
            patch.object(native, "qualify") as qualify,
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as result,
        ):
            native.main()
        self.assertEqual(result.exception.code, 2)
        qualify.assert_not_called()

    def test_cli_current_outcome_and_errors_are_sanitized(self):
        report = {
            "scope": "controlled-cli-only",
            "status": "pass",
            "cases": ["controlled"],
            "release_ready": False,
        }
        for error in (
            None,
            Rejected("private-path"),
            psycopg.OperationalError("private-database"),
            OSError("private-log"),
            RuntimeError("private-thread-state"),
        ):
            with (
                patch.object(native.sys, "argv", self.argv),
                patch.object(native, "validate"),
                patch.object(native, "qualify", return_value=report, side_effect=error),
                contextlib.redirect_stdout(io.StringIO()) as stdout,
                contextlib.redirect_stderr(io.StringIO()) as stderr,
            ):
                self.assertEqual(native.main(), 1 if error else 0)
            self.assertNotIn("private", stdout.getvalue() + stderr.getvalue())
            self.assertEqual(
                read_json(self.state / "evidence/promotion-native.json")["status"],
                "fail" if error else "pass",
            )

    def test_foreign_state_is_not_overwritten_and_write_failure_is_nonzero(self):
        output = self.state / "evidence/promotion-native.json"
        original = {"status": "pass", "campaign_id": "historical"}
        write_json(output, original)
        with (
            patch.object(native.sys, "argv", self.argv),
            patch.object(native, "validate", side_effect=Rejected("foreign-runtime")),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(native.main(), 1)
        self.assertEqual(read_json(output), original)
        with (
            patch.object(native.sys, "argv", self.argv),
            patch.object(native, "validate"),
            patch.object(native, "write_json", side_effect=OSError("private-output")),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(native.main(), 1)

    def test_record_uses_one_transaction_and_returns_database_reference(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.execute.return_value.fetchone.return_value = ("a" * 64,)
        with patch.object(native.storage, "connect", return_value=connection):
            self.assertEqual(native.record("promoter", "a" * 64), "a" * 64)
        self.assertEqual(connection.execute.call_count, 1)
        connection.__exit__.assert_called_once_with(None, None, None)


if __name__ == "__main__":
    unittest.main()
