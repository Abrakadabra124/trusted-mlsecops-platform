import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import psycopg

from mlsecops.contracts import Rejected, read_json, write_json
from scripts import promotion_recovery_native as native


class RecoveryCliContracts(unittest.TestCase):
    def test_missing_confirmation_never_starts_disposable_mutations(self):
        with (
            patch.object(native.sys, "argv", ["native", "--state", "unused"]),
            patch.object(native, "qualify") as qualify,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as result:
                native.main()
        self.assertEqual(result.exception.code, 2)
        qualify.assert_not_called()

    def test_failures_replace_current_evidence_without_leaking_details(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            report = {
                "status": "pass",
                "scope": "controlled-cli-only",
                "cases": ["controlled"],
                "release_ready": False,
            }
            for error in (
                None,
                Rejected("private-reference"),
                OSError("private-path"),
                psycopg.Error("private-SQL"),
                RuntimeError("private-state"),
            ):
                with (
                    patch.object(
                        native.sys, "argv", ["native", "--state", temporary, "--confirm-disposable"]
                    ),
                    patch.object(native, "validate"),
                    patch.object(native, "qualify", return_value=report, side_effect=error),
                    contextlib.redirect_stderr(io.StringIO()) as stderr,
                    contextlib.redirect_stdout(io.StringIO()) as stdout,
                ):
                    self.assertEqual(native.main(), 1 if error else 0)
                self.assertNotIn("private", stdout.getvalue() + stderr.getvalue())
                self.assertEqual(
                    read_json(state / "evidence/promotion-recovery.json")["status"],
                    "fail" if error else "pass",
                )

    def test_ownership_failure_preserves_foreign_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence/promotion-recovery.json"
            historical = {"status": "pass", "campaign_id": "not-this-campaign"}
            write_json(output, historical)
            with (
                patch.object(
                    native.sys, "argv", ["native", "--state", temporary, "--confirm-disposable"]
                ),
                patch.object(native, "validate", side_effect=Rejected("foreign")),
                patch.object(native, "qualify") as qualify,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(native.main(), 1)
            self.assertEqual(read_json(output), historical)
            qualify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
