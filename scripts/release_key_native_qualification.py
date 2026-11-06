import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import psycopg

from mlsecops.contracts import Rejected, read_json
from scripts import release_key_native as native


class ReleaseKeyNativeCliContracts(unittest.TestCase):
    def test_policy_uses_epoch_seconds_before_first_sql_mutation(self):
        # contracts.now() is an ISO report timestamp, not an arithmetic clock.
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            with (
                patch.object(native, "validate", return_value={"name": "owned"}),
                patch.object(native, "command", side_effect=["", "a" * 40]),
                patch.object(native, "source_fingerprint", return_value="b" * 64),
                patch.object(
                    native.promotion_state, "install", side_effect=Rejected("first-sql-boundary")
                ) as install,
                self.assertRaisesRegex(Rejected, "first-sql-boundary"),
            ):
                native.qualify(state, state)
            install.assert_called_once_with(state.resolve())

    def test_confirmation_and_owned_state_are_required_before_mutation(self):
        with (
            patch.object(native.sys, "argv", ["native", "--state", "foreign"]),
            patch.object(native, "qualify") as qualify,
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as error,
        ):
            native.main()
        self.assertEqual(error.exception.code, 2)
        qualify.assert_not_called()
        with (
            patch.object(
                native.sys, "argv", ["native", "--state", "foreign", "--confirm-disposable"]
            ),
            patch.object(native, "validate", side_effect=Rejected("foreign")),
            patch.object(native, "qualify") as qualify,
            patch.object(native, "write_json") as write,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(native.main(), 1)
        qualify.assert_not_called()
        write.assert_not_called()

    def test_cli_records_current_outcome_without_private_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            report = {"status": "pass", "release_ready": False, "cases": ["controlled"]}
            for failure in (
                None,
                Rejected("private-data"),
                psycopg.Error("private-sql"),
                OSError("private-path"),
            ):
                with (
                    patch.object(
                        native.sys,
                        "argv",
                        ["native", "--state", str(state), "--confirm-disposable"],
                    ),
                    patch.object(native, "validate"),
                    patch.object(native, "qualify", return_value=report, side_effect=failure),
                    contextlib.redirect_stdout(io.StringIO()) as stdout,
                    contextlib.redirect_stderr(io.StringIO()) as stderr,
                ):
                    self.assertEqual(native.main(), 1 if failure else 0)
                self.assertNotIn("private", stdout.getvalue() + stderr.getvalue())
                self.assertEqual(
                    read_json(state / "evidence/release-key-native.json")["status"],
                    "fail" if failure else "pass",
                )


if __name__ == "__main__":
    unittest.main()
