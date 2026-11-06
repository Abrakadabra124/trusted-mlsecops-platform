import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import psycopg

from mlsecops.contracts import Rejected, read_json
from scripts import release_key_serving_native as native


class SignerServingCliContracts(unittest.TestCase):
    def test_disposable_confirmation_and_image_are_required(self):
        for arguments in (
            ["--state", "owned", "--worker-image", "test"],
            ["--state", "owned", "--confirm-disposable"],
        ):
            with (
                patch.object(native, "qualify") as qualify,
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as error,
            ):
                native.main(arguments)
            self.assertEqual(error.exception.code, 2)
            qualify.assert_not_called()

    def test_cli_reports_current_result_without_private_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            report = {"status": "pass", "release_ready": False, "cases": ["controlled"]}
            arguments = ["--state", directory, "--worker-image", "test", "--confirm-disposable"]
            for failure in (
                None,
                Rejected("private-reference"),
                psycopg.Error("private-sql"),
                OSError("private-path"),
            ):
                with (
                    patch.object(native.storage_bootstrap, "validate"),
                    patch.object(native, "qualify", return_value=report, side_effect=failure),
                    contextlib.redirect_stdout(io.StringIO()) as stdout,
                    contextlib.redirect_stderr(io.StringIO()) as stderr,
                ):
                    self.assertEqual(native.main(arguments), 1 if failure else 0)
                self.assertNotIn("private", stdout.getvalue() + stderr.getvalue())
                self.assertEqual(
                    read_json(state / "evidence/release-key-serving.json")["status"],
                    "fail" if failure else "pass",
                )
            with (
                patch.object(native.storage_bootstrap, "validate", side_effect=Rejected("foreign")),
                patch.object(native, "write_json") as write,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(native.main(arguments), 1)
            write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
