import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops import promotion_state, storage_backup
from mlsecops.contracts import Rejected, read_json
from scripts import trust_native


class TrustRunnerContracts(unittest.TestCase):
    def test_confirmation_required_before_work(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            trust_native.main(["--state", "private"])
        self.assertEqual(error.exception.code, 2)

    def test_unowned_state_does_not_run_campaign_or_create_output(self):
        with (
            patch.object(
                trust_native.storage_bootstrap, "validate", side_effect=Rejected("private endpoint")
            ),
            patch.object(trust_native, "qualify") as qualify,
            redirect_stderr(io.StringIO()) as output,
        ):
            self.assertEqual(trust_native.main(["--state", "private", "--confirm-disposable"]), 1)
        qualify.assert_not_called()
        self.assertNotIn("private", output.getvalue())

    def test_report_and_failure_redaction(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            report = {"status": "pass", "cases": ["controlled-runner-test"], "release_ready": False}
            with (
                patch.object(trust_native.storage_bootstrap, "validate", return_value={}),
                patch.object(trust_native, "qualify", return_value=report),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    trust_native.main(["--state", str(state), "--confirm-disposable"]), 0
                )
            self.assertEqual(read_json(state / "evidence/trust-qualification.json"), report)
            with (
                patch.object(trust_native.storage_bootstrap, "validate", return_value={}),
                patch.object(
                    trust_native, "qualify", side_effect=RuntimeError("private SQL and credentials")
                ),
                redirect_stderr(io.StringIO()) as output,
            ):
                self.assertEqual(
                    trust_native.main(["--state", str(state), "--confirm-disposable"]), 1
                )
            self.assertNotIn("private", output.getvalue())
            self.assertEqual(
                read_json(state / "evidence/trust-qualification.json")["status"], "fail"
            )


class BackupAuthorityBoundaryContracts(unittest.TestCase):
    def test_authority_refusal_precedes_model_and_promotion_migration_or_export(self):
        for extended in (False, True):
            for reply in ("t", "", "unexpected"):
                with (
                    self.subTest(extended=extended, reply=reply),
                    patch.object(storage_backup, "validate", return_value={"name": "owned"}),
                    patch.object(storage_backup, "admin", return_value=reply),
                    patch.object(storage_backup, "verify_configuration"),
                    patch.object(promotion_state, "require_legacy_backup_scope") as legacy,
                    patch.object(storage_backup, "snapshot") as export,
                    self.assertRaisesRegex(Rejected, "^trust_authority_backup_forbidden$"),
                ):
                    storage_backup.create(Path("root"), Path("owned"), include_promotion=extended)
                legacy.assert_not_called()
                export.assert_not_called()

    def test_confirmed_model_storage_continues_to_existing_configuration_checks(self):
        for extended in (False, True):
            with (
                self.subTest(extended=extended),
                patch.object(storage_backup, "validate", return_value={"name": "owned"}),
                patch.object(storage_backup, "admin", return_value="f") as query,
                patch.object(promotion_state, "require_legacy_backup_scope"),
                patch.object(
                    storage_backup,
                    "verify_configuration",
                    side_effect=RuntimeError("configuration-check"),
                ),
                self.assertRaisesRegex(RuntimeError, "^configuration-check$"),
            ):
                storage_backup.create(Path("root"), Path("owned"), include_promotion=extended)
            query.assert_called_once_with(
                "owned", "SELECT to_regnamespace('ml_trust') IS NOT NULL;"
            )


if __name__ == "__main__":
    unittest.main()
