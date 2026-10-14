import io
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, decode, read_json, write_json
from scripts import release_reader_native as native


class ReaderDiagnosticContracts(unittest.TestCase):
    def test_cli_requires_explicit_disposable_confirmation(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            native.main(["--state", "missing"])
        self.assertEqual(error.exception.code, 2)

    def test_cli_reports_only_sanitized_status_and_writes_final_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            report = {"status": "pass", "release_ready": False, "cases": ["controlled"]}
            with (
                patch.object(native.storage_bootstrap, "validate", return_value={}),
                patch.object(native, "qualify", return_value=report),
                redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(native.main(["--state", str(state), "--confirm-disposable"]), 0)
                self.assertEqual(decode(output.getvalue())["cases"], 1)
                self.assertEqual(
                    read_json(state / "evidence/release-reader-qualification.json"), report
                )
            with (
                patch.object(native.storage_bootstrap, "validate", return_value={}),
                patch.object(native, "qualify", side_effect=Rejected("PRIVATE-CANARY")),
                redirect_stderr(io.StringIO()) as output,
            ):
                self.assertEqual(native.main(["--state", str(state), "--confirm-disposable"]), 1)
                self.assertNotIn("PRIVATE-CANARY", output.getvalue())
                self.assertEqual(
                    read_json(state / "evidence/release-reader-qualification.json")["status"],
                    "fail",
                )

    def test_unowned_state_never_enters_qualification(self):
        with (
            patch.object(native.storage_bootstrap, "validate", side_effect=Rejected("unowned")),
            patch.object(native, "qualify") as qualify,
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(native.main(["--state", "missing", "--confirm-disposable"]), 1)
            qualify.assert_not_called()

    def test_cleanup_requires_same_owned_container_and_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            owner = {
                "container_id": "owned",
                "workspace_id": "workspace",
                "network": "net",
                "network_id": "network-owned",
                "volume": "vol",
            }
            for field in (None, "container_id", "workspace_id", "network_id", "volume"):
                with self.subTest(field=field), ExitStack() as stack:
                    observed = {**owner, **({field: "foreign"} if field else {})}
                    stack.enter_context(patch.object(native.bootstrap, "initialize"))
                    stack.enter_context(patch.object(native.storage_bootstrap, "bootstrap"))
                    stack.enter_context(
                        patch.object(
                            native.storage_bootstrap, "validate", side_effect=[owner, observed]
                        )
                    )
                    docker = stack.enter_context(patch.object(native.storage_bootstrap, "docker"))
                    docker.return_value.stdout = b""
                    remove = stack.enter_context(patch.object(native.shutil, "rmtree"))
                    if field:
                        with self.assertRaisesRegex(Rejected, "reader_cleanup_ownership"):
                            with native.disposable(state, state, "campaign", "models", 15444):
                                pass
                        docker.assert_not_called()
                        remove.assert_not_called()
                    else:
                        with native.disposable(
                            state, state, "campaign", "models", 15444
                        ) as destination:
                            self.assertEqual(destination.parent, (state / "evidence").resolve())
                        self.assertEqual(docker.call_count, 6)
                        remove.assert_called_once_with(destination)

    def test_bootstrap_failure_after_marker_cleans_only_verified_owned_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            owner = {
                "container_id": "owned",
                "workspace_id": "workspace",
                "network": "net",
                "network_id": "network-owned",
                "volume": "vol",
            }

            def fail_after_marker(destination, port):
                write_json(destination / "storage.json", owner)
                raise Rejected("storage_startup_deadline")

            with (
                patch.object(native.bootstrap, "initialize"),
                patch.object(native.storage_bootstrap, "bootstrap", side_effect=fail_after_marker),
                patch.object(native.storage_bootstrap, "validate", return_value=owner) as validate,
                patch.object(native.storage_bootstrap, "docker") as docker,
                patch.object(native.shutil, "rmtree") as remove,
            ):
                docker.return_value.stdout = b""
                with self.assertRaisesRegex(Rejected, "^storage_startup_deadline$"):
                    with native.disposable(state, state, "campaign", "models", 15444):
                        self.fail("bootstrap failure must not enter qualification")
                self.assertEqual(validate.call_count, 2)
                self.assertEqual(docker.call_count, 6)
                remove.assert_called_once()

    def test_bootstrap_without_identity_reports_unconfirmed_cleanup_and_preserves_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            with (
                patch.object(native.bootstrap, "initialize"),
                patch.object(
                    native.storage_bootstrap, "bootstrap", side_effect=Rejected("partial")
                ),
                patch.object(native.storage_bootstrap, "docker") as docker,
                patch.object(native.shutil, "rmtree") as remove,
            ):
                with self.assertRaisesRegex(Rejected, "reader_bootstrap_cleanup_unconfirmed"):
                    with native.disposable(state, state, "campaign", "models", 15444):
                        self.fail("partial bootstrap must not enter qualification")
                docker.assert_not_called()
                remove.assert_not_called()

    def test_cleanup_keeps_private_state_if_resources_still_exist(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            owner = {
                "container_id": "owned",
                "workspace_id": "workspace",
                "network": "net",
                "network_id": "network-owned",
                "volume": "vol",
            }
            with (
                patch.object(native.bootstrap, "initialize"),
                patch.object(native.storage_bootstrap, "bootstrap"),
                patch.object(native.storage_bootstrap, "validate", return_value=owner),
                patch.object(native.storage_bootstrap, "docker") as docker,
                patch.object(native.shutil, "rmtree") as remove,
            ):
                docker.return_value.stdout = b"still-present"
                with self.assertRaisesRegex(Rejected, "reader_cleanup_unconfirmed"):
                    with native.disposable(state, state, "campaign", "models", 15444):
                        pass
                remove.assert_not_called()

    def test_path_escape_is_rejected_before_bootstrap(self):
        with (
            patch.object(native, "safe_child", side_effect=Rejected("artifact_path_escape")),
            patch.object(native.bootstrap, "initialize") as initialize,
        ):
            with self.assertRaisesRegex(Rejected, "artifact_path_escape"):
                with native.disposable(Path("."), Path("."), "campaign", "models", 15444):
                    pass
            initialize.assert_not_called()


if __name__ == "__main__":
    unittest.main()
