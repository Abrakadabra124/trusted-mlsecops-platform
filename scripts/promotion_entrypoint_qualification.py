import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, read_json, write_json
from scripts import promotion_entrypoint_native as native


class EntrypointProbeContracts(unittest.TestCase):
    def test_real_cli_command_uses_separate_private_files_and_validates_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = {
                "state": "recorded-not-activated",
                "release_ready": False,
                "sequence": 1,
                "request_sha256": "a" * 64,
            }
            with patch.object(
                native.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=0, stdout=canonical(receipt), stderr=b""),
            ) as run:
                self.assertEqual(
                    native.invoke(root, root / "case", {"pin": "fixed"}, {"ref": "submitted"}),
                    receipt,
                )
            arguments = run.call_args.args[0]
            self.assertEqual(arguments[1:3], ["-m", "mlsecops.promotion_controller"])
            self.assertEqual(run.call_args.kwargs["timeout"], 90)
            self.assertEqual(read_json(root / "case/config.json"), {"pin": "fixed"})
            self.assertEqual(read_json(root / "case/request.json"), {"ref": "submitted"})

    def test_missing_or_false_success_and_private_denial_output_are_rejected(self):
        for index, (code, stdout, stderr, denied) in enumerate(
            [
                (1, b"", b"promotion_rejected\n", False),
                (0, b"{}", b"", False),
                (
                    0,
                    canonical({"state": "recorded-not-activated", "release_ready": True}),
                    b"",
                    False,
                ),
                (0, b"{}", b"", True),
                (1, b"", b"private-path", True),
                (1, b"private-content", b"promotion_rejected\n", True),
            ]
        ):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with patch.object(
                    native.subprocess,
                    "run",
                    return_value=SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr),
                ):
                    with self.subTest(index=index), self.assertRaises(Rejected):
                        native.invoke(root, root / "case", {}, {}, denied=denied)

    def test_exact_constant_denial_is_observed_without_inventing_a_reason(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                native.subprocess,
                "run",
                return_value=SimpleNamespace(
                    returncode=1, stdout=b"", stderr=b"promotion_rejected\n"
                ),
            ):
                self.assertEqual(
                    native.invoke(root, root / "case", {}, {}, denied=True),
                    {"status": "rejected", "release_ready": False},
                )

    def test_non_hosted_execution_is_rejected_before_storage(self):
        with (
            patch.dict(native.os.environ, {"GITHUB_ACTIONS": "false"}),
            patch.object(native, "validate") as validate,
        ):
            with self.assertRaisesRegex(Rejected, "hosted_runner_required"):
                native.qualify(Path("."), Path("missing"), "image")
            validate.assert_not_called()

    def test_failed_retry_cannot_leave_stale_completed_native_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            output = state / "evidence/promotion-entrypoint.json"
            write_json(output, {"status": "pass", "release_ready": False})
            with (
                patch.object(native, "hosted"),
                patch.object(native, "validate"),
                patch.object(native, "qualify", side_effect=Rejected("private-canary")),
                contextlib.redirect_stderr(io.StringIO()) as err,
            ):
                self.assertEqual(native.main(["--state", str(state)]), 1)
            self.assertEqual(read_json(output)["status"], "fail")
            self.assertEqual(err.getvalue(), "promotion_entrypoint_native_rejected\n")

    def test_evidence_write_failure_does_not_leak_private_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch.object(native, "hosted"),
                patch.object(native, "validate"),
                patch.object(native, "write_json", side_effect=OSError("private-path")),
                contextlib.redirect_stderr(io.StringIO()) as err,
            ):
                self.assertEqual(native.main(["--state", temporary]), 1)
            self.assertEqual(err.getvalue(), "promotion_entrypoint_native_rejected\n")
