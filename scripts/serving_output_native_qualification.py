import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops import (
    inventory,
    process_privacy,
    sandbox,
    storage_bootstrap,
    storage_pki,
    worker_transport,
)
from mlsecops.contracts import Rejected, decode, read_json, write_json
from scripts import candidate_serving_native
from scripts import serving_output_native as native
from scripts import serving_output_probe as probe
from scripts.serving_output_qualification import expected, operation, report


class OutputNativeContracts(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(
            os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
        )
        environment.start()
        self.addCleanup(environment.stop)

    def test_guard_and_explicit_confirmation_precede_state_access(self):
        for arguments, error in (
            ([], None),
            (["--state", "private", "--confirm-disposable"], Rejected("private-guard")),
        ):
            with (
                patch.object(process_privacy, "enforce", side_effect=error),
                patch.object(storage_pki, "workspace_id") as ownership,
                redirect_stderr(io.StringIO()) as diagnostic,
                redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(native.main(arguments), 1)
            ownership.assert_not_called()
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(diagnostic.getvalue(), "serving_output_rejected\n")

    def test_non_hosted_environment_is_rejected_before_private_access(self):
        with (
            patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "self-hosted"}),
            patch.object(process_privacy, "enforce"),
            patch.object(storage_pki, "workspace_id") as owner,
            redirect_stderr(io.StringIO()) as diagnostic,
        ):
            self.assertEqual(native.main(["--state", "private", "--confirm-disposable"]), 1)
        owner.assert_not_called()
        self.assertEqual(diagnostic.getvalue(), "serving_output_rejected\n")

    def test_source_is_clean_pinned_and_child_cannot_publish_campaign_report(self):
        with (
            patch.object(inventory, "command", side_effect=["", "b" * 40]),
            patch.object(inventory, "source_fingerprint", return_value="c" * 64),
            patch.object(sandbox, "resolve_image", return_value="sha256:" + "a" * 64),
        ):
            self.assertEqual(native.source(Path("root"), "alias"), expected())
        with (
            patch.object(inventory, "command", return_value="changed"),
            self.assertRaisesRegex(Rejected, "serving_output_source_dirty"),
        ):
            native.source(Path("root"), "alias")
        observer = object()
        with patch.object(candidate_serving_native, "qualify", return_value=report()) as action:
            self.assertEqual(
                native.qualified(Path("root"), Path("state"), "image", 15446, observer), report()
            )
        action.assert_called_once_with(
            Path("root"),
            Path("state"),
            "image",
            trust_port=15446,
            privacy_observer=observer,
            publish_report=False,
        )

    def test_parent_only_publishes_verified_result_and_constant_failure(self):
        for failure in (None, Rejected("private-canary"), KeyboardInterrupt()):
            with tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                write_json(
                    state / "evidence/candidate-serving.json", {"status": "pass", "old": True}
                )
                with (
                    patch.object(process_privacy, "enforce"),
                    patch.object(storage_pki, "workspace_id"),
                    patch.object(storage_bootstrap, "validate"),
                    patch.object(native, "run", return_value=report(), side_effect=failure),
                    redirect_stdout(io.StringIO()) as output,
                    redirect_stderr(io.StringIO()) as diagnostic,
                ):
                    code = native.main(["--state", str(state), "--confirm-disposable"])
                if failure is None:
                    self.assertEqual(code, 0)
                    self.assertEqual(decode(output.getvalue()), report())
                    self.assertEqual(read_json(state / "evidence/candidate-serving.json"), report())
                    self.assertEqual(diagnostic.getvalue(), "")
                else:
                    self.assertEqual(code, 130 if isinstance(failure, KeyboardInterrupt) else 1)
                    self.assertEqual(output.getvalue(), "")
                    self.assertNotIn("private", diagnostic.getvalue())
                    self.assertEqual(
                        read_json(state / "evidence/candidate-serving.json")["status"],
                        "inconclusive",
                    )

    def test_child_does_not_claim_fd_observation_or_write_final_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            with (
                patch.object(process_privacy, "enforce"),
                patch.object(storage_pki, "workspace_id"),
                patch.object(storage_bootstrap, "validate"),
                patch.object(
                    native,
                    "qualified",
                    side_effect=lambda root, location, image, port, observer: operation(observer),
                ),
                redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(
                    native.main(["--state", str(state), "--confirm-disposable", "--child"]), 0
                )
            value = decode(output.getvalue())
            self.assertEqual(value["observation"]["status"], "inconclusive")
            self.assertFalse((state / "evidence/candidate-serving.json").exists())

    def test_run_uses_fixed_owned_child_and_rejects_changed_source_or_failed_transport(self):
        child = {
            "schema_version": 1,
            "output": probe.produce(operation),
            "diagnostics": {
                "bytes": 0,
                "gpu_discovery_warning": False,
                "raw_output_retained": False,
            },
        }
        for failure in (None, "changed", "timeout", "cleanup", "cancel"):
            error = {
                "timeout": Rejected("worker_transport_deadline"),
                "cleanup": Rejected("worker_cleanup_incomplete"),
                "cancel": KeyboardInterrupt(),
            }.get(failure)
            with (
                patch.object(
                    native,
                    "source",
                    side_effect=[expected(), {} if failure == "changed" else expected()],
                ),
                patch.object(
                    worker_transport, "capture", return_value=child, side_effect=error
                ) as captured,
            ):
                if failure is None:
                    self.assertEqual(
                        native.run(Path("root"), Path("state"), "image", 15446)["runtime"][
                            "output_privacy"
                        ]["status"],
                        "pass",
                    )
                else:
                    with self.assertRaises(KeyboardInterrupt if failure == "cancel" else Rejected):
                        native.run(Path("root"), Path("state"), "image", 15446)
            arguments = captured.call_args.args[0]
            self.assertEqual(arguments[1:3], ["-m", "scripts.serving_output_native"])
            self.assertIn("--child", arguments)
            self.assertEqual(captured.call_args.kwargs["timeout"], 570)
            self.assertIs(captured.call_args.kwargs["canonical_output"], True)


if __name__ == "__main__":
    unittest.main()
