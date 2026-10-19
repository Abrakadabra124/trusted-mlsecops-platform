import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import serving_context
from mlsecops.contracts import Rejected, read_json, write_json
from scripts import candidate_serving_native as native
from scripts import serving_core_qualification as core
from scripts.serving_native import site


class CandidateServingHarnessContracts(unittest.TestCase):
    def test_audit_idle_requires_healthy_confirmed_and_drained_state(self):
        idle = {"healthy": True, "unconfirmed": 0, "pending": 0, "reservations": 0}
        request = Mock()
        for changed in ({"healthy": False}, {"unconfirmed": 1}):
            request.audit_status.return_value = {**idle, **changed}
            with self.assertRaisesRegex(Rejected, "candidate_audit_unavailable"):
                native.audit_idle(request)
        for field in ("pending", "reservations"):
            request.audit_status.return_value = {**idle, field: 1}
            with patch.object(native.time, "monotonic", side_effect=[0, 5]):
                with self.assertRaisesRegex(Rejected, "candidate_audit_pending"):
                    native.audit_idle(request)
        request.audit_status.side_effect = [{**idle, "pending": 1}, idle]
        with patch.object(native.time, "sleep") as sleep:
            self.assertEqual(native.audit_idle(request), idle)
        sleep.assert_called_once_with(0.01)

    def owned_workspace(self, state):
        write_json(
            state / "workspace.json",
            {"product": "trusted-mlsecops", "schema_version": 1, "workspace_id": "a" * 32},
        )

    def test_actual_candidate_controller_does_not_import_model_parsers_or_fixture_approval(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; import scripts.candidate_serving_native; "
                "assert not any(name in sys.modules for name in "
                "('onnx', 'onnxruntime', 'scripts.promotion_qualification', "
                "'scripts.model_contract_qualification'))",
            ],
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_real_http_matrix_checks_input_boundary_and_lock_pressure(self):
        fixture = core.ServingCoreContracts()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.loaded.audit_context = serving_context.QualificationContext(
            "d" * 64, "e" * 64, fixture.loaded.subject_sha256, fixture.loaded.model_sha256
        )
        cases = []

        def confirmed(name, condition):
            self.assertTrue(condition, name)
            cases.append(name)

        with site(fixture.engine) as request:
            body = {
                "schema_version": 1,
                "instances": [dict.fromkeys(native.FEATURES, 0.5)],
            }
            native.http_matrix(fixture.engine, request, body, confirmed)
            audit = native.context_matrix(
                fixture.engine, request, body, confirmed, fixture.loaded.audit_context
            )
            self.assertEqual(audit["accepted_delta"], 8)
            self.assertEqual(audit["durable_delta"], 8)
            self.assertFalse(audit["release_ready"])
            privacy = native.privacy_matrix(request, body, confirmed)
            self.assertEqual(privacy["request_cases"], 12)
            self.assertEqual(privacy["audit_events_confirmed"], 36)
        self.assertEqual(len(cases), 24)
        self.assertEqual(len(cases), len(set(cases)))
        self.assertIsNone(fixture.engine.worker)

    def test_cli_requires_disposable_confirmation_before_access(self):
        with patch.object(native.storage_bootstrap, "validate") as validate:
            with patch("sys.argv", ["candidate-serving", "--state", "unused"]):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit) as failure,
                ):
                    native.main()
            self.assertEqual(failure.exception.code, 2)
            validate.assert_not_called()

    def test_cli_writes_current_report_and_clears_old_pass_on_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            self.owned_workspace(state)
            destination = state / "evidence/candidate-serving.json"
            for fails in (False, True):
                with self.subTest(fails=fails):
                    write_json(destination, {"status": "pass", "stale": True})
                    result = {"status": "pass", "release_ready": False, "full_M12": "inconclusive"}
                    arguments = (
                        {"side_effect": OSError("PRIVATE-CANARY")}
                        if fails
                        else {"return_value": result}
                    )
                    stream = io.StringIO()
                    with (
                        patch(
                            "sys.argv",
                            ["candidate-serving", "--state", str(state), "--confirm-disposable"],
                        ),
                        patch.object(native.storage_bootstrap, "validate"),
                        patch.object(native, "qualify", **arguments),
                        contextlib.redirect_stdout(stream),
                        contextlib.redirect_stderr(stream),
                    ):
                        code = native.main()
                    self.assertEqual(code, 2 if fails else 0)
                    observed = read_json(destination)
                    self.assertEqual(observed["status"], "inconclusive" if fails else "pass")
                    self.assertFalse(observed["release_ready"])
                    self.assertNotIn("stale", observed)
                    self.assertNotIn("PRIVATE-CANARY", stream.getvalue())

    def test_owned_workspace_preflight_failure_invalidates_previous_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            self.owned_workspace(state)
            output = state / "evidence/candidate-serving.json"
            write_json(output, {"status": "pass", "stale": True})
            with (
                patch(
                    "sys.argv", ["candidate-serving", "--state", str(state), "--confirm-disposable"]
                ),
                patch.object(
                    native.storage_bootstrap, "validate", side_effect=Rejected("PRIVATE-CANARY")
                ),
                patch.object(native, "qualify") as qualify,
                contextlib.redirect_stderr(io.StringIO()) as stream,
            ):
                self.assertEqual(native.main(), 2)
            self.assertEqual(read_json(output)["status"], "inconclusive")
            self.assertNotIn("stale", read_json(output))
            self.assertNotIn("PRIVATE-CANARY", stream.getvalue())
            qualify.assert_not_called()

    def test_unowned_workspace_report_is_not_modified(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            output = state / "evidence/candidate-serving.json"
            original = {"status": "pass", "foreign": True}
            write_json(output, original)
            with (
                patch(
                    "sys.argv", ["candidate-serving", "--state", str(state), "--confirm-disposable"]
                ),
                patch.object(native.storage_bootstrap, "validate") as validate,
                patch.object(native, "qualify") as qualify,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(native.main(), 2)
            self.assertEqual(read_json(output), original)
            validate.assert_not_called()
            qualify.assert_not_called()

    def test_cli_forwards_configurable_trust_port(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            self.owned_workspace(state)
            with (
                patch(
                    "sys.argv",
                    [
                        "candidate-serving",
                        "--state",
                        str(state),
                        "--confirm-disposable",
                        "--trust-port",
                        "15446",
                    ],
                ),
                patch.object(native.storage_bootstrap, "validate"),
                patch.object(
                    native, "qualify", return_value={"status": "pass", "release_ready": False}
                ) as qualify,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(native.main(), 0)
            self.assertEqual(qualify.call_args.kwargs["trust_port"], 15446)


if __name__ == "__main__":
    unittest.main()
