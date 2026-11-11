"""Real intake denial boundaries, finite projection and unavailable-audit refusal."""

import inspect
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import artifact_intake, pipeline, worker
from mlsecops.contracts import Rejected, canonical, digest, read_json

IMAGE = "sha256:" + "1" * 64
CONTENT = b"not-onnx PRIVATE-CANARY"


class IntakeSource(unittest.TestCase):
    def setUp(self):
        self.assertIn(
            "audit",
            inspect.signature(artifact_intake.inspect_candidate).parameters,
            "actual intake cannot emit its authenticated controller decision",
        )
        self.audit = Mock()

    def inspect(self, *, expected=None, executor=None):
        def execute(image, request):
            return worker.execute(request), {"image_id": IMAGE}

        return artifact_intake.inspect_candidate(
            CONTENT,
            expected or digest(CONTENT),
            IMAGE,
            IMAGE,
            executor or execute,
            audit=self.audit,
        )

    def event(self):
        self.audit.emit.assert_called_once()
        return self.audit.emit.call_args.args[0]

    def test_real_parser_denial_emits_only_bounded_controller_projection(self):
        with self.assertRaises(artifact_intake.IntakeFailure):
            self.inspect()
        value = self.event()
        self.assertEqual(
            (value["kind"], value["reason"]), ("artifact.rejected", "unsupported_format")
        )
        self.assertEqual(value["asset_sha256"], digest(CONTENT))
        self.assertNotIn(b"PRIVATE-CANARY", canonical(value))
        self.assertEqual(
            set(value), {"kind", "reason", "correlation_id", "asset_sha256", "bundle_sha256"}
        )

    def test_digest_mismatch_emits_integrity_without_launching_worker(self):
        execute = Mock()
        with self.assertRaisesRegex(Rejected, "intake_subject_mismatch"):
            self.inspect(expected="0" * 64, executor=execute)
        execute.assert_not_called()
        self.assertEqual(self.event()["reason"], "integrity")

    def test_worker_protocol_violation_is_observed_by_controller(self):
        with self.assertRaises(artifact_intake.IntakeFailure):
            self.inspect(executor=lambda *_: ({"status": "PRIVATE-CANARY"}, {"image_id": IMAGE}))
        value = self.event()
        self.assertEqual(
            (value["kind"], value["reason"]), ("worker.policy_violation", "output_schema")
        )
        self.assertNotIn(b"PRIVATE-CANARY", canonical(value))

    def test_transport_outage_still_denies_and_never_returns_model_or_receipt(self):
        self.audit.emit.side_effect = OSError("PRIVATE-CANARY")
        with self.assertRaisesRegex(Rejected, "^intake_security_audit_unavailable$"):
            self.inspect()
        self.audit.emit.assert_called_once()

    def test_unavailable_scanner_is_not_falsely_labelled_security_violation(self):
        with self.assertRaises(artifact_intake.IntakeFailure):
            self.inspect(executor=Mock(side_effect=OSError("PRIVATE-CANARY")))
        self.audit.emit.assert_not_called()

    def test_evaluation_forwards_audit_and_cannot_predict_after_denial(self):
        self.assertIn("audit", inspect.signature(pipeline.evaluate_verified_candidate).parameters)
        actions = []

        def execute(image, request):
            actions.append(request["action"])
            return worker.execute(request), {"image_id": IMAGE}

        policy = read_json(Path(__file__).resolve().parents[1] / "policies/local-cpu.json")
        with self.assertRaises(artifact_intake.IntakeFailure):
            pipeline.evaluate_verified_candidate(
                {"image_id": IMAGE, "model_digest": digest(CONTENT)},
                CONTENT,
                [],
                {},
                policy,
                IMAGE,
                execute,
                audit=self.audit,
            )
        self.assertEqual(actions, ["inspect"])
        self.assertEqual(self.event()["kind"], "artifact.rejected")

    def test_controller_cli_uses_operator_config_not_worker_request_for_audit(self):
        from mlsecops import controller, security_event_delivery

        audit = Mock()
        audit.store.registry.producer.return_value.role = "controller"
        with (
            patch(
                "sys.argv",
                [
                    "controller",
                    "--request",
                    "request.json",
                    "--security-event-config",
                    "private.json",
                ],
            ),
            patch.object(controller, "enforce_privacy"),
            patch.object(controller, "read_json", return_value={"role": "scorer"}),
            patch.object(security_event_delivery, "configured", return_value=audit) as configure,
            patch.object(controller, "execute", return_value={"release_ready": False}) as execute,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(controller.main(), 0)
            configure.assert_called_once_with("private.json")
            execute.assert_called_once_with({"role": "scorer"}, audit=audit)

    def test_controller_cli_wrong_event_role_cannot_start_evaluation(self):
        from mlsecops import controller, security_event_delivery

        audit = Mock()
        audit.store.registry.producer.return_value.role = "intake"
        output = io.StringIO()
        with (
            patch(
                "sys.argv",
                [
                    "controller",
                    "--request",
                    "request.json",
                    "--security-event-config",
                    "private.json",
                ],
            ),
            patch.object(controller, "enforce_privacy"),
            patch.object(security_event_delivery, "configured", return_value=audit),
            patch.object(controller, "execute") as execute,
            redirect_stderr(output),
        ):
            self.assertEqual(controller.main(), 1)
            execute.assert_not_called()
        self.assertEqual(output.getvalue(), "controller_rejected\n")


if __name__ == "__main__":
    unittest.main()
