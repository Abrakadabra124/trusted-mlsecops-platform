"""Bound identity decisions, serving authority, private CLI and exact replay."""

import contextlib
import io
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import security_identity_events as source
from mlsecops.contracts import Rejected, canonical, digest


class IdentityEvents(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "identity.json"
        self.config = dict(
            schema_version=1,
            producer_config=str(self.root / "producer.json"),
            service_sha256="a" * 64,
        )
        self.content = canonical(self.config)
        self.path.write_bytes(self.content)
        self.pin = digest(self.content)
        self.audit = Mock()
        self.audit.store.snapshot.return_value = {"producer_id": "b" * 64}
        self.audit.store.registry.producer.return_value.role = "serving"

    def execute(self, action="credential", **changes):
        args = dict(path=str(self.path), expected=self.pin, action=action, correlation="c" * 32)
        with patch.object(source.security_event_delivery, "configured", return_value=self.audit):
            return source.execute(**{**args, **changes})

    def test_probe_retries_pending_without_creating_identity_denial(self):
        self.assertEqual(source.configuration(str(self.path)), (self.config, self.pin))
        result = self.execute("probe")
        self.audit.retry.assert_called_once()
        self.audit.heartbeat.assert_called_once()
        self.audit.emit.assert_not_called()
        self.assertEqual(
            result,
            dict(
                state="ready",
                config_sha256=self.pin,
                service_sha256="a" * 64,
                correlation_id="c" * 32,
                action="probe",
                release_ready=False,
            ),
        )

    def test_credential_and_role_are_bound_to_operator_service_and_request_id(self):
        for reason in ("credential", "role"):
            result = self.execute(reason)
            self.assertEqual(result["state"], "delivered")
            self.assertEqual(result["action"], reason)
            self.assertEqual(
                self.audit.emit.call_args.args[0],
                dict(
                    kind="identity.denied",
                    reason=reason,
                    correlation_id="c" * 32,
                    asset_sha256="a" * 64,
                    bundle_sha256=None,
                ),
            )

    def test_wrong_role_or_changed_pin_never_emits(self):
        self.audit.store.registry.producer.return_value.role = "promoter"
        with self.assertRaisesRegex(Rejected, "identity_security_producer_role"):
            self.execute()
        self.audit.emit.assert_not_called()
        self.path.write_bytes(self.content + b" ")
        with patch.object(source.security_event_delivery, "configured") as configure:
            with self.assertRaisesRegex(Rejected, "identity_security_configuration_changed"):
                source.execute(str(self.path), self.pin, "credential", "c" * 32)
            configure.assert_not_called()

    def test_strict_schema_paths_service_and_finite_input(self):
        for changes in (
            {"schema_version": True},
            {"extra": "PRIVATE-CANARY"},
            {"producer_config": "relative"},
            {"service_sha256": "bad"},
        ):
            self.path.write_bytes(canonical({**self.config, **changes}))
            with self.assertRaises(Rejected):
                source.configuration(str(self.path))
        self.path.write_bytes(self.content)
        for changes in (
            {"action": "PRIVATE-CANARY"},
            {"correlation": "x" * 4096},
            {"expected": "short"},
            {"expected": None},
        ):
            with self.assertRaises(Rejected):
                self.execute(**changes)
        self.audit.emit.assert_not_called()

    def test_unconfirmed_delivery_never_returns_success(self):
        self.audit.emit.side_effect = OSError("PRIVATE-CANARY")
        with self.assertRaises(OSError):
            self.execute()
        self.audit.retry.side_effect = Rejected("PRIVATE-CANARY")
        with self.assertRaises(Rejected):
            self.execute("probe")

    def test_heartbeat_has_no_identity_event_and_failure_never_claims_success(self):
        result = self.execute("heartbeat")
        self.assertEqual(result["state"], "ready")
        self.audit.emit.assert_not_called()
        self.audit.retry.assert_called_once()
        self.audit.heartbeat.assert_called_once()
        self.audit.heartbeat.side_effect = Rejected("PRIVATE-CANARY")
        with self.assertRaises(Rejected):
            self.execute("role")

    def test_cli_constant_errors_and_finite_success(self):
        arguments = [
            "--config",
            str(self.path),
            "--config-sha256",
            self.pin,
            "--action",
            "credential",
            "--correlation",
            "c" * 32,
        ]
        with (
            patch.object(source, "enforce"),
            patch.object(source.security_event_delivery, "configured", return_value=self.audit),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(source.main(arguments), 0)
        self.assertIn('"state":"delivered"', out.getvalue())
        self.assertNotIn("producer_config", out.getvalue())
        for failure, expected in ((OSError("PRIVATE-CANARY"), 1), (KeyboardInterrupt(), 130)):
            with (
                patch.object(source, "enforce"),
                patch.object(source, "execute", side_effect=failure),
                contextlib.redirect_stderr(io.StringIO()) as err,
            ):
                self.assertEqual(source.main(arguments), expected)
            self.assertEqual(err.getvalue(), "identity_security_rejected\n")

    def test_module_entrypoint_without_arguments_fails_privately(self):
        with (
            patch.dict(sys.modules),
            patch.object(sys, "argv", ["identity-source"]),
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            sys.modules.pop("mlsecops.security_identity_events", None)
            with self.assertRaises(SystemExit) as caught:
                runpy.run_module("mlsecops.security_identity_events", run_name="__main__")
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(err.getvalue(), "identity_security_rejected\n")


if __name__ == "__main__":
    unittest.main()
