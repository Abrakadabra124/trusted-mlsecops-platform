"""Controlled authorization with mocked SQL/transport; no local services."""

import copy
import importlib
import io
import runpy
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import psycopg

from mlsecops import process_privacy, promotion, signing, storage
from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts import promotion_qualification as fixtures
from scripts import security_events_qualification as event_fixtures


class AuditBoundaryProbe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.PromotionAdmissionContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.PromotionAdmissionContracts.tearDownClass()

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("scripts.security_audit_boundary_probe"),
            "outage proof must distinguish the reached audit boundary from earlier refusals",
        )
        self.module = importlib.import_module("scripts.security_audit_boundary_probe")
        self.fixture = fixtures.PromotionAdmissionContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.enterContext(patch.object(self.fixture, "doCleanups", return_value=True))
        self.fixture.setUp = Mock()
        self.factory = Mock(return_value=self.fixture)
        self.enterContext(
            patch.object(self.module.fixtures, "PromotionAdmissionContracts", self.factory)
        )
        self.fx = event_fixtures.EventContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.bundle = digest(canonical(self.fixture.arguments["package"]["envelope"]))
        self.producer = digest(signing.decode64(self.fx.publics["promoter"]))
        self.records = []
        self.store = SimpleNamespace(
            registry=self.fx.registry,
            pin="e" * 64,
            snapshot=lambda: dict(
                producer_id=self.producer,
                config_sha256=self.fx.registry.sha256,
                records=copy.deepcopy(self.records),
            ),
        )
        self.emitter = self.enterContext(
            patch.object(
                self.module.admission, "emitter", return_value=SimpleNamespace(store=self.store)
            )
        )
        self.audit = Mock()
        self.audit.check.side_effect = Rejected("promotion_audit_unavailable")
        self.audit.denied.side_effect = self.deny
        self.enterContext(
            patch.object(self.module.admission, "Configured", return_value=self.audit)
        )
        self.enterContext(
            patch.object(storage, "connection_parameters", return_value={"user": "ml_promoter"})
        )
        self.connection = MagicMock()
        self.connection.__enter__.return_value = self.connection
        self.connection.execute.return_value.fetchone.return_value = (self.fixture.clock,)
        self.enterContext(patch.object(storage, "connect", return_value=self.connection))
        self.publish = self.enterContext(
            patch.object(
                promotion.release_bundle,
                "publish",
                side_effect=AssertionError("publication forbidden"),
            )
        )

    def deny(self, *, reason, bundle_sha256):
        value = self.fx.event(
            "promotion.denied",
            "promoter",
            reason=reason,
            asset_sha256=bundle_sha256,
            bundle_sha256=bundle_sha256,
        )
        self.records.append(
            dict(
                envelope=signing.sign(value, "security-event", self.fx.keys["promoter"]),
                queued_at_ms=2000,
                receipt=None,
            )
        )
        raise Rejected("security_delivery_unconfirmed")

    def rejected(self):
        with self.assertRaises(Rejected):
            self.module.qualify()
        self.publish.assert_not_called()

    def test_actual_authorizer_and_trust_reach_first_audit_then_authenticated_pending(self):
        proof = self.module.qualify()
        self.assertEqual(
            proof["scope"], "controlled-authorization-and-trust-real-sql-audit-boundary"
        )
        self.assertEqual(proof["fixture_bundle_sha256"], self.bundle)
        self.assertEqual((proof["audit_checks"], proof["audit_denials"]), (1, 1))
        self.assertEqual(proof["audit_check_error"], "promotion_audit_unavailable")
        self.assertEqual(proof["promotion_error"], "promotion_denial_audit_unconfirmed")
        self.assertEqual(proof["pending"]["reason"], "audit_unavailable")
        self.assertEqual(
            proof["pending"]["envelope_sha256"], digest(canonical(self.records[0]["envelope"]))
        )
        self.assertIsNone(proof["pending"]["receipt"])
        self.assertFalse(proof["release_ready"])
        self.publish.assert_not_called()
        self.assertEqual(self.connection.execute.call_count, 1)

    def test_missing_assurance_cannot_masquerade_as_audit_outage(self):
        self.fixture.arguments["assurance_envelope"] = None
        self.rejected()
        self.audit.check.assert_not_called()
        self.audit.denied.assert_not_called()

    def test_trust_failure_cannot_masquerade_as_audit_outage(self):
        self.fixture.trust_fixture.failure = Rejected("trust_service_unavailable")
        self.rejected()
        self.audit.check.assert_not_called()

    def test_sql_clock_failure_never_reaches_audit(self):
        self.connection.execute.side_effect = psycopg.OperationalError("PRIVATE-CANARY")
        self.rejected()
        self.audit.check.assert_not_called()

    def test_actual_sql_time_expiry_cannot_masquerade_as_outage(self):
        self.connection.execute.return_value.fetchone.return_value = (self.fixture.clock + 7200,)
        self.rejected()
        self.audit.check.assert_not_called()

    def test_healthy_audit_is_stopped_before_publication(self):
        self.audit.check.side_effect = None
        self.audit.check.return_value = {"healthy": True}
        self.rejected()
        self.audit.denied.assert_not_called()

    def test_wrong_check_error_is_not_outage_evidence(self):
        self.audit.check.side_effect = Rejected("different_error")
        self.rejected()
        self.audit.denied.assert_not_called()

    def test_unavailable_configuration_prevents_promotion(self):
        self.emitter.side_effect = Rejected("security_audit_config_schema")
        self.rejected()
        self.connection.execute.assert_not_called()

    def test_delivered_or_missing_or_forged_pending_is_refused(self):
        for fault in ("delivered", "missing", "forged", "wrong-subject", "wrong-reason", "extra"):
            with self.subTest(fault=fault):
                self.records.clear()

                def broken(*, reason, bundle_sha256):
                    try:
                        self.deny(
                            reason="authorization" if fault == "wrong-reason" else reason,
                            bundle_sha256="f" * 64 if fault == "wrong-subject" else bundle_sha256,
                        )
                    except Rejected:
                        if fault == "delivered":
                            self.records[0]["receipt"] = {"unexpected": True}
                        elif fault == "missing":
                            self.records.clear()
                        elif fault == "forged":
                            self.records[0]["envelope"]["signatures"][0]["sig"] = "AAAA"
                        elif fault == "extra":
                            self.records.append(copy.deepcopy(self.records[0]))
                        raise

                self.audit.denied.side_effect = broken
                self.rejected()

    def test_wrong_denial_reason_bundle_or_counts_cannot_pass(self):
        for fault in ("reason", "bundle", "checks", "denials", "pass"):
            with self.subTest(fault=fault):
                self.records.clear()

                def fake_promote(client, *, trust_lease, audit, **arguments):
                    if fault == "pass":
                        return {"state": "recorded-not-activated"}
                    try:
                        audit.check("b" * 64)
                    except Rejected:
                        pass
                    if fault == "checks":
                        try:
                            audit.check("b" * 64)
                        except Rejected:
                            pass
                    for _ in range(2 if fault == "denials" else 1):
                        try:
                            audit.denied(
                                reason="authorization"
                                if fault == "reason"
                                else "audit_unavailable",
                                bundle_sha256="f" * 64 if fault == "bundle" else self.bundle,
                            )
                        except Rejected:
                            pass
                    raise Rejected("promotion_denial_audit_unconfirmed")

                with patch.object(promotion, "promote", side_effect=fake_promote):
                    self.rejected()

    def test_existing_pending_is_not_a_fresh_boundary_proof(self):
        try:
            self.deny(reason="authorization", bundle_sha256=self.bundle)
        except Rejected:
            pass
        self.rejected()
        self.audit.check.assert_not_called()

    def test_fixture_cleanup_failure_refuses_success(self):
        with patch.object(self.fixture, "doCleanups", return_value=False):
            self.rejected()

    def test_fixture_setup_failure_still_cleans_instance_and_class(self):
        self.fixture.setUp.side_effect = Rejected("fixture_failed")
        self.rejected()
        self.fixture.doCleanups.assert_called_once()
        self.factory.tearDownClass.assert_called_once()

    def test_changed_outbox_identity_does_not_pass(self):
        original = self.store.snapshot
        calls = 0

        def changed():
            nonlocal calls
            calls += 1
            value = original()
            if calls > 1:
                value["producer_id"] = "0" * 64
            return value

        self.store.snapshot = changed
        self.rejected()

    def test_module_entrypoint_emits_only_finite_proof(self):
        output = io.StringIO()
        with patch.object(process_privacy, "enforce"), redirect_stdout(output):
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_path(self.module.__file__, run_name="__main__")
        self.assertEqual(stopped.exception.code, 0)
        result = decode(output.getvalue().encode())
        self.assertEqual(result["fixture_bundle_sha256"], self.bundle)
        self.assertNotIn("package", result)
        self.assertNotIn("assurance", result)

    def test_cli_failure_is_finite_and_does_not_disclose_exception(self):
        output, errors = io.StringIO(), io.StringIO()
        with (
            patch.object(self.module, "qualify", side_effect=RuntimeError("PRIVATE-CANARY")),
            patch.object(self.module, "enforce"),
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            self.assertEqual(self.module.main(), 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "security_audit_boundary_probe_rejected\n")


if __name__ == "__main__":
    unittest.main()
