"""Actual inventory predicates, bounded source projection and private CLI."""

import contextlib
import copy
import io
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import asset_graph
from mlsecops import security_inventory_events as source
from mlsecops.contracts import Rejected, canonical, digest
from scripts import candidate_lineage_qualification as candidate_fixtures
from scripts.asset_graph_fixture import ENVIRONMENT, OWNERS, fixture


class InventoryDecisions(unittest.TestCase):
    def test_native_guard_precedes_local_infrastructure(self):
        from scripts import security_inventory_events_native as native

        with (
            patch.object(native.sys, "platform", "win32"),
            patch.object(native, "validate") as infrastructure,
        ):
            with self.assertRaisesRegex(Rejected, "inventory_security_hosted_required"):
                native.qualify("private", "image")
            infrastructure.assert_not_called()

    def test_unknown_owner_is_a_typed_decision_not_a_string_classifier(self):
        graph, snapshot, revoked = fixture()
        graph["assets"][0]["owner"] = "unknown-owner"
        with self.assertRaises(Rejected) as caught:
            asset_graph.assess(graph, OWNERS, ENVIRONMENT, snapshot, revoked)
        self.assertEqual(getattr(caught.exception, "reason", None), "owner")

    def test_actual_graph_digest_dangling_and_cycle_decisions(self):
        graph, snapshot, revoked = fixture()
        for reason in ("digest", "dangling", "cycle"):
            changed, observed = copy.deepcopy(graph), copy.deepcopy(snapshot)
            if reason == "digest":
                observed["deployments"][0]["model_sha256"] = "f" * 64
            elif reason == "dangling":
                observed["deployments"].pop()
            else:
                asset = changed["assets"][0]
                asset["dependencies"] = [{"asset_id": asset["asset_id"], "sha256": asset["sha256"]}]
                observed["graph_sha256"] = digest(canonical(changed))
            with self.subTest(reason=reason), self.assertRaises(Rejected) as caught:
                asset_graph.assess(changed, OWNERS, ENVIRONMENT, observed, revoked)
            self.assertEqual(getattr(caught.exception, "reason", None), reason)


class SourceContracts(unittest.TestCase):
    def setUp(self):
        self.audit = Mock()
        self.audit.store.snapshot.return_value = {"producer_id": "a" * 64}
        self.audit.store.registry.producer.return_value.role = "controller"
        graph, snapshot, revoked = fixture()
        self.request = dict(
            document=graph,
            snapshot=snapshot,
            revoked=revoked,
            trusted_owners=OWNERS,
            environment=ENVIRONMENT,
        )

    def observe(self):
        return source.capture(
            lambda: asset_graph.assess(**self.request),
            audit=self.audit,
            subject=lambda: digest(canonical(self.request)),
        )

    def test_valid_inventory_has_no_security_event_or_release_authority(self):
        self.assertFalse(self.observe()["release_ready"])
        self.audit.emit.assert_not_called()
        self.audit.retry.assert_called_once()
        self.assertEqual(source.capture(lambda: "pure", audit=None, subject=lambda: None), "pure")

    def test_finite_projection_and_original_denial_after_emitting(self):
        self.request["document"]["assets"][0]["owner"] = "private-canary"
        with self.assertRaisesRegex(asset_graph.InventoryMismatch, "^inventory_unknown_owner$"):
            self.observe()
        fields = self.audit.emit.call_args.args[0]
        self.assertEqual(
            set(fields), {"kind", "reason", "correlation_id", "asset_sha256", "bundle_sha256"}
        )
        self.assertEqual((fields["kind"], fields["reason"]), ("inventory.mismatch", "owner"))
        self.assertEqual(fields["asset_sha256"], digest(canonical(self.request)))
        self.assertIsNone(fields["bundle_sha256"])
        self.assertEqual(len(fields["correlation_id"]), 32)
        self.assertNotIn(b"private-canary", canonical(fields))

    def test_no_string_classification_of_parser_or_storage_errors(self):
        for failure in (Rejected("inventory_unknown_owner"), OSError("PRIVATE-CANARY")):
            with self.assertRaises(type(failure)):
                source.capture(
                    Mock(side_effect=failure), audit=self.audit, subject=lambda: "a" * 64
                )
        self.audit.emit.assert_not_called()
        self.request["document"]["extra"] = "PRIVATE-CANARY"
        with self.assertRaises(Rejected):
            self.observe()
        self.audit.emit.assert_not_called()

    def test_wrong_role_and_pending_outage_precede_operation(self):
        operation = Mock()
        self.audit.store.registry.producer.return_value.role = "trust"
        with self.assertRaisesRegex(Rejected, "inventory_security_producer_role"):
            source.capture(operation, audit=self.audit, subject=lambda: "a" * 64)
        operation.assert_not_called()
        self.audit.retry.assert_not_called()
        self.audit.store.registry.producer.return_value.role = "controller"
        self.audit.retry.side_effect = OSError("PRIVATE-CANARY")
        with self.assertRaisesRegex(Rejected, "^inventory_security_delivery_unconfirmed$"):
            source.capture(operation, audit=self.audit, subject=lambda: "a" * 64)
        operation.assert_not_called()

    def test_event_write_or_network_failure_cannot_allow_verification(self):
        self.request["snapshot"]["deployments"].pop()
        self.audit.emit.side_effect = OSError("PRIVATE-CANARY")
        with self.assertRaisesRegex(Rejected, "^inventory_security_delivery_unconfirmed$"):
            self.observe()

    def test_unknown_category_or_unbounded_subject_cannot_be_emitted(self):
        for reason, subject in (("private-canary", "a" * 64), ("owner", "PRIVATE-CANARY")):
            with self.assertRaises(Rejected):
                source.capture(
                    Mock(side_effect=asset_graph.InventoryMismatch("refused", reason)),
                    audit=self.audit,
                    subject=lambda: subject,
                )
        self.audit.emit.assert_not_called()

    def test_pinned_graph_config_and_fail_closed_input_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            body = canonical(self.request)
            (root / "request.json").write_bytes(body)
            config = dict(
                schema_version=1,
                mode="graph",
                request_file=str(root / "request.json"),
                request_sha256=digest(body),
                producer_config=str(root / "producer.json"),
            )
            path = root / "config.json"
            path.write_bytes(canonical(config))
            with patch.object(
                source.security_event_delivery, "configured", return_value=self.audit
            ) as producer:
                result = source.configured(str(path))
                self.assertEqual(result["state"], "verified")
                self.assertEqual(result["full_M19"], "inconclusive")
                self.assertNotIn("assets", result)
                for changes in (
                    {"mode": "raw"},
                    {"request_sha256": "0" * 64},
                    {"schema_version": True},
                    {"extra": True},
                ):
                    producer.reset_mock()
                    path.write_bytes(canonical({**config, **changes}))
                    with self.assertRaises(Rejected):
                        source.configured(str(path))
                    producer.assert_not_called()

    def test_cli_finite_success_private_failure_and_interrupt(self):
        result = dict(state="verified", release_ready=False)
        with (
            patch.object(source, "enforce"),
            patch.object(source, "configured", return_value=result),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(source.main(["--config", "private.json"]), 0)
        self.assertEqual(out.getvalue(), canonical(result).decode() + "\n")
        for failure, expected in ((RuntimeError("PRIVATE-CANARY"), 1), (KeyboardInterrupt(), 130)):
            with (
                patch.object(source, "enforce"),
                patch.object(source, "configured", side_effect=failure),
                contextlib.redirect_stderr(io.StringIO()) as err,
            ):
                self.assertEqual(source.main(["--config", "private.json"]), expected)
            self.assertEqual(err.getvalue(), "inventory_security_rejected\n")

    def test_module_entrypoint_refuses_without_configuration(self):
        from mlsecops import process_privacy

        with (
            patch.dict(sys.modules),
            patch.object(sys, "argv", ["observer"]),
            patch.object(process_privacy, "enforce"),
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            sys.modules.pop("mlsecops.security_inventory_events", None)
            with self.assertRaises(SystemExit) as caught:
                runpy.run_module("mlsecops.security_inventory_events", run_name="__main__")
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(err.getvalue(), "inventory_security_rejected\n")


class CandidateSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        candidate_fixtures.CandidateLineageContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        candidate_fixtures.CandidateLineageContracts.tearDownClass()

    def setUp(self):
        self.fx = candidate_fixtures.CandidateLineageContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.audit = Mock()
        self.audit.store.snapshot.return_value = {"producer_id": "a" * 64}
        self.audit.store.registry.producer.return_value.role = "promoter"

    def test_actual_lineage_binding_predicate_emits_candidate_reference(self):
        with self.assertRaisesRegex(
            asset_graph.InventoryMismatch, "inventory_candidate_build_binding"
        ):
            self.fx.collect(
                audit=self.audit, expected={**self.fx.expected, "source_revision": "0" * 40}
            )
        self.assertEqual(self.audit.emit.call_args.args[0]["asset_sha256"], self.fx.candidate_ref)
        self.assertEqual(self.audit.emit.call_args.args[0]["reason"], "digest")

    def test_candidate_config_flows_through_real_validator_without_source_payload_output(self):
        from mlsecops import candidate_lineage

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = dict(
                metadata_client=str(root / "publisher"),
                review_client=str(root / "promoter"),
                context=dict(
                    candidate_reference=self.fx.candidate_ref,
                    evaluation_reference=self.fx.evaluation_ref,
                    policy=self.fx.policy,
                    trust=self.fx.trust,
                    expected=self.fx.expected,
                    owners=candidate_fixtures.OWNERS,
                    known_owners=candidate_fixtures.KNOWN_OWNERS,
                ),
            )
            body = canonical(request)
            (root / "request.json").write_bytes(body)
            config = dict(
                schema_version=1,
                mode="candidate",
                request_file=str(root / "request.json"),
                request_sha256=digest(body),
                producer_config=str(root / "producer.json"),
            )
            (root / "config.json").write_bytes(canonical(config))
            original = candidate_lineage.collect

            def collect(metadata, review, **kwargs):
                self.assertEqual(
                    (Path(metadata).name, Path(review).name), ("publisher", "promoter")
                )
                # Fixture injects bounded SQL reads, but uses the actual collect/reconcile.
                with patch.object(candidate_lineage, "collect", original):
                    return self.fx.collect(**kwargs)

            with (
                patch.object(source.security_event_delivery, "configured", return_value=self.audit),
                patch.object(candidate_lineage, "collect", side_effect=collect),
            ):
                result = source.configured(str(root / "config.json"))
            self.assertEqual(result["subject_sha256"], self.fx.candidate_ref)
            self.assertEqual(result["scope"], "verified-candidate-lineage-not-deployment-inventory")
            self.audit.emit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
