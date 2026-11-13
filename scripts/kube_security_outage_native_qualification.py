"""Mode conflicts must reject before touching the hosted infrastructure."""

import copy
import dataclasses
import io
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import security_outage_packet, signing
from mlsecops.contracts import Rejected, canonical, decode, digest, read_json, write_json
from mlsecops.security_event_ledger import Ledger
from mlsecops.security_event_outbox import Outbox
from mlsecops.security_outage_exchange import PHASES
from scripts import kube_candidate_native as candidate
from scripts import kube_serving_native as serving
from scripts import security_events_qualification as event_fixtures
from scripts.kube_serving_runtime_qualification import PROFILE
from scripts.security_outage_packet_qualification import fixture, timeline


class OutageCompositionContracts(unittest.TestCase):
    def test_runtime_request_failure_keeps_callers_and_never_private_error_text(self):
        from scripts import kube_security_outage_native as native

        def failing(*_):
            try:
                raise RuntimeError("PRIVATE CANARY")
            except RuntimeError as error:
                raise Rejected("kubernetes_request_failed:apply:unknown") from error

        with (
            patch.object(native, "run", side_effect=failing),
            patch.object(sys, "argv", ["probe"]),
            patch.object(sys, "stdout", io.StringIO()) as output,
        ):
            self.assertEqual(native.main(), 1)
        result = decode(output.getvalue().encode())
        self.assertEqual(result["request"], {"operation": "apply", "category": "unknown"})
        self.assertTrue(
            any(
                site["source_file"].endswith("kube_security_outage_native_qualification.py")
                for site in result["callers"]
            )
        )
        self.assertNotIn("PRIVATE", output.getvalue())

    def test_native_entrypoint_rejects_unowned_host_without_disclosing_exception(self):
        from scripts import kube_security_outage_native as native

        with (
            patch("scripts.kube_trust_native.hosted", side_effect=Rejected("PRIVATE")),
            patch.object(sys, "argv", ["security-outage"]),
            patch.object(sys, "stdout", io.StringIO()) as output,
            self.assertRaises(SystemExit) as stopped,
        ):
            runpy.run_path(native.__file__, run_name="__main__")
        self.assertEqual(stopped.exception.code, 1)
        self.assertNotIn("PRIVATE", output.getvalue())

    def test_candidate_conflicts_reject_before_source_and_cluster_reads(self):
        for other in (
            "privacy",
            "load",
            "monitoring",
            "include_key_revocation",
            "include_trust_lifecycle",
        ):
            with patch.object(candidate, "hosted"), patch.object(candidate, "command") as command:
                with self.assertRaises(Rejected):
                    candidate.qualify("unused", "unused", "unused", security=True, **{other: True})
            command.assert_not_called()
        with patch.object(candidate, "hosted"), self.assertRaises(Rejected):
            candidate.qualify("unused", "unused", "unused", security=1)

    def test_probe_conflicts_reject_before_resource_creation(self):
        for options in (
            {},
            {"candidate_probe": True, "privacy_operator": Mock()},
            {"candidate_probe": True, "load_operator": Mock()},
            {"candidate_probe": True, "monitoring_operator": Mock()},
            {"candidate_probe": True, "coordinator": Mock()},
            {"candidate_probe": True, "cli_privacy": True},
            {"candidate_probe": True, "trust_target": serving.Target.MODEL_REVOCATION},
        ):
            with patch.object(serving, "kubectl") as api, self.assertRaises(Rejected):
                serving.invoke(Path("unused"), PROFILE, {}, {}, security_operator=Mock(), **options)
            api.assert_not_called()


class RetentionContracts(unittest.TestCase):
    def setUp(self):
        from scripts import kube_security_outage_native as native

        self.native = native
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "state"
        self.directory = self.state / ("evidence/security-outage/" + "1" * 32)
        self.directory.mkdir(parents=True)
        self.packet, ref, trace, golden = fixture()
        self.summary = security_outage_packet.verify(
            self.packet, reference=ref, context=trace, golden=golden, campaign="1" * 32
        )
        boundary = {
            "status": "pass",
            "release_ready": False,
            "scope": "controlled-authorization-and-trust-real-sql-audit-boundary",
            "audit_checks": 1,
            "audit_denials": 1,
            "audit_check_error": "promotion_audit_unavailable",
            "promotion_error": "promotion_denial_audit_unconfirmed",
            "pending": {
                "event_id": "a" * 64,
                "envelope_sha256": "b" * 64,
                "reason": "audit_unavailable",
                "receipt": None,
                "kind": "promotion.denied",
            },
        }
        recovery = {
            "original_denial": {
                "id": "a" * 64,
                "envelope": "b" * 64,
                "kind": "promotion.denied",
                "receipt": "c" * 64,
            },
            "fault_removed": True,
            "fault_removed_at_ms": 4025,
            "SQL_and_CAS_unchanged": True,
        }
        self.binding = {
            "context": dataclasses.asdict(trace),
            "campaign": "1" * 32,
            "reference": ref,
            "golden": {
                "body": golden.body.decode(),
                "model": golden.model,
                "bundle": golden.bundle,
                "score": golden.score,
            },
            "summary": self.summary,
            "boundary": boundary,
            "recovery": recovery,
            "base_snapshot_sha256": "d" * 64,
        }
        source = {
            "source_revision": "f" * 40,
            "source_fingerprint": "e" * 64,
            "image_id": "sha256:" + "d" * 64,
        }
        self.primary = {
            "source": source,
            "source_dirty": False,
            "release_ready": False,
            "full_M23": "inconclusive",
            "security_campaign_id": "1" * 32,
            "qualification_permit_sha256": trace.permit_sha256,
            "proposal_reference": trace.proposal_sha256,
            "subject_sha256": trace.bundle_sha256,
            "model_sha256": trace.model_sha256,
            "base_snapshot_sha256": "d" * 64,
            "native": {
                **self.summary,
                "operator_retained_reverified": self.summary,
                "worker_cleanup_verified": True,
                "audit_boundary": boundary,
                "recovery": recovery,
            },
        }
        self.operator = {
            "campaign": "1" * 32,
            "phases": list(PHASES),
            "requests": {},
            "results": {},
            "timeline": timeline(),
        }
        for phase in PHASES:
            payload = {"packet": self.packet, "summary": self.summary} if phase == "finish" else {}
            self.operator["requests"][phase] = digest(
                canonical({"phase": phase, "campaign": "1" * 32, "payload": payload})
            )
            self.operator["results"][phase] = (
                {"packet_sha256": self.summary["packet_sha256"]} if phase == "finish" else {}
            )
        self.public = {"source": source, "method_materials": {"method": "f" * 64}}
        self.public.update(
            schema_version=1,
            status="pass",
            scope="actual-candidate-ML-and-monitoring-during-audit-outage",
            release_ready=False,
            full_M23="inconclusive",
        )
        self.primary.update(
            schema_version=1, status="pass", scope="actual-candidate-kubernetes-inference"
        )
        self.primary["native"]["ownership_return"] = {
            "transfer": {"before": "old-pod", "after": "new-pod", "release_ready": False},
            "observation": None,
            "heartbeat_before": 1,
            "heartbeat_after": 2,
            "return_seconds": 1.5,
            "identity_events_delivered": 0,
            "outbox_retained": True,
            "release_ready": False,
        }
        self.fx = event_fixtures.EventContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.install_authority()
        self.signed_recovery()
        self.publish()

    def install_authority(self):
        self.local = self.state / "kubernetes-security"
        self.marker = {
            "schema_version": 1,
            "ready": True,
            "workspace_id": "1" * 32,
            "profile": self.primary["source"],
            "context": {
                "environment": "lab",
                "initial_root": self.fx.publics["trust"],
                "policy": self.fx.policy,
            },
            "pins": {"promoter": "2" * 64, "collector": "3" * 64},
        }
        registry = signing.sign(self.fx.document, "security-event-config", self.fx.keys["root"])
        write_json(self.local / "materials/registry.json", registry)
        self.identity = {
            "schema_version": 1,
            "workspace": "1" * 32,
            **self.marker["context"],
            "registry_root": self.fx.publics["root"],
            "registry_sha256": self.fx.registry.sha256,
            "files": {
                "registry.json": digest((self.local / "materials/registry.json").read_bytes())
            },
        }
        write_json(self.local / "resources.json", self.marker)
        write_json(self.local / "materials/identity.json", self.identity)
        write_json(
            self.state / "workspace.json",
            {
                "schema_version": 1,
                "product": "trusted-mlsecops",
                "workspace_id": "1" * 32,
            },
        )

    def signed_recovery(
        self,
        *,
        reason="audit_unavailable",
        bundle=None,
        asset=None,
        role="promoter",
        kind="promotion.denied",
        queued_at_ms=3030,
        ingested_at_ms=4030,
        routed_at_ms=4035,
        acknowledged_at_ms=4038,
    ):
        bundle = bundle or "5" * 64
        producer = digest(signing.decode64(self.fx.publics[role]))
        box = Outbox.empty(self.fx.registry, producer, clock_ms=1000)
        record = box.enqueue(
            (
                {
                    "kind": kind,
                    "reason": reason,
                    "correlation_id": "4" * 32,
                    "asset_sha256": asset or bundle,
                    "bundle_sha256": bundle,
                },
                self.fx.keys[role],
            ),
            clock_ms=queued_at_ms,
        )
        event = self.fx.registry.verify(record["envelope"], clock_ms=queued_at_ms).document()
        book = Ledger.empty(self.fx.registry, clock_ms=1000)
        book.ingest(record["envelope"], clock_ms=ingested_at_ms)
        delivered = book.route((event["event_id"], self.fx.keys["receipt"]), clock_ms=routed_at_ms)
        box.acknowledge(delivered["receipt"], clock_ms=acknowledged_at_ms)
        boundary = self.binding["boundary"]
        boundary.update(
            schema_version=1,
            fixture_bundle_sha256="5" * 64,
            registry_sha256=self.fx.registry.sha256,
            outbox_pin="2" * 64,
        )
        boundary["pending"].update(
            event_id=event["event_id"], envelope_sha256=digest(canonical(record["envelope"]))
        )
        recovery = self.binding["recovery"]
        recovery["original_denial"] = {
            "id": event["event_id"],
            "envelope": digest(canonical(record["envelope"])),
            "kind": "promotion.denied",
            "receipt": digest(canonical(delivered["receipt"])),
        }
        recovery["signed_evidence"] = {
            "schema_version": 1,
            "registry": signing.sign(
                self.fx.document, "security-event-config", self.fx.keys["root"]
            ),
            "registry_root": self.fx.publics["root"],
            "registry_sha256": self.fx.registry.sha256,
            "outbox": {"pin": "2" * 64, "snapshot": box.document()},
            "collector": {"pin": "3" * 64, "snapshot": book.document()},
        }

    def publish(self):
        write_json(self.directory / "recovery.json", self.binding["recovery"])
        write_json(self.directory / "packet.json", self.packet)
        self.binding["packet_hash"] = digest((self.directory / "packet.json").read_bytes())
        write_json(self.directory / "binding.json", self.binding)
        write_json(self.directory / "operator.json", self.operator)
        write_json(self.state / self.native.PRIVATE, self.primary)
        self.public["primary_sha256"] = digest((self.state / self.native.PRIVATE).read_bytes())
        self.public["retained_sha256"] = {
            name: digest((self.directory / name).read_bytes())
            for name in ("binding.json", "packet.json", "operator.json")
        }
        write_json(self.state / self.native.PUBLIC, self.public)

    def verify(self):
        with (
            patch.object(self.native, "command", return_value="f" * 40),
            patch.object(self.native, "source_fingerprint", return_value="e" * 64),
            patch.object(self.native, "materials", return_value={"method": "f" * 64}),
        ):
            return self.native.reverify(self.root, self.state)

    def test_primary_replay_uses_retained_files_without_infrastructure(self):
        with patch.object(self.native.kube_storage, "admin") as sql:
            self.assertTrue(self.verify()["retained_primary_reverified"])
        sql.assert_not_called()

    def test_hash_only_recovery_is_not_complete_evidence(self):
        del self.binding["recovery"]["signed_evidence"]
        self.publish()
        with self.assertRaises(Rejected):
            self.verify()

    def test_rehashed_historical_signed_recovery_cannot_prove_current_campaign(self):
        self.signed_recovery(
            queued_at_ms=1200, ingested_at_ms=1300, routed_at_ms=1400, acknowledged_at_ms=1500
        )
        self.publish()
        with self.assertRaisesRegex(Rejected, "recovery_timeline"):
            self.verify()

    def test_rehashed_creation_and_delivery_must_fit_current_phase(self):
        for clocks in (
            {"queued_at_ms": 3019},
            {"queued_at_ms": 3041},
            {"ingested_at_ms": 4019},
            {"ingested_at_ms": 4024},
            {"routed_at_ms": 4041, "acknowledged_at_ms": 4042},
        ):
            self.signed_recovery(**clocks)
            self.publish()
            with self.subTest(clocks=clocks), self.assertRaisesRegex(Rejected, "recovery_timeline"):
                self.verify()

    def test_same_host_floor_millisecond_boundaries_are_inclusive_without_extra_skew(self):
        for queued, removed, ingested, routed in (
            (3020, 4020, 4020, 4020),
            (3040, 4040, 4040, 4040),
            (3030, 4025, 4025, 4040),
        ):
            self.signed_recovery(
                queued_at_ms=queued,
                ingested_at_ms=ingested,
                routed_at_ms=routed,
                acknowledged_at_ms=routed,
            )
            self.binding["recovery"]["fault_removed_at_ms"] = removed
            self.publish()
            with self.subTest(queued=queued, removed=removed):
                self.assertTrue(self.verify()["retained_primary_reverified"])

    def test_rehashed_fault_removal_requires_strict_timestamp_inside_recover(self):
        recovery = self.binding["recovery"]
        for removed in (True, 4025.0, "4025", None, 0, -1, 4019, 4041, 4031):
            recovery["fault_removed_at_ms"] = removed
            self.publish()
            with self.subTest(removed=removed), self.assertRaises(Rejected):
                self.verify()
        recovery.pop("fault_removed_at_ms")
        self.publish()
        with self.assertRaises(Rejected):
            self.verify()
        recovery["fault_removed_at_ms"] = 4025
        recovery["clock_skew_ms"] = 5000
        self.publish()
        with self.assertRaises(Rejected):
            self.verify()

    def test_rehashed_fault_removal_type_must_match_in_every_retained_copy(self):
        original = copy.deepcopy(self.binding["recovery"])
        for location in ("primary", "binding"):
            self.binding["recovery"] = copy.deepcopy(original)
            self.primary["native"]["recovery"] = copy.deepcopy(original)
            target = self.primary["native"] if location == "primary" else self.binding
            target["recovery"]["fault_removed_at_ms"] = 4025.0
            self.publish()
            write_json(self.directory / "recovery.json", original)
            with self.subTest(location=location), self.assertRaises(Rejected):
                self.verify()

    def test_resigned_denial_must_bind_audit_reason_and_controlled_fixture_bundle(self):
        for changes in ({"reason": "policy"}, {"bundle": "6" * 64}, {"asset": "6" * 64}):
            with self.subTest(changes=changes):
                self.signed_recovery(**changes)
                self.publish()
                with self.assertRaises(Rejected):
                    self.verify()

    def test_resigned_receipt_route_or_event_identity_cannot_be_rehashed_into_acceptance(self):
        for changes in ({"route": "security.identity"}, {"event_id": "7" * 64}):
            self.signed_recovery()
            packet = self.binding["recovery"]["signed_evidence"]
            original = packet["outbox"]["snapshot"]["records"][0]["receipt"]
            value = decode(signing.decode64(original["payload"]))
            value.update(changes)
            replacement = signing.sign(value, "security-event-receipt", self.fx.keys["receipt"])
            for role in ("outbox", "collector"):
                packet[role]["snapshot"]["records"][0]["receipt"] = replacement
            self.binding["recovery"]["original_denial"]["receipt"] = digest(canonical(replacement))
            self.publish()
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                self.verify()

    def test_self_declared_root_and_resigned_registry_do_not_replace_owner_authority(self):
        packet = self.binding["recovery"]["signed_evidence"]
        packet["registry_root"] = self.fx.publics["worker"]
        packet["registry"] = signing.sign(
            self.fx.document, "security-event-config", self.fx.keys["worker"]
        )
        self.publish()
        with self.assertRaises(Rejected):
            self.verify()

    def test_signed_evidence_corruption_and_full_journal_semantics_are_checked(self):
        for case in ("signature", "missing", "sequence", "telemetry", "pin", "extra"):
            self.signed_recovery()
            packet = self.binding["recovery"]["signed_evidence"]
            if case == "signature":
                packet["registry"]["signatures"][0]["sig"] = signing.encode64(b"x" * 64)
            elif case == "missing":
                packet["collector"]["snapshot"]["records"] = []
            elif case == "sequence":
                packet["outbox"]["snapshot"]["records"] *= 2
            elif case == "telemetry":
                packet["collector"]["snapshot"]["telemetry"] = {}
            elif case == "pin":
                packet["outbox"]["pin"] = "9" * 64
                self.binding["boundary"]["outbox_pin"] = "9" * 64
            else:
                packet["credentials"] = "PRIVATE-CANARY"
            self.publish()
            with self.subTest(case=case), self.assertRaises(Rejected):
                self.verify()

    def test_rehashed_public_and_private_status_and_ownership_debt_fail_closed(self):
        ownership = self.primary["native"]["ownership_return"]
        for target, field, value in (
            (self.public, "status", "fail"),
            (self.public, "scope", "other"),
            (self.public, "schema_version", True),
            (self.public, "release_ready", True),
            (self.public, "full_M23", "pass"),
            (self.primary, "status", "fail"),
            (self.primary, "schema_version", True),
            (self.primary["native"], "ownership_return", None),
            (ownership, "heartbeat_after", 1),
            (ownership, "outbox_retained", False),
            (ownership, "return_seconds", 120.01),
            (ownership, "return_seconds", True),
            (ownership["transfer"], "after", "old-pod"),
            (ownership["transfer"], "release_ready", True),
        ):
            original = target[field]
            target[field] = value
            self.publish()
            with self.subTest(field=field, value=value), self.assertRaises(Rejected):
                self.verify()
            target[field] = original

    def test_public_replay_does_not_return_signed_private_evidence(self):
        output = canonical(self.verify())
        for forbidden in (b"signatures", b"payload", b"registry_root", b"signed_evidence"):
            self.assertNotIn(forbidden, output)

    def test_rehashed_native_and_public_summary_boolean_type_confusion_is_rejected(self):
        self.public["observation"] = self.verify()
        for target in (self.primary["native"], self.public["observation"]):
            target["release_ready"] = 0
            self.publish()
            with self.subTest(scope=target.get("scope")), self.assertRaises(Rejected):
                self.verify()
            target["release_ready"] = False

    def test_owner_marker_configuration_policy_and_profile_are_independent_anchors(self):
        from scripts import kube_security_outage_operator as operator

        for target, field, value in (
            (self.marker, "ready", False),
            (self.marker, "workspace_id", "2" * 32),
            (self.identity, "workspace", "2" * 32),
            (self.identity, "environment", "foreign"),
            (self.identity["files"], "registry.json", "0" * 64),
            (self.marker["profile"], "image_id", "sha256:" + "0" * 64),
        ):
            old = target[field]
            target[field] = value
            write_json(self.local / "resources.json", self.marker)
            write_json(self.local / "materials/identity.json", self.identity)
            with self.subTest(field=field), self.assertRaises(Rejected):
                # A copied source prevents the test's runtime marker from altering its oracle.
                operator.owner_authority(
                    self.state,
                    source={
                        "source_revision": "f" * 40,
                        "source_fingerprint": "e" * 64,
                        "image_id": "sha256:" + "d" * 64,
                    },
                )
            target[field] = old
        write_json(self.local / "resources.json", self.marker)
        write_json(self.local / "materials/identity.json", self.identity)
        with self.assertRaises(Rejected):
            operator.owner_authority(self.state, marker={**self.marker, "ready": False})
        self.identity.pop("registry_root")
        write_json(self.local / "materials/identity.json", self.identity)
        with self.assertRaises(Rejected):
            operator.owner_authority(self.state)

    def test_private_replay_rejects_limits_malformed_snapshot_and_owner_policy_mismatch(self):
        from scripts import kube_security_outage_operator as operator

        authority = operator.owner_authority(self.state)
        original = self.binding["recovery"]
        for case in ("packet-limit", "journal-limit", "malformed", "policy", "projection"):
            value = copy.deepcopy(original)
            anchor = copy.deepcopy(authority)
            if case == "packet-limit":
                value["extra"] = "x" * (17 * 1024 * 1024)
            elif case == "journal-limit":
                value["signed_evidence"]["collector"]["snapshot"] = "x" * (8 * 1024 * 1024)
            elif case == "malformed":
                value["signed_evidence"]["outbox"]["snapshot"] = {}
            elif case == "policy":
                anchor["policy_sha256"] = "0" * 64
            else:
                value["original_denial"]["receipt"] = "0" * 64
            with self.subTest(case=case), self.assertRaises(Rejected):
                operator.verify_recovery(
                    self.binding["boundary"], value, anchor, timeline=self.operator["timeline"]
                )

    def test_replay_verifies_registry_signature_even_when_owner_file_hash_matches(self):
        packet = self.binding["recovery"]["signed_evidence"]
        packet["registry"]["signatures"][0]["sig"] = signing.encode64(b"x" * 64)
        write_json(self.local / "materials/registry.json", packet["registry"])
        self.identity["files"]["registry.json"] = digest(
            (self.local / "materials/registry.json").read_bytes()
        )
        write_json(self.local / "materials/identity.json", self.identity)
        self.publish()
        with self.assertRaises(Rejected):
            self.verify()

    def test_other_valid_producer_cannot_supply_outage_denial(self):
        self.signed_recovery(role="intake", kind="artifact.rejected", reason="integrity")
        self.publish()
        with self.assertRaisesRegex(Rejected, "producer_role"):
            self.verify()

    def test_unrelated_valid_history_does_not_replace_or_hide_original_denial(self):
        packet = self.binding["recovery"]["signed_evidence"]
        book = Ledger(self.fx.registry, packet["collector"]["snapshot"])
        envelope = signing.sign(self.fx.event(), "security-event", self.fx.keys["intake"])
        book.ingest(envelope, clock_ms=4039)
        packet["collector"]["snapshot"] = book.document()
        self.publish()
        self.assertTrue(self.verify()["retained_primary_reverified"])
        self.binding["boundary"]["pending"]["event_id"] = "0" * 64
        self.publish()
        with self.assertRaises(Rejected):
            self.verify()

    def test_missing_or_different_valid_receipt_cannot_prove_original_delivery(self):
        for case in ("missing", "different"):
            self.signed_recovery()
            packet = self.binding["recovery"]["signed_evidence"]
            sent = packet["outbox"]["snapshot"]["records"][0]
            if case == "missing":
                sent["receipt"] = None
            else:
                value = decode(signing.decode64(sent["receipt"]["payload"]))
                value["routed_at_ms"] += 1
                sent["receipt"] = signing.sign(
                    value, "security-event-receipt", self.fx.keys["receipt"]
                )
                self.binding["recovery"]["original_denial"]["receipt"] = digest(
                    canonical(sent["receipt"])
                )
            self.publish()
            with self.subTest(case=case), self.assertRaises(Rejected):
                self.verify()

    def test_public_observation_and_retained_recovery_are_checked_after_hash_verification(self):
        observation = self.verify()
        self.public["observation"] = observation
        self.publish()
        self.assertEqual(self.verify(), observation)
        self.public["observation"] = {**observation, "full_M23": "pass"}
        self.publish()
        with self.assertRaises(Rejected):
            self.verify()
        self.public.pop("observation")
        self.publish()
        write_json(self.directory / "recovery.json", {})
        with self.assertRaises(Rejected):
            self.verify()

    def test_primary_hash_source_and_owner_uid_fail_closed(self):
        self.public["primary_sha256"] = "0" * 64
        write_json(self.state / self.native.PUBLIC, self.public)
        with self.assertRaises(Rejected):
            self.verify()
        self.primary["source_dirty"] = True
        self.publish()
        with self.assertRaises(Rejected):
            self.verify()
        self.primary["source_dirty"] = False
        self.primary["native"]["ownership_return"]["transfer"]["before"] = ""
        self.publish()
        with self.assertRaises(Rejected):
            self.verify()

    def test_controlled_run_publishes_only_reverified_summary_and_failures_remove_pass(self):
        for broken in (False, True):
            self.primary["status"] = "fail" if broken else "pass"
            with (
                patch.object(self.native, "hosted"),
                patch.object(self.native.promotion_state, "install"),
                patch.object(self.native, "prepare", return_value={"profile": {}, "actual": {}}),
                patch.object(self.native, "qualify", return_value=self.primary),
                patch.object(self.native, "command", return_value="f" * 40),
                patch.object(self.native, "source_fingerprint", return_value="e" * 64),
                patch.object(self.native, "materials", return_value={"method": "f" * 64}),
            ):
                if broken:
                    with self.assertRaises(Rejected):
                        self.native.run(self.root, self.state)
                    self.assertEqual(read_json(self.state / self.native.PUBLIC)["status"], "fail")
                else:
                    result = self.native.run(self.root, self.state)
                    self.assertTrue(result["observation"]["retained_primary_reverified"])
                    self.assertNotIn(b"signatures", canonical(result))
                    self.assertEqual(read_json(self.state / self.native.PRIVATE), self.primary)

    def test_cli_modes_emit_safe_summaries_and_invalid_arguments_do_not_run(self):
        for args in ([], ["--reverify"], ["--bad"]):
            with (
                patch.object(sys, "argv", ["outage", *args]),
                patch.object(sys, "stdout", io.StringIO()) as output,
                patch.object(self.native, "run", return_value={"status": "pass"}) as run,
                patch.object(self.native, "reverify", return_value={"status": "pass"}) as replay,
            ):
                status = self.native.main()
            self.assertEqual(status, 1 if args == ["--bad"] else 0)
            if args == ["--bad"]:
                run.assert_not_called()
                replay.assert_not_called()
                self.assertEqual(
                    decode(output.getvalue().encode())["code"], "security_outage_native_rejected"
                )

    def test_changed_packet_rejected_before_acceptance(self):
        (self.directory / "packet.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(Rejected):
            self.verify()

    def test_precollected_green_windows_do_not_prove_later_operator_outage(self):
        self.operator["timeline"] = {
            phase: {
                "started_at_ms": 10000 + index * 1000,
                "finished_at_ms": 10500 + index * 1000,
                "started_ns": (10000 + index * 1000) * 1000000,
                "finished_ns": (10500 + index * 1000) * 1000000,
            }
            for index, phase in enumerate(PHASES[:-1])
        }
        self.operator["timeline"]["finish"] = {"started_at_ms": 15000, "started_ns": 15000000000}
        self.publish()
        with self.assertRaises(Rejected):
            self.verify()

    def test_rehashed_lineage_from_foreign_commit_is_not_current_source(self):
        from mlsecops.audit_lineage import checked
        from mlsecops.load_golden import Golden
        from mlsecops.serving_context import QualificationTrace

        context = self.binding["context"]
        context["lineage"]["source_revision"] = "0" * 40
        self.packet["context"] = copy.deepcopy(context)
        trace = QualificationTrace(
            *(
                context[name]
                for name in ("permit_sha256", "proposal_sha256", "bundle_sha256", "model_sha256")
            ),
            checked(context["lineage"]),
        )
        # Closed windows carry the same lineage. Rebuild their derived hashes,
        # not a trivially inconsistent tamper that the existing verifier catches.
        from mlsecops import monitoring, monitoring_stream

        reference = self.binding["reference"]
        evaluator = monitoring.Evaluator(reference, digest(canonical(reference)))
        for item in self.packet["windows"]:
            old = item["document"]
            stream = monitoring_stream.Accumulator(
                reference, digest(canonical(reference)), started_at_ms=old["started_at_ms"]
            )
            for record in item["http"]:
                stream.add(
                    trace,
                    record["features"],
                    record["response"]["predictions"],
                    record["response"]["request_id"],
                )
            closed = stream.close(sequence=old["sequence"], ended_at_ms=old["ended_at_ms"])
            item["document"] = closed.document()
            item["monitor"]["reports"] = [evaluator.evaluate(closed.document())]
        golden = self.binding["golden"]
        self.summary = security_outage_packet.verify(
            self.packet,
            reference=reference,
            context=trace,
            golden=Golden(
                golden["body"].encode(), golden["model"], golden["bundle"], golden["score"]
            ),
            campaign="1" * 32,
        )
        self.binding["summary"] = self.summary
        self.primary["native"].update(self.summary)
        self.primary["native"]["operator_retained_reverified"] = self.summary
        self.operator["requests"]["finish"] = digest(
            canonical(
                {
                    "phase": "finish",
                    "campaign": "1" * 32,
                    "payload": {"packet": self.packet, "summary": self.summary},
                }
            )
        )
        self.operator["results"]["finish"] = {"packet_sha256": self.summary["packet_sha256"]}
        self.publish()
        with self.assertRaises(Rejected):
            self.verify()

    def test_rehashed_semantic_tampering_of_fault_cleanup_and_binding_rejected(self):
        for target, field, value in (
            (self.binding["recovery"], "fault_removed", False),
            (self.binding["recovery"], "SQL_and_CAS_unchanged", False),
            (self.binding["boundary"], "audit_checks", 0),
            (self.binding["boundary"], "audit_check_error", "release_assurance_required"),
            (self.primary, "proposal_reference", "1" * 64),
            (self.operator["requests"], "attempt", "0" * 64),
        ):
            original = copy.deepcopy(target[field])
            target[field] = value
            self.publish()
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.verify()
            target[field] = original
        self.publish()


if __name__ == "__main__":
    unittest.main()
