"""Pure replay with real signatures; synthetic observations are not native evidence."""

import copy
import importlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import security_event_config as config
from mlsecops import security_event_ledger as ledger
from mlsecops import security_event_outbox as outbox
from mlsecops import security_events as events
from mlsecops import security_trust_events as source
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, digest

CASES = [
    "source-heartbeat-reaches-independent-collector",
    "second-supervisor-refused-before-child",
    "confirmed-lock-contention-cannot-publish-heartbeat",
    "confirmed-lock-contention-recovers-within-original-wait",
    "committed-revocation-delivered-by-actual-periodic-source",
    "unavailable-source-cannot-mask-failure-with-heartbeat",
    "collector-outage-keeps-owned-supervisor-and-pending-event",
    "recovery-preserves-original-event-and-no-duplicates",
    "supervisor-stopped-with-confirmed-child-cleanup",
    "supervisor-restart-preserves-history-and-increases-counter",
    "supervisor-stopped-with-confirmed-child-cleanup",
    "stopped-observer-detected-by-signed-gap-within-120s",
    "absent-source-denies-fresh-promotion-audit",
    "private-output-has-no-credentials-or-source-payload",
    "collector-private-state-cleaned",
    "owned-sql-volume-cleaned",
    "source-unchanged",
]


class TrustEvidence(unittest.TestCase):
    def setUp(self):
        runtime = Path(__file__).resolve().parents[1] / ".runtime"
        runtime.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="trust-replay-test-", dir=runtime)
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.keys, self.publics = {}, {}
        for role in ("root", "receipt", "trust", "collector", "authority", "foreign"):
            self.keys[role] = self.directory / (role + ".pem")
            self.publics[role] = signing.create_key(self.keys[role])
        registry_doc = dict(
            schema_version=1,
            policy_sha256="a" * 64,
            issued_at_ms=99000,
            expires_at_ms=700000,
            receipt_public=self.publics["receipt"],
            producers=[
                dict(
                    public_key=self.publics[role],
                    role=role,
                    epoch="b" * 32,
                    heartbeat_required=role == "trust",
                )
                for role in ("trust", "collector")
            ],
        )
        registry_envelope = signing.sign(registry_doc, "security-event-config", self.keys["root"])
        self.pin = digest(canonical(registry_doc))
        self.registry = config.Registry(
            registry_envelope,
            trusted_root=self.publics["root"],
            expected_sha256=self.pin,
            clock_ms=100000,
        )
        self.identity = outbox.key_identity(self.keys["trust"])
        self.queue = outbox.Outbox.empty(self.registry, self.identity, clock_ms=100000)
        self.book = ledger.Ledger.empty(self.registry, clock_ms=100000)
        self.authority = dict(
            envelope=registry_envelope, root=self.publics["root"], pin=self.pin, clock_ms=100000
        )
        self.payloads = [
            dict(
                schema_version=1,
                environment="local-cpu",
                version=i,
                promotion_policy_sha256="a" * 64,
                issued_at=100 if i < 3 else 193,
                expires_at=3700,
                revoked_keys=[],
                revoked_artifacts=(["b" * 64, "c" * 64][: i - 1]),
            )
            for i in (1, 2, 3)
        ]
        envelopes = [signing.sign(p, "trust-policy", self.keys["authority"]) for p in self.payloads]
        self.documents = [
            dict(version=i, envelope=e, sha256=digest(canonical(e)))
            for i, e in enumerate(envelopes, 1)
        ]
        self.history2, self.history3 = self.history(2, 100), self.history(3, 193)
        self.stages = []
        self.beat(100000)
        self.stage("initial", 0)
        self.emit(self.history2, 132000)
        self.deliver(132000)
        self.beat(132000)
        self.stage("revoked_b", 32)
        self.stage("unavailable_before", 32.1)
        self.stage("unavailable_after", 67.1)
        self.beat(192000)
        self.stage("restored", 92)
        self.emit(self.history3, 222000)
        self.stage("pending_c", 122)
        self.deliver(252000)
        self.beat(252000)
        self.stage("recovered", 152)
        self.beat(253000)
        self.stage("restarted", 153)
        self.stage("stopped", 154)
        problems = self.book.poll(clock_ms=343100)["problems"]
        self.assertEqual(len(problems), 1)
        notice = self.book.notice(
            (problems[0]["notice_id"], self.keys["collector"]), clock_ms=343100
        )
        event = self.registry.verify(notice["envelope"], clock_ms=343100).document()
        self.book.route((event["event_id"], self.keys["receipt"]), clock_ms=343100)
        self.stage("gap", 243.1)
        # Independent expected materials, never read back from a candidate packet.
        module = importlib.import_module("mlsecops.security_trust_evidence")
        names = module.METHOD_FILES
        self.materials = {name: "d" * 64 for name in names}
        self.packet = dict(
            schema_version=1,
            source="a" * 40,
            fingerprint="b" * 64,
            materials=self.materials.copy(),
            cases=CASES.copy(),
            trust=dict(
                environment="local-cpu",
                initial_root=self.publics["authority"],
                commits=[
                    dict(
                        at_seconds=t,
                        result=dict(
                            version=n, document_sha256=self.documents[n - 1]["sha256"], reused=False
                        ),
                        history=h,
                    )
                    for n, t, h in ((2, 0.2, self.history2), (3, 93, self.history3))
                ],
            ),
            stages=self.stages,
            observations=dict(
                commit_started_seconds=0.1,
                contention_released_seconds=30,
                first_delivery_seconds=32,
                busy_failures=1,
                contention_heartbeat=copy.deepcopy(
                    self.stages[0]["state"]["outboxes"][0]["heartbeat"]
                ),
                source_failed_checks=1,
                duplicate_exit_code=1,
                duplicate_stdout_empty=True,
                duplicate_rejection=True,
                unavailable_observer_alive=True,
                outage_observer_alive=True,
                initial_health=200,
                final_health=503,
                promotion_denied=True,
                private_output_clean=True,
                stops=[
                    dict(at_seconds=t, exit_code=0, graceful=True, group_absent=True)
                    for t in (152.5, 154)
                ],
            ),
            cleanup=dict(
                at_seconds=244,
                collector_stopped=True,
                collector_directory_absent=True,
                sql_directory_absent=True,
                source_unchanged=True,
            ),
        )

    def history(self, n, clock):
        return dict(
            schema_version=1,
            root_public=self.publics["authority"],
            head_version=n,
            head_sha256=self.documents[n - 1]["sha256"],
            clock=clock,
            documents=copy.deepcopy(self.documents[:n]),
        )

    def beat(self, clock):
        heartbeat = self.queue.heartbeat(self.keys["trust"], clock_ms=clock)
        self.book.heartbeat(heartbeat, clock_ms=clock)

    def emit(self, history, clock):
        fields = source.project(
            history, environment="local-cpu", initial_root=self.publics["authority"]
        )[-1]
        self.queue.enqueue((fields, self.keys["trust"]), clock_ms=clock)

    def deliver(self, clock):
        record = self.queue.pending()[0]
        self.book.ingest(record["envelope"], clock_ms=clock)
        event = self.registry.verify(record["envelope"], clock_ms=clock).document()
        routed = self.book.route((event["event_id"], self.keys["receipt"]), clock_ms=clock)
        self.queue.acknowledge(routed["receipt"], clock_ms=clock)

    def stage(self, name, elapsed):
        clock = 100000 + round(elapsed * 1000)
        self.book.poll(clock_ms=clock)
        self.stages.append(
            dict(
                name=name,
                at_seconds=elapsed,
                state=dict(
                    registry={**self.authority, "clock_ms": clock},
                    outboxes=[self.queue.document()],
                    collector=self.book.document(),
                    incidents=self.book.document()["records"],
                ),
            )
        )

    def options(self):
        return dict(
            expected_source="a" * 40,
            expected_fingerprint="b" * 64,
            expected_materials=self.materials.copy(),
            expected_registry_root=self.publics["root"],
            expected_registry_pin=self.pin,
            expected_trust_root=self.publics["authority"],
        )

    def verifier(self):
        name = "mlsecops.security_trust_evidence"
        self.assertIsNotNone(importlib.util.find_spec(name), "trust evidence replay is missing")
        return importlib.import_module(name).verify

    def verify(self, packet=None, **changes):
        options = self.options()
        options.update(changes)
        return self.verifier()(self.packet if packet is None else packet, **options)

    def reject(self, packet=None, **changes):
        with self.assertRaisesRegex(Rejected, "^security_trust_evidence_invalid$"):
            self.verify(packet, **changes)

    def test_signed_primary_replay_preserves_public_summary_and_no_release_claim(self):
        before = copy.deepcopy(self.packet)
        report = self.verify()
        self.assertEqual(report["cases"], CASES)
        self.assertEqual(report["periodic_seconds"], 32)
        self.assertAlmostEqual(report["max_commit_delivery_seconds"], 31.9)
        self.assertEqual(report["forced_contention_recovery_seconds"], 2)
        self.assertAlmostEqual(report["stopped_source_notice_seconds"], 90.1)
        self.assertEqual(report["scope"], "continuous-trust-source-not-full-M23-or-R1")
        self.assertIs(report["release_ready"], False)
        self.assertEqual(report["packet_sha256"], digest(canonical(before)))
        self.assertEqual(self.packet, before)

    def test_caller_owned_source_fingerprint_method_and_authorities_required(self):
        for field, value in (
            ("expected_source", "f" * 40),
            ("expected_fingerprint", "f" * 64),
            ("expected_materials", {}),
            ("expected_registry_root", self.publics["foreign"]),
            ("expected_registry_pin", "f" * 64),
            ("expected_trust_root", self.publics["foreign"]),
        ):
            with self.subTest(field=field):
                self.reject(**{field: value})
        for field, value in (
            ("source", "f" * 40),
            ("fingerprint", "f" * 64),
            ("materials", {}),
            ("cases", CASES[:-1]),
        ):
            changed = copy.deepcopy(self.packet)
            changed[field] = value
            self.reject(changed)

    def test_resigned_rehashed_wrong_committed_document_still_rejects(self):
        # Valid trust signature, hash and head: only event-to-document binding is wrong.
        changed = copy.deepcopy(self.packet)
        payload = {**self.payloads[-1], "expires_at": 3701}
        envelope = signing.sign(payload, "trust-policy", self.keys["authority"])
        commit = changed["trust"]["commits"][1]
        commit["history"]["documents"][-1].update(
            envelope=envelope, sha256=digest(canonical(envelope))
        )
        commit["history"]["head_sha256"] = digest(canonical(envelope))
        commit["result"]["document_sha256"] = digest(canonical(envelope))
        source.project(
            commit["history"], environment="local-cpu", initial_root=self.publics["authority"]
        )
        self.reject(changed)

    def test_resigned_rehashed_wrong_revoked_artifact_rejects(self):
        changed = copy.deepcopy(self.packet)
        payload = {**self.payloads[-1], "revoked_artifacts": ["b" * 64, "d" * 64]}
        envelope = signing.sign(payload, "trust-policy", self.keys["authority"])
        commit = changed["trust"]["commits"][1]
        commit["history"]["documents"][-1].update(
            envelope=envelope, sha256=digest(canonical(envelope))
        )
        commit["history"]["head_sha256"] = digest(canonical(envelope))
        commit["result"]["document_sha256"] = digest(canonical(envelope))
        source.project(
            commit["history"], environment="local-cpu", initial_root=self.publics["authority"]
        )
        self.reject(changed)

    def test_history_root_commit_status_version_or_missing_proof_rejects(self):
        for target, field, value in (
            ("history", "root_public", self.publics["foreign"]),
            ("history", "documents", []),
            ("result", "reused", True),
            ("result", "version", 2),
        ):
            changed = copy.deepcopy(self.packet)
            changed["trust"]["commits"][1][target][field] = value
            self.reject(changed)

    def test_validly_resigned_restart_counter_regression_rejects(self):
        changed = copy.deepcopy(self.packet)
        for stage in changed["stages"][-3:]:
            state = stage["state"]
            original = state["outboxes"][0]["heartbeat"]
            value = self.registry.heartbeat(original, clock_ms=state["registry"]["clock_ms"])
            value["sequence"] = 4
            envelope = signing.sign(value, "security-heartbeat", self.keys["trust"])
            state["outboxes"][0]["heartbeat"] = envelope
            stream = next(
                s
                for s in state["collector"]["telemetry"]["streams"]
                if s["producer_id"] == self.identity
            )
            stream["heartbeat"]["envelope"] = envelope
            # Each local snapshot remains internally valid; lifecycle must reject.
            outbox.Outbox(self.registry, self.identity, state["outboxes"][0])
            ledger.Ledger(self.registry, state["collector"])
        self.reject(changed)

    def test_pending_or_lost_original_event_and_missing_incident_rejects(self):
        for index, operation in ((-1, "pending"), (5, "not_pending"), (-1, "incident")):
            changed = copy.deepcopy(self.packet)
            state = changed["stages"][index]["state"]
            if operation == "pending":
                state["outboxes"][0]["records"][-1]["receipt"] = None
            elif operation == "not_pending":
                state["outboxes"][0]["records"][-1] = copy.deepcopy(
                    changed["stages"][6]["state"]["outboxes"][0]["records"][-1]
                )
            else:
                state["incidents"] = []
            self.reject(changed)

    def test_intermediate_incidents_require_exact_canonical_collector_copy(self):
        for index in range(1, 9):
            with self.subTest(stage=self.packet["stages"][index]["name"]):
                changed = copy.deepcopy(self.packet)
                state = changed["stages"][index]["state"]
                state["incidents"] = copy.deepcopy(state["collector"]["records"])
                self.assertIs(state["incidents"][0]["late"], False)
                state["incidents"][0]["late"] = 0
                self.assertEqual(state["incidents"], state["collector"]["records"])
                self.assertNotEqual(
                    canonical(state["incidents"]), canonical(state["collector"]["records"])
                )
                ledger.Ledger(self.registry, state["collector"])
                self.reject(changed)

    def test_cleanup_lifecycle_inventory_and_finite_timing_are_required(self):
        for field, value in (
            ("collector_stopped", False),
            ("collector_directory_absent", False),
            ("sql_directory_absent", False),
            ("source_unchanged", False),
            ("at_seconds", 10),
            ("at_seconds", True),
        ):
            changed = copy.deepcopy(self.packet)
            changed["cleanup"][field] = value
            self.reject(changed)
        for field, value in (
            ("busy_failures", 0),
            ("source_failed_checks", 0),
            ("first_delivery_seconds", float("nan")),
            ("contention_released_seconds", float("inf")),
            ("promotion_denied", False),
        ):
            changed = copy.deepcopy(self.packet)
            changed["observations"][field] = value
            self.reject(changed)
        changed = copy.deepcopy(self.packet)
        changed["observations"]["stops"][1]["group_absent"] = False
        self.reject(changed)
        changed = copy.deepcopy(self.packet)
        changed["stages"][-1]["at_seconds"] = 700
        self.reject(changed)

    def test_forged_signatures_raw_fields_and_unbounded_packets_reject(self):
        for target in ("envelope", "receipt"):
            changed = copy.deepcopy(self.packet)
            changed["stages"][-1]["state"]["collector"]["records"][0][target]["signatures"][0][
                "sig"
            ] = signing.encode64(b"x" * 64)
            self.reject(changed)
        for field in ("raw_payload", "private_key", "token"):
            self.reject({**self.packet, field: "PRIVATE-CANARY"})
        self.reject({**self.packet, "stages": self.packet["stages"] * 100})
        self.reject({**self.packet, "cases": ["x" * (5 * 1024 * 1024)]})

    def test_native_capture_exports_full_records_without_reading_private_configuration(self):
        native = importlib.import_module("scripts.security_trust_service_native")
        self.assertTrue(
            callable(getattr(native, "capture_state", None)), "primary capture is missing"
        )
        expected = self.packet["stages"][-1]["state"]
        fixture = SimpleNamespace(
            now=lambda: 343100, registry=self.registry, fx=SimpleNamespace(publics=self.publics)
        )
        actual = native.capture_state(
            fixture,
            lambda: self.queue.document(),
            self.book.document,
            registry_envelope=self.authority["envelope"],
        )
        self.assertEqual(actual, expected)

    def test_atomic_private_retention_requires_cleanup_and_replays_readback(self):
        native = importlib.import_module("scripts.security_trust_service_native")
        self.assertTrue(
            callable(getattr(native, "retain_packet", None)), "private retention is missing"
        )
        report = native.retain_packet(self.directory, self.packet, **self.options())
        files = list((self.directory / ".runtime/evidence").glob("trust-service-*.primary.json"))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].read_bytes(), canonical(self.packet))
        self.assertEqual(report["packet_sha256"], digest(files[0].read_bytes()))
        self.assertEqual(report["primary_sha256"], report["packet_sha256"])
        bindings = files[0].with_name(files[0].name.replace(".primary.json", ".binding.json"))
        self.assertEqual(bindings.read_bytes(), canonical(self.options()))
        self.assertEqual(report["binding_sha256"], digest(bindings.read_bytes()))
        self.assertEqual(list(files[0].parent.glob(".pending-*")), [])
        changed = copy.deepcopy(self.packet)
        changed["cleanup"]["collector_stopped"] = False
        with self.assertRaises(Rejected):
            native.retain_packet(self.directory, changed, **self.options())
        self.assertEqual(len(list(files[0].parent.glob("*.json"))), 2)
        with patch.object(native, "bounded_read", return_value=b"{}"):
            with self.assertRaises(Rejected):
                native.retain_packet(self.directory, self.packet, **self.options())

    def test_retained_owner_bindings_are_separate_and_readback_tampering_rejects(self):
        native = importlib.import_module("scripts.security_trust_service_native")
        actual_read = native.bounded_read
        replacement = {**self.options(), "expected_source": "f" * 40}

        def substituted(path, limit):
            return (
                canonical(replacement)
                if path.name.endswith(".binding.json")
                else actual_read(path, limit)
            )

        with patch.object(native, "bounded_read", side_effect=substituted):
            with self.assertRaisesRegex(Rejected, "binding_readback"):
                native.retain_packet(self.directory, self.packet, **self.options())

    def test_native_hosted_guard_precedes_all_infrastructure(self):
        native = importlib.import_module("scripts.security_trust_service_native")
        with (
            patch.object(native.sys, "platform", "win32"),
            patch.object(native, "disposable") as start,
        ):
            with self.assertRaisesRegex(Rejected, "trust_observer_hosted_required"):
                native.qualify()
            start.assert_not_called()

    def resign_event(self, packet, index, *, queued_at_ms=None, **changes):
        """Rebuild event identity and all actual producer/receipt signatures consistently."""
        record = copy.deepcopy(packet["stages"][-1]["state"]["collector"]["records"][index])
        old = self.registry.verify(record["envelope"], clock_ms=record["ingested_at_ms"]).document()
        fields = {
            k: v
            for k, v in old.items()
            if k not in ("schema_version", "event_id", "action", "outcome")
        }
        if queued_at_ms is not None:
            changes.update(occurred_at_ms=queued_at_ms, observed_at_ms=queued_at_ms)
        value = events.create(**{**fields, **changes})
        role = "collector" if value["kind"] == "telemetry.gap" else "trust"
        envelope = signing.sign(value, "security-event", self.keys[role])
        verified = self.registry.verify(envelope, clock_ms=record["ingested_at_ms"])
        for stage in packet["stages"]:
            state = stage["state"]
            for target in (
                state["outboxes"][0]["records"],
                state["collector"]["records"],
                state["incidents"],
            ):
                for item in target:
                    if item["envelope"] != record["envelope"]:
                        continue
                    if item["receipt"] is not None:
                        receipt = self.registry.receipt(
                            item["receipt"],
                            self.registry.verify(
                                item["envelope"],
                                clock_ms=item.get("queued_at_ms", item.get("ingested_at_ms")),
                            ),
                        )
                        receipt["event_id"] = value["event_id"]
                        item["receipt"] = signing.sign(
                            receipt, "security-event-receipt", self.keys["receipt"]
                        )
                        self.registry.receipt(item["receipt"], verified)
                    item["envelope"] = envelope
                    if queued_at_ms is not None and "queued_at_ms" in item:
                        item["queued_at_ms"] = queued_at_ms
        for stage in packet["stages"]:
            outbox.Outbox(self.registry, self.identity, stage["state"]["outboxes"][0])
            ledger.Ledger(self.registry, stage["state"]["collector"])

    def test_valid_signatures_do_not_authorize_wrong_reason_asset_or_correlation(self):
        for field, value in (
            ("reason", "key"),
            ("asset_sha256", self.documents[0]["sha256"]),
            ("correlation_id", "f" * 32),
            ("bundle_sha256", "e" * 64),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.packet)
                self.resign_event(changed, 1, **{field: value})
                self.reject(changed)

    def test_resigned_gap_for_another_subject_is_not_stopped_trust_evidence(self):
        changed = copy.deepcopy(self.packet)
        self.resign_event(changed, 2, asset_sha256="f" * 64, correlation_id="f" * 32)
        self.reject(changed)

    def test_initial_healthy_observation_cannot_replace_received_heartbeat(self):
        changed = copy.deepcopy(self.packet)
        stream = next(
            s
            for s in changed["stages"][0]["state"]["collector"]["telemetry"]["streams"]
            if s["producer_id"] == self.identity
        )
        stream["heartbeat"] = None
        ledger.Ledger(self.registry, changed["stages"][0]["state"]["collector"])
        self.reject(changed)

    def test_contention_cannot_be_claimed_without_saved_received_heartbeat(self):
        changed = copy.deepcopy(self.packet)
        changed["observations"].pop("contention_heartbeat", None)
        self.reject(changed)
        changed = copy.deepcopy(self.packet)
        changed["observations"]["contention_heartbeat"] = copy.deepcopy(
            self.packet["stages"][1]["state"]["outboxes"][0]["heartbeat"]
        )
        self.reject(changed)

    def test_resigned_periodic_heartbeat_must_cover_committed_event_counter(self):
        changed = copy.deepcopy(self.packet)
        for stage in changed["stages"][1:4]:
            state = stage["state"]
            value = self.registry.heartbeat(
                state["outboxes"][0]["heartbeat"], clock_ms=state["registry"]["clock_ms"]
            )
            value["last_event_sequence"] = 0
            envelope = signing.sign(value, "security-heartbeat", self.keys["trust"])
            state["outboxes"][0]["heartbeat"] = envelope
            stream = next(
                s
                for s in state["collector"]["telemetry"]["streams"]
                if s["producer_id"] == self.identity
            )
            stream["heartbeat"]["envelope"] = envelope
            outbox.Outbox(self.registry, self.identity, state["outboxes"][0])
            ledger.Ledger(self.registry, state["collector"])
        self.reject(changed)

    def test_extra_signed_trust_event_cannot_hide_outside_expected_inventory(self):
        changed = copy.deepcopy(self.packet)
        state = changed["stages"][-1]["state"]
        book = ledger.Ledger(self.registry, state["collector"])
        fields = source.project(
            self.history3, environment="local-cpu", initial_root=self.publics["authority"]
        )[-1]
        value = events.create(
            **{**fields, "correlation_id": "f" * 32},
            producer_id=self.identity,
            epoch="b" * 32,
            sequence=3,
            occurred_at_ms=343100,
            observed_at_ms=343100,
            policy_sha256="a" * 64,
        )
        book.ingest(signing.sign(value, "security-event", self.keys["trust"]), clock_ms=343100)
        book.route((value["event_id"], self.keys["receipt"]), clock_ms=343100)
        state["collector"] = book.document()
        state["incidents"] = book.document()["records"]
        self.reject(changed)

    def retime_receipt(self, packet, index, *, ingested=None, routed=None):
        record = packet["stages"][-1]["state"]["collector"]["records"][index]
        event = self.registry.verify(record["envelope"], clock_ms=record["ingested_at_ms"])
        receipt = self.registry.receipt(record["receipt"], event)
        if ingested is not None:
            receipt["ingested_at_ms"] = ingested
        if routed is not None:
            receipt["routed_at_ms"] = routed
        signed = signing.sign(receipt, "security-event-receipt", self.keys["receipt"])
        self.registry.receipt(signed, event)
        for stage in packet["stages"]:
            state = stage["state"]
            for records in (
                state["outboxes"][0]["records"],
                state["collector"]["records"],
                state["incidents"],
            ):
                for item in records:
                    if item["envelope"] == record["envelope"] and item["receipt"] is not None:
                        item["receipt"] = copy.deepcopy(signed)
                        if "ingested_at_ms" in item:
                            item["ingested_at_ms"] = receipt["ingested_at_ms"]

    def test_new_signed_collector_heartbeat_during_source_unavailability_rejects(self):
        changed = copy.deepcopy(self.packet)
        state = changed["stages"][3]["state"]
        clock = state["registry"]["clock_ms"]
        beat = self.registry.heartbeat(state["outboxes"][0]["heartbeat"], clock_ms=clock)
        beat.update(sequence=beat["sequence"] + 1, observed_at_ms=clock)
        book = ledger.Ledger(self.registry, state["collector"])
        book.heartbeat(signing.sign(beat, "security-heartbeat", self.keys["trust"]), clock_ms=clock)
        state.update(collector=book.document(), incidents=book.document()["records"])
        self.assertEqual(changed["stages"][2]["state"]["outboxes"], state["outboxes"])
        self.reject(changed)

    def test_signed_event_before_trust_document_issue_floor_rejects(self):
        changed = copy.deepcopy(self.packet)
        self.resign_event(changed, 1, queued_at_ms=192999)
        self.reject(changed)

    def test_trust_document_second_precision_lower_bound_is_inclusive(self):
        changed = copy.deepcopy(self.packet)
        self.resign_event(changed, 1, queued_at_ms=193000)
        self.assertEqual(self.verify(changed)["status"], "pass")

    def test_signed_ingest_before_same_host_enqueue_rejects(self):
        changed = copy.deepcopy(self.packet)
        self.retime_receipt(changed, 0, ingested=131999)
        for stage in changed["stages"]:
            ledger.Ledger(self.registry, stage["state"]["collector"])
        self.reject(changed)

    def test_recovery_receipt_cannot_predate_pending_capture(self):
        changed = copy.deepcopy(self.packet)
        self.resign_event(changed, 1, queued_at_ms=221000)
        self.retime_receipt(changed, 1, ingested=221999)
        self.reject(changed)
        self.retime_receipt(changed, 1, ingested=222000)
        self.assertEqual(self.verify(changed)["status"], "pass")

    def gap_delivery(self, elapsed_ms):
        changed = copy.deepcopy(self.packet)
        state = changed["stages"][-1]["state"]
        clock = 253000 + elapsed_ms
        self.retime_receipt(changed, 2, routed=clock)
        state["collector"]["updated_at_ms"] = clock
        state["registry"]["clock_ms"] = clock
        changed["stages"][-1]["at_seconds"] = 273.0
        changed["cleanup"]["at_seconds"] = 274
        ledger.Ledger(self.registry, state["collector"])
        return changed

    def test_gap_receipt_after_120_seconds_cannot_hide_in_clock_precision(self):
        self.reject(self.gap_delivery(120001))

    def test_gap_receipt_deadline_is_inclusive(self):
        self.assertEqual(self.verify(self.gap_delivery(120000))["status"], "pass")

    def test_large_stage_clock_shrink_and_receipt_after_capture_already_reject(self):
        changed = self.gap_delivery(120000)
        changed["stages"][-1]["at_seconds"] = 243.1
        self.reject(changed)
        changed = self.gap_delivery(120000)
        changed["stages"][-1]["state"]["registry"]["clock_ms"] -= 1
        self.reject(changed)


if __name__ == "__main__":
    unittest.main()
