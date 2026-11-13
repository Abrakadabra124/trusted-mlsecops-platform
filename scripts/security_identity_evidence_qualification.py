"""Pure signed synthetic packets only. No HTTP, sockets or process fixtures."""

import copy
import importlib.util
import tempfile
import unittest
from pathlib import Path

from mlsecops import security_event_ledger as ledger
from mlsecops import security_event_outbox as outbox
from mlsecops import security_events as events
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts import security_events_qualification as fixtures

SCOPE = "actual-http-and-identity-child-with-controlled-unready-engine-not-M13-M14-M23"
SERVICE = digest(b"controlled-unready-http-service-for-identity-audit")
CASES = (
    [
        "startup-probe-creates-no-denial",
        "startup-actual-producer-heartbeat",
        "live-producer-allows-fresh-audit-challenge",
        "valid-metrics-does-not-emit-identity-denial",
        "audit-outage-denies-with-503",
        "offline-event-retained-before-child-exit",
        "liveness-and-operator-remain-available",
        "pending-outage-denies-server-startup",
        "failed-startup-keeps-original-pending",
        "startup-probe-delivers-original-event",
        "restart-retains-heartbeat-counter-and-complete-head",
        "operator-retry-is-idempotent",
        "credentials-and-input-absent-from-outbox",
        "actual-thirty-second-owned-scheduler",
        "periodic-heartbeat-reached-collector",
        "actual-stopped-producer-gap-within-120s",
        "stopped-owner-cannot-keep-sending-heartbeats",
        "missing-producer-denies-fresh-promotion-audit",
        "all-three-server-lifecycles-reaped-their-children",
        "no-credentials-in-private-server-log",
        "collector-and-private-files-cleaned",
        "source-unchanged",
    ]
    + ["signed-identity-subject-and-route-" + str(i) for i in range(1, 7)]
    + (
        ["bounded-private-http-output"] * 11
        + ["actual-http-identity-denied-after-delivery"] * 5
        + ["owned-http-exit-and-port-closed"] * 2
    )
)


class IdentityEvidence(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("mlsecops.security_identity_evidence"),
            "identity primary retention/replay is missing; summary cannot reject forgery",
        )
        from mlsecops import security_identity_evidence

        self.subject = security_identity_evidence
        self.fx = fixtures.EventContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.registry = self.fx.registry
        self.owner = {
            "source": "1" * 40,
            "fingerprint": "2" * 64,
            "method_materials": {name: "3" * 64 for name in self.subject.METHOD_FILES},
            "registry_root": self.fx.publics["root"],
            "registry_sha256": self.registry.sha256,
        }
        self.queue = outbox.Outbox.empty(
            self.registry, outbox.key_identity(self.fx.keys["serving"]), clock_ms=10000
        )
        self.book = ledger.Ledger.empty(self.registry, clock_ms=10000)
        self.snapshots, self.observations = {}, []
        self.heartbeat(10000)
        self.http("startup", "/livez", 200, 10010)
        self.snapshot("startup", 10030)
        requests = [
            ("predict-missing", "/v1/predict", "credential"),
            ("ready-invalid", "/readyz", "credential"),
            ("predict-role", "/v1/predict", "role"),
            ("metrics-role", "/metrics", "role"),
            ("metrics-missing", "/metrics", "credential"),
            ("outage-denial", "/v1/predict", "credential"),
        ]
        for index, (case, route, reason) in enumerate(requests, 1):
            when = 11000 + index * 100
            correlation = f"{index:032x}"
            record = self.queue.enqueue(
                (
                    dict(
                        kind="identity.denied",
                        reason=reason,
                        correlation_id=correlation,
                        asset_sha256=SERVICE,
                        bundle_sha256=None,
                    ),
                    self.fx.keys["serving"],
                ),
                clock_ms=when + 5,
            )
            if index < 6:
                self.deliver(record, when + 6)
            self.http(
                case, route, 503 if index == 6 else 401, when, request_id=correlation, reason=reason
            )
            if index == 5:
                self.http("metrics-authorized", "/metrics", 200, 11550)
        self.snapshot("outage", 11630)
        self.http("outage-live", "/livez", 200, 11640)
        self.http("outage-metrics", "/metrics", 200, 11670)
        self.snapshot("failed-startup", 11800)
        self.deliver(self.queue.pending()[0], 12000)
        self.heartbeat(12020)
        self.http("recovered", "/livez", 200, 12030)
        self.snapshot("recovered", 12100)
        self.heartbeat(42020)
        self.snapshot("periodic", 42100)
        problem = self.book.poll(clock_ms=132020)["problems"][0]
        notice = self.book.notice(
            (problem["notice_id"], self.fx.keys["collector"]), clock_ms=132020
        )
        event = self.registry.verify(notice["envelope"], clock_ms=132020)
        self.book.route((event.document()["event_id"], self.fx.keys["receipt"]), clock_ms=132021)
        self.snapshot("stopped", 132030)
        self.packet = {
            "schema_version": 1,
            "source": self.owner["source"],
            "fingerprint": self.owner["fingerprint"],
            "method": SCOPE,
            "method_materials": self.owner["method_materials"],
            "service_sha256": SERVICE,
            "delivery": {
                "registry": {
                    "envelope": signing.sign(
                        self.fx.document, "security-event-config", self.fx.keys["root"]
                    ),
                    "root": self.fx.publics["root"],
                    "pin": self.registry.sha256,
                    "clock_ms": 132030,
                },
                "outboxes": [self.queue.document()],
                "collector": self.book.document(),
                "incidents": self.book.document()["records"],
            },
            "snapshots": self.snapshots,
            "http": self.observations,
            "gap": {"observed_at_ms": 132030, "elapsed_seconds": 90.01, "health_status": 503},
            "cleanup": {
                "http_exits": [
                    {"phase": "outage", "exit_code": 0, "port_closed": True},
                    {"phase": "failed-startup", "exit_code": 1, "port_closed": True},
                    {"phase": "stopped", "exit_code": 0, "port_closed": True},
                ],
                "child_cleanup_markers": 3,
                "collector_exit_code": 0,
                "outage_exit_code": 0,
                "outage_port_closed": True,
                "collector_port_closed": True,
                "fixture_removed": True,
                "http_owner_reaped": True,
                "collector_owner_reaped": True,
                "captured_at_ms": 132030,
                "confirmed_at_ms": 132100,
            },
            "summary": dict(
                status="pass",
                source="1" * 40,
                fingerprint="2" * 64,
                cases=CASES,
                max_http_seconds=0.02,
                heartbeat_interval_seconds=30.0,
                stopped_producer_notice_seconds=90.01,
                release_ready=False,
                scope=SCOPE,
            ),
        }

    def heartbeat(self, when):
        self.book.heartbeat(
            self.queue.heartbeat(self.fx.keys["serving"], clock_ms=when), clock_ms=when
        )

    def deliver(self, record, when):
        self.book.ingest(record["envelope"], clock_ms=when)
        event = self.registry.verify(record["envelope"], clock_ms=when)
        routed = self.book.route(
            (event.document()["event_id"], self.fx.keys["receipt"]), clock_ms=when + 1
        )
        self.queue.acknowledge(routed["receipt"], clock_ms=when + 2)

    def snapshot(self, phase, when):
        self.snapshots[phase] = dict(
            outbox=self.queue.document(), collector=self.book.document(), captured_at_ms=when
        )

    def http(self, case, path, status, when, request_id=None, reason=None):
        self.observations.append(
            dict(
                case=case,
                method="POST" if path == "/v1/predict" else "GET",
                path=path,
                status=status,
                request_id=request_id,
                reason=reason,
                service_sha256=SERVICE,
                error_code=(
                    "unauthorized"
                    if status == 401
                    else "security_audit_unavailable"
                    if status == 503
                    else None
                ),
                started_at_ms=when,
                completed_at_ms=when + 20,
                elapsed_seconds=0.02,
            )
        )

    def replay(self, packet=None, *, pinned=True, owner=None):
        value = self.packet if packet is None else packet
        path = self.fx.directory / "packet.json"
        path.write_bytes(canonical(value))
        pin = digest(canonical(value if pinned else self.packet))
        return self.subject.replay(path, expected_sha256=pin, expected=owner or self.owner)

    def replace_record(self, packet, original, replacement):
        """Keep every primary copy consistent so rejection tests source semantics."""
        documents = [packet["delivery"]["collector"], *packet["delivery"]["outboxes"]]
        for snapshot in packet["snapshots"].values():
            documents.extend((snapshot["outbox"], snapshot["collector"]))
        histories = [document["records"] for document in documents]
        histories.append(packet["delivery"]["incidents"])
        for records in histories:
            for record in records:
                if record["envelope"] == original["envelope"]:
                    for field in ("envelope", "receipt", "ingested_at_ms"):
                        if field in record:
                            record[field] = copy.deepcopy(replacement[field])

    def receipt_packet(self, index, *, ingested_at_ms, routed_at_ms):
        original = self.packet["delivery"]["collector"]["records"][index]
        event = self.registry.verify(original["envelope"], clock_ms=original["ingested_at_ms"])
        receipt = self.registry.receipt(original["receipt"], event)
        receipt.update(ingested_at_ms=ingested_at_ms, routed_at_ms=routed_at_ms)
        replacement = dict(
            original,
            ingested_at_ms=ingested_at_ms,
            receipt=signing.sign(receipt, "security-event-receipt", self.fx.keys["receipt"]),
        )
        packet = copy.deepcopy(self.packet)
        self.replace_record(packet, original, replacement)
        return packet

    def test_http_401_receipt_requires_same_host_causal_order(self):
        # Request 11100..11120, occurrence/enqueue 11105. Transport skew alone
        # permits these signed receipts; a same-host HTTP campaign must not.
        for ingested, routed in ((10100, 10101), (11100, 11101), (11104, 11107), (11106, 11121)):
            packet = self.receipt_packet(0, ingested_at_ms=ingested, routed_at_ms=routed)
            with self.subTest(ingested=ingested, routed=routed), self.assertRaises(Rejected):
                self.replay(packet)

    def test_http_401_allows_equal_millisecond_causal_boundaries(self):
        for routed in (11105, 11120):
            packet = self.receipt_packet(0, ingested_at_ms=11105, routed_at_ms=routed)
            packet["http"][1].update(started_at_ms=11105, elapsed_seconds=0.015)
            with self.subTest(routed=routed):
                self.assertEqual(self.replay(packet)["status"], "pass")

    def test_gap_receipt_cannot_follow_incident_readback(self):
        packet = self.receipt_packet(-1, ingested_at_ms=132020, routed_at_ms=139000)
        packet["delivery"]["collector"]["updated_at_ms"] = 139000
        packet["snapshots"]["stopped"]["collector"]["updated_at_ms"] = 139000
        packet["snapshots"]["stopped"]["captured_at_ms"] = 139001
        packet["delivery"]["registry"]["clock_ms"] = 139001
        packet["cleanup"].update(captured_at_ms=139001, confirmed_at_ms=139002)
        # Full signed incident was reportedly read at 132030, before its route.
        with self.assertRaises(Rejected):
            self.replay(packet)

    def test_gap_allows_all_six_timestamps_in_the_same_millisecond(self):
        # The fixture reads back and captures at 132030.
        tick = 132030
        packet = self.receipt_packet(-1, ingested_at_ms=tick, routed_at_ms=tick)
        self.resign_gap(packet, occurred_at_ms=tick, observed_at_ms=tick)
        packet["delivery"]["collector"]["updated_at_ms"] = tick
        packet["snapshots"]["stopped"]["collector"]["updated_at_ms"] = tick
        self.assertEqual(self.replay(packet)["status"], "pass")

    def resign_gap(self, packet, **event_fields):
        original = copy.deepcopy(packet["delivery"]["collector"]["records"][-1])
        event = self.registry.verify(original["envelope"], clock_ms=original["ingested_at_ms"])
        values = {
            key: value
            for key, value in event.document().items()
            if key not in ("schema_version", "event_id", "action", "outcome")
        }
        values.update(event_fields)
        envelope = signing.sign(
            events.create(**values), "security-event", self.fx.keys["collector"]
        )
        substituted = self.registry.verify(envelope, clock_ms=original["ingested_at_ms"])
        receipt = self.registry.receipt(original["receipt"], event)
        receipt["event_id"] = substituted.document()["event_id"]
        replacement = dict(
            original,
            envelope=envelope,
            receipt=signing.sign(receipt, "security-event-receipt", self.fx.keys["receipt"]),
        )
        self.replace_record(packet, original, replacement)

    def test_gap_rejects_resigned_observation_after_ingest(self):
        # Ingest 132020, route 132021, readback/capture 132030, cleanup 132100.
        for occurred, observed in ((132020, 132021), (136000, 136000)):
            packet = copy.deepcopy(self.packet)
            self.resign_gap(packet, occurred_at_ms=occurred, observed_at_ms=observed)
            with self.subTest(occurred=occurred, observed=observed), self.assertRaises(Rejected):
                self.replay(packet)

    def test_gap_rejects_resigned_foreign_bundle_subject(self):
        packet = copy.deepcopy(self.packet)
        self.resign_gap(packet, bundle_sha256="f" * 64)
        with self.assertRaises(Rejected):
            self.replay(packet)

    def test_valid_complete_packet_replays_without_live_fixture_or_private_keys(self):
        for path in self.fx.keys.values():
            path.unlink()
        result = self.replay()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["scope"], SCOPE)
        self.assertFalse(result["release_ready"])
        self.assertEqual(result["primary_sha256"], digest(canonical(self.packet)))
        for forbidden in ("signatures", "payload", "registry", "http", "cleanup", "token"):
            self.assertNotIn(forbidden, result)

    def test_missing_packet_and_wrong_external_hash_fail_closed(self):
        with self.assertRaises(Rejected):
            self.subject.replay(
                self.fx.directory / "absent", expected_sha256="0" * 64, expected=self.owner
            )
        changed = copy.deepcopy(self.packet)
        changed["summary"]["max_http_seconds"] = 0
        with self.assertRaises(Rejected):
            self.replay(changed, pinned=False)

    def test_source_method_and_registry_substitution_rejected_even_with_new_packet_hash(self):
        for key, replacement in (
            ("source", "f" * 40),
            ("fingerprint", "f" * 64),
            ("method", "actual-model-candidate"),
            ("method_materials", {}),
        ):
            changed = copy.deepcopy(self.packet)
            changed[key] = replacement
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.replay(changed)
        changed = copy.deepcopy(self.packet)
        changed["delivery"]["registry"]["root"] = self.fx.publics["worker"]
        with self.assertRaises(Rejected):
            self.replay(changed)

    def test_bad_signature_receipt_and_missing_incident_rejected(self):
        for target in ("registry", "outbox", "receipt", "incident"):
            changed = copy.deepcopy(self.packet)
            if target == "incident":
                changed["delivery"]["incidents"].pop()
            else:
                envelope = (
                    changed["delivery"]["registry"]["envelope"]
                    if target == "registry"
                    else changed["delivery"]["outboxes"][0]["records"][0][
                        "receipt" if target == "receipt" else "envelope"
                    ]
                )
                envelope["signatures"][0]["sig"] = signing.encode64(b"x" * 64)
            with self.subTest(target=target), self.assertRaises(Rejected):
                self.replay(changed)

    def test_http_status_correlation_subject_reason_and_inventory_are_bound(self):
        for field, value in (
            ("status", 200),
            ("request_id", "f" * 32),
            ("reason", "role"),
            ("service_sha256", "f" * 64),
            ("path", "/metrics"),
            ("method", "GET"),
            ("completed_at_ms", 11001),
            ("error_code", "other"),
        ):
            changed = copy.deepcopy(self.packet)
            changed["http"][1][field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.replay(changed)
        for key in ("http", "snapshots"):
            changed = copy.deepcopy(self.packet)
            changed[key] = [] if key == "http" else {}
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.replay(changed)

    def test_pending_identity_is_exact_and_not_fabricated_from_final_receipt(self):
        for phase in ("outage", "failed-startup"):
            for replacement in (
                self.snapshots["recovered"]["outbox"],
                self.snapshots["startup"]["outbox"],
            ):
                changed = copy.deepcopy(self.packet)
                changed["snapshots"][phase]["outbox"] = replacement
                with self.subTest(phase=phase), self.assertRaises(Rejected):
                    self.replay(changed)

    def test_missing_heartbeat_gap_or_forged_elapsed_summary_rejected(self):
        for field in (
            "heartbeat_interval_seconds",
            "stopped_producer_notice_seconds",
            "max_http_seconds",
        ):
            changed = copy.deepcopy(self.packet)
            changed["summary"][field] = 0
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.replay(changed)
        changed = copy.deepcopy(self.packet)
        changed["snapshots"]["periodic"] = changed["snapshots"]["recovered"]
        with self.assertRaises(Rejected):
            self.replay(changed)

    def test_cleanup_summary_cannot_hide_unreaped_owner_or_incomplete_capture(self):
        for field, value in (
            ("fixture_removed", False),
            ("collector_port_closed", False),
            ("child_cleanup_markers", 2),
            ("collector_exit_code", 1),
            ("confirmed_at_ms", 1000),
            ("http_owner_reaped", False),
        ):
            changed = copy.deepcopy(self.packet)
            changed["cleanup"][field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.replay(changed)
        changed = copy.deepcopy(self.packet)
        changed["cleanup"]["http_exits"][0]["exit_code"] = 1
        with self.assertRaises(Rejected):
            self.replay(changed)

    def test_summary_case_omission_duplicate_and_added_credentials_are_rejected(self):
        for change in ("missing", "duplicate", "credential"):
            changed = copy.deepcopy(self.packet)
            if change == "missing":
                changed["summary"]["cases"].pop()
            elif change == "duplicate":
                changed["summary"]["cases"].append("source-unchanged")
            else:
                changed["http"][0]["headers"] = {"Authorization": "PRIVATE-CANARY"}
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.replay(changed)

    def test_retention_requires_cleanup_and_writes_only_under_private_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            changed = copy.deepcopy(self.packet)
            changed["cleanup"]["fixture_removed"] = False
            with self.assertRaises(Rejected):
                self.subject.retain(root, changed, expected=self.owner)
            self.assertFalse((root / ".runtime").exists())
            report = self.subject.retain(root, self.packet, expected=self.owner)
            path = (
                root / ".runtime/security-identity-primary" / (report["primary_sha256"] + ".json")
            )
            self.assertTrue(decode(path.read_bytes()) == self.packet)
            self.assertEqual(report["status"], "pass")

    def test_gap_summary_cannot_substitute_plausible_elapsed_or_healthy_status(self):
        for key, value in (
            ("health_status", 200),
            ("elapsed_seconds", 91.01),
            ("observed_at_ms", 131000),
        ):
            changed = copy.deepcopy(self.packet)
            changed["gap"][key] = value
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.replay(changed)
        changed = copy.deepcopy(self.packet)
        changed["summary"]["stopped_producer_notice_seconds"] = 91.01
        with self.assertRaises(Rejected):
            self.replay(changed)

    def test_observation_projection_rejects_credential_fields_and_wrong_http_case(self):
        args = dict(
            case="predict-missing",
            path="/v1/predict",
            status=401,
            started_at_ms=1000,
            completed_at_ms=1001,
            elapsed_seconds=0.001,
        )
        content = canonical(
            dict(schema_version=1, request_id="a" * 32, error={"code": "unauthorized"})
        )
        observed = self.subject.observation(**args, content=content)
        self.assertEqual(observed["request_id"], "a" * 32)
        self.assertNotIn("payload", observed)
        for changed in (
            dict(decode(content), credentials="PRIVATE-CANARY"),
            dict(decode(content), request_id="PRIVATE-CANARY"),
        ):
            with self.assertRaises(Rejected):
                self.subject.observation(**args, content=canonical(changed))

    def test_capture_is_detached_before_files_disappear_and_retention_after_cleanup(self):
        state = self.fx.directory / "state.json"
        state.write_bytes(canonical(self.snapshots["stopped"]))
        captured = self.subject.capture(
            lambda: decode(state.read_bytes())["outbox"],
            lambda: decode(state.read_bytes())["collector"],
            lambda: 132030,
        )
        state.unlink()
        self.assertTrue(captured == self.snapshots["stopped"])
        packet = copy.deepcopy(self.packet)
        packet["snapshots"]["stopped"] = captured
        report = self.subject.retain(self.fx.directory, packet, expected=self.owner)
        self.assertEqual(report["status"], "pass")

    def test_method_material_bytes_and_missing_method_are_independently_bound(self):
        root = self.fx.directory / "checkout"
        for name in self.subject.METHOD_FILES:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"method-source")
        before = self.subject.method_materials(root)
        changed = root / "scripts/security_identity_events_native.py"
        changed.write_bytes(b"substituted-method")
        after = self.subject.method_materials(root)
        self.assertNotEqual(before, after)
        self.assertEqual(
            after["scripts/security_identity_events_native.py"], digest(b"substituted-method")
        )
        changed.unlink()
        with self.assertRaises(Rejected):
            self.subject.method_materials(root)

    def test_owner_binding_survives_separately_from_primary(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.subject.retain(Path(directory), self.packet, expected=self.owner)
            path = (
                Path(directory)
                / ".runtime/security-identity-primary"
                / (result["primary_sha256"] + ".bindings.json")
            )
            self.assertTrue(path.is_file(), "owner pins discarded after fixture exit")
            self.assertEqual(
                decode(path.read_bytes()),
                {"expected": self.owner, "primary_sha256": result["primary_sha256"]},
            )
            self.assertEqual(result["binding_sha256"], digest(path.read_bytes()))

    def test_finite_http_projection_discards_success_body_and_rejects_wrong_case(self):
        args = dict(
            case="metrics-authorized",
            path="/metrics",
            status=200,
            started_at_ms=1000,
            completed_at_ms=1001,
            elapsed_seconds=0.001,
        )
        result = self.subject.observation(**args, content=b"PRIVATE-CANARY")
        self.assertNotIn(b"PRIVATE-CANARY", canonical(result))
        for change in (dict(case="unknown"), dict(status=401), dict(path="/secret")):
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.subject.observation(**{**args, **change}, content=b"PRIVATE-CANARY")

    def test_truncated_noncanonical_duplicate_json_and_nonfinite_measurement_rejected(self):
        path = self.fx.directory / "malformed.json"
        for raw in (canonical(self.packet) + b"\n", b'{"summary":{},"summary":{}}', b"{"):
            path.write_bytes(raw)
            with self.assertRaises(Rejected):
                self.subject.replay(path, expected_sha256=digest(raw), expected=self.owner)
        for value in (True, float("inf"), float("nan"), -1, "PRIVATE-CANARY"):
            changed = copy.deepcopy(self.packet)
            changed["http"][0]["elapsed_seconds"] = value
            with self.subTest(kind=type(value).__name__), self.assertRaises(Rejected):
                self.subject.verify(changed, expected=self.owner)

    def test_consistently_resigned_wrong_service_or_request_cannot_become_identity_evidence(self):
        for field, replacement in (("asset_sha256", "f" * 64), ("correlation_id", "f" * 32)):
            changed = copy.deepcopy(self.packet)
            original = self.registry.verify(
                self.queue.document()["records"][0]["envelope"], clock_ms=11105
            ).document()
            values = {
                k: v
                for k, v in original.items()
                if k not in ("schema_version", "event_id", "action", "outcome")
            }
            values[field] = replacement
            envelope = signing.sign(
                events.create(**values), "security-event", self.fx.keys["serving"]
            )
            event = self.registry.verify(envelope, clock_ms=11105)

            def substitute(value):
                if isinstance(value, dict):
                    if (
                        "envelope" in value
                        and value["envelope"] == self.queue.document()["records"][0]["envelope"]
                    ):
                        value["envelope"] = envelope
                        if value.get("receipt") is not None:
                            receipt = self.registry.receipt(
                                value["receipt"], events.Event(canonical(original))
                            )
                            value["receipt"] = signing.sign(
                                events.delivered(
                                    event,
                                    self.registry.sha256,
                                    ingested_at_ms=receipt["ingested_at_ms"],
                                    routed_at_ms=receipt["routed_at_ms"],
                                    late=receipt["late"],
                                ),
                                "security-event-receipt",
                                self.fx.keys["receipt"],
                            )
                    else:
                        for child in value.values():
                            substitute(child)
                elif isinstance(value, list):
                    for child in value:
                        substitute(child)

            substitute(changed)
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.replay(changed)

    def test_unknown_lifecycle_missing_snapshot_and_boolean_exit_never_reach_retention(self):
        for change in ("missing", "phase", "exit", "outage", "capture"):
            packet = copy.deepcopy(self.packet)
            if change == "missing":
                del packet["snapshots"]["failed-startup"]
            elif change == "phase":
                packet["cleanup"]["http_exits"][1]["phase"] = "recovered"
            elif change == "exit":
                packet["cleanup"]["http_exits"][0]["exit_code"] = False
            elif change == "outage":
                packet["cleanup"]["outage_port_closed"] = False
            else:
                packet["snapshots"]["outage"]["captured_at_ms"] = 11000
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.replay(packet)


if __name__ == "__main__":
    unittest.main()
