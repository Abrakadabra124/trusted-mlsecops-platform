"""Pure signed-packet negatives. Never start the native campaign locally."""

import copy
import importlib
import importlib.util
import unittest
from unittest.mock import patch

from mlsecops import security_event_ledger as ledger
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, digest
from scripts import security_events_qualification as fixtures

SOURCE = "a" * 40
FINGERPRINT = "b" * 64


class SequencePacketContracts(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.find_spec("scripts.security_event_sequence_native")
        self.assertIsNotNone(spec, "sequence campaign/verifier is not implemented")
        self.module = importlib.import_module("scripts.security_event_sequence_native")
        self.fx = fixtures.EventContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        for producer in self.fx.document["producers"]:
            producer["heartbeat_required"] = producer["role"] == "intake"
        self.registry = self.fx.registry_for()

    @staticmethod
    def window(t):
        return dict(
            started_ns=t * 1000000, finished_ns=(t + 1) * 1000000, started_ms=t, finished_ms=t + 1
        )

    def mode(self, mode):
        book = ledger.Ledger.empty(self.registry, clock_ms=2000)
        producer = digest(signing.decode64(self.fx.publics["intake"]))
        heartbeats, requests = [], []

        def heartbeat(t, head):
            value = self.fx.heartbeat(
                sequence=len(heartbeats) + 1,
                producer_id=producer,
                observed_at_ms=t,
                last_event_sequence=head,
            )
            envelope = signing.sign(value, "security-heartbeat", self.fx.keys["intake"])
            record = book.heartbeat(envelope, clock_ms=t)
            heartbeats.append(dict(**self.window(t), envelope=envelope, record=record))

        def envelope(n):
            return signing.sign(self.fx.event(sequence=n), "security-event", self.fx.keys["intake"])

        def deliver(name, message, t):
            record = book.admit(message, clock_ms=t)
            identity = self.registry.verify(message, clock_ms=record["ingested_at_ms"]).document()[
                "event_id"
            ]
            response = book.route((identity, self.fx.keys["receipt"]), clock_ms=t)["receipt"]
            requests.append(
                dict(**self.window(t), name=name, envelope=message, status=200, response=response)
            )

        def capture(t):
            report = book.poll(clock_ms=t)
            return dict(
                **self.window(t),
                state=book.document(),
                health={**report, "collector_available": True},
                health_status=200 if report["healthy"] else 503,
                incidents=[r for r in book.document()["records"] if r["receipt"] is not None],
            )

        heartbeat(2000, 0)
        deliver("first", envelope(1), 2100)
        held = envelope(2)
        head = 3 if mode == "ingest-hole" else 2
        if mode == "ingest-hole":
            deliver("opening", envelope(3), 2200)
            heartbeat(2201, head)
        else:
            heartbeat(2200, head)
        captures = {"opened": capture(2300)}
        book = ledger.Ledger(self.registry, book.document())
        captures["restarted"] = capture(3200)
        for t in (32000, 62000, 92000):
            heartbeat(t, head)
        problem = book.poll(clock_ms=92200)["problems"][0]
        notice = book.notice((problem["notice_id"], self.fx.keys["collector"]), clock_ms=92200)
        identity = self.registry.verify(notice["envelope"], clock_ms=92200).document()["event_id"]
        book.route((identity, self.fx.keys["receipt"]), clock_ms=92201)
        captures["noticed"] = capture(92300)
        deliver("healing", held, 92400)
        captures["healed"] = capture(92500)
        deliver("duplicate", held, 92600)
        forged = signing.sign(self.fx.event(sequence=2), "security-event", self.fx.keys["serving"])
        requests.append(
            dict(
                **self.window(92700),
                name="forged",
                envelope=forged,
                status=503,
                response={"status": "unavailable"},
            )
        )
        book = ledger.Ledger(self.registry, book.document())
        captures["final"] = capture(92800)
        return dict(
            mode=mode,
            registry=signing.sign(self.fx.document, "security-event-config", self.fx.keys["root"]),
            registry_root=self.fx.publics["root"],
            registry_sha256=self.registry.sha256,
            producer=producer,
            held_envelope=held,
            heartbeats=heartbeats,
            requests=requests,
            captures=captures,
            restarts=[
                dict(before_pid=101, after_pid=102, exit_code=0),
                dict(before_pid=102, after_pid=103, exit_code=-15),
            ],
            cleanup=dict(process_reaped=True, port_closed=True, directory_removed=True),
        )

    def packet(self):
        return dict(
            schema_version=1,
            source=SOURCE,
            fingerprint=FINGERPRINT,
            source_after=SOURCE,
            fingerprint_after=FINGERPRINT,
            source_clean=True,
            modes=[self.mode("ingest-hole"), self.mode("heartbeat-head-only")],
        )

    def verify(self, packet):
        return self.module.verify(packet, expected_source=SOURCE, expected_fingerprint=FINGERPRINT)

    def test_positive_replay_has_two_measured_modes_and_no_private_projection(self):
        packet = self.packet()
        original = copy.deepcopy(packet)
        result = self.verify(packet)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(len(result["cases"]), 25)
        self.assertEqual(result["primary_sha256"], digest(canonical(packet)))
        self.assertEqual(result["timings"]["ingest-hole"]["notice_seconds"], 90.101)
        self.assertEqual(result["timings"]["heartbeat-head-only"]["notice_seconds"], 90.101)
        self.assertFalse(result["release_ready"])
        self.assertEqual(packet, original)
        raw = canonical(result)
        for forbidden in (b'"envelope"', b'"payload"', b'"registry_root"', b'"producer"'):
            self.assertNotIn(forbidden, raw)

    def test_source_fingerprint_cleanup_and_mode_inventory_cannot_be_faked_by_status(self):
        packet = self.packet()
        variants = []
        for key, value in (
            ("source", "c" * 40),
            ("fingerprint", "c" * 64),
            ("source_after", "c" * 40),
            ("source_clean", False),
            ("schema_version", True),
            ("status", "pass"),
        ):
            variants.append({**packet, key: value})
        variants.extend(
            (
                {**packet, "modes": packet["modes"][:1]},
                {**packet, "modes": [packet["modes"][0]] * 2},
            )
        )
        broken = copy.deepcopy(packet)
        broken["modes"][0]["cleanup"]["port_closed"] = False
        variants.append(broken)
        for value in variants:
            with self.subTest(keys=list(value)), self.assertRaises(Rejected):
                self.verify(value)

    def test_notice_requires_valid_signature_receipt_reason_and_episode_identity(self):
        packet = self.packet()
        for change in ("signature", "receipt", "reason", "episode"):
            value = copy.deepcopy(packet)
            sample = value["modes"][0]["captures"]["noticed"]
            record = sample["state"]["records"][-1]
            if change == "signature":
                record["envelope"]["signatures"][0]["sig"] = signing.encode64(b"x" * 64)
            elif change == "receipt":
                record["receipt"] = None
            else:
                event = self.registry.verify(
                    record["envelope"], clock_ms=record["ingested_at_ms"]
                ).document()
                from mlsecops import security_events as events

                fields = {
                    k: event[k]
                    for k in (
                        "kind",
                        "producer_id",
                        "epoch",
                        "sequence",
                        "occurred_at_ms",
                        "observed_at_ms",
                        "correlation_id",
                        "asset_sha256",
                        "bundle_sha256",
                        "policy_sha256",
                        "reason",
                    )
                }
                fields["reason" if change == "reason" else "asset_sha256"] = (
                    "heartbeat" if change == "reason" else "f" * 64
                )
                event = events.Event(canonical(events.create(**fields)))
                record["envelope"] = signing.sign(
                    event.document(), "security-event", self.fx.keys["collector"]
                )
                receipt = events.delivered(
                    event,
                    self.registry.sha256,
                    ingested_at_ms=92200,
                    routed_at_ms=92201,
                    late=False,
                )
                record["receipt"] = signing.sign(
                    receipt, "security-event-receipt", self.fx.keys["receipt"]
                )
                sample["incidents"][-1] = copy.deepcopy(record)
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.verify(value)

    def test_real_elapsed_and_clock_consistency_are_required(self):
        packet = self.packet()
        for phase, key, delta in (
            ("noticed", "finished_ns", 31000000000),
            ("noticed", "finished_ms", -90000),
            ("restarted", "started_ns", -10000000000),
        ):
            value = copy.deepcopy(packet)
            value["modes"][0]["captures"][phase][key] += delta
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.verify(value)

    def test_health_503_alone_or_another_producer_does_not_prove_sequence_gap(self):
        packet = self.packet()
        for field, value in (
            ("problems", []),
            ("open_sequence_gaps", 0),
            ("expired_heartbeats", 1),
            ("collector_available", False),
        ):
            broken = copy.deepcopy(packet)
            broken["modes"][0]["captures"]["noticed"]["health"][field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.verify(broken)
        packet["modes"][0]["producer"] = digest(signing.decode64(self.fx.publics["serving"]))
        with self.assertRaises(Rejected):
            self.verify(packet)

    def test_restart_reset_late_tamper_and_forged_success_are_rejected(self):
        packet = self.packet()
        for change in ("reset", "late", "forged", "duplicate", "restart"):
            broken = copy.deepcopy(packet)
            mode = broken["modes"][0]
            if change == "reset":
                for s in mode["captures"]["restarted"]["state"]["telemetry"]["streams"]:
                    if s["producer_id"] == mode["producer"]:
                        s["sequence_gap_since_ms"] += 100
            elif change == "late":
                mode["captures"]["healed"]["state"]["records"][-1]["late"] = False
            elif change == "forged":
                mode["requests"][-1]["status"] = 200
            elif change == "duplicate":
                mode["requests"][-2]["response"] = mode["requests"][0]["response"]
            else:
                mode["restarts"][0]["after_pid"] = 101
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.verify(broken)

    def test_missing_periodic_heartbeats_and_head_only_relabel_are_rejected(self):
        packet = self.packet()
        broken = copy.deepcopy(packet)
        broken["modes"][0]["heartbeats"] = broken["modes"][0]["heartbeats"][:2]
        with self.assertRaises(Rejected):
            self.verify(broken)
        packet["modes"].reverse()
        with self.assertRaises(Rejected):
            self.verify(packet)

    def test_non_hosted_qualify_refuses_before_fixture_or_packet_write(self):
        with patch.object(self.module.sys, "platform", "win32"):
            with self.assertRaisesRegex(Rejected, "sequence_hosted_required"):
                self.module.qualify()

    def test_retry_and_forgery_observations_must_follow_healing_and_precede_final_readback(self):
        for name in ("duplicate", "forged"):
            packet = self.packet()
            request = next(r for r in packet["modes"][0]["requests"] if r["name"] == name)
            request.update(self.window(5000))
            with self.subTest(name=name), self.assertRaises(Rejected):
                self.verify(packet)

    def test_heartbeat_wire_windows_cannot_overlap_or_precede_previous_delivery(self):
        packet = self.packet()
        item = packet["modes"][0]["heartbeats"][2]
        item["started_ms"] = 2000
        item["started_ns"] = 2000000000
        with self.assertRaises(Rejected):
            self.verify(packet)

    def test_unknown_fields_and_nonfinite_observations_have_finite_rejection(self):
        packet = self.packet()
        for alteration in (None, [], {**packet, "private": "PRIVATE-CANARY"}):
            with (
                self.subTest(kind=type(alteration).__name__),
                self.assertRaisesRegex(Rejected, "^sequence_packet_invalid$"),
            ):
                self.verify(alteration)
        packet["modes"][0]["captures"]["noticed"]["finished_ns"] = float("nan")
        with self.assertRaisesRegex(Rejected, "^sequence_packet_invalid$"):
            self.verify(packet)

    def test_capture_reads_all_incident_pages_and_rejects_pagination_cycle(self):
        from types import SimpleNamespace

        sample = self.mode("ingest-hole")["captures"]["healed"]
        rows = sample["incidents"]

        class InMemoryHTTP:
            cycle = False

            def exchange(self, method, path):
                if path == "/health":
                    return 200, sample["health"]
                offset = int(path.rsplit("/", 1)[1])
                return 200, dict(
                    incidents=rows[offset : offset + 2],
                    next_offset=0 if self.cycle else (2 if offset == 0 else None),
                    release_ready=False,
                )

        wire = InMemoryHTTP()
        store = SimpleNamespace(snapshot=lambda: sample["state"])
        result = self.module._capture(wire, store)
        self.assertEqual(result["incidents"], rows)
        wire.cycle = True
        with self.assertRaises(Rejected):
            self.module._capture(wire, store)

    def test_finite_failure_does_not_echo_exception_or_claim_cleanup(self):
        result = self.module.failure_report(RuntimeError("PRIVATE-CANARY"))
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["cases"], [])
        self.assertFalse(result["release_ready"])
        self.assertNotIn(b"PRIVATE-CANARY", canonical(result))

    def test_retained_packet_matches_public_hash_and_replays_after_private_fixture_removal(self):
        self.assertTrue(hasattr(self.module, "retain_packet"), "private retention helper missing")
        packet = self.packet()
        path = self.fx.directory / "packet.json"
        public = self.module.retain_packet(
            packet, path, expected_source=SOURCE, expected_fingerprint=FINGERPRINT
        )
        retained = path.read_bytes()
        self.assertEqual(retained, canonical(packet))
        self.assertEqual(digest(retained), public["primary_sha256"])
        self.fx.doCleanups()
        from mlsecops.contracts import decode

        self.assertEqual(self.verify(decode(retained)), public)

    def test_invalid_packet_never_overwrites_and_readback_failure_never_returns_pass(self):
        self.assertTrue(hasattr(self.module, "retain_packet"), "private retention helper missing")
        packet = self.packet()
        path = self.fx.directory / "packet.json"
        path.write_bytes(b"previous-private-packet")
        broken = {**packet, "source_clean": False}
        with self.assertRaises(Rejected):
            self.module.retain_packet(
                broken, path, expected_source=SOURCE, expected_fingerprint=FINGERPRINT
            )
        self.assertEqual(path.read_bytes(), b"previous-private-packet")
        with patch.object(self.module, "bounded_read", return_value=b"{}"):
            with self.assertRaises(Rejected):
                self.module.retain_packet(
                    packet, path, expected_source=SOURCE, expected_fingerprint=FINGERPRINT
                )


if __name__ == "__main__":
    unittest.main()
