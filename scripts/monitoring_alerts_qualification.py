"""Real producer/sink signatures and delivery ordering, without a network service."""

import copy
import tempfile
import unittest
from pathlib import Path

from mlsecops import monitoring_alerts, signing
from mlsecops.contracts import Rejected, canonical, digest


class AlertContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.producer, self.sink_key = self.root / "producer.pem", self.root / "sink.pem"
        self.producer_public = signing.create_key(self.producer)
        self.sink_public = signing.create_key(self.sink_key)
        self.sink = monitoring_alerts.Sink(
            self.producer_public, self.sink_key, reference_sha256="a" * 64, epoch="b" * 32
        )

    def event(self, sequence=1, kind="data_drift"):
        return monitoring_alerts.event(
            reference_sha256="a" * 64,
            window_sha256="c" * 64,
            evidence_sha256="d" * 64,
            epoch="b" * 32,
            sequence=sequence,
            kind=kind,
            admitted_at_ms=1000,
        )

    def send(self, event=None, clock=2000):
        return self.sink.accept(
            signing.sign(event or self.event(), "monitor-alert", self.producer), clock_ms=clock
        )

    def test_real_delivery_receipt_is_bound_and_duplicate_preserves_original_time(self):
        event = self.event()
        first = self.send(event)
        self.assertEqual(self.send(event, clock=3000), first)
        receipt = monitoring_alerts.receipt(first, event, self.sink_public)
        self.assertEqual(receipt["received_at_ms"], 2000)
        self.assertEqual(receipt["event_sha256"], digest(canonical(event)))
        first["payload"] = "corrupted"
        self.assertEqual(
            monitoring_alerts.receipt(self.send(event), event, self.sink_public), receipt
        )

    def test_sequence_gap_conflict_and_replay_do_not_advance_sink(self):
        with self.assertRaisesRegex(Rejected, "monitor_alert_sequence"):
            self.send(self.event(2))
        self.send()
        with self.assertRaisesRegex(Rejected, "monitor_alert_conflict"):
            self.send(self.event(kind="prediction_drift"))
        self.assertEqual(
            monitoring_alerts.receipt(self.send(self.event(2)), self.event(2), self.sink_public)[
                "sequence"
            ],
            2,
        )

    def test_bounded_receipt_cache_does_not_reaccept_evicted_events(self):
        for sequence in range(1, 130):
            self.send(self.event(sequence))
        with self.assertRaisesRegex(Rejected, "monitor_alert_replay"):
            self.send()
        recent = self.event(129)
        self.assertEqual(
            monitoring_alerts.receipt(self.send(recent), recent, self.sink_public)["sequence"], 129
        )

    def test_wrong_producer_reference_epoch_kind_and_signature_are_rejected(self):
        envelope = signing.sign(self.event(), "monitor-alert", self.sink_key)
        with self.assertRaises(Rejected):
            self.sink.accept(envelope, clock_ms=2000)
        with self.assertRaises(Rejected):
            self.sink.accept(signing.sign(self.event(), "feedback", self.producer), clock_ms=2000)
        for key, value in (
            ("reference_sha256", "f" * 64),
            ("epoch", "f" * 32),
            ("kind", "promote"),
            ("window_sha256", "bad"),
            ("evidence_sha256", True),
            ("sequence", True),
            ("schema_version", True),
            ("extra", "private-canary"),
        ):
            payload = {**self.event(), key: value}
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.send(payload)
        signed = signing.sign(self.event(), "monitor-alert", self.producer)
        signed["payload"] = signing.encode64(canonical(self.event(2)))
        with self.assertRaises(Rejected):
            self.sink.accept(signed, clock_ms=2000)
        self.send()  # No invalid event consumed sequence1.

    def test_delivery_expiry_is_measured_from_admission_and_cannot_be_extended(self):
        for clock in (999, 121000, True):
            with self.subTest(clock=clock), self.assertRaises(Rejected):
                self.send(clock=clock)
        for issued, expires in ((1000, 121001), (1000, 1000), (True, 121000), (1000, True)):
            with self.subTest(times=(issued, expires)), self.assertRaises(Rejected):
                self.send({**self.event(), "admitted_at_ms": issued, "expires_at_ms": expires})
        self.send(clock=120999)

    def test_receipt_rejects_forgery_wrong_event_sequence_reference_and_clock(self):
        event = self.event()
        signed = self.send(event)
        data = signing.verify(signed, "monitor-alert-receipt", self.sink_public)
        for key, value in (
            ("event_sha256", "f" * 64),
            ("reference_sha256", "f" * 64),
            ("epoch", "f" * 32),
            ("sequence", 2),
            ("sequence", True),
            ("schema_version", True),
            ("received_at_ms", 999),
            ("received_at_ms", 121000),
            ("received_at_ms", True),
            ("extra", "private-canary"),
        ):
            tampered = signing.sign({**data, key: value}, "monitor-alert-receipt", self.sink_key)
            with self.subTest(key=key), self.assertRaises(Rejected):
                monitoring_alerts.receipt(tampered, event, self.sink_public)
        forged = signing.sign(data, "monitor-alert-receipt", self.producer)
        with self.assertRaises(Rejected):
            monitoring_alerts.receipt(forged, event, self.sink_public)
        self.assertEqual(event, self.event())

    def test_role_separation_and_configuration_bounds(self):
        for public, ref, epoch in (
            (self.sink_public, "a" * 64, "b" * 32),
            ("bad", "a" * 64, "b" * 32),
            (signing.encode64(b"short"), "a" * 64, "b" * 32),
            (self.producer_public, "bad", "b" * 32),
            (self.producer_public, "a" * 64, "bad"),
        ):
            with self.subTest(ref=ref), self.assertRaises(Rejected):
                monitoring_alerts.Sink(public, self.sink_key, reference_sha256=ref, epoch=epoch)
        for kind in monitoring_alerts.KINDS:
            self.assertEqual(self.event(kind=kind)["kind"], kind)
        payload = self.event()
        clone = copy.deepcopy(payload)
        self.send(payload)
        self.assertEqual(payload, clone)


if __name__ == "__main__":
    unittest.main()
