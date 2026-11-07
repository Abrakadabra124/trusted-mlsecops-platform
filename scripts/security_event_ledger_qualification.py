"""Persisted-event transitions; signatures are real, clocks are controlled."""

import copy
import unittest

from mlsecops import security_event_ledger as ledger
from mlsecops import security_events as events
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical
from scripts import security_events_qualification as fixtures


class LedgerContracts(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.EventContracts("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.registry = self.fixture.registry
        self.book = ledger.Ledger.empty(self.registry, clock_ms=2000)

    def envelope(self, sequence=1, **changes):
        return signing.sign(
            self.fixture.event(sequence=sequence, **changes),
            "security-event",
            self.fixture.keys["intake"],
        )

    def receipt(self, record, **changes):
        event = self.registry.verify(record["envelope"], clock_ms=record["ingested_at_ms"])
        value = events.delivered(
            event,
            self.registry.sha256,
            ingested_at_ms=record["ingested_at_ms"],
            routed_at_ms=record["ingested_at_ms"] + 100,
            late=record["late"],
        )
        value.update(changes)
        return signing.sign(value, "security-event-receipt", self.fixture.keys["receipt"])

    def test_ingestion_remains_pending_and_exact_retry_is_immutable(self):
        envelope = self.envelope()
        record = self.book.ingest(envelope, clock_ms=2100)
        self.assertIsNone(record["receipt"])
        before = self.book.document()
        self.assertEqual(self.book.ingest(envelope, clock_ms=2200), record)
        self.assertEqual(self.book.document(), before)
        envelope["payload"] = "modified"
        record["late"] = True
        self.assertEqual(self.book.document(), before)
        self.assertEqual(len(self.book.pending()), 1)

    def test_conflicting_sequence_and_forged_retries_preserve_state(self):
        original = self.envelope()
        self.book.ingest(original, clock_ms=2100)
        before = self.book.document()
        altered = self.envelope(asset_sha256="f" * 64)
        forged = copy.deepcopy(original)
        forged["signatures"][0]["sig"] = signing.encode64(b"x" * 64)
        for value in (altered, forged, {}, None):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(Rejected):
                self.book.ingest(value, clock_ms=2200)
            self.assertEqual(self.book.document(), before)

    def test_late_and_missing_sequence_are_retained_without_inventing_delivery(self):
        records = [
            self.book.ingest(self.envelope(n), clock_ms=2100 + i) for i, n in enumerate((1, 3, 2))
        ]
        self.assertEqual([v["late"] for v in records], [False, False, True])
        recovered = ledger.Ledger(self.registry, self.book.document())
        self.assertEqual(len(recovered.pending()), 3)
        self.assertEqual(recovered.ingest(self.envelope(2), clock_ms=2400), records[2])

    def test_sequence_window_and_storage_capacity_fail_without_eviction(self):
        with self.assertRaises(Rejected):
            self.book.ingest(self.envelope(ledger.REORDER_WINDOW + 1), clock_ms=2100)
        # Build a genuinely full bounded journal; do not lower the production cap.
        for sequence in range(1, ledger.MAX_RECORDS + 1):
            self.book.ingest(self.envelope(sequence), clock_ms=2100 + sequence)
        before = self.book.document()
        with self.assertRaises(Rejected):
            self.book.ingest(self.envelope(ledger.MAX_RECORDS + 1), clock_ms=5000)
        self.assertEqual(self.book.document(), before)
        self.assertEqual(self.book.ingest(self.envelope(1), clock_ms=5000), before["records"][0])
        state = self.book.poll(clock_ms=6000)
        self.assertTrue(state["storage_full"])
        self.assertEqual(state["pending_deliveries"], ledger.MAX_RECORDS)
        self.assertFalse(state["healthy"])

    def test_historical_retry_after_age_limit_uses_original_verified_admission(self):
        envelope = self.envelope()
        record = self.book.ingest(envelope, clock_ms=2100)
        restored = ledger.Ledger(self.registry, self.book.document())
        self.assertEqual(restored.ingest(envelope, clock_ms=400000), record)
        with self.assertRaises(Rejected):
            restored.ingest(self.envelope(2), clock_ms=400000)
        with self.assertRaises(Rejected):
            restored.ingest(envelope, clock_ms=self.registry.expires_at_ms)

    def test_acknowledgement_binds_original_ingest_late_route_and_receipt(self):
        record = self.book.ingest(self.envelope(), clock_ms=2100)
        envelope = self.receipt(record)
        result = self.book.acknowledge(envelope, clock_ms=2300)
        self.assertEqual(result["receipt"], envelope)
        self.assertEqual(self.book.pending(), [])
        before = self.book.document()
        self.assertEqual(self.book.acknowledge(envelope, clock_ms=2500), result)
        self.assertEqual(self.book.document(), before)
        self.assertEqual(ledger.Ledger(self.registry, before).pending(), [])

    def test_wrong_or_conflicting_receipt_and_unknown_event_do_not_commit(self):
        record = self.book.ingest(self.envelope(), clock_ms=2100)
        before = self.book.document()
        for changes in (
            {"ingested_at_ms": 2101},
            {"late": True},
            {"event_id": "f" * 64},
            {"route": "security.trust"},
            {"routed_at_ms": 2500},
        ):
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                self.book.acknowledge(self.receipt(record, **changes), clock_ms=2300)
            self.assertEqual(self.book.document(), before)
        self.book.acknowledge(self.receipt(record), clock_ms=2300)
        before = self.book.document()
        with self.assertRaises(Rejected):
            self.book.acknowledge(self.receipt(record, routed_at_ms=2201), clock_ms=2400)
        self.assertEqual(self.book.document(), before)

    def test_recovery_revalidates_signatures_schema_order_and_config(self):
        self.book.ingest(self.envelope(), clock_ms=2100)
        baseline = self.book.document()
        variants = [
            None,
            {},
            {**baseline, "config_sha256": "f" * 64},
            {**baseline, "updated_at_ms": 2099},
            {**baseline, "records": {}},
            {**baseline, "records": baseline["records"] * (ledger.MAX_RECORDS + 1)},
        ]
        for field, value in (
            ("late", True),
            ("ingested_at_ms", True),
            ("receipt", {}),
            ("envelope", {}),
            ("extra", "PRIVATE-CANARY"),
        ):
            changed = copy.deepcopy(baseline)
            changed["records"][0][field] = value
            variants.append(changed)
        duplicated = copy.deepcopy(baseline)
        duplicated["records"].append(copy.deepcopy(duplicated["records"][0]))
        variants.append(duplicated)
        for value in variants:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(Rejected):
                ledger.Ledger(self.registry, value)
        recovered = ledger.Ledger(self.registry, baseline)
        baseline["records"].clear()
        self.assertEqual(len(recovered.pending()), 1)

    def test_backward_clock_and_expired_config_do_not_advance_state(self):
        self.book.ingest(self.envelope(), clock_ms=2100)
        before = canonical(self.book.document())
        for clock in (2099, True, 1000000):
            with self.subTest(clock=clock), self.assertRaises(Rejected):
                self.book.ingest(self.envelope(2), clock_ms=clock)
            self.assertEqual(canonical(self.book.document()), before)


if __name__ == "__main__":
    unittest.main()
