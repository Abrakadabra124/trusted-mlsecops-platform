"""Durable fixed-route receipts and idempotent collector-generated notices."""

import sys
import unittest
from unittest.mock import patch

from mlsecops import security_event_ledger as ledger
from mlsecops import security_event_store as storage
from mlsecops.contracts import Rejected, canonical
from scripts import security_event_health_qualification as fixtures


class RouteContracts(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.HealthContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.book = self.fx.book
        self.keys = self.fx.fx.fixture.keys

    def test_routes_commit_signed_receipt_and_retry_returns_original(self):
        record = self.book.ingest(self.fx.fx.envelope(), clock_ms=2100)
        event = self.fx.registry.verify(record["envelope"], clock_ms=2100)
        event_id = event.document()["event_id"]
        routed = self.book.route((event_id, self.keys["receipt"]), clock_ms=2200)
        receipt = self.fx.registry.receipt(routed["receipt"], event)
        self.assertEqual(receipt["route"], "security.artifacts")
        self.assertEqual(receipt["ingested_at_ms"], 2100)
        self.assertEqual(receipt["routed_at_ms"], 2200)
        self.assertFalse(receipt["release_ready"])
        restored = ledger.Ledger(self.fx.registry, self.book.document())
        self.assertEqual(restored.route((event_id, self.keys["receipt"]), clock_ms=400000), routed)
        self.assertEqual(restored.document(), self.book.document())

    def test_wrong_receipt_key_unknown_event_or_late_delivery_cannot_acknowledge(self):
        record = self.book.ingest(self.fx.fx.envelope(), clock_ms=2100)
        event_id = self.fx.registry.verify(record["envelope"], clock_ms=2100).document()["event_id"]
        original = self.book.document()
        for identity, key, clock in (
            (event_id, self.keys["intake"], 2200),
            ("f" * 64, self.keys["receipt"], 2200),
            (event_id, self.keys["receipt"], 62101),
        ):
            with self.subTest(clock=clock), self.assertRaises(Rejected):
                self.book.route((identity, key), clock_ms=clock)
            self.assertEqual(self.book.document(), original)

    def test_gap_notice_is_signed_once_per_episode_and_survives_reopen(self):
        problem = self.book.poll(clock_ms=92000)["problems"][0]
        original = self.book.notice((problem["notice_id"], self.keys["collector"]), clock_ms=92001)
        event = self.fx.registry.verify(original["envelope"], clock_ms=92001)
        value = event.document()
        self.assertEqual((value["kind"], value["reason"]), ("telemetry.gap", "heartbeat"))
        self.assertEqual(value["asset_sha256"], problem["notice_id"])
        self.assertEqual(value["correlation_id"], problem["notice_id"][:32])
        reopened = ledger.Ledger(self.fx.registry, self.book.document())
        self.assertEqual(
            reopened.notice((problem["notice_id"], self.keys["collector"]), clock_ms=93000),
            original,
        )
        self.assertEqual(len(reopened.document()["records"]), 1)
        routed = reopened.route((value["event_id"], self.keys["receipt"]), clock_ms=93001)
        self.assertIsNotNone(routed["receipt"])
        self.assertEqual(
            reopened.notice((problem["notice_id"], self.keys["collector"]), clock_ms=94000), routed
        )

    def test_forged_notice_identity_or_wrong_role_does_not_create_an_event(self):
        problem = self.book.poll(clock_ms=92000)["problems"][0]
        before = canonical(self.book.document())
        for identity, key in (
            ("f" * 64, self.keys["collector"]),
            (problem["notice_id"], self.keys["serving"]),
            (problem["notice_id"], self.keys["worker"]),
        ):
            with self.subTest(identity=identity), self.assertRaises(Rejected):
                self.book.notice((identity, key), clock_ms=92001)
            self.assertEqual(canonical(self.book.document()), before)

    def test_external_admission_rejects_new_backlog_but_preserves_exact_retry(self):
        for sequence in range(1, ledger.MAX_PENDING + 1):
            self.book.admit(self.fx.fx.envelope(sequence), clock_ms=2100 + sequence)
        before = self.book.document()
        with self.assertRaises(Rejected):
            self.book.admit(self.fx.fx.envelope(ledger.MAX_PENDING + 1), clock_ms=2500)
        self.assertEqual(self.book.document(), before)
        self.assertEqual(
            self.book.admit(self.fx.fx.envelope(), clock_ms=2600), before["records"][0]
        )

    def test_healed_episode_retries_original_and_new_episode_gets_new_identity(self):
        problem = self.book.poll(clock_ms=92000)["problems"][0]
        first = self.book.notice((problem["notice_id"], self.keys["collector"]), clock_ms=92001)
        self.book.heartbeat(self.fx.heartbeat(observed=93000), clock_ms=93000)
        self.assertEqual(self.book.poll(clock_ms=93001)["problems"], [])
        self.assertEqual(
            self.book.notice((problem["notice_id"], self.keys["collector"]), clock_ms=93002),
            first,
        )
        later = self.book.poll(clock_ms=183000)["problems"][0]
        self.assertNotEqual(later["notice_id"], problem["notice_id"])
        second = self.book.notice((later["notice_id"], self.keys["collector"]), clock_ms=183001)
        self.assertEqual(ledger.candidate(second["envelope"]).document()["sequence"], 2)


@unittest.skipUnless(sys.platform == "linux", "Linux private directory handles required")
class DurableRoutes(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.HealthContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.keys = self.fx.fx.fixture.keys
        self.root = self.fx.fx.fixture.directory / "route-journal"
        self.pin = storage.initialize(str(self.root), self.fx.registry, clock_ms=2000)

    def reopen(self):
        return storage.Store(str(self.root), self.pin, self.fx.registry)

    def test_commit_readback_and_reopen_preserve_original_route(self):
        store = self.reopen()
        record = store.admit(self.fx.fx.envelope(), clock_ms=2100)
        identity = ledger.candidate(record["envelope"]).document()["event_id"]
        routed = store.route((identity, self.keys["receipt"]), clock_ms=2200)
        self.assertEqual(self.reopen().snapshot()["records"], [routed])
        self.assertEqual(
            self.reopen().route((identity, self.keys["receipt"]), clock_ms=400000), routed
        )

    def test_notice_and_receipt_unknown_outcomes_retry_without_duplicate(self):
        store = self.reopen()
        problem = store.poll(clock_ms=92000)["problems"][0]
        replace = storage.os.replace

        def renamed_then_failed(*args, **kwargs):
            replace(*args, **kwargs)
            raise OSError("simulated committed write with unknown outcome")

        with patch.object(storage.os, "replace", side_effect=renamed_then_failed):
            with self.assertRaises(Rejected):
                store.notice((problem["notice_id"], self.keys["collector"]), clock_ms=92001)
        record = self.reopen().notice(
            (problem["notice_id"], self.keys["collector"]), clock_ms=92002
        )
        identity = ledger.candidate(record["envelope"]).document()["event_id"]
        with patch.object(storage.os, "replace", side_effect=renamed_then_failed):
            with self.assertRaises(Rejected):
                store.route((identity, self.keys["receipt"]), clock_ms=92003)
        routed = self.reopen().route((identity, self.keys["receipt"]), clock_ms=92004)
        receipt = self.fx.registry.receipt(routed["receipt"], ledger.candidate(record["envelope"]))
        self.assertEqual(receipt["routed_at_ms"], 92003)
        self.assertEqual(self.reopen().snapshot()["records"], [routed])

    def test_precommit_failure_cannot_return_route_or_lose_pending_event(self):
        store = self.reopen()
        record = store.admit(self.fx.fx.envelope(), clock_ms=2100)
        identity = ledger.candidate(record["envelope"]).document()["event_id"]
        with patch.object(storage.os, "replace", side_effect=OSError("simulated write failure")):
            with self.assertRaises(Rejected):
                store.route((identity, self.keys["receipt"]), clock_ms=2200)
        self.assertEqual(self.reopen().snapshot()["records"], [record])
        self.assertIsNotNone(
            self.reopen().route((identity, self.keys["receipt"]), clock_ms=2300)["receipt"]
        )


if __name__ == "__main__":
    unittest.main()
