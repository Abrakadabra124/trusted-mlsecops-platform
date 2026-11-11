"""Producer counter, immutable retry and receiver receipt binding."""

import importlib
import unittest

from mlsecops import security_events as events
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, digest
from scripts import security_events_qualification as fixtures


class OutboxContracts(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("mlsecops.security_event_outbox"),
            "persistent producer outbox is not implemented",
        )
        self.module = importlib.import_module("mlsecops.security_event_outbox")
        self.fx = fixtures.EventContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.identity = digest(signing.decode64(self.fx.publics["controller"]))
        self.box = self.module.Outbox.empty(self.fx.registry, self.identity, clock_ms=2000)
        self.fields = dict(
            kind="artifact.rejected",
            reason="unsupported_format",
            correlation_id="c" * 32,
            asset_sha256="d" * 64,
            bundle_sha256=None,
        )

    def enqueue(self, **changes):
        return self.box.enqueue(
            ({**self.fields, **changes}, self.fx.keys["controller"]), clock_ms=2100
        )

    def receipt(self, record, *, ingested=2200):
        event = self.fx.registry.verify(record["envelope"], clock_ms=2100)
        value = events.delivered(
            event,
            self.fx.registry.sha256,
            ingested_at_ms=ingested,
            routed_at_ms=ingested + 1,
            late=False,
        )
        return signing.sign(value, "security-event-receipt", self.fx.keys["receipt"])

    def test_exact_retry_survives_reopen_without_new_sequence_or_time(self):
        original = self.enqueue()
        self.box = self.module.Outbox(self.fx.registry, self.identity, self.box.document())
        self.assertEqual(
            self.box.enqueue((self.fields, self.fx.keys["controller"]), clock_ms=400000), original
        )
        self.assertEqual(len(self.box.document()["records"]), 1)
        self.assertEqual(
            self.fx.registry.verify(original["envelope"], clock_ms=2100).document()["sequence"], 1
        )

    def test_receipt_uses_receiver_ingest_not_local_enqueue_and_retry_is_immutable(self):
        original = self.enqueue()
        receipt = self.receipt(original)
        result = self.box.acknowledge(receipt, clock_ms=2300)
        self.assertEqual(result["receipt"], receipt)
        self.assertEqual(result["queued_at_ms"], 2100)
        self.assertEqual(self.box.acknowledge(receipt, clock_ms=400000), result)
        before = self.box.document()
        with self.assertRaises(Rejected):
            self.box.acknowledge(self.receipt(original, ingested=2300), clock_ms=2400)
        self.assertEqual(before, self.box.document())

    def test_unknown_receipt_wrong_producer_role_and_correlated_conflict_are_atomic(self):
        original = self.enqueue()
        before = self.box.document()
        for fields, key in (
            ({**self.fields, "asset_sha256": "e" * 64}, self.fx.keys["controller"]),
            (self.fields, self.fx.keys["worker"]),
            ({**self.fields, "kind": "trust.revoked", "reason": "key"}, self.fx.keys["controller"]),
        ):
            with self.assertRaises(Rejected):
                self.box.enqueue((fields, key), clock_ms=2200)
            self.assertEqual(self.box.document(), before)
        bad = dict(
            self.receipt(original), signatures=[{"keyid": "0" * 64, "sig": "PRIVATE-CANARY"}]
        )
        with self.assertRaises(Rejected):
            self.box.acknowledge(bad, clock_ms=2300)
        self.assertEqual(self.box.document(), before)

    def test_pending_bound_preserves_old_retries_and_success_releases_one_slot(self):
        first = self.enqueue()
        for index in range(1, 16):
            self.enqueue(correlation_id=f"{index:032x}")
        with self.assertRaises(Rejected):
            self.enqueue(correlation_id="f" * 32)
        self.assertEqual(self.enqueue(), first)
        self.box.acknowledge(self.receipt(first), clock_ms=2300)
        new = self.box.enqueue(
            ({**self.fields, "correlation_id": "f" * 32}, self.fx.keys["controller"]), clock_ms=2400
        )
        self.assertEqual(
            self.fx.registry.verify(new["envelope"], clock_ms=2400).document()["sequence"], 17
        )

    def test_cross_producer_state_and_corrupt_record_are_rejected(self):
        self.enqueue()
        document = self.box.document()
        with self.assertRaises(Rejected):
            self.module.Outbox(
                self.fx.registry, digest(signing.decode64(self.fx.publics["intake"])), document
            )
        document["records"][0]["queued_at_ms"] = 1001
        with self.assertRaises(Rejected):
            self.module.Outbox(self.fx.registry, self.identity, document)
        self.assertNotIn(b"PRIVATE-CANARY", canonical(self.box.document()))


if __name__ == "__main__":
    unittest.main()
