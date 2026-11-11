"""Signed delivery, pending recovery and bounded loopback transport."""

import importlib
import unittest
from unittest.mock import Mock

from mlsecops import security_event_ledger as ledger
from mlsecops import security_events as events
from mlsecops import signing
from mlsecops.contracts import Rejected
from scripts import security_event_outbox_qualification as fixtures


class DeliveryContracts(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("mlsecops.security_event_delivery"),
            "producer delivery not implemented",
        )
        self.module = importlib.import_module("mlsecops.security_event_delivery")
        self.fx = fixtures.OutboxContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.box = self.fx.box
        self.box.snapshot = self.box.document
        self.book = ledger.Ledger.empty(self.fx.fx.registry, clock_ms=2000)
        self.clock = 2100
        self.client = Mock()

        def deliver(envelope):
            record = self.book.ingest(envelope, clock_ms=2200)
            event = self.fx.fx.registry.verify(
                record["envelope"], clock_ms=record["ingested_at_ms"]
            )
            value = events.delivered(
                event,
                self.fx.fx.registry.sha256,
                ingested_at_ms=record["ingested_at_ms"],
                routed_at_ms=2201,
                late=False,
            )
            return signing.sign(value, "security-event-receipt", self.fx.fx.keys["receipt"])

        self.client.send.side_effect = deliver
        self.emitter = self.module.Emitter(
            self.box, self.fx.fx.keys["controller"], self.client, clock=lambda: self.clock
        )

    def test_signed_receipt_settles_once_and_retry_retains_original_event(self):
        receipt = self.emitter.emit(self.fx.fields)
        self.assertEqual(receipt, self.box.document()["records"][0]["receipt"])
        self.assertEqual(self.emitter.emit(self.fx.fields), receipt)
        self.client.send.assert_called_once()

    def test_unknown_network_outcome_keeps_signed_envelope_for_retry(self):
        original = self.client.send.side_effect

        def lost(envelope):
            original(envelope)
            raise OSError("PRIVATE-CANARY")

        self.client.send.side_effect = lost
        with self.assertRaisesRegex(Rejected, "^security_delivery_unconfirmed$"):
            self.emitter.emit(self.fx.fields)
        pending = self.box.document()["records"][0]
        self.assertIsNone(pending["receipt"])
        self.client.send.side_effect = original
        result = self.emitter.emit(self.fx.fields)
        self.assertIsNotNone(result)
        self.assertEqual(len(self.book.document()["records"]), 1)
        self.assertEqual(self.box.document()["records"][0]["envelope"], pending["envelope"])

    def test_forged_receipt_never_settles_and_missing_key_never_enqueues(self):
        self.client.send.side_effect = None
        self.client.send.return_value = {"private": "PRIVATE-CANARY"}
        with self.assertRaises(Rejected):
            self.emitter.emit(self.fx.fields)
        self.assertIsNone(self.box.document()["records"][0]["receipt"])
        with self.assertRaises(Rejected):
            self.module.Emitter(self.box, self.fx.fx.keys["intake"], self.client)

    def test_clock_regression_refuses_before_network_and_state_mutation(self):
        self.emitter.emit(self.fx.fields)
        self.clock = 1000
        before = self.box.document()
        with self.assertRaises(Rejected):
            self.emitter.emit(self.fx.fields)
        self.assertEqual(self.box.document(), before)
        self.client.send.assert_called_once()

    def test_retry_skips_acked_records_and_rejects_regressed_clock(self):
        self.emitter.emit(self.fx.fields)
        self.assertEqual(self.emitter.retry(), 0)
        self.clock = 2000
        with self.assertRaisesRegex(Rejected, "security_outbox_clock"):
            self.emitter.retry()
        self.client.send.assert_called_once()

    def test_receipt_for_another_pending_event_cannot_settle_the_current_send(self):
        self.box.enqueue((self.fx.fields, self.fx.fx.keys["controller"]), clock_ms=2100)
        other = self.box.enqueue(
            ({**self.fx.fields, "correlation_id": "e" * 32}, self.fx.fx.keys["controller"]),
            clock_ms=2100,
        )
        wrong = self.client.send.side_effect(other["envelope"])
        self.client.send.side_effect = None
        self.client.send.return_value = wrong
        before = self.box.document()
        with self.assertRaises(Rejected):
            self.emitter.retry()
        self.assertEqual(self.box.document(), before)


if __name__ == "__main__":
    unittest.main()
