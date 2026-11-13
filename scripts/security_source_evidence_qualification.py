"""Pure signed primary replay; no native services or source-decision claims."""

import copy
import importlib
import importlib.util
import unittest

from mlsecops import security_event_ledger as ledger
from mlsecops import security_event_outbox as outbox
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, digest
from scripts import security_events_qualification as fixtures


class PrimaryEvidence(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.EventContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.producer = outbox.key_identity(self.fx.keys["intake"])
        self.queue = outbox.Outbox.empty(self.fx.registry, self.producer, clock_ms=2000)
        self.book = ledger.Ledger.empty(self.fx.registry, clock_ms=2000)
        self.fields = dict(
            kind="artifact.rejected",
            reason="integrity",
            correlation_id="c" * 32,
            asset_sha256="d" * 64,
            bundle_sha256=None,
        )
        queued = self.queue.enqueue((self.fields, self.fx.keys["intake"]), clock_ms=2000)
        event = self.fx.registry.verify(queued["envelope"], clock_ms=2000).document()
        self.event_id = event["event_id"]
        self.book.ingest(queued["envelope"], clock_ms=2100)
        routed = self.book.route((self.event_id, self.fx.keys["receipt"]), clock_ms=2150)
        self.queue.acknowledge(routed["receipt"], clock_ms=2200)
        self.bundle = {
            "registry": {
                "envelope": signing.sign(
                    self.fx.document, "security-event-config", self.fx.keys["root"]
                ),
                "root": self.fx.publics["root"],
                "pin": self.fx.registry.sha256,
                "clock_ms": 2300,
            },
            "outboxes": [self.queue.document()],
            "collector": self.book.document(),
            "incidents": [routed],
        }
        self.expected = {
            self.event_id: {
                k: event[k]
                for k in ("kind", "reason", "asset_sha256", "bundle_sha256", "producer_id")
            }
        }

    def verify(self, bundle=None, **changes):
        name = "mlsecops.security_source_evidence"
        self.assertIsNotNone(importlib.util.find_spec(name), "signed primary replay is missing")
        options = dict(
            expected_root=self.fx.publics["root"],
            expected_pin=self.fx.registry.sha256,
            expected_events=self.expected,
        )
        options.update(changes)
        return importlib.import_module(name).verify_delivery(
            self.bundle if bundle is None else bundle, **options
        )

    def reject(self, value=None, **changes):
        with self.assertRaisesRegex(Rejected, "^security_source_evidence_invalid$"):
            self.verify(self.bundle if value is None else value, **changes)

    def test_real_signatures_are_replayed_with_no_source_or_release_claim(self):
        before = copy.deepcopy(self.bundle)
        report = self.verify()
        self.assertEqual(self.bundle, before)
        self.assertEqual(
            report["events"],
            [
                {
                    "event_id": self.event_id,
                    "kind": "artifact.rejected",
                    "route": "security.artifacts",
                    "delivery_ms": 50,
                }
            ],
        )
        self.assertEqual(report["primary_sha256"], digest(canonical(self.bundle)))
        self.assertIs(report["release_ready"], False)
        self.assertEqual(report["scope"], "signed-delivery-not-source-decision-or-M23")

    def test_summary_and_hash_projection_cannot_replace_primary(self):
        for value in (
            {"status": "pass", "release_ready": False},
            {},
            {**self.bundle, "collector": digest(canonical(self.bundle["collector"]))},
        ):
            with self.subTest(value_type=type(value).__name__):
                self.reject(value)

    def test_operator_pin_and_root_are_required_outside_the_packet(self):
        self.reject(expected_root=self.fx.publics["worker"])
        self.reject(expected_pin="0" * 64)
        changed = copy.deepcopy(self.bundle)
        changed["registry"]["root"] = self.fx.publics["worker"]
        self.reject(changed)
        changed = copy.deepcopy(self.bundle)
        changed["registry"]["pin"] = "0" * 64
        self.reject(changed)

    def test_forged_signed_event_and_receipt_are_rejected(self):
        for field in ("envelope", "receipt"):
            changed = copy.deepcopy(self.bundle)
            changed["collector"]["records"][0][field]["signatures"][0]["sig"] = signing.encode64(
                b"x" * 64
            )
            self.reject(changed)

    def test_resigned_wrong_route_does_not_establish_delivery(self):
        record = self.bundle["collector"]["records"][0]
        event = self.fx.registry.verify(record["envelope"], clock_ms=2100)
        receipt = self.fx.registry.receipt(record["receipt"], event)
        receipt["route"] = "security.workers"
        signed = signing.sign(receipt, "security-event-receipt", self.fx.keys["receipt"])
        changed = copy.deepcopy(self.bundle)
        for item in (
            changed["collector"]["records"][0],
            changed["outboxes"][0]["records"][0],
            changed["incidents"][0],
        ):
            item["receipt"] = signed
        self.reject(changed)

    def test_missing_duplicate_extra_or_different_incident_is_rejected(self):
        for incidents in (
            [],
            self.bundle["incidents"] * 2,
            [{**self.bundle["incidents"][0], "late": True}],
        ):
            changed = copy.deepcopy(self.bundle)
            changed["incidents"] = incidents
            self.reject(changed)

    def test_incident_boolean_cannot_be_replaced_with_equal_integer(self):
        changed = copy.deepcopy(self.bundle)
        changed["incidents"][0]["late"] = 0
        self.reject(changed)

    def test_expected_subject_reason_role_and_inventory_cannot_be_chosen_by_packet(self):
        for key, value in (
            ("kind", "identity.denied"),
            ("reason", "signature"),
            ("asset_sha256", "e" * 64),
            ("bundle_sha256", "a" * 64),
            ("producer_id", "f" * 64),
        ):
            expected = copy.deepcopy(self.expected)
            expected[self.event_id][key] = value
            self.reject(expected_events=expected)
        self.reject(expected_events={})
        self.reject(expected_events={"f" * 64: self.expected[self.event_id]})
        self.reject(
            expected_events={
                self.event_id: {**self.expected[self.event_id], "raw": "PRIVATE-CANARY"}
            }
        )

    def test_source_event_requires_its_full_producer_outbox(self):
        changed = copy.deepcopy(self.bundle)
        changed["outboxes"] = []
        self.reject(changed)
        changed["outboxes"] = [self.queue.document()] * 2
        self.reject(changed)

    def test_incomplete_producer_acknowledgement_cannot_be_called_recovered(self):
        changed = copy.deepcopy(self.bundle)
        changed["outboxes"][0]["records"][0]["receipt"] = None
        self.reject(changed)

    def test_two_individually_valid_but_different_receipts_do_not_match(self):
        changed = copy.deepcopy(self.bundle)
        record = changed["outboxes"][0]["records"][0]
        event = self.fx.registry.verify(record["envelope"], clock_ms=2000)
        receipt = self.fx.registry.receipt(record["receipt"], event)
        receipt["routed_at_ms"] += 1
        record["receipt"] = signing.sign(receipt, "security-event-receipt", self.fx.keys["receipt"])
        outbox.Outbox(self.fx.registry, self.producer, changed["outboxes"][0])
        self.reject(changed)

    def test_source_ack_without_its_collector_record_is_rejected(self):
        second = self.queue.enqueue(
            ({**self.fields, "correlation_id": "e" * 32}, self.fx.keys["intake"]), clock_ms=2250
        )
        value = self.fx.registry.verify(second["envelope"], clock_ms=2250).document()
        self.book.ingest(second["envelope"], clock_ms=2251)
        routed = self.book.route((value["event_id"], self.fx.keys["receipt"]), clock_ms=2252)
        self.queue.acknowledge(routed["receipt"], clock_ms=2253)
        changed = copy.deepcopy(self.bundle)
        changed["outboxes"] = [self.queue.document()]
        self.reject(changed)

    def test_signed_delivery_over_60_seconds_is_not_accepted(self):
        changed = copy.deepcopy(self.bundle)
        record = changed["collector"]["records"][0]
        event = self.fx.registry.verify(record["envelope"], clock_ms=2100)
        receipt = self.fx.registry.receipt(record["receipt"], event)
        receipt["routed_at_ms"] = 62101
        signed = signing.sign(receipt, "security-event-receipt", self.fx.keys["receipt"])
        for item in (record, changed["outboxes"][0]["records"][0], changed["incidents"][0]):
            item["receipt"] = signed
        changed["registry"]["clock_ms"] = 63000
        changed["outboxes"][0]["updated_at_ms"] = 63000
        changed["collector"]["updated_at_ms"] = 63000
        self.reject(changed)

    def test_collector_notice_requires_no_fictional_producer_outbox(self):
        book = ledger.Ledger.empty(self.fx.registry, clock_ms=2000)
        value = self.fx.event("telemetry.gap", "collector", reason="heartbeat")
        envelope = signing.sign(value, "security-event", self.fx.keys["collector"])
        book.ingest(envelope, clock_ms=2100)
        record = book.route((value["event_id"], self.fx.keys["receipt"]), clock_ms=2150)
        changed = copy.deepcopy(self.bundle)
        changed.update(outboxes=[], collector=book.document(), incidents=[record])
        expected = {
            value["event_id"]: {
                key: value[key]
                for key in ("kind", "reason", "asset_sha256", "bundle_sha256", "producer_id")
            }
        }
        report = self.verify(changed, expected_events=expected)
        self.assertEqual(report["events"][0]["route"], "security.telemetry")
        self.assertEqual(report["scope"], "signed-delivery-not-source-decision-or-M23")

    def test_incomplete_collector_route_is_rejected_even_with_outbox_receipt(self):
        changed = copy.deepcopy(self.bundle)
        changed["collector"]["records"][0]["receipt"] = None
        changed["incidents"] = []
        self.reject(changed)

    def test_additional_undelivered_source_event_is_not_silently_dropped(self):
        self.queue.enqueue(
            ({**self.fields, "correlation_id": "e" * 32}, self.fx.keys["intake"]), clock_ms=2250
        )
        changed = copy.deepcopy(self.bundle)
        changed["outboxes"] = [self.queue.document()]
        self.reject(changed)

    def test_capture_clock_must_cover_collector_and_producer_snapshots(self):
        for clock in (True, 0, 2100, 2175, 1000000):
            changed = copy.deepcopy(self.bundle)
            changed["registry"]["clock_ms"] = clock
            self.reject(changed)

    def test_raw_private_fields_and_unbounded_or_malformed_inputs_are_rejected(self):
        for value in (None, [], True, "PRIVATE-CANARY"):
            with self.assertRaises(Rejected):
                self.verify(value if value is not None else {"registry": None})
        for field in ("registry", "collector"):
            changed = copy.deepcopy(self.bundle)
            changed[field]["secret"] = "PRIVATE-CANARY"
            self.reject(changed)
        changed = copy.deepcopy(self.bundle)
        changed["outboxes"] *= 17
        self.reject(changed)
        changed = copy.deepcopy(self.bundle)
        changed["incidents"] = changed
        self.reject(changed)


if __name__ == "__main__":
    unittest.main()
