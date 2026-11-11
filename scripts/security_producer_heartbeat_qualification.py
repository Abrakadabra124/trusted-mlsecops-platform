"""Durable producer heartbeat head, counter, replay boundaries and private echo."""

import copy
import sys
import unittest
from unittest.mock import Mock, patch

from mlsecops import security_event_delivery as delivery
from mlsecops import security_event_outbox as outbox
from mlsecops import security_event_store as storage
from mlsecops import security_events as events
from mlsecops import signing
from mlsecops.contracts import Rejected
from scripts import security_events_qualification as fixtures


class HeartbeatContracts(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.EventContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.key = self.fx.keys["serving"]
        self.identity = outbox.key_identity(self.key)
        self.box = outbox.Outbox.empty(self.fx.registry, self.identity, clock_ms=2000)
        self.fields = dict(
            kind="identity.denied",
            reason="credential",
            correlation_id="c" * 32,
            asset_sha256="d" * 64,
            bundle_sha256=None,
        )

    def value(self, envelope):
        return self.fx.registry.heartbeat(envelope, clock_ms=2100)

    def test_counter_survives_reopen_and_head_includes_pending_without_consuming_event_capacity(
        self,
    ):
        first = self.box.heartbeat(self.key, clock_ms=2100)
        self.assertEqual(
            (self.value(first)["sequence"], self.value(first)["last_event_sequence"]), (1, 0)
        )
        self.box.enqueue((self.fields, self.key), clock_ms=2100)
        self.box = outbox.Outbox(self.fx.registry, self.identity, self.box.document())
        second = self.box.heartbeat(self.key, clock_ms=2100)
        self.assertEqual(
            (self.value(second)["sequence"], self.value(second)["last_event_sequence"]), (2, 1)
        )
        self.assertEqual(len(self.box.pending()), 1)
        for _ in range(20):
            self.box.heartbeat(self.key, clock_ms=2100)
        self.assertEqual(len(self.box.document()["records"]), 1)
        self.assertEqual(self.value(self.box.document()["heartbeat"])["sequence"], 22)

    def test_schema1_readable_but_no_implicit_heartbeat_counter_migration(self):
        legacy = self.box.document()
        legacy.pop("heartbeat")
        legacy["schema_version"] = 1
        box = outbox.Outbox(self.fx.registry, self.identity, legacy)
        before = box.document()
        with self.assertRaisesRegex(Rejected, "security_outbox_heartbeat_migration"):
            box.heartbeat(self.key, clock_ms=2100)
        self.assertEqual(box.document(), before)
        box.enqueue((self.fields, self.key), clock_ms=2100)
        self.assertEqual(box.document()["schema_version"], 1)

    def test_wrong_key_clock_schema_and_corrupt_heartbeat_fail_without_mutation(self):
        original = self.box.heartbeat(self.key, clock_ms=2100)
        before = self.box.document()
        for key, now in ((self.fx.keys["controller"], 2200), (self.key, 2099), (self.key, 1000001)):
            with self.assertRaises(Rejected):
                self.box.heartbeat(key, clock_ms=now)
            self.assertEqual(self.box.document(), before)
        for version in (None, True, 0, 3):
            with self.assertRaises(Rejected):
                outbox.Outbox(
                    self.fx.registry, self.identity, {**before, "schema_version": version}
                )
        for change in ({"sequence": 0}, {"last_event_sequence": 1}, {"observed_at_ms": 2200}):
            value = {**self.value(original), **change}
            document = {**before, "heartbeat": signing.sign(value, "security-heartbeat", self.key)}
            with self.assertRaises(Rejected):
                outbox.Outbox(self.fx.registry, self.identity, document)
        for heartbeat in ({}, {"private": "canary"}):
            with self.assertRaises(Rejected):
                outbox.Outbox(self.fx.registry, self.identity, {**before, "heartbeat": heartbeat})

    def test_old_signed_heartbeat_remains_loadable_but_new_counter_cannot_overflow(self):
        original = self.box.heartbeat(self.key, clock_ms=2100)
        self.box.enqueue((self.fields, self.key), clock_ms=400000)
        reopened = outbox.Outbox(self.fx.registry, self.identity, self.box.document())
        self.assertEqual(reopened.document()["heartbeat"], original)
        value = {**self.value(original), "sequence": events.MAX_INTEGER}
        document = {
            **self.box.document(),
            "heartbeat": signing.sign(value, "security-heartbeat", self.key),
        }
        reopened = outbox.Outbox(self.fx.registry, self.identity, document)
        with self.assertRaises(Rejected):
            reopened.heartbeat(self.key, clock_ms=400001)
        self.assertEqual(reopened.document(), document)

    def test_heartbeat_cannot_reopen_corrupt_event_head_or_excessive_backlog(self):
        self.box.enqueue((self.fields, self.key), clock_ms=2100)
        before = self.box.document()
        invalid = [
            None,
            {**before, "records": None},
            {**before, "records": [{}] * (outbox.MAX_RECORDS + 1)},
        ]
        clock = copy.deepcopy(before)
        clock["records"][0]["queued_at_ms"] = 2200
        invalid.append(clock)
        records = []
        for index in range(outbox.MAX_PENDING + 1):
            value = events.create(
                **{**self.fields, "correlation_id": f"{index:032x}"},
                producer_id=self.identity,
                epoch="b" * 32,
                sequence=index + 1,
                occurred_at_ms=2100,
                observed_at_ms=2100,
                policy_sha256=self.fx.policy,
            )
            records.append(
                dict(
                    envelope=signing.sign(value, "security-event", self.key),
                    queued_at_ms=2100,
                    receipt=None,
                )
            )
        invalid.extend(({**before, "records": records}, {**before, "records": records[1:2]}))
        duplicate = events.create(
            **self.fields,
            producer_id=self.identity,
            epoch="b" * 32,
            sequence=2,
            occurred_at_ms=2100,
            observed_at_ms=2100,
            policy_sha256=self.fx.policy,
        )
        invalid.append(
            {
                **before,
                "records": before["records"]
                + [
                    dict(
                        envelope=signing.sign(duplicate, "security-event", self.key),
                        queued_at_ms=2100,
                        receipt=None,
                    )
                ],
            }
        )
        for document in invalid:
            with self.subTest(document_type=type(document).__name__), self.assertRaises(Rejected):
                outbox.Outbox(self.fx.registry, self.identity, document)

    def test_heartbeat_echo_rejects_clock_rollback_and_ancient_receiver_timestamp(self):
        emitter = self.emitter()
        emitter.clock = Mock(side_effect=[2100, 2099])
        with self.assertRaisesRegex(Rejected, "security_heartbeat_delivery_unconfirmed"):
            emitter.heartbeat()
        emitter = self.emitter(
            lambda v: {**v, "heartbeat": {**v["heartbeat"], "ingested_at_ms": 1}}
        )
        emitter.clock = lambda: 400000
        with self.assertRaisesRegex(Rejected, "security_heartbeat_delivery_unconfirmed"):
            emitter.heartbeat()

    def emitter(self, transform=lambda value: value):
        self.box.snapshot = self.box.document

        def send(envelope, *, path):
            self.assertEqual(path, "/heartbeat")
            self.assertEqual(self.box.document()["heartbeat"], envelope)
            return transform(
                dict(heartbeat=dict(envelope=envelope, ingested_at_ms=2100), release_ready=False)
            )

        self.client = Mock(send=Mock(side_effect=send))
        return delivery.Emitter(self.box, self.key, self.client, clock=lambda: 2100)

    def test_delivery_saves_before_send_and_returns_no_health_or_release_authority(self):
        result = self.emitter().heartbeat()
        self.assertEqual(
            result, dict(state="sent", sequence=1, last_event_sequence=0, release_ready=False)
        )
        self.assertEqual(self.client.send.call_count, 1)

    def test_unknown_delivery_keeps_counter_and_next_attempt_advances(self):
        emitter = self.emitter()
        original = self.client.send.side_effect
        self.client.send.side_effect = OSError("PRIVATE-CANARY")
        with self.assertRaisesRegex(Rejected, "^security_heartbeat_delivery_unconfirmed$"):
            emitter.heartbeat()
        self.assertEqual(self.value(self.box.document()["heartbeat"])["sequence"], 1)
        self.client.send.side_effect = original
        self.assertEqual(emitter.heartbeat()["sequence"], 2)

    def test_forged_stale_wrong_echo_never_claims_success(self):
        def altered(value, change):
            value = copy.deepcopy(value)
            change(value)
            return value

        for change in (
            lambda v: v.update(release_ready=True),
            lambda v: v.update(extra="PRIVATE-CANARY"),
            lambda v: v["heartbeat"].update(envelope={}),
            lambda v: v["heartbeat"].update(ingested_at_ms=2100 + events.CLOCK_SKEW_MS + 1),
            lambda v: v["heartbeat"].update(ingested_at_ms=True),
        ):
            emitter = self.emitter(lambda v: altered(v, change))
            with self.assertRaisesRegex(Rejected, "^security_heartbeat_delivery_unconfirmed$"):
                emitter.heartbeat()


@unittest.skipUnless(sys.platform == "linux", "owned POSIX journal required")
class DurableHeartbeat(unittest.TestCase):
    setUp = HeartbeatContracts.setUp
    value = HeartbeatContracts.value

    def test_reopen_and_unknown_commit_preserve_sequence_before_network(self):
        root = str(self.fx.directory / "heartbeat-outbox")
        pin = outbox.initialize(root, self.fx.registry, self.identity, clock_ms=2000)

        def reopen():
            return outbox.Store(root, pin, self.fx.registry, self.identity)

        store = reopen()
        first = store.heartbeat(self.key, clock_ms=2100)
        self.assertEqual(reopen().snapshot()["heartbeat"], first)
        replace = storage.os.replace

        def unknown(*args, **kwargs):
            replace(*args, **kwargs)
            raise OSError("PRIVATE-CANARY")

        with patch.object(storage.os, "replace", side_effect=unknown), self.assertRaises(Rejected):
            store.heartbeat(self.key, clock_ms=2100)
        self.assertEqual(self.value(reopen().snapshot()["heartbeat"])["sequence"], 2)
        self.assertEqual(self.value(reopen().heartbeat(self.key, clock_ms=2100))["sequence"], 3)


if __name__ == "__main__":
    unittest.main()
