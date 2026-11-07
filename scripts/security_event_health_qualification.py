"""Durable gap/heartbeat semantics with authenticated messages and controlled clocks."""

import copy
import sys
import unittest

from mlsecops import security_event_health as health
from mlsecops import security_event_ledger as ledger
from mlsecops import security_event_store as storage
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, digest
from scripts import security_event_ledger_qualification as fixtures


class HealthContracts(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.LedgerContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.book = self.fx.book
        self.registry = self.fx.registry

    def heartbeat(self, sequence=1, *, observed=2000, last=0, role="serving", **changes):
        value = self.fx.fixture.heartbeat(
            sequence=sequence,
            observed_at_ms=observed,
            last_event_sequence=last,
            producer_id=digest(signing.decode64(self.fx.fixture.publics[role])),
            **changes,
        )
        return signing.sign(value, "security-heartbeat", self.fx.fixture.keys[role])

    def restore(self):
        self.book = ledger.Ledger(self.registry, self.book.document())

    def test_first_heartbeat_is_required_and_no_report_grants_release(self):
        initial = self.book.poll(clock_ms=2100)
        self.assertFalse(initial["healthy"])
        self.assertEqual(len(initial["awaiting_heartbeat"]), 1)
        self.assertEqual(initial["problems"], [])
        self.book.heartbeat(self.heartbeat(), clock_ms=2100)
        result = self.book.poll(clock_ms=2200)
        self.assertTrue(result["healthy"])
        self.assertIs(result["release_ready"], False)
        self.assertEqual(result["config_sha256"], self.registry.sha256)

    def test_detection_reserves_scheduler_budget_before_the_hard_deadline(self):
        self.book.heartbeat(self.heartbeat(), clock_ms=2100)
        self.assertEqual(self.book.poll(clock_ms=91999)["problems"], [])
        problems = self.book.poll(clock_ms=92000)["problems"]
        self.assertEqual(len(problems), 1)
        problem = problems[0]
        self.assertEqual(problem["since_ms"], 92000)
        self.assertEqual(problem["deadline_at_ms"], 122000)

    def test_retry_cannot_extend_heartbeat_deadline_and_restart_preserves_episode(self):
        message = self.heartbeat()
        original = self.book.heartbeat(message, clock_ms=2100)
        self.assertEqual(self.book.heartbeat(message, clock_ms=100000), original)
        self.assertEqual(self.book.poll(clock_ms=91999)["problems"], [])
        due = self.book.poll(clock_ms=92000)
        self.assertFalse(due["healthy"])
        self.assertEqual([p["reason"] for p in due["problems"]], ["heartbeat"])
        self.restore()
        later = self.book.poll(clock_ms=123000)
        self.assertEqual(due["problems"], later["problems"])
        self.assertEqual(due["problems"][0]["deadline_at_ms"], 122000)

    def test_stale_higher_heartbeat_does_not_create_new_outage_episode(self):
        self.book.heartbeat(self.heartbeat(), clock_ms=2100)
        due = self.book.poll(clock_ms=140000)["problems"][0]
        self.book.heartbeat(self.heartbeat(2, observed=3000), clock_ms=140001)
        self.assertEqual(self.book.poll(clock_ms=140002)["problems"][0], due)
        self.book.heartbeat(self.heartbeat(3, observed=140003), clock_ms=140003)
        self.assertTrue(self.book.poll(clock_ms=140004)["healthy"])
        reopened = self.book.poll(clock_ms=260003)["problems"][0]
        self.assertNotEqual(reopened["notice_id"], due["notice_id"])

    def test_heartbeat_sequence_claim_exposes_missing_events_and_late_arrival_heals(self):
        self.book.heartbeat(self.heartbeat(role="intake", last=3), clock_ms=2100)
        self.book.ingest(self.fx.envelope(3), clock_ms=2200)
        self.restore()
        before = self.book.poll(clock_ms=92099)
        self.assertEqual([p for p in before["problems"] if p["reason"] == "sequence"], [])
        due = self.book.poll(clock_ms=92100)
        problem = [p for p in due["problems"] if p["reason"] == "sequence"][0]
        self.assertEqual(problem["since_ms"], 2100)
        self.assertEqual(due["open_sequence_gaps"], 1)
        self.book.ingest(self.fx.envelope(1), clock_ms=122101)
        self.book.ingest(self.fx.envelope(2), clock_ms=122102)
        healed = self.book.poll(clock_ms=122103)
        self.assertEqual(healed["open_sequence_gaps"], 0)
        self.assertEqual([p for p in healed["problems"] if p["reason"] == "sequence"], [])

    def test_later_heartbeat_claim_never_restarts_existing_gap_timer(self):
        self.book.heartbeat(self.heartbeat(role="intake", last=2), clock_ms=2100)
        self.book.heartbeat(self.heartbeat(2, role="intake", last=4, observed=5000), clock_ms=5000)
        self.book.ingest(self.fx.envelope(2), clock_ms=5100)
        self.restore()
        value = self.book.poll(clock_ms=122100)
        problem = [p for p in value["problems"] if p["reason"] == "sequence"][0]
        self.assertEqual(problem["since_ms"], 2100)
        self.assertEqual(problem["deadline_at_ms"], 122100)

    def test_forgery_conflict_backwards_counter_time_and_oversized_claim_are_rejected(self):
        self.book.heartbeat(self.heartbeat(2, last=2, observed=3000), clock_ms=3100)
        before = self.book.document()
        variants = [
            self.heartbeat(2, last=3, observed=3000),
            self.heartbeat(1, observed=3100),
            self.heartbeat(3, last=1, observed=3200),
            self.heartbeat(3, last=2, observed=2999),
            self.heartbeat(3, last=health.REORDER_WINDOW + 1, observed=3200),
            self.heartbeat(3, last=2**53 - 1, observed=3200),
            self.heartbeat(3, last=2, observed=3200, role="worker"),
        ]
        forged = copy.deepcopy(variants[0])
        forged["signatures"][0]["sig"] = signing.encode64(b"x" * 64)
        variants.extend([forged, {}])
        for value in variants:
            with self.subTest(type=type(value).__name__), self.assertRaises(Rejected):
                self.book.heartbeat(value, clock_ms=3300)
            self.assertEqual(self.book.document(), before)

    def test_pending_delivery_and_capacity_are_unhealthy_even_with_fresh_heartbeat(self):
        self.book.heartbeat(self.heartbeat(), clock_ms=2100)
        record = self.book.ingest(self.fx.envelope(), clock_ms=2200)
        result = self.book.poll(clock_ms=2300)
        self.assertFalse(result["healthy"])
        self.assertEqual(result["pending_deliveries"], 1)
        self.book.acknowledge(self.fx.receipt(record), clock_ms=2400)
        self.assertTrue(self.book.poll(clock_ms=2500)["healthy"])

    def test_missing_stream_tampered_control_and_legacy_schema_fail_closed(self):
        self.book.heartbeat(self.heartbeat(), clock_ms=2100)
        baseline = self.book.document()
        variants = []
        old = copy.deepcopy(baseline)
        old["schema_version"] = 1
        del old["telemetry"]
        variants.append(old)
        for field, value in (
            ("started_at_ms", True),
            ("started_at_ms", 3000),
            ("streams", []),
            ("streams", {}),
        ):
            bad = copy.deepcopy(baseline)
            bad["telemetry"][field] = value
            variants.append(bad)
        for field, value in (
            ("producer_id", "f" * 64),
            ("sequence_generation", True),
            ("sequence_gap_since_ms", 2100),
            ("heartbeat_gap_since_ms", 2100),
            ("heartbeat", {}),
            ("extra", "PRIVATE-CANARY"),
        ):
            bad = copy.deepcopy(baseline)
            bad["telemetry"]["streams"][0][field] = value
            variants.append(bad)
        for value in variants:
            with self.subTest(kind=type(value).__name__), self.assertRaises(Rejected):
                ledger.Ledger(self.registry, value)

    def test_readonly_copies_and_clock_rejection_preserve_control_history(self):
        original = self.book.heartbeat(self.heartbeat(), clock_ms=2100)
        snapshot = self.book.document()
        original["ingested_at_ms"] = 999
        snapshot["telemetry"]["streams"].clear()
        before = self.book.document()
        for clock in (2099, True, 1000000):
            with self.subTest(clock=clock), self.assertRaises(Rejected):
                self.book.poll(clock_ms=clock)
            self.assertEqual(self.book.document(), before)
        self.assertTrue(self.book.poll(clock_ms=2200)["healthy"])

    def test_recovered_heartbeat_binding_and_episode_timestamps_are_revalidated(self):
        self.book.heartbeat(self.heartbeat(), clock_ms=2100)
        self.book.poll(clock_ms=130000)
        baseline = self.book.document()
        serving = digest(signing.decode64(self.fx.fixture.publics["serving"]))
        intake = digest(signing.decode64(self.fx.fixture.publics["intake"]))
        variants = []
        for field, value in (
            ("heartbeat_gap_since_ms", 123000),
            ("heartbeat_gap_since_ms", 1999),
            ("heartbeat_generation", 0),
        ):
            changed = copy.deepcopy(baseline)
            row = next(s for s in changed["telemetry"]["streams"] if s["producer_id"] == serving)
            row[field] = value
            variants.append(changed)
        for time in (1999, 130001):
            changed = copy.deepcopy(baseline)
            row = next(s for s in changed["telemetry"]["streams"] if s["producer_id"] == serving)
            row["heartbeat"]["ingested_at_ms"] = time
            variants.append(changed)
        changed = copy.deepcopy(baseline)
        rows = {s["producer_id"]: s for s in changed["telemetry"]["streams"]}
        rows[intake]["heartbeat"] = copy.deepcopy(rows[serving]["heartbeat"])
        variants.append(changed)
        for version in (True, 1, 2):
            variants.append({**baseline, "schema_version": version})
        for value in variants:
            with self.subTest(version=value["schema_version"]), self.assertRaises(Rejected):
                ledger.Ledger(self.registry, value)

    def test_generation_exhaustion_never_partially_commits_event_or_receipt(self):
        from mlsecops.security_events import MAX_INTEGER

        intake = digest(signing.decode64(self.fx.fixture.publics["intake"]))
        serving = digest(signing.decode64(self.fx.fixture.publics["serving"]))
        document = self.book.document()
        next(s for s in document["telemetry"]["streams"] if s["producer_id"] == intake)[
            "sequence_generation"
        ] = MAX_INTEGER
        self.book = ledger.Ledger(self.registry, document)
        before = self.book.document()
        with self.assertRaises(Rejected):
            self.book.ingest(self.fx.envelope(2), clock_ms=2100)
        self.assertEqual(self.book.document(), before)
        record = self.book.ingest(self.fx.envelope(), clock_ms=2100)
        document = self.book.document()
        next(s for s in document["telemetry"]["streams"] if s["producer_id"] == serving)[
            "heartbeat_generation"
        ] = MAX_INTEGER
        self.book = ledger.Ledger(self.registry, document)
        before = self.book.document()
        with self.assertRaises(Rejected):
            self.book.acknowledge(self.fx.receipt(record), clock_ms=130000)
        self.assertEqual(self.book.document(), before)
        with self.assertRaises(Rejected):
            self.book.poll(clock_ms=130000)
        self.assertEqual(self.book.document(), before)

    def test_initial_missing_heartbeat_and_future_skew_cannot_extend_observation(self):
        initial = self.book.poll(clock_ms=122000)
        self.assertEqual(initial["problems"][0]["deadline_at_ms"], 122000)
        fresh = ledger.Ledger.empty(self.registry, clock_ms=2000)
        fresh.heartbeat(self.heartbeat(observed=10000), clock_ms=5000)
        self.assertEqual(fresh.poll(clock_ms=125000)["problems"][0]["deadline_at_ms"], 125000)


@unittest.skipUnless(sys.platform == "linux", "Linux persistent telemetry state required")
class PersistedHealth(unittest.TestCase):
    def test_real_store_reopen_retains_heartbeat_gap_and_original_admission(self):
        fx = HealthContracts("runTest")
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        root = fx.fx.fixture.directory / "health-store"
        pin = storage.initialize(str(root), fx.registry, clock_ms=2000)

        def opened():
            return storage.Store(str(root), pin, fx.registry)

        original = opened().heartbeat(fx.heartbeat(), clock_ms=2100)
        opened().ingest(fx.fx.envelope(3), clock_ms=2200)
        due = opened().poll(clock_ms=122200)
        self.assertEqual({p["reason"] for p in due["problems"]}, {"heartbeat", "sequence"})
        self.assertEqual(opened().heartbeat(fx.heartbeat(), clock_ms=122201), original)
        restored = opened().poll(clock_ms=122202)
        self.assertEqual(restored["problems"], due["problems"])
        self.assertFalse(restored["healthy"])
        self.assertNotIn(b"PRIVATE-CANARY", canonical(opened().snapshot()))


if __name__ == "__main__":
    unittest.main()
