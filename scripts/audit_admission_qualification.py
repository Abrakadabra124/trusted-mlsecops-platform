import os
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
from pathlib import Path
from unittest.mock import patch

from mlsecops import audit_retention, serving_audit
from mlsecops.contracts import Rejected, decode
from scripts.serving_audit_qualification import event


@contextmanager
def journal_fixture(**options):
    with tempfile.TemporaryDirectory() as temporary:
        journal = serving_audit.Journal(Path(temporary) / "audit.jsonl", **options)
        journal.start()
        try:
            yield journal, Path(temporary) / "audit.jsonl"
        finally:
            with suppress(Rejected):
                journal.close()


def wait_for(predicate):
    deadline = time.monotonic() + 3
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("test_wait_expired")
        time.sleep(0.005)


class AdmissionContracts(unittest.TestCase):
    def test_consumed_reservation_still_protects_ack_from_normal_overload(self):
        for capacity, max_bytes in (
            (4, serving_audit.MAX_BYTES),
            (64, 4 * serving_audit.MAX_RECORD),
        ):
            with (
                self.subTest(capacity=capacity),
                journal_fixture(capacity=capacity, max_bytes=max_bytes) as (journal, _),
            ):
                entered, resume = threading.Event(), threading.Event()
                original = journal._write

                def pause(content):
                    entered.set()
                    if not resume.wait(3):
                        raise OSError("test_wait_expired")
                    original(content)

                ticket = journal.reserve()
                with patch.object(journal, "_write", pause):
                    try:
                        for _index in range(4):
                            sequence = journal.emit(event(), ticket=ticket)
                        self.assertTrue(entered.wait(2))
                        self.assertEqual(journal.status()["held_slots"], 0)
                        if capacity > 4:
                            content_size = journal.status()["reserved_bytes"] // 4
                            while journal.status()["reserved_bytes"] + content_size <= max_bytes:
                                journal.emit(event())
                        with self.assertRaisesRegex(Rejected, "audit_admission_full"):
                            journal.emit(event())
                        self.assertTrue(journal.status()["healthy"])
                        self.assertFalse(journal.confirmed(ticket, sequence))
                    finally:
                        resume.set()
                    wait_for(lambda: journal.status()["pending"] == 0)
                self.assertTrue(journal.confirmed(ticket, sequence))
                journal.release(ticket)

    def test_release_while_writer_is_pending_does_not_return_accepted_capacity(self):
        with journal_fixture(capacity=4) as (journal, _):
            entered, resume = threading.Event(), threading.Event()
            original = journal._write

            def pause(content):
                entered.set()
                if not resume.wait(3):
                    raise OSError("test_wait_expired")
                original(content)

            ticket = journal.reserve()
            with patch.object(journal, "_write", pause):
                try:
                    journal.emit(event(), ticket=ticket)
                    self.assertTrue(entered.wait(2))
                    accepted_bytes = journal.status()["reserved_bytes"]
                    journal.release(ticket)
                    self.assertEqual(journal.status()["pending"], 1)
                    self.assertEqual(journal.status()["reserved_bytes"], accepted_bytes)
                    with self.assertRaisesRegex(Rejected, "audit_admission_full"):
                        journal.reserve()
                    self.assertTrue(journal.status()["healthy"])
                finally:
                    resume.set()
                wait_for(lambda: journal.status()["durable"] == 1)
            journal.release(journal.reserve())

    def test_malformed_reserved_event_is_sticky_without_spending_the_ticket(self):
        with journal_fixture() as (journal, _):
            ticket = journal.reserve()
            with self.assertRaisesRegex(Rejected, "audit_event_invalid"):
                journal.emit({"secret": "PRIVATE_CANARY"}, ticket=ticket)
            self.assertFalse(journal.status()["healthy"])
            self.assertEqual(journal.status()["held_slots"], 4)
            self.assertEqual(journal.status()["accepted"], 0)
            journal.release(ticket)

    @unittest.skipUnless(os.name == "posix", "retained restart requires Linux CI")
    def test_native_restart_confirms_new_owned_sequence_not_retained_prefix(self):
        from scripts.audit_event_qualification import event as versioned_event

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            journal = serving_audit.Journal(root, retention=audit_retention.Policy())
            journal.start()
            try:
                journal.emit(event())
                journal.emit(versioned_event())
            finally:
                journal.close()
            reopened = serving_audit.Journal(root, retention=audit_retention.Policy())
            reopened.start()
            ticket = reopened.reserve()
            try:
                sequence = reopened.emit(versioned_event(), ticket=ticket)
                self.assertEqual(sequence, 3)
                with self.assertRaisesRegex(Rejected, "audit_reservation_invalid"):
                    reopened.confirmed(ticket, 2)
                wait_for(lambda: reopened.confirmed(ticket, sequence))
                self.assertEqual(reopened.status()["durable"], 1)
            finally:
                reopened.release(ticket)
                reopened.close()

    def test_reservation_is_atomic_and_overload_does_not_poison_sink(self):
        with journal_fixture(capacity=8) as (journal, _):

            def admit(_index):
                try:
                    return journal.reserve()
                except Rejected as failure:
                    self.assertEqual(str(failure), "audit_admission_full")
                    return None

            with ThreadPoolExecutor(max_workers=16) as pool:
                tickets = [value for value in pool.map(admit, range(64)) if value is not None]
            self.assertEqual(len(tickets), 2)
            self.assertEqual(journal.status()["held_slots"], 8)
            self.assertEqual(journal.status()["held_bytes"], 8 * serving_audit.MAX_RECORD)
            self.assertTrue(journal.status()["healthy"])
            for ticket in tickets:
                journal.release(ticket)
                journal.release(ticket)
            self.assertEqual(journal.status()["held_slots"], 0)
            self.assertEqual(journal.status()["reservations"], 0)

    def test_pending_and_held_bytes_share_the_hard_storage_budget(self):
        with journal_fixture(max_bytes=4 * serving_audit.MAX_RECORD) as (journal, path):
            ticket = journal.reserve()
            with self.assertRaisesRegex(Rejected, "audit_admission_full"):
                journal.emit(event())
            sequences = [journal.emit(event(), ticket=ticket) for _ in range(4)]
            wait_for(lambda: journal.confirmed(ticket, sequences[-1]))
            size = path.stat().st_size
            self.assertEqual(journal.status()["reserved_bytes"], size)
            journal.release(ticket)
            with self.assertRaisesRegex(Rejected, "audit_admission_full"):
                journal.reserve()
            self.assertTrue(journal.status()["healthy"])
            self.assertEqual(journal.status()["held_bytes"], 0)

    def test_reserved_terminal_slots_survive_competing_unreserved_producer(self):
        with journal_fixture(capacity=4) as (journal, _):
            ticket = journal.reserve()
            with self.assertRaisesRegex(Rejected, "audit_admission_full"):
                journal.emit(event())
            for _index in range(4):
                journal.emit(event(), ticket=ticket)
            with self.assertRaisesRegex(Rejected, "audit_reservation_invalid"):
                journal.emit(event(), ticket=ticket)
            self.assertTrue(journal.status()["healthy"])
            journal.release(ticket)

    def test_durability_wait_is_bound_to_owned_sequence_not_old_prefix(self):
        with journal_fixture() as (journal, _), journal_fixture() as (other, _):
            journal._base_sequence = 100
            ticket, foreign = journal.reserve(), other.reserve()
            entered, resume = threading.Event(), threading.Event()
            original = journal._write

            def slow_write(content):
                entered.set()
                if not resume.wait(3):
                    raise OSError("test_wait_expired")
                original(content)

            with patch.object(journal, "_write", slow_write):
                try:
                    sequence = journal.emit(event(), ticket=ticket)
                    self.assertEqual(sequence, 101)
                    self.assertTrue(entered.wait(2))
                    self.assertFalse(journal.confirmed(ticket, sequence))
                    for invalid in (True, 0, 100, 102, "101", None):
                        with (
                            self.subTest(sequence=invalid),
                            self.assertRaisesRegex(Rejected, "audit_reservation_invalid"),
                        ):
                            journal.confirmed(ticket, invalid)
                    with self.assertRaisesRegex(Rejected, "audit_reservation_invalid"):
                        journal.confirmed(foreign, sequence)
                    with self.assertRaisesRegex(Rejected, "audit_reservation_invalid"):
                        journal.emit(event(), ticket=foreign)
                    before = journal.status()["held_slots"]
                    journal.release(foreign)
                    self.assertEqual(journal.status()["held_slots"], before)
                finally:
                    resume.set()
                wait_for(lambda: journal.confirmed(ticket, sequence))
            journal.release(ticket)
            other.release(foreign)
            with self.assertRaisesRegex(Rejected, "audit_reservation_invalid"):
                journal.confirmed(ticket, sequence)

    def test_release_returns_only_unused_capacity_not_accepted_data(self):
        with journal_fixture() as (journal, path):
            ticket = journal.reserve()
            sequence = journal.emit(event(), ticket=ticket)
            wait_for(lambda: journal.confirmed(ticket, sequence))
            before = journal.status()["reserved_bytes"]
            self.assertEqual(journal.status()["held_slots"], 3)
            journal.release(ticket)
            self.assertEqual(journal.status()["reserved_bytes"], before)
            self.assertEqual(journal.status()["held_bytes"], 0)
            journal.close()
            self.assertEqual(decode(path.read_bytes())["sequence"], sequence)

    def test_consumed_tickets_cannot_accumulate_unbounded_metadata(self):
        with journal_fixture(capacity=4) as (journal, _):
            ticket = journal.reserve()
            for _index in range(4):
                sequence = journal.emit(event(), ticket=ticket)
                wait_for(lambda: journal.confirmed(ticket, sequence))
            with self.assertRaisesRegex(Rejected, "audit_admission_full"):
                journal.reserve()
            journal.release(ticket)
            next_ticket = journal.reserve()
            journal.release(next_ticket)

    def test_stopped_failed_or_closing_sink_never_admits_or_confirms(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = serving_audit.Journal(Path(temporary) / "audit.jsonl")
            try:
                with self.assertRaisesRegex(Rejected, "audit_unavailable"):
                    journal.reserve()
            finally:
                journal.close()
            with self.assertRaisesRegex(Rejected, "audit_unavailable"):
                journal.reserve()
        with journal_fixture() as (journal, _):
            ticket = journal.reserve()
            with patch.object(journal, "_write", side_effect=OSError("PRIVATE_CANARY")):
                sequence = journal.emit(event(), ticket=ticket)
                wait_for(lambda: not journal.status()["healthy"])
                with self.assertRaisesRegex(Rejected, "audit_unavailable"):
                    journal.confirmed(ticket, sequence)
                with self.assertRaisesRegex(Rejected, "audit_unavailable"):
                    journal.reserve()
            journal.release(ticket)
            self.assertEqual(journal.status()["unconfirmed"], 1)

    def test_close_reports_abandoned_reservations_instead_of_success(self):
        with journal_fixture() as (journal, _):
            ticket = journal.reserve()
            with self.assertRaisesRegex(Rejected, "audit_failed"):
                journal.close()
            self.assertEqual(journal.status()["failure"], "reservations_open")
            with self.assertRaisesRegex(Rejected, "audit_unavailable"):
                journal.emit(event(), ticket=ticket)
            journal.release(ticket)
            journal.release(ticket)
            self.assertEqual(journal.status()["held_slots"], 0)


if __name__ == "__main__":
    unittest.main()
