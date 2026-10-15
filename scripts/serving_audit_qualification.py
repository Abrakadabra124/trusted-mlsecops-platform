import copy
import inspect
import os
import queue
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops import serving_audit
from mlsecops.contracts import Rejected, decode


def event():
    return {
        "request_id": "a" * 32,
        "principal_id": "b" * 32,
        "route": "predict",
        "stage": "response_completed",
        "status": 200,
        "release": {
            "selection_sha256": "c" * 64,
            "bundle_sha256": "d" * 64,
            "model_sha256": "e" * 64,
        },
    }


class AuditContracts(unittest.TestCase):
    def test_invalid_close_timeout_is_sticky_and_huge_integer_is_bounded(self):
        for invalid in (-1, 10**1000):
            with self.subTest(huge=invalid > 5), tempfile.TemporaryDirectory() as temporary:
                journal = serving_audit.Journal(Path(temporary) / "audit.jsonl")
                journal.start()
                try:
                    with self.assertRaisesRegex(Rejected, "audit_close_timeout_invalid"):
                        journal.close(invalid)
                    self.assertFalse(journal.status()["healthy"])
                    with self.assertRaisesRegex(Rejected, "audit_unavailable"):
                        journal.emit(event())
                finally:
                    with suppress(Rejected):
                        journal.close()

    def test_stale_empty_observation_cannot_discard_later_accepted_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.jsonl"
            journal = serving_audit.Journal(path)
            observed, resume = threading.Event(), threading.Event()
            original = journal._queue.get

            def get(*arguments, **keywords):
                if not observed.is_set():
                    observed.set()
                    if not resume.wait(5):
                        raise RuntimeError("test_wait_expired")
                    raise queue.Empty
                return original(*arguments, **keywords)

            with patch.object(journal._queue, "get", get):
                try:
                    journal.start()
                    self.assertTrue(observed.wait(2))
                    journal.emit(event())
                    with self.assertRaisesRegex(Rejected, "audit_shutdown_pending"):
                        journal.close(timeout=0)
                finally:
                    resume.set()
                    journal.close()
            self.assertEqual(journal.status()["durable"], 1)
            self.assertEqual(journal.status()["unconfirmed"], 0)
            self.assertEqual(decode(path.read_bytes())["event"], event())

    def test_close_cannot_claim_success_with_unconfirmed_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = serving_audit.Journal(Path(temporary) / "audit.jsonl")
            journal._accepted = 1
            with self.assertRaisesRegex(Rejected, "audit_failed"):
                journal.close()
            self.assertEqual(journal.status()["failure"], "unconfirmed")

    def test_posix_descriptor_checks_and_creation_share_one_directory_identity(self):
        for mode, owner, sync_failure in (
            (0o40700, 1000, False),
            (0o40755, 1000, False),
            (0o40700, 1001, False),
            (0o40700, 1000, True),
        ):
            system = SimpleNamespace(
                name="posix",
                O_WRONLY=1,
                O_CREAT=2,
                O_EXCL=4,
                O_RDONLY=8,
                O_DIRECTORY=16,
                O_NOFOLLOW=32,
                open=Mock(side_effect=[71, 72]),
                fstat=Mock(return_value=SimpleNamespace(st_mode=mode, st_uid=owner)),
                geteuid=lambda: 1000,
                fsync=Mock(side_effect=OSError("CANARY") if sync_failure else None),
                close=Mock(),
            )
            with (
                self.subTest(mode=mode, owner=owner, failure=sync_failure),
                tempfile.TemporaryDirectory() as temporary,
                patch.object(serving_audit, "os", system),
            ):
                path = Path(temporary) / "audit.jsonl"
                if mode != 0o40700 or owner != 1000 or sync_failure:
                    with self.assertRaisesRegex(Rejected, "audit_path_rejected"):
                        serving_audit.Journal(path)
                else:
                    journal = serving_audit.Journal(path)
                    journal.close()
                system.fstat.assert_called_once_with(71)
                if mode == 0o40700 and owner == 1000:
                    self.assertEqual(system.open.call_args.args[0], "audit.jsonl")
                    self.assertEqual(system.open.call_args.kwargs, {"dir_fd": 71})
                    system.fsync.assert_called_once_with(71)
                    self.assertEqual(
                        [call.args[0] for call in system.close.call_args_list], [71, 72]
                    )
                else:
                    self.assertEqual(system.open.call_count, 1)
                    system.close.assert_called_once_with(71)

    @unittest.skipUnless(os.name == "posix", "native POSIX directory identity requires Linux CI")
    def test_native_parent_replacement_cannot_redirect_created_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, retained = root / "private", root / "retained"
            parent.mkdir(mode=0o700)
            original = os.open

            def replace(path, flags, mode=0o777, *, dir_fd=None):
                if dir_fd is not None:
                    parent.rename(retained)
                    parent.mkdir(mode=0o700)
                return original(path, flags, mode, dir_fd=dir_fd)

            with patch.object(serving_audit.os, "open", replace):
                journal = serving_audit.Journal(parent / "audit.jsonl")
            journal.start()
            journal.emit(event())
            journal.close()
            self.assertFalse((parent / "audit.jsonl").exists())
            self.assertEqual(decode((retained / "audit.jsonl").read_bytes())["event"], event())
            parent.chmod(0o755)
            with self.assertRaisesRegex(Rejected, "audit_path_rejected"):
                serving_audit.Journal(parent / "insecure.jsonl")
            link = root / "link"
            link.symlink_to(retained, target_is_directory=True)
            with self.assertRaisesRegex(Rejected, "audit_path_rejected"):
                serving_audit.Journal(link / "linked.jsonl")

    def test_close_error_is_sticky_without_retrying_a_released_descriptor(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = serving_audit.Journal(Path(temporary) / "audit.jsonl")
            original = os.close

            def close(descriptor):
                original(descriptor)
                raise OSError("CANARY")

            with patch.object(serving_audit.os, "close", close):
                with self.assertRaisesRegex(Rejected, "audit_failed"):
                    journal.close()
                with self.assertRaisesRegex(Rejected, "audit_failed"):
                    journal.close()
            self.assertTrue(journal.status()["closed"])
            self.assertEqual(journal.status()["failure"], "close_failed")

    def test_close_and_emit_have_one_admission_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.jsonl"
            journal = serving_audit.Journal(path)
            journal.start()
            entered, closing, resume = threading.Event(), threading.Event(), threading.Event()
            original = serving_audit.checked

            def checked(value):
                entered.set()
                if not resume.wait(5):
                    raise RuntimeError("test_wait_expired")
                return original(value)

            def close():
                closing.set()
                journal.close()

            with (
                patch.object(serving_audit, "checked", checked),
                ThreadPoolExecutor(max_workers=2) as executor,
            ):
                admission = executor.submit(journal.emit, event())
                self.assertTrue(entered.wait(2))
                finished = executor.submit(close)
                self.assertTrue(closing.wait(2))
                resume.set()
                self.assertEqual(admission.result(2), 1)
                finished.result(2)
            self.assertEqual(len(path.read_bytes().splitlines()), 1)
            with self.assertRaisesRegex(Rejected, "audit_unavailable"):
                journal.emit(event())

    def test_mutation_between_shape_check_and_snapshot_cannot_add_a_field(self):
        source = event()
        lines, first = inspect.getsourcelines(serving_audit.checked)
        capture_line = first + next(index for index, line in enumerate(lines) if "result =" in line)

        def mutate(frame, action, argument):
            if (
                frame.f_code is serving_audit.checked.__code__
                and action == "line"
                and frame.f_lineno == capture_line
            ):
                source["raw_payload"] = "a" * 64
            return mutate

        previous = sys.gettrace()
        try:
            sys.settrace(mutate)
            captured = serving_audit.checked(source)
        finally:
            sys.settrace(previous)
        self.assertIn("raw_payload", source)
        self.assertEqual(captured, event())

    def test_schema_checks_every_phase_status_and_reference_boundary(self):
        for stage, status in (
            ("request_started", None),
            ("response_started", 401),
            ("response_completed", 599),
            ("aborted", None),
            ("aborted", 200),
        ):
            for route in ("predict", "ready", "live", "other"):
                value = {**event(), "stage": stage, "status": status, "route": route}
                if status != 200 or route not in {"predict", "ready"}:
                    value.update(release=None, principal_id=None)
                self.assertEqual(serving_audit.checked(value), value)
        for changes in (
            {"request_id": True},
            {"request_id": "A" * 32},
            {"route": []},
            {"stage": []},
            {"status": 199},
            {"status": 600},
            {"status": 200.0},
            {"status": None},
            {"stage": "request_started"},
            {"release": []},
            {"release": {}},
            {"release": {**event()["release"], "extra": "a" * 64}},
            {"release": {**event()["release"], "model_sha256": "g" * 64}},
            {"route": "live"},
            {"principal_id": None},
        ):
            with (
                self.subTest(fields=list(changes)),
                self.assertRaisesRegex(Rejected, "audit_event_invalid"),
            ):
                serving_audit.checked({**event(), **changes})
        for value in (None, [], {}, {**event(), "extra": "CANARY"}):
            with self.assertRaisesRegex(Rejected, "audit_event_invalid"):
                serving_audit.checked(value)

    def test_clock_record_size_and_sequence_fail_closed(self):
        for invalid in (-1, True, float("nan"), 2**63):
            with self.subTest(clock=invalid), tempfile.TemporaryDirectory() as temporary:
                journal = serving_audit.Journal(Path(temporary) / "audit.jsonl")
                journal.start()
                with patch.object(serving_audit.time, "time_ns", return_value=invalid):
                    with self.assertRaisesRegex(Rejected, "audit_clock_invalid"):
                        journal.emit(event())
                with self.assertRaisesRegex(Rejected, "audit_failed"):
                    journal.close()
        with tempfile.TemporaryDirectory() as temporary:
            journal = serving_audit.Journal(Path(temporary) / "audit.jsonl")
            journal.start()
            with patch.object(serving_audit.time, "time_ns", side_effect=[100, 99]):
                journal.emit(event())
                with self.assertRaisesRegex(Rejected, "audit_clock_invalid"):
                    journal.emit(event())
            with self.assertRaisesRegex(Rejected, "audit_failed"):
                journal.close()
        for overflow in ("sequence", "record"):
            with self.subTest(overflow=overflow), tempfile.TemporaryDirectory() as temporary:
                journal = serving_audit.Journal(Path(temporary) / "audit.jsonl")
                if overflow == "sequence":
                    journal._accepted = journal._durable = 2**63 - 1
                journal.start()
                with patch.object(serving_audit, "canonical", return_value=b"x" * 2048):
                    with self.assertRaisesRegex(
                        Rejected, "audit_sequence_exhausted|audit_record_too_large"
                    ):
                        journal.emit(event())
                with self.assertRaisesRegex(Rejected, "audit_failed"):
                    journal.close()

    def test_short_writes_are_completed_before_durable_acknowledgement(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.jsonl"
            journal = serving_audit.Journal(path)
            entered, resume = threading.Event(), threading.Event()
            write, sync = os.write, os.fsync

            def pending_sync(descriptor):
                entered.set()
                if not resume.wait(5):
                    raise OSError("test_wait_expired")
                sync(descriptor)

            with (
                patch.object(
                    serving_audit.os, "write", lambda descriptor, data: write(descriptor, data[:7])
                ),
                patch.object(serving_audit.os, "fsync", pending_sync),
            ):
                try:
                    journal.start()
                    journal.emit(event())
                    self.assertTrue(entered.wait(2))
                    self.assertEqual(journal.status()["durable"], 0)
                    self.assertEqual(journal.status()["pending"], 1)
                    with self.assertRaisesRegex(Rejected, "audit_shutdown_pending"):
                        journal.close(timeout=0.01)
                finally:
                    resume.set()
                    journal.close()
            self.assertEqual(decode(path.read_bytes())["event"], event())
            self.assertEqual(journal.status()["durable_bytes"], path.stat().st_size)

    def test_sink_failure_reports_unconfirmed_records_and_never_prints_payload(self):
        for failure in (0, -1, None, 4096, OSError("CANARY"), SystemExit("CANARY")):
            with (
                self.subTest(failure_type=type(failure)),
                tempfile.TemporaryDirectory() as temporary,
            ):
                journal = serving_audit.Journal(Path(temporary) / "audit.jsonl")

                def write(*arguments):
                    if isinstance(failure, BaseException):
                        raise failure
                    return failure

                with patch.object(serving_audit.os, "write", write):
                    journal.start()
                    journal.emit(event())
                    with self.assertRaisesRegex(Rejected, "audit_failed"):
                        journal.close()
                self.assertEqual(journal.status()["failure"], "sink_failed")
                self.assertEqual(journal.status()["unconfirmed"], 1)
                self.assertEqual(journal.status()["pending"], 0)
                self.assertEqual(journal.status()["durable"], 0)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.jsonl"
            journal = serving_audit.Journal(path)
            with patch.object(serving_audit.os, "fsync", side_effect=OSError("CANARY")):
                journal.start()
                journal.emit(event())
                with self.assertRaisesRegex(Rejected, "audit_failed"):
                    journal.close()
            self.assertGreater(path.stat().st_size, 0)
            self.assertEqual(journal.status()["durable"], 0)
            self.assertEqual(journal.status()["unconfirmed"], 1)

    def test_concurrent_emitters_have_unique_ordered_sequences(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.jsonl"
            journal = serving_audit.Journal(path)
            journal.start()
            with ThreadPoolExecutor(max_workers=16) as executor:
                sequences = list(executor.map(lambda attempt: journal.emit(event()), range(32)))
            journal.close()
            self.assertEqual(sorted(sequences), list(range(1, 33)))
            records = [decode(line) for line in path.read_bytes().splitlines()]
            self.assertEqual([record["sequence"] for record in records], list(range(1, 33)))
            self.assertEqual(journal.status()["accepted"], journal.status()["durable"])
            self.assertEqual(journal.status()["unconfirmed"], 0)

    def test_limit_configuration_and_closed_lifecycle_fail_before_writing(self):
        for changes in (
            {"capacity": True},
            {"capacity": 0},
            {"capacity": 65},
            {"max_bytes": 2047},
            {"max_bytes": 2**30},
            {"max_bytes": 2048.0},
        ):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "audit.jsonl"
                with self.assertRaisesRegex(Rejected, "audit_limits_invalid"):
                    serving_audit.Journal(path, **changes)
                self.assertFalse(path.exists())
        with self.assertRaisesRegex(Rejected, "audit_path_rejected"):
            serving_audit.Journal(Path("audit-relative.jsonl"))
        with tempfile.TemporaryDirectory() as temporary:
            journal = serving_audit.Journal(Path(temporary) / "audit.jsonl")
            for invalid in (True, -1, 6, float("inf"), float("nan"), "1"):
                with self.assertRaisesRegex(Rejected, "audit_close_timeout_invalid"):
                    journal.close(invalid)
            with self.assertRaisesRegex(Rejected, "audit_failed"):
                journal.close()
            with self.assertRaisesRegex(Rejected, "audit_failed"):
                journal.close()
            with self.assertRaisesRegex(Rejected, "audit_start_rejected"):
                journal.start()
            with self.assertRaisesRegex(Rejected, "audit_unavailable"):
                journal.emit(event())

    def test_thread_start_failure_before_and_after_dispatch_is_owned(self):
        for launched in (False, True):
            with self.subTest(launched=launched), tempfile.TemporaryDirectory() as temporary:
                journal = serving_audit.Journal(Path(temporary) / "audit.jsonl")
                original = threading.Thread.start

                def failed(thread):
                    if launched:
                        original(thread)
                    raise RuntimeError("CANARY_THREAD_SECRET")

                with patch.object(threading.Thread, "start", failed):
                    with self.assertRaisesRegex(Rejected, "audit_thread_start"):
                        journal.start()
                with self.assertRaisesRegex(Rejected, "audit_failed"):
                    journal.close()
                self.assertTrue(journal.status()["closed"])
                self.assertFalse(journal.status()["healthy"])
                self.assertNotIn("CANARY", str(journal.status()))

    def test_thread_construction_and_unknown_producer_errors_are_redacted(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = serving_audit.Journal(Path(temporary) / "audit.jsonl")
            with patch.object(
                serving_audit.threading, "Thread", side_effect=RuntimeError("CANARY")
            ):
                with self.assertRaisesRegex(Rejected, "audit_thread_start"):
                    journal.start()
            with self.assertRaisesRegex(Rejected, "audit_failed"):
                journal.close()
        for exception in (RuntimeError("CANARY"), Rejected("CANARY")):
            with self.subTest(kind=type(exception)), tempfile.TemporaryDirectory() as temporary:
                journal = serving_audit.Journal(Path(temporary) / "audit.jsonl")
                journal.start()
                with patch.object(serving_audit, "canonical", side_effect=exception):
                    with self.assertRaisesRegex(Rejected, "audit_producer_failed") as failure:
                        journal.emit(event())
                with self.assertRaisesRegex(Rejected, "audit_failed"):
                    journal.close()
                self.assertNotIn("CANARY", str(failure.exception))
                self.assertNotIn("CANARY", str(journal.status()))

    def test_serialization_uses_the_validated_copy_not_mutable_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.jsonl"
            journal = serving_audit.Journal(path)
            source = event()
            original = serving_audit.canonical

            def serialize(snapshot):
                source["raw_body"] = "CANARY"
                source["release"]["model_sha256"] = "CANARY"
                return original(snapshot)

            journal.start()
            with patch.object(serving_audit, "canonical", serialize):
                journal.emit(source)
            journal.close()
            self.assertEqual(decode(path.read_bytes())["event"], event())
            self.assertNotIn(b"CANARY", path.read_bytes())

    def test_byte_limit_rejects_before_acceptance_and_preserves_existing_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.jsonl"
            journal = serving_audit.Journal(path, max_bytes=2048)
            journal.start()
            with self.assertRaisesRegex(Rejected, "audit_capacity_exhausted"):
                for attempt in range(10):
                    journal.emit(event())
            accepted = journal.status()["accepted"]
            with self.assertRaisesRegex(Rejected, "audit_unavailable"):
                journal.emit(event())
            with self.assertRaisesRegex(Rejected, "audit_failed"):
                journal.close()
            records = path.read_bytes().splitlines()
            self.assertEqual(accepted, len(records))
            self.assertEqual(journal.status()["durable"], accepted)
            self.assertLessEqual(path.stat().st_size, 2048)

    def test_real_file_is_exclusive_private_and_contains_owned_snapshots(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.jsonl"
            journal = serving_audit.Journal(path)
            with self.assertRaises(Rejected):
                journal.emit(event())
            journal.start()
            source = event()
            self.assertEqual(journal.emit(source), 1)
            source["release"]["model_sha256"] = "f" * 64
            self.assertEqual(journal.emit(event()), 2)
            journal.close()
            journal.close()
            records = [decode(line) for line in path.read_bytes().splitlines()]
            self.assertEqual([record["sequence"] for record in records], [1, 2])
            self.assertEqual([record["event"] for record in records], [event(), event()])
            self.assertEqual(journal.status()["durable"], 2)
            self.assertEqual(journal.status()["pending"], 0)
            self.assertEqual(journal.status()["unconfirmed"], 0)
            self.assertFalse(journal.status()["healthy"])
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            original = path.read_bytes()
            with self.assertRaises(Rejected):
                serving_audit.Journal(path)
            self.assertEqual(path.read_bytes(), original)

    def test_bounded_pending_includes_active_write_and_shutdown_retains_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = serving_audit.Journal(Path(temporary) / "audit.jsonl", capacity=2)
            entered, resume = threading.Event(), threading.Event()
            original = os.write

            def blocked(descriptor, content):
                entered.set()
                if not resume.wait(5):
                    raise OSError("test_wait_expired")
                return original(descriptor, content)

            with patch.object(serving_audit.os, "write", blocked):
                try:
                    journal.start()
                    journal.emit(event())
                    self.assertTrue(entered.wait(2))
                    journal.emit(event())
                    with self.assertRaisesRegex(Rejected, "audit_queue_full"):
                        journal.emit(event())
                    self.assertEqual(journal.status()["pending"], 2)
                    self.assertFalse(journal.status()["healthy"])
                    with self.assertRaisesRegex(Rejected, "audit_shutdown_pending"):
                        journal.close(timeout=0.01)
                    self.assertTrue(journal.thread.is_alive())
                    with self.assertRaises(Rejected):
                        journal.start()
                finally:
                    resume.set()
                    with self.assertRaisesRegex(Rejected, "audit_failed"):
                        journal.close()
            self.assertEqual(journal.status()["durable"], 2)
            self.assertEqual(journal.status()["pending"], 0)

    def test_event_allowlist_never_serializes_canary_or_exception_text(self):
        mutations = (
            {"raw_body": "CANARY_SECRET_123"},
            {"route": "/private/CANARY_SECRET_123"},
            {"request_id": "CANARY_SECRET_123"},
            {"principal_id": "CANARY_SECRET_123"},
            {"status": True},
            {"stage": "CANARY_SECRET_123"},
            {"release": None},
        )
        for changes in mutations:
            with self.subTest(fields=list(changes)), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "audit.jsonl"
                journal = serving_audit.Journal(path)
                journal.start()
                with self.assertRaisesRegex(Rejected, "audit_event_invalid") as failure:
                    journal.emit({**event(), **copy.deepcopy(changes)})
                with self.assertRaisesRegex(Rejected, "audit_failed"):
                    journal.close()
                self.assertEqual(path.read_bytes(), b"")
                self.assertNotIn("CANARY", str(failure.exception))
                self.assertNotIn("CANARY", str(journal.status()))


if __name__ == "__main__":
    unittest.main()
