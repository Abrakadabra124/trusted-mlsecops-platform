import copy
import os
import tempfile
import threading
import time
import unittest
from contextlib import nullcontext, suppress
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops import audit_retention, serving_audit
from mlsecops.contracts import Rejected, canonical, decode
from scripts.serving_audit_qualification import event


class PolicyContracts(unittest.TestCase):
    def test_each_inventory_scan_has_an_independent_directory_cursor(self):
        spool = audit_retention.Spool.__new__(audit_retention.Spool)
        spool.directory = 71
        spool.policy = audit_retention.Policy()
        visited = set()

        def scan(descriptor):
            names = [] if descriptor in visited else [SimpleNamespace(name=".lease")]
            visited.add(descriptor)
            return nullcontext(iter(names))

        system = SimpleNamespace(
            O_RDONLY=0,
            O_DIRECTORY=1,
            open=Mock(side_effect=[72, 73]),
            close=Mock(),
            scandir=scan,
        )
        with patch.object(audit_retention, "os", system):
            self.assertEqual(spool._names(), {".lease"})
            self.assertEqual(spool._names(), {".lease"})
        self.assertEqual([call.args for call in system.close.call_args_list], [(72,), (73,)])

    def test_closed_spool_never_resolves_names_against_current_directory(self):
        spool = audit_retention.Spool.__new__(audit_retention.Spool)
        spool.directory = None
        with self.assertRaisesRegex(Rejected, "audit_spool_closed"):
            spool.write(b"{}\n")
        with self.assertRaisesRegex(Rejected, "audit_spool_closed"):
            spool.maintain()

    def test_startup_cleanup_failure_does_not_leak_original_exception(self):
        with (
            patch.object(audit_retention.os, "name", "posix"),
            patch.object(audit_retention.Spool, "close", side_effect=OSError("PRIVATE_CANARY")),
        ):
            with self.assertRaisesRegex(Rejected, "audit_spool_open"):
                audit_retention.Spool("relative", audit_retention.Policy(), 2**24)

    def test_invalid_policy_never_creates_files(self):
        for field, value in (
            ("segment_bytes", True),
            ("segment_bytes", 2047),
            ("segment_bytes", 16 * 1024 * 1024 + 1),
            ("max_segments", 0),
            ("max_segments", 65),
            ("rotate_seconds", 0),
            ("rotate_seconds", 3601),
            ("retain_seconds", False),
            ("retain_seconds", 0),
            ("retain_seconds", 86401),
        ):
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as root:
                policy = audit_retention.Policy(**{field: value})
                with self.assertRaisesRegex(Rejected, "audit_retention_policy"):
                    audit_retention.Spool(Path(root), policy, 16 * 1024 * 1024)
                self.assertEqual(list(Path(root).iterdir()), [])

    def test_policy_is_immutable_and_has_explicit_payload_budget(self):
        policy = audit_retention.Policy()
        with self.assertRaises(AttributeError):
            policy.retain_seconds = 1
        with self.assertRaisesRegex(Rejected, "audit_retention_policy"):
            policy.validate(2048)
        self.assertEqual(policy.validate(16 * 1024 * 1024), policy)


class JournalIntegration(unittest.TestCase):
    def test_retained_budget_and_sequence_are_restored_before_admission(self):
        spool = Mock(retained_bytes=2048, sequence=19)
        spool.maintain.return_value = 0
        with patch.object(audit_retention, "Spool", return_value=spool):
            journal = serving_audit.Journal(
                Path.cwd(), max_bytes=2048, retention=audit_retention.Policy()
            )
            journal.start()
            try:
                with self.assertRaisesRegex(Rejected, "audit_capacity_exhausted"):
                    journal.emit(event())
            finally:
                with suppress(Rejected):
                    journal.close()
        spool.write.assert_not_called()
        spool.close.assert_called_once_with(clean=False)


class ClockContracts(unittest.TestCase):
    def test_invalid_clock_and_boot_changes_do_not_authorize_expiry(self):
        anchor = {"boot": "test-boot", "wall": 10**12, "mono": 10**10}
        for wall, mono, boot in (
            (10**12 - 1, 10**10, "test-boot"),
            (10**12, 10**10 - 1, "test-boot"),
            (10**12 + 2_000_000_000, 10**10, "test-boot"),
            (10**12, 10**10, "other-boot"),
            (True, 10**10, "test-boot"),
            (10**12, float("nan"), "test-boot"),
        ):
            with (
                self.subTest(wall=wall, mono=mono, boot=boot),
                patch.object(audit_retention, "boot_id", return_value=boot),
                patch.object(
                    audit_retention,
                    "time",
                    SimpleNamespace(time_ns=lambda: wall, monotonic_ns=lambda: mono),
                ),
                self.assertRaisesRegex(Rejected, "audit_retention_clock"),
            ):
                audit_retention.Clock(anchor)


def record(sequence):
    return (
        canonical(
            {"schema_version": 1, "sequence": sequence, "recorded_at_ns": 1, "event": event()}
        )
        + b"\n"
    )


@unittest.skipUnless(os.name == "posix", "native retained filesystem requires Linux CI")
class NativeRetention(unittest.TestCase):
    def setUp(self):
        self.elapsed = 0
        replacement = SimpleNamespace(
            time_ns=lambda: 1_790_000_000_000_000_000 + self.elapsed,
            monotonic_ns=lambda: 10_000_000_000 + self.elapsed,
        )
        patcher = patch.object(audit_retention, "time", replacement)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy = audit_retention.Policy(
            segment_bytes=2048, max_segments=4, rotate_seconds=1, retain_seconds=2
        )

    def spool(self, **changes):
        spool = audit_retention.Spool(
            self.root, changes.get("policy", self.policy), changes.get("budget", 8192)
        )
        self.addCleanup(lambda: spool.close(clean=False))
        return spool

    def test_repeated_native_inventory_does_not_reuse_directory_cursor(self):
        spool = self.spool()
        for _attempt in range(4):
            self.assertEqual(spool.maintain(), 0)
            self.assertEqual(spool._names(), {".lease"})
        spool.close(clean=True)

    def test_corrupt_manifest_or_changed_policy_never_purges_data(self):
        changes = (
            ("schema_version", True),
            ("budget", 8193),
            ("sequence", -1),
            ("next_index", -1),
            ("segments", {}),
            (
                "policy",
                {
                    "segment_bytes": 2048,
                    "max_segments": 4,
                    "rotate_seconds": True,
                    "retain_seconds": 2,
                },
            ),
        )
        segment_changes = (
            ("name", "../outside"),
            ("name", "0000000000000000.jsonl"),
            ("sha256", "g" * 64),
            ("size", 0),
            ("size", 2049),
            ("first", -1),
            ("last", -1),
            ("identity", [0, 0]),
            ("identity", [True, 0]),
        )
        for field, value, segment in [(field, value, False) for field, value in changes] + [
            (field, value, True) for field, value in segment_changes
        ]:
            with (
                self.subTest(field=field, segment=segment),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                spool = audit_retention.Spool(root, self.policy, 8192)
                spool.write(record(1))
                spool.close(clean=True)
                path = next(root.glob("*.jsonl"))
                expected = path.read_bytes()
                saved = decode((root / "manifest.json").read_bytes())
                target = saved["segments"][0] if segment else saved
                target[field] = copy.deepcopy(value)
                (root / "manifest.json").write_bytes(canonical(saved))
                with self.assertRaisesRegex(Rejected, "audit_spool_open"):
                    audit_retention.Spool(root, self.policy, 8192)
                self.assertEqual(path.read_bytes(), expected)

    def test_private_parent_platform_and_unknown_inventory_bound(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(Rejected, "audit_spool_open"):
            self.spool()
        self.assertEqual(list(self.root.iterdir()), [])
        self.root.chmod(0o700)
        for index in range(8):
            (self.root / str(index)).write_bytes(b"FOREIGN")
        with self.assertRaisesRegex(Rejected, "audit_spool_open"):
            self.spool()
        self.assertEqual(
            [(self.root / str(index)).read_bytes() for index in range(8)], [b"FOREIGN"] * 8
        )

    def test_short_writes_and_failed_sync_preserve_unconfirmed_segment(self):
        spool = self.spool()
        original = os.write
        with patch.object(
            audit_retention.os,
            "write",
            lambda descriptor, content: original(descriptor, content[:7]),
        ):
            spool.write(record(1))
        self.assertEqual(next(self.root.glob("*.jsonl")).read_bytes(), record(1))
        with patch.object(audit_retention.os, "fsync", side_effect=OSError("PRIVATE_CANARY")):
            with self.assertRaises(OSError):
                spool.write(record(2))
        self.assertEqual(spool.sequence, 1)
        self.assertEqual(spool.retained_bytes, len(record(1)))
        spool.close(clean=False)
        with self.assertRaisesRegex(Rejected, "audit_spool_open"):
            self.spool()

    def test_lease_capture_precedes_snapshot_even_with_interleaved_clean_writer(self):
        entered, resume = threading.Event(), threading.Event()
        original = audit_retention.Spool._new
        first_thread = [None]
        result = []
        failures = []

        def create(spool, name, content):
            if name == ".lease" and threading.get_ident() == first_thread[0]:
                entered.set()
                if not resume.wait(5):
                    raise RuntimeError("test_timeout")
            return original(spool, name, content)

        def worker():
            first_thread[0] = threading.get_ident()
            try:
                result.append(audit_retention.Spool(self.root, self.policy, 8192))
            except Exception as error:
                failures.append(type(error).__name__)

        with patch.object(audit_retention.Spool, "_new", create):
            thread = threading.Thread(target=worker)
            thread.start()
            try:
                self.assertTrue(entered.wait(2))
                second = self.spool()
                second.write(record(1))
                second.close(clean=True)
            finally:
                resume.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(result[0].sequence, 1)
        result[0].close(clean=True)

    def test_rotation_readback_and_restart_preserve_sequence_budget_and_age(self):
        spool = self.spool()
        for sequence in range(1, 11):
            spool.write(record(sequence))
        self.assertGreater(len(spool.segments), 1)
        self.assertTrue(all(segment["size"] <= 2048 for segment in spool.segments))
        self.assertEqual(
            [
                decode(line)["sequence"]
                for segment in spool.segments
                for line in (self.root / segment["name"]).read_bytes().splitlines()
            ],
            list(range(1, 11)),
        )
        stored = spool.retained_bytes
        spool.close(clean=True)
        self.elapsed = 1_000_000_000
        resumed = self.spool()
        self.assertEqual((resumed.sequence, resumed.retained_bytes), (10, stored))
        self.assertEqual(resumed.maintain(), 0)
        self.elapsed = 2_000_000_000
        self.assertEqual(resumed.maintain(), stored)
        self.assertEqual(list(self.root.glob("*.jsonl")), [])
        resumed.write(record(11))
        resumed.close(clean=True)

    def test_young_segments_are_not_evicted_to_bypass_file_or_byte_cap(self):
        for count, budget in ((1, 8192), (4, 2048)):
            with tempfile.TemporaryDirectory() as temporary:
                policy = audit_retention.Policy(2048, count, 1, 2)
                spool = audit_retention.Spool(Path(temporary), policy, budget)
                try:
                    accepted = 0
                    with self.assertRaisesRegex(Rejected, "audit_spool_capacity"):
                        for sequence in range(1, 30):
                            spool.write(record(sequence))
                            accepted += 1
                    self.assertGreater(accepted, 0)
                    self.assertLessEqual(spool.retained_bytes, budget)
                    self.assertLessEqual(len(spool.segments), count)
                    self.assertEqual(
                        sum(path.stat().st_size for path in Path(temporary).glob("*.jsonl")),
                        spool.retained_bytes,
                    )
                finally:
                    spool.close(clean=False)

    def test_background_maintenance_expires_idle_journal_and_keeps_global_sequence(self):
        journal = serving_audit.Journal(self.root, max_bytes=8192, retention=self.policy)
        journal.start()
        try:
            self.assertEqual(journal.emit(event()), 1)
            for _attempt in range(200):
                if journal.status()["durable"] == 1:
                    break
                time.sleep(0.005)
            self.assertEqual(journal.status()["durable"], 1)
            self.elapsed = 3_000_000_000
            for _attempt in range(200):
                if journal.status()["reserved_bytes"] == 0:
                    break
                time.sleep(0.005)
            self.assertEqual(journal.status()["reserved_bytes"], 0)
            self.assertEqual(list(self.root.glob("*.jsonl")), [])
        finally:
            journal.close()
        reopened = serving_audit.Journal(self.root, max_bytes=8192, retention=self.policy)
        reopened.start()
        try:
            self.assertEqual(reopened.emit(event()), 2)
        finally:
            reopened.close()

    def test_foreign_file_and_changed_segment_are_preserved(self):
        spool = self.spool()
        spool.write(record(1))
        segment = self.root / spool.segments[0]["name"]
        original = segment.read_bytes()
        segment.write_bytes(b"X" + original[1:])
        self.elapsed = 3_000_000_000
        with self.assertRaisesRegex(Rejected, "audit_spool_identity"):
            spool.maintain()
        self.assertEqual(segment.read_bytes(), b"X" + original[1:])
        segment.write_bytes(original)
        (self.root / "foreign").write_bytes(b"DO_NOT_DELETE")
        with self.assertRaisesRegex(Rejected, "audit_spool_inventory"):
            spool.maintain()
        self.assertTrue(segment.exists())
        self.assertEqual((self.root / "foreign").read_bytes(), b"DO_NOT_DELETE")

    def test_concurrent_open_and_interrupted_session_never_remove_owner_lease(self):
        spool = self.spool()
        lease = (self.root / ".lease").read_bytes()
        with self.assertRaisesRegex(Rejected, "audit_spool_open"):
            self.spool()
        self.assertEqual((self.root / ".lease").read_bytes(), lease)
        spool.write(record(1))
        spool.close(clean=False)
        with self.assertRaisesRegex(Rejected, "audit_spool_open"):
            self.spool()
        self.assertEqual((self.root / ".lease").read_bytes(), lease)
        self.assertEqual(len(list(self.root.glob("*.jsonl"))), 1)

    def test_parent_rename_cannot_redirect_writes_or_cleanup(self):
        private = self.root / "private"
        private.mkdir(mode=0o700)
        spool = audit_retention.Spool(private, self.policy, 8192)
        retained = self.root / "retained"
        private.rename(retained)
        private.mkdir(mode=0o700)
        sentinel = private / ".lease"
        sentinel.write_bytes(b"FOREIGN")
        try:
            spool.write(record(1))
            spool.close(clean=True)
            self.assertEqual(sentinel.read_bytes(), b"FOREIGN")
            self.assertEqual(len(list(retained.glob("*.jsonl"))), 1)
            self.assertTrue((retained / "manifest.json").exists())
        finally:
            spool.close(clean=False)

    def test_unlink_sync_failure_returns_no_storage_credit_and_keeps_guard(self):
        spool = self.spool()
        spool.write(record(1))
        before = spool.retained_bytes
        self.elapsed = 3_000_000_000
        with patch.object(audit_retention.os, "fsync", side_effect=OSError("PRIVATE_CANARY")):
            with self.assertRaises(OSError):
                spool.maintain()
        self.assertEqual(spool.retained_bytes, before)
        self.assertTrue((self.root / ".lease").exists())
        self.assertEqual(list(self.root.glob("*.jsonl")), [])

    def test_failed_manifest_replace_preserves_guard_and_closed_data(self):
        spool = self.spool()
        spool.write(record(1))
        with patch.object(audit_retention.os, "replace", side_effect=OSError("PRIVATE_CANARY")):
            with self.assertRaises(OSError):
                spool.close(clean=True)
        self.assertTrue((self.root / ".lease").exists())
        self.assertTrue((self.root / ".next").exists())
        self.assertEqual(len(list(self.root.glob("*.jsonl"))), 1)

    def test_symlink_and_hardlink_do_not_authorize_expiry(self):
        spool = self.spool()
        spool.write(record(1))
        segment = self.root / spool.segments[0]["name"]
        with tempfile.TemporaryDirectory() as external:
            hardlink = Path(external) / "retained"
            os.link(segment, hardlink)
            self.elapsed = 3_000_000_000
            with self.assertRaisesRegex(Rejected, "audit_spool_identity"):
                spool.maintain()
            self.assertTrue(hardlink.exists())
            hardlink.unlink()
            original = segment.read_bytes()
            segment.unlink()
            target = Path(external) / "target"
            target.write_bytes(original)
            segment.symlink_to(target)
            with self.assertRaises(OSError):
                spool.maintain()
            self.assertEqual(target.read_bytes(), original)

    def test_handoff_cleanup_error_never_changes_new_owners_lease(self):
        first = self.spool()
        first.write(record(1))
        original = os.fsync
        second = []
        armed = True

        def sync(descriptor):
            nonlocal armed
            if armed and descriptor == first.directory and not (self.root / ".lease").exists():
                armed = False
                second.append(self.spool())
                raise OSError("cleanup_failed_after_handoff")
            return original(descriptor)

        with patch.object(audit_retention.os, "fsync", sync):
            with self.assertRaises(OSError):
                first.close(clean=True)
        self.assertTrue(first.released)
        self.assertEqual(second[0].sequence, 1)
        lease = (self.root / ".lease").read_bytes()
        first.close(clean=False)
        self.assertEqual((self.root / ".lease").read_bytes(), lease)
        second[0].write(record(2))
        second[0].close(clean=True)


class RetainedJournalContracts(unittest.TestCase):
    def test_reclaimed_bytes_allow_new_records_without_resetting_sequence(self):
        spool = Mock(retained_bytes=2048, sequence=19)
        spool.maintain.side_effect = [2048] + [0] * 100
        with patch.object(audit_retention, "Spool", return_value=spool):
            journal = serving_audit.Journal(
                Path.cwd(), max_bytes=2048, retention=audit_retention.Policy()
            )
            journal.start()
            try:
                for _attempt in range(100):
                    if journal.status()["reserved_bytes"] == 0:
                        break
                    time.sleep(0.005)
                self.assertEqual(journal.emit(event()), 20)
            finally:
                journal.close()
        self.assertEqual(journal.status()["accepted"], 1)
        self.assertEqual(journal.status()["durable"], 1)
        spool.close.assert_called_once_with(clean=True)

    def test_retention_failure_is_sticky_and_never_exports_raw_exception(self):
        spool = Mock(retained_bytes=0, sequence=0)
        spool.maintain.side_effect = OSError("PRIVATE_CANARY")
        with patch.object(audit_retention, "Spool", return_value=spool):
            journal = serving_audit.Journal(Path.cwd(), retention=audit_retention.Policy())
            journal.start()
            with self.assertRaisesRegex(Rejected, "audit_failed"):
                journal.close()
        self.assertEqual(journal.status()["failure"], "sink_failed")
        self.assertNotIn("PRIVATE_CANARY", str(journal.status()))
        spool.close.assert_called_once_with(clean=False)


if __name__ == "__main__":
    unittest.main()
