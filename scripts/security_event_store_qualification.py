"""Linux filesystem crash/retry contracts. No database or container is started."""

import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from mlsecops import security_event_store as storage
from mlsecops.contracts import Rejected, canonical
from scripts import security_event_ledger_qualification as fixtures


class UnsupportedHost(unittest.TestCase):
    def test_unsupported_platform_fails_before_mutation(self):
        with (
            patch.object(storage.sys, "platform", "win32"),
            patch.object(storage.os, "open") as opened,
        ):
            with self.assertRaises(Rejected):
                storage.Store("relative", "a" * 64, None)
            opened.assert_not_called()


@unittest.skipUnless(sys.platform == "linux", "Linux private directory handles required")
class DurableStore(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.LedgerContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.root = self.fx.fixture.directory / "journal"
        self.pin = storage.initialize(str(self.root), self.fx.registry, clock_ms=2000)
        self.store = storage.Store(str(self.root), self.pin, self.fx.registry)

    def reopen(self):
        return storage.Store(str(self.root), self.pin, self.fx.registry)

    def test_restart_retains_pending_and_acked_records_with_exact_retry(self):
        envelope = self.fx.envelope()
        record = self.store.ingest(envelope, clock_ms=2100)
        self.assertEqual(self.reopen().ingest(envelope, clock_ms=2200), record)
        ack = self.fx.receipt(record)
        acknowledged = self.reopen().acknowledge(ack, clock_ms=2300)
        before = (self.root / "state").read_bytes()
        self.assertEqual(self.reopen().ingest(envelope, clock_ms=2400), acknowledged)
        self.assertEqual(self.reopen().acknowledge(ack, clock_ms=2500), acknowledged)
        self.assertEqual((self.root / "state").read_bytes(), before)
        self.assertEqual(len(self.reopen().snapshot()["records"]), 1)

    def test_missing_identity_state_wrong_pin_and_unknown_files_never_initialize(self):
        with self.assertRaises(Rejected):
            storage.initialize(str(self.root), self.fx.registry, clock_ms=2000)
        with self.assertRaises(Rejected):
            storage.Store(str(self.root), "f" * 64, self.fx.registry).snapshot()
        for name in ("identity", "state"):
            original = (self.root / name).read_bytes()
            (self.root / name).unlink()
            with self.assertRaises(Rejected):
                self.reopen().snapshot()
            (self.root / name).write_bytes(original)
            (self.root / name).chmod(0o600)
        (self.root / "unknown").touch(mode=0o600)
        with self.assertRaises(Rejected):
            self.reopen().snapshot()

    def test_partial_write_and_pre_rename_failure_preserve_previous_commit(self):
        initial = (self.root / "state").read_bytes()
        with patch.object(storage.os, "write", side_effect=OSError("PRIVATE-CANARY")):
            with self.assertRaises(Rejected):
                self.store.ingest(self.fx.envelope(), clock_ms=2100)
        self.assertEqual(self.reopen().snapshot()["records"], [])
        self.assertEqual((self.root / "state").read_bytes(), initial)
        self.assertFalse((self.root / ".pending").exists())
        with patch.object(storage.os, "replace", side_effect=OSError("PRIVATE-CANARY")):
            with self.assertRaises(Rejected):
                self.store.ingest(self.fx.envelope(), clock_ms=2100)
        self.assertEqual(self.reopen().snapshot()["records"], [])
        self.assertEqual(len(self.store.ingest(self.fx.envelope(), clock_ms=2200)), 4)

    def test_unknown_outcome_after_rename_recovers_once_without_duplicate(self):
        original = storage.os.replace

        def renamed_then_failed(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("simulated failure after rename")

        envelope = self.fx.envelope()
        with patch.object(storage.os, "replace", side_effect=renamed_then_failed):
            with self.assertRaises(Rejected):
                self.store.ingest(envelope, clock_ms=2100)
        restored = self.reopen().snapshot()
        self.assertEqual(len(restored["records"]), 1)
        self.assertEqual(self.reopen().ingest(envelope, clock_ms=2300), restored["records"][0])

    def test_corrupt_state_and_noncanonical_state_are_not_repaired(self):
        valid = (self.root / "state").read_bytes()
        for content in (b"{", b" " + valid, b"{}", b"x" * (storage.MAX_BYTES + 1)):
            (self.root / "state").write_bytes(content)
            with self.assertRaises(Rejected):
                self.reopen().snapshot()
            self.assertEqual((self.root / "state").read_bytes(), content)

    def test_symlink_hardlink_permissions_and_lock_contention_are_rejected(self):
        import fcntl

        original = (self.root / "state").read_bytes()
        outside = self.root.parent / "outside"
        outside.write_bytes(original)
        outside.chmod(0o600)
        for fault in ("symlink", "hardlink", "permissions"):
            (self.root / "state").unlink()
            if fault == "symlink":
                (self.root / "state").symlink_to(outside)
            elif fault == "hardlink":
                os.link(outside, self.root / "state")
            else:
                (self.root / "state").write_bytes(original)
                (self.root / "state").chmod(0o644)
            with self.subTest(fault=fault), self.assertRaises(Rejected):
                self.reopen().snapshot()
        (self.root / "state").unlink()
        (self.root / "state").write_bytes(original)
        (self.root / "state").chmod(0o600)
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(Rejected):
                self.reopen().snapshot()
        finally:
            os.close(fd)
        self.root.chmod(0o755)
        with self.assertRaises(Rejected):
            self.reopen().snapshot()

    def test_abrupt_child_exit_with_partial_pending_file_preserves_committed_record(self):
        self.store.ingest(self.fx.envelope(), clock_ms=2100)
        # No finally/cleanup runs in this child. Its private pending bytes survive.
        code = "import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,b'{');os.fsync(fd);os._exit(23)"
        result = subprocess.run(
            [sys.executable, "-c", code, str(self.root / ".pending")],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 23)
        self.assertEqual((result.stdout, result.stderr), (b"", b""))
        self.assertEqual(len(self.reopen().snapshot()["records"]), 1)
        self.assertFalse((self.root / ".pending").exists())
        self.assertEqual(set(p.name for p in self.root.iterdir()), {"identity", "state"})

    def test_real_process_reads_and_verifies_record_after_parent_commit(self):
        self.store.ingest(self.fx.envelope(), clock_ms=2100)
        config_file = self.root.parent / "config"
        from mlsecops import signing

        config_file.write_bytes(
            canonical(
                signing.sign(
                    self.fx.fixture.document, "security-event-config", self.fx.fixture.keys["root"]
                )
            )
        )
        code = "import sys;from pathlib import Path;from mlsecops.contracts import decode;from mlsecops.security_event_config import Registry;from mlsecops.security_event_store import Store;r=Registry(decode(Path(sys.argv[3]).read_bytes()),trusted_root=sys.argv[4],expected_sha256=sys.argv[5],clock_ms=2200);assert len(Store(sys.argv[1],sys.argv[2],r).snapshot()['records'])==1"
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                code,
                str(self.root),
                self.pin,
                str(config_file),
                self.fx.fixture.publics["root"],
                self.fx.registry.sha256,
            ],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"")

    def test_abrupt_exit_inside_real_store_before_and_after_rename_is_retryable(self):
        from mlsecops import signing

        config_file = self.root.parent / "crash-config"
        config_file.write_bytes(
            canonical(
                signing.sign(
                    self.fx.fixture.document, "security-event-config", self.fx.fixture.keys["root"]
                )
            )
        )
        event_file = self.root.parent / "crash-event"
        event_file.write_bytes(canonical(self.fx.envelope()))
        code = """
import os, sys
from pathlib import Path
from mlsecops.contracts import decode
from mlsecops.security_event_config import Registry
from mlsecops.security_event_store import Store
registry = Registry(decode(Path(sys.argv[3]).read_bytes()), trusted_root=sys.argv[4], expected_sha256=sys.argv[5], clock_ms=2100)
original = os.replace
def crash(*args, **kwargs):
    if sys.argv[7] == 'after':
        original(*args, **kwargs)
    os._exit(23)
os.replace = crash
Store(sys.argv[1], sys.argv[2], registry).ingest(decode(Path(sys.argv[6]).read_bytes()), clock_ms=2100)
"""
        for point, count in (("before", 0), ("after", 1)):
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    code,
                    str(self.root),
                    self.pin,
                    str(config_file),
                    self.fx.fixture.publics["root"],
                    self.fx.registry.sha256,
                    str(event_file),
                    point,
                ],
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 23, result.stderr.decode())
            self.assertEqual((result.stdout, result.stderr), (b"", b""))
            self.assertEqual(len(self.reopen().snapshot()["records"]), count)
        original = self.reopen().snapshot()["records"][0]
        self.assertEqual(self.reopen().ingest(self.fx.envelope(), clock_ms=2200), original)
        self.assertFalse((self.root / ".pending").exists())

    def test_invalid_path_pin_and_symlink_root_do_not_open_another_journal(self):
        for root, pin in (("relative", self.pin), (None, self.pin), (str(self.root), "invalid")):
            with self.subTest(root=root), self.assertRaises(Rejected):
                storage.Store(root, pin, self.fx.registry)
        alias = self.root.parent / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(Rejected):
            storage.Store(str(alias), self.pin, self.fx.registry).snapshot()

    def test_file_growth_and_metadata_change_during_read_are_rejected(self):
        state_file = self.root / "state"
        before = state_file.read_bytes()
        actual_read = storage.os.read
        for fault in ("growth", "metadata"):
            state_file.write_bytes(before)
            inode = state_file.stat().st_ino
            changed = False

            def change_during_read(descriptor, size):
                nonlocal changed
                if not changed and os.fstat(descriptor).st_ino == inode:
                    changed = True
                    if fault == "growth":
                        with state_file.open("ab") as output:
                            output.write(b"x")
                    else:
                        metadata = state_file.stat()
                        os.utime(
                            state_file, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1000000)
                        )
                return actual_read(descriptor, size)

            with storage.locked(str(self.root)) as directory:
                with patch.object(storage.os, "read", side_effect=change_during_read):
                    with self.subTest(fault=fault), self.assertRaises(Rejected):
                        storage.read(directory, "state", limit=len(before))
            self.assertTrue(changed)

    def test_short_writes_finish_but_zero_write_never_acknowledges_commit(self):
        actual_write = storage.os.write
        with patch.object(
            storage.os, "write", side_effect=lambda fd, data: actual_write(fd, data[:7])
        ):
            first = self.store.ingest(self.fx.envelope(), clock_ms=2100)
        self.assertEqual(self.reopen().snapshot()["records"], [first])
        with patch.object(storage.os, "write", return_value=0):
            with self.assertRaises(Rejected):
                self.store.ingest(self.fx.envelope(2), clock_ms=2200)
        self.assertEqual(self.reopen().snapshot()["records"], [first])

    def test_bad_readback_has_unknown_outcome_resolved_by_exact_retry(self):
        actual_read = storage.read
        count = 0

        def corrupted_readback(descriptor, name, limit=storage.MAX_BYTES):
            nonlocal count
            content = actual_read(descriptor, name, limit)
            if name == "state":
                count += 1
                if count == 2:
                    return b"{}"
            return content

        envelope = self.fx.envelope()
        with patch.object(storage, "read", side_effect=corrupted_readback):
            with self.assertRaises(Rejected):
                self.store.ingest(envelope, clock_ms=2100)
        original = self.reopen().snapshot()["records"]
        self.assertEqual(len(original), 1)
        self.assertEqual(self.reopen().ingest(envelope, clock_ms=2200), original[0])

    def test_snapshot_size_guard_preserves_previous_state_before_writing(self):
        original = (self.root / "state").read_bytes()
        with storage.locked(str(self.root)) as directory:
            with self.assertRaises(Rejected):
                storage.replace(directory, {"oversize": "x" * storage.MAX_BYTES})
        self.assertEqual((self.root / "state").read_bytes(), original)
        self.assertFalse((self.root / ".pending").exists())


if __name__ == "__main__":
    unittest.main()
