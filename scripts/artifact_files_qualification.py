"""Synthetic filesystem boundary tests; no services, keys or external models."""

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import contracts
from mlsecops.contracts import Rejected, atomic_write, bounded_read


class ArtifactFiles(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "artifact"
        self.path.write_bytes(b"original")

    def test_special_device_is_rejected_before_read(self):
        with self.assertRaisesRegex(Rejected, "artifact_file_type"):
            bounded_read(Path(os.devnull))

    def test_invalid_limit_is_rejected(self):
        for limit in (-1, True, 1.5, "8"):
            with self.subTest(limit=limit), self.assertRaisesRegex(Rejected, "artifact_read_limit"):
                bounded_read(self.path, limit)

    def test_change_during_read_is_rejected(self):
        original = os.fstat
        calls = []

        def metadata(descriptor):
            calls.append(descriptor)
            if len(calls) == 2:
                with self.path.open("ab") as output:
                    output.write(b"changed")
            return original(descriptor)

        with patch.object(os, "fstat", side_effect=metadata):
            with self.assertRaisesRegex(Rejected, "artifact_changed"):
                bounded_read(self.path)

    def test_oversize_rejected_without_reading_content(self):
        with patch.object(os, "fdopen") as opened:
            with self.assertRaisesRegex(Rejected, "artifact_too_large"):
                bounded_read(self.path, 3)
            opened.assert_not_called()

    def test_read_success_empty_exact_bound_and_missing(self):
        self.assertEqual(bounded_read(self.path, 8), b"original")
        self.path.write_bytes(b"")
        self.assertEqual(bounded_read(self.path, 0), b"")
        with self.assertRaisesRegex(Rejected, "artifact_unavailable"):
            bounded_read(self.root / "missing")

    def test_parent_traversal_is_rejected(self):
        for operation in (lambda p: bounded_read(p), lambda p: atomic_write(p, b"changed")):
            with self.assertRaisesRegex(Rejected, "invalid_artifact_path"):
                operation(self.root / "nested" / ".." / "artifact")
        self.assertEqual(self.path.read_bytes(), b"original")

    def test_write_failure_preserves_old_artifact_and_cleans_temporary(self):
        with patch.object(os, "fsync", side_effect=OSError("synthetic disk failure")):
            with self.assertRaisesRegex(Rejected, "artifact_unavailable"):
                atomic_write(self.path, b"changed")
        self.assertEqual(self.path.read_bytes(), b"original")
        self.assertEqual(list(self.root.glob(".pending-*")), [])

    def test_write_new_nested_file_and_replace_readback(self):
        path = self.root / "new" / "nested" / "artifact"
        atomic_write(path, b"first")
        self.assertEqual(bounded_read(path), b"first")
        atomic_write(path, b"second")
        self.assertEqual(bounded_read(path), b"second")
        self.assertEqual(list(path.parent.glob(".pending-*")), [])
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_directory_nul_and_root_reject(self):
        for path in (self.root, self.root / "bad\x00name", Path(self.root.anchor)):
            with self.subTest(path=str(path)), self.assertRaises(Rejected):
                bounded_read(path)
        with self.assertRaisesRegex(Rejected, "artifact_file_type"):
            atomic_write(self.root, b"changed")

    def test_write_collision_preserves_unowned_file(self):
        pending = self.root / (".pending-" + "a" * 32)
        pending.write_bytes(b"foreign-canary")
        with patch.object(contracts.secrets, "token_hex", return_value="a" * 32):
            with self.assertRaisesRegex(Rejected, "artifact_unavailable"):
                atomic_write(self.path, b"changed")
        self.assertEqual(pending.read_bytes(), b"foreign-canary")
        self.assertEqual(self.path.read_bytes(), b"original")

    def test_fdopen_failure_closes_descriptor_read_and_write(self):
        opened = []
        actual_open = os.open

        def remember(*args, **kwargs):
            descriptor = actual_open(*args, **kwargs)
            opened.append(descriptor)
            return descriptor

        for operation in (lambda: bounded_read(self.path), lambda: atomic_write(self.path, b"new")):
            with patch.object(os, "open", side_effect=remember):
                with patch.object(os, "fdopen", side_effect=OSError("synthetic fdopen error")):
                    with self.assertRaisesRegex(Rejected, "artifact_unavailable"):
                        operation()
            for descriptor in opened:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
        self.assertEqual(self.path.read_bytes(), b"original")
        self.assertEqual(list(self.root.glob(".pending-*")), [])

    def test_metadata_change_and_truncated_read_reject(self):
        original = os.fstat
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
        for changed in fields:
            calls = []

            def metadata(descriptor):
                actual = original(descriptor)
                values = {field: getattr(actual, field) for field in fields}
                calls.append(descriptor)
                if len(calls) == 2:
                    values[changed] = stat.S_IFDIR if changed == "st_mode" else values[changed] + 1
                return SimpleNamespace(**values)

            with self.subTest(changed=changed), patch.object(os, "fstat", side_effect=metadata):
                with self.assertRaises(Rejected):
                    bounded_read(self.path)

        fdopen = os.fdopen

        def truncate(descriptor, *args, **kwargs):
            self.path.write_bytes(b"short")
            return fdopen(descriptor, *args, **kwargs)

        with patch.object(os, "fdopen", side_effect=truncate):
            with self.assertRaisesRegex(Rejected, "artifact_changed"):
                bounded_read(self.path)

    def test_growth_past_limit_is_rejected(self):
        fdopen = os.fdopen

        def grow(descriptor, *args, **kwargs):
            with self.path.open("ab") as output:
                output.write(b"growth")
            return fdopen(descriptor, *args, **kwargs)

        with patch.object(os, "fdopen", side_effect=grow):
            with self.assertRaisesRegex(Rejected, "artifact_too_large"):
                bounded_read(self.path, 8)

    def test_non_posix_compatibility_branch_does_not_claim_acl_enforcement(self):
        compatible_os = SimpleNamespace(**{**vars(os), "name": "nt"})
        with patch.object(contracts, "os", compatible_os):
            self.assertEqual(bounded_read(self.path), b"original")
            atomic_write(self.path, b"portable")
            self.assertEqual(bounded_read(self.path), b"portable")
            with patch.object(Path, "is_junction", return_value=True):
                with self.assertRaisesRegex(Rejected, "symlink_rejected"):
                    bounded_read(self.path)

    def test_json_contracts_and_safe_child(self):
        contracts.write_json(self.path, {"value": 1})
        self.assertEqual(contracts.read_json(self.path), {"value": 1})
        self.assertEqual(contracts.safe_child(self.root, "artifact"), self.path.resolve())
        self.assertEqual(len(contracts.digest(b"content")), 64)
        self.assertIn("+00:00", contracts.now())
        contracts.require_fields({"value": 1}, ["value"])
        for value in ({"unexpected": 1}, [], None):
            with self.assertRaisesRegex(Rejected, "unexpected_fields"):
                contracts.require_fields(value, ["value"])
        for content in (b'{"x":1,"x":2}', b"NaN", b"invalid", b"\xff"):
            with self.assertRaisesRegex(Rejected, "invalid_json"):
                contracts.decode(content)
        with self.assertRaisesRegex(Rejected, "document_too_large"):
            contracts.decode(b"{}", 1)
        for value in (object(), float("nan")):
            with self.assertRaisesRegex(Rejected, "invalid_json_value"):
                contracts.canonical(value)
        for name in (
            None,
            "",
            "../artifact",
            "nested/../../escape",
            "a\\b",
            "c:escape",
            str(self.path),
        ):
            with self.assertRaises(Rejected):
                contracts.safe_child(self.root, name)

    @unittest.skipUnless(os.name == "posix", "native POSIX special-file and descriptor semantics")
    def test_fifo_without_writer_rejects_with_deadline(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        code = (
            "import sys; from mlsecops.contracts import Rejected,bounded_read; "
            "\ntry: bounded_read(sys.argv[1])"
            "\nexcept Rejected as e: print(str(e))"
            "\nelse: raise SystemExit(1)"
        )
        result = subprocess.run(
            [sys.executable, "-c", code, str(fifo)],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        self.assertEqual(result.stdout.strip(), "artifact_file_type")
        self.assertEqual(result.stderr, "")

    @unittest.skipUnless(os.name == "posix", "native POSIX no-follow semantics")
    def test_leaf_swap_at_open_cannot_read_symlink_target(self):
        foreign = self.root / "foreign"
        foreign.write_bytes(b"canary")
        actual_open = os.open

        def swap(name, flags, *args, **options):
            if name == self.path.name:
                self.path.unlink()
                self.path.symlink_to(foreign)
            return actual_open(name, flags, *args, **options)

        with patch.object(os, "open", side_effect=swap):
            with self.assertRaisesRegex(Rejected, "artifact_unavailable"):
                bounded_read(self.path)
        self.assertEqual(foreign.read_bytes(), b"canary")
        with self.assertRaisesRegex(Rejected, "symlink_rejected"):
            atomic_write(self.path, b"changed")

    @unittest.skipUnless(os.name == "posix", "native POSIX directory descriptor semantics")
    def test_parent_swap_at_read_keeps_original_opened_directory(self):
        owned = self.root / "owned"
        owned.mkdir()
        (owned / "artifact").write_bytes(b"original")
        foreign = self.root / "foreign"
        foreign.mkdir()
        (foreign / "artifact").write_bytes(b"foreign-canary")
        actual_open = os.open

        def swap(name, flags, *args, **options):
            if name == "artifact":
                owned.rename(self.root / "renamed")
                owned.symlink_to(foreign, target_is_directory=True)
            return actual_open(name, flags, *args, **options)

        with patch.object(os, "open", side_effect=swap):
            self.assertEqual(bounded_read(owned / "artifact"), b"original")

    @unittest.skipUnless(os.name == "posix", "native POSIX directory fsync")
    def test_directory_sync_failure_reports_error_but_leaves_complete_new_file(self):
        actual_sync = os.fsync

        def sync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("synthetic directory fsync failure")
            actual_sync(descriptor)

        with patch.object(os, "fsync", side_effect=sync):
            with self.assertRaisesRegex(Rejected, "artifact_unavailable"):
                atomic_write(self.path, b"new")
        self.assertEqual(bounded_read(self.path), b"new")
        self.assertEqual(list(self.root.glob(".pending-*")), [])

    @unittest.skipUnless(os.name == "posix", "native POSIX symlink semantics")
    def test_safe_child_rejects_symlinks_and_escape(self):
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(Rejected, "symlink_rejected"):
            contracts.safe_child(link, "artifact")
        with self.assertRaisesRegex(Rejected, "symlink_rejected"):
            contracts.safe_child(self.root, "link/artifact")
        link.unlink()
        link.symlink_to(self.root.parent, target_is_directory=True)
        with self.assertRaisesRegex(Rejected, "artifact_path_escape"):
            contracts.safe_child(self.root, "link/artifact")

    @unittest.skipUnless(os.name == "posix", "native POSIX directory descriptor semantics")
    def test_read_and_write_reject_symlink_in_ancestor(self):
        actual = self.root / "actual"
        (actual / "child").mkdir(parents=True)
        target = actual / "child" / "artifact"
        target.write_bytes(b"canary")
        link = self.root / "link"
        link.symlink_to(actual, target_is_directory=True)
        for operation in (lambda p: bounded_read(p), lambda p: atomic_write(p, b"changed")):
            with self.assertRaises(Rejected):
                operation(link / "child" / "artifact")
        self.assertEqual(target.read_bytes(), b"canary")

    @unittest.skipUnless(os.name == "posix", "native POSIX directory descriptor semantics")
    def test_parent_swap_at_replace_does_not_write_foreign_directory(self):
        parent = self.root / "owned"
        parent.mkdir()
        target = parent / "artifact"
        target.write_bytes(b"original")
        foreign = self.root / "foreign"
        foreign.mkdir()
        (foreign / "artifact").write_bytes(b"canary")
        renamed = self.root / "renamed"
        replace = os.replace

        def swap(source, destination, **options):
            parent.rename(renamed)
            parent.symlink_to(foreign, target_is_directory=True)
            return replace(source, destination, **options)

        with patch.object(os, "replace", side_effect=swap):
            atomic_write(target, b"new")
        self.assertEqual((foreign / "artifact").read_bytes(), b"canary")
        self.assertEqual((renamed / "artifact").read_bytes(), b"new")
        self.assertEqual(list(renamed.glob(".pending-*")), [])


if __name__ == "__main__":
    unittest.main()
