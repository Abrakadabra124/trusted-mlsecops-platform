import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import audit_export, audit_retention, audit_snapshot
from mlsecops.contracts import Rejected, canonical, decode
from scripts.audit_export_qualification import encoded, records


def metadata():
    return {
        "schema_version": 1,
        "policy": {
            "segment_bytes": 2048,
            "max_segments": 16,
            "rotate_seconds": 60,
            "retain_seconds": 300,
        },
        "budget": 16384,
        "clock": {"boot": "a" * 8 + ("-" + "a" * 4) * 3 + "-" + "a" * 12, "wall": 100, "mono": 100},
        "sequence": 4,
        "next_index": 1,
        "segments": [
            {
                "name": "0000000000000001.jsonl",
                "size": 100,
                "first": 1,
                "last": 100,
                "sha256": "b" * 64,
                "identity": [1, 2],
            }
        ],
    }


class SnapshotManifestContracts(unittest.TestCase):
    def test_zero_manifest_clock_and_segment_times_are_not_valid_writer_history(self):
        for field in ("wall", "mono", "first", "last"):
            saved = metadata()
            target = saved["clock"] if field in ("wall", "mono") else saved["segments"][0]
            target[field] = 0
            with self.subTest(field=field), self.assertRaises(Rejected):
                audit_snapshot.manifest(canonical(saved))

    def test_valid_metadata_is_structural_and_does_not_read_the_current_boot_or_clock(self):
        saved = metadata()
        with patch.object(audit_retention, "Clock", side_effect=AssertionError("clock accessed")):
            self.assertEqual(audit_snapshot.manifest(canonical(saved)), saved)

    def test_bad_canonical_schema_policy_clock_and_capacity_reject(self):
        for field, replacement in (
            ("schema_version", True),
            ("schema_version", 2),
            ("extra", 1),
            ("budget", 0),
            ("policy", {}),
            ("sequence", True),
            ("next_index", -1),
            ("segments", []),
            ("segments", {}),
            ("clock", {"boot": 1, "wall": 100, "mono": 100}),
            ("clock", {"boot": "private", "wall": 100, "mono": 100}),
            ("clock", {**metadata()["clock"], "mono": 2**63}),
        ):
            saved = metadata()
            saved[field] = replacement
            with self.subTest(field=field, replacement=replacement), self.assertRaises(Rejected):
                audit_snapshot.manifest(canonical(saved))
        for content in (b"{}", b"[]", b" " + canonical(metadata()), b"x" * 65537):
            with self.assertRaises(Rejected):
                audit_snapshot.manifest(content)

    def test_bad_segment_metadata_and_budget_reject(self):
        for field, replacement in (
            ("name", "../secret"),
            ("name", 1),
            ("name", "0000000000000000.jsonl"),
            ("name", "0000000000000002.jsonl"),
            ("size", 0),
            ("size", 2049),
            ("first", 101),
            ("last", 101),
            ("sha256", 1),
            ("sha256", "x" * 64),
            ("identity", "private"),
            ("identity", []),
            ("identity", [1, -1]),
            ("identity", [True, 1]),
            ("extra", "private"),
        ):
            saved = metadata()
            saved["segments"][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(Rejected):
                audit_snapshot.manifest(canonical(saved))
        for count in (2, 17):
            saved = metadata()
            saved["segments"] *= count
            with self.assertRaises(Rejected):
                audit_snapshot.manifest(canonical(saved))
        saved = metadata()
        saved["budget"] = 2048
        saved["next_index"] = 2
        saved["segments"][0]["size"] = 2048
        saved["segments"].append({**saved["segments"][0], "name": "0000000000000002.jsonl"})
        with self.assertRaises(Rejected):
            audit_snapshot.manifest(canonical(saved))

    def test_relative_path_and_reader_fault_are_constant(self):
        with self.assertRaisesRegex(Rejected, "^audit_snapshot_unavailable$"):
            audit_snapshot.read_closed(Path("private-relative"))


def retained(path):
    spool = audit_retention.Spool(path, audit_retention.Policy(segment_bytes=2048), 16384)
    try:
        for record in records():
            spool.write(canonical(record) + b"\n")
    finally:
        spool.close(clean=True)


@unittest.skipUnless(os.name == "posix", "owned retained snapshot requires native POSIX CI")
class OwnedSnapshotContracts(unittest.TestCase):
    def test_multiple_segments_are_contiguous_and_unchanged_across_projection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spool = audit_retention.Spool(root, audit_retention.Policy(segment_bytes=2048), 16384)
            values = records() + records(request="3" * 32)
            for index, record in enumerate(values):
                record["sequence"] = index + 1
                spool.write(canonical(record) + b"\n")
            spool.close(clean=True)
            chunks = audit_snapshot.read_closed(root)
            self.assertGreater(len(chunks), 1)
            self.assertEqual(audit_export.project(chunks)["requests"]["completed"], 2)
            saved = decode((root / "manifest.json").read_bytes())
            segment = saved["segments"][1]
            source = root / segment["name"]
            rows = [decode(line) for line in source.read_bytes().splitlines()]
            for record in rows:
                record["sequence"] += 100
            changed = encoded(rows)
            source.write_bytes(changed)
            segment.update(size=len(changed), sha256=hashlib.sha256(changed).hexdigest())
            (root / "manifest.json").write_bytes(canonical(saved))
            with self.assertRaises(Rejected):
                audit_snapshot.read_closed(root)
            self.assertFalse((root / ".lease").exists())

    def test_read_time_mutation_manifest_replacement_and_excess_inventory_reject(self):
        for fault in ("read-time", "manifest-final", "inventory-final", "inventory-limit"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                retained(root)
                original_read, original_names, changed = os.read, audit_snapshot._names, False
                manifest_reads, inventories = 0, 0
                original_snapshot_read = audit_snapshot._read

                def read(descriptor, limit):
                    nonlocal changed
                    block = original_read(descriptor, limit)
                    if fault == "read-time" and b'"event"' in block and not changed:
                        changed = True
                        next(root.glob("*.jsonl")).write_bytes(b"x")
                    return block

                def snapshot_read(directory, name, limit):
                    nonlocal manifest_reads
                    if name == "manifest.json":
                        manifest_reads += 1
                        if fault == "manifest-final" and manifest_reads == 2:
                            source = root / name
                            saved = decode(source.read_bytes())
                            saved["clock"]["wall"] += 1
                            source.write_bytes(canonical(saved))
                    return original_snapshot_read(directory, name, limit)

                def names(directory):
                    nonlocal inventories
                    inventories += 1
                    if fault == "inventory-final" and inventories == 2:
                        (root / "extra").write_bytes(b"x")
                    if fault == "inventory-limit":
                        for index in range(67):
                            (root / f"extra-{index}").write_bytes(b"x")
                    return original_names(directory)

                with (
                    patch.object(os, "read", side_effect=read),
                    patch.object(audit_snapshot, "_read", side_effect=snapshot_read),
                    patch.object(audit_snapshot, "_names", side_effect=names),
                ):
                    with self.assertRaises(Rejected):
                        audit_snapshot.read_closed(root)
                self.assertFalse((root / ".lease").exists())

    def test_foreign_owner_and_alias_directory_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "spool"
            root.mkdir(mode=0o700)
            retained(root)
            with patch.object(os, "geteuid", return_value=os.geteuid() + 1):
                with self.assertRaises(Rejected):
                    audit_snapshot.read_closed(root)
            alias = parent / "alias"
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaises(Rejected):
                audit_snapshot.read_closed(alias)
            self.assertFalse((root / ".lease").exists())

    def test_partial_lease_write_failure_cleans_only_the_owned_prefix(self):
        for failure in ("zero", "short-error", "sync"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                retained(root)
                original_write, original_sync = os.write, os.fsync
                calls = 0

                def write(descriptor, content):
                    nonlocal calls
                    calls += 1
                    if failure == "zero":
                        return 0
                    if failure == "short-error":
                        if calls == 1:
                            return original_write(descriptor, content[:7])
                        raise OSError("private-write-fault")
                    return original_write(descriptor, content)

                def sync(descriptor):
                    if failure == "sync":
                        raise OSError("private-sync-fault")
                    return original_sync(descriptor)

                with (
                    patch.object(os, "write", side_effect=write),
                    patch.object(os, "fsync", side_effect=sync),
                ):
                    with self.assertRaises(Rejected):
                        audit_snapshot.read_closed(root)
                self.assertFalse((root / ".lease").exists())

    def test_cleanup_failure_and_cancellation_never_return_a_snapshot(self):
        for fault in ("unlink", "cancel", "after-unlink-sync"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                retained(root)
                original_read, original_unlink, original_sync = (
                    audit_snapshot._read,
                    os.unlink,
                    os.fsync,
                )
                removed = False

                def read(directory, name, limit):
                    if name == "manifest.json" and fault == "cancel":
                        raise KeyboardInterrupt("private-cancel")
                    return original_read(directory, name, limit)

                def unlink(name, **options):
                    nonlocal removed
                    if fault == "unlink":
                        raise OSError("private-unlink")
                    original_unlink(name, **options)
                    removed = True
                    if fault == "after-unlink-sync":
                        (root / ".lease").write_bytes(b"next-owner")
                        (root / ".lease").chmod(0o600)

                def sync(descriptor):
                    if removed and fault == "after-unlink-sync":
                        raise OSError("private-sync")
                    return original_sync(descriptor)

                with (
                    patch.object(audit_snapshot, "_read", side_effect=read),
                    patch.object(os, "unlink", side_effect=unlink),
                    patch.object(os, "fsync", side_effect=sync),
                ):
                    with self.assertRaises(KeyboardInterrupt if fault == "cancel" else Rejected):
                        audit_snapshot.read_closed(root)
                self.assertEqual((root / ".lease").exists(), fault != "cancel")
                if fault == "after-unlink-sync":
                    self.assertEqual((root / ".lease").read_bytes(), b"next-owner")

    def test_cli_real_guard_and_closed_snapshot_are_verified_without_private_output(self):
        from scripts.audit_export_probe import exercise

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            retained(root)
            self.assertEqual(exercise(root)["requests"]["completed"], 1)
            script = """
import runpy, sys
from unittest.mock import patch
from mlsecops import audit_snapshot, process_privacy
original = audit_snapshot.read_closed
def checked(path):
    state = process_privacy.readback()
    assert state['dumpable'] == 0 and state['core_limits'] == [0, 0]
    return original(path)
sys.argv = ['export', '--spool', sys.argv[1]]
with patch.object(audit_snapshot, 'read_closed', side_effect=checked):
    runpy.run_module('mlsecops.audit_export', run_name='__main__')
"""
            result = subprocess.run(
                [sys.executable, "-c", script, str(root)],
                capture_output=True,
                check=False,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b"")
            self.assertNotIn(str(root).encode(), result.stdout)

    def test_projection_receives_verified_bytes_not_a_later_segment_reopen(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            retained(root)
            original, changed = audit_snapshot._read, False

            def replace(directory, name, limit):
                nonlocal changed
                content, identity = original(directory, name, limit)
                if name.endswith(".jsonl") and not changed:
                    changed = True
                    replacement = content.replace(b'"predict"', b'"ready  "')
                    self.assertNotEqual(
                        hashlib.sha256(content).digest(), hashlib.sha256(replacement).digest()
                    )
                    (root / name).write_bytes(replacement)
                return content, identity

            with patch.object(audit_snapshot, "_read", side_effect=replace):
                chunks = audit_snapshot.read_closed(root)
            self.assertEqual(audit_export.project(chunks)["routes"], {"predict": 1, "ready": 0})

    def test_clean_snapshot_does_not_rewrite_payload_manifest_or_retain_lease(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            retained(root)
            before = {item.name: item.read_bytes() for item in root.iterdir()}
            chunks = audit_snapshot.read_closed(root)
            self.assertEqual(b"".join(chunks), encoded(records()))
            self.assertEqual(audit_export.project(chunks)["requests"]["completed"], 1)
            self.assertEqual(before, {item.name: item.read_bytes() for item in root.iterdir()})

    def test_active_or_stale_lease_is_never_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            retained(root)
            marker = root / ".lease"
            marker.write_bytes(b"private-owner" * 2)
            marker.chmod(0o600)
            before = marker.read_bytes()
            with self.assertRaises(Rejected):
                audit_snapshot.read_closed(root)
            self.assertEqual(marker.read_bytes(), before)

    def test_existing_writer_excludes_export_and_can_close_normally(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spool = audit_retention.Spool(root, audit_retention.Policy(segment_bytes=2048), 16384)
            try:
                with self.assertRaises(Rejected):
                    audit_snapshot.read_closed(root)
                self.assertTrue((root / ".lease").is_file())
                spool.write(canonical(records()[0]) + b"\n")
            finally:
                spool.close(clean=True)
            self.assertEqual(
                audit_export.project(audit_snapshot.read_closed(root))["status"], "inconclusive"
            )

    def test_payload_manifest_mutations_and_inventory_mismatch_are_rejected(self):
        for mutation in (
            "payload",
            "missing",
            "extra",
            "schema",
            "unknown",
            "sequence",
            "identity",
            "size",
            "digest",
            "empty",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                retained(root)
                manifest = root / "manifest.json"
                value = decode(manifest.read_bytes())
                segment = root / value["segments"][0]["name"]
                if mutation == "payload":
                    segment.write_bytes(segment.read_bytes() + b"x")
                elif mutation == "missing":
                    segment.unlink()
                elif mutation == "extra":
                    (root / "private-extra").write_text("private", encoding="utf-8")
                elif mutation == "schema":
                    value["schema_version"] = True
                elif mutation == "unknown":
                    value["private_url"] = "https://private.invalid/secret"
                elif mutation == "sequence":
                    value["sequence"] += 1
                elif mutation == "identity":
                    value["segments"][0]["identity"][1] += 1
                elif mutation == "size":
                    value["segments"][0]["size"] += 1
                elif mutation == "digest":
                    value["segments"][0]["sha256"] = "0" * 64
                else:
                    value["segments"] = []
                manifest.write_bytes(canonical(value))
                before = {item.name: item.read_bytes() for item in root.iterdir()}
                with self.assertRaises(Rejected):
                    audit_snapshot.read_closed(root)
                self.assertEqual(before, {item.name: item.read_bytes() for item in root.iterdir()})

    def test_symlink_hardlink_fifo_and_nonprivate_mode_are_rejected_without_hanging(self):
        for mutation in ("symlink", "hardlink", "fifo", "mode", "directory-mode"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                retained(root)
                manifest = decode((root / "manifest.json").read_bytes())
                source = root / manifest["segments"][0]["name"]
                if mutation in ("symlink", "fifo"):
                    source.unlink()
                    if mutation == "symlink":
                        source.symlink_to(root / "manifest.json")
                    else:
                        os.mkfifo(source, 0o600)
                elif mutation == "hardlink":
                    os.link(source, root / "extra-link")
                elif mutation == "mode":
                    source.chmod(0o644)
                else:
                    root.chmod(0o755)
                with self.assertRaises(Rejected):
                    audit_snapshot.read_closed(root)
                self.assertFalse((root / ".lease").exists())
                root.chmod(0o700)

    def test_reader_lease_blocks_writer_and_is_not_deleted_after_identity_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            retained(root)
            original = audit_snapshot._read
            changed = False
            replacement = None

            def replace(directory, name, limit):
                nonlocal changed, replacement
                if name == "manifest.json" and not changed:
                    changed = True
                    with self.assertRaises(Rejected):
                        audit_retention.Spool(
                            root, audit_retention.Policy(segment_bytes=2048), 16384
                        )
                    lease = root / ".lease"
                    replacement = lease.read_bytes()
                    lease.unlink()
                    lease.write_bytes(replacement)
                    lease.chmod(0o600)
                return original(directory, name, limit)

            with (
                patch.object(audit_snapshot, "_read", side_effect=replace),
                self.assertRaises(Rejected),
            ):
                audit_snapshot.read_closed(root)
            self.assertEqual((root / ".lease").read_bytes(), replacement)


if __name__ == "__main__":
    unittest.main()
