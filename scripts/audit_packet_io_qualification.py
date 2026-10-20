import os
import tempfile
import unittest
from contextlib import nullcontext
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from mlsecops import audit_evidence, audit_snapshot, serving_context
from mlsecops.contracts import Rejected, canonical, digest
from scripts import audit_evidence_probe, serving_native
from scripts import serving_core_qualification as core
from scripts.audit_correlation_qualification import lineage
from scripts.audit_evidence_qualification import binding, fixture, packet
from scripts.audit_http_observation import Ledger
from scripts.audit_snapshot_qualification import metadata


class CapturedSnapshotContracts(unittest.TestCase):
    def test_packet_fsync_includes_parent_directory_entry_and_readback_faults_reject(self):
        for fault in (None, "readback", "inventory", "parent-sync"):
            with tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary).resolve() / "archive"
                synced = []

                def sync(descriptor):
                    synced.append(descriptor)
                    if fault == "parent-sync" and descriptor == 12:
                        raise OSError("controlled parent sync failure")

                with (
                    patch.object(audit_snapshot.os, "name", "posix"),
                    patch.object(audit_snapshot.os, "O_NOFOLLOW", 0, create=True),
                    patch.object(audit_snapshot.os, "O_DIRECTORY", 0, create=True),
                    patch.object(audit_snapshot.os, "open", side_effect=[11, 12]),
                    patch.object(audit_snapshot.os, "close"),
                    patch.object(audit_snapshot.os, "write", return_value=7),
                    patch.object(audit_snapshot.os, "fsync", side_effect=sync),
                    patch.object(audit_snapshot, "_leased", return_value=nullcontext(42)),
                    patch.object(
                        audit_snapshot,
                        "_names",
                        return_value=set() if fault == "inventory" else {".lease", "packet.json"},
                    ),
                    patch.object(
                        audit_snapshot,
                        "_read",
                        return_value=(b"changed" if fault == "readback" else b"private", [1, 2]),
                    ),
                ):
                    if fault:
                        with self.subTest(fault=fault), self.assertRaises(Rejected):
                            audit_snapshot.store_packet(target, b"private")
                    else:
                        audit_snapshot.store_packet(target, b"private")
                        self.assertEqual(synced, [11, 42, 12])

    def test_capture_preserves_exact_manifest_and_immutable_ordered_chunks(self):
        manifest, chunks, _, _ = fixture()
        names = {".lease", "manifest.json", metadata()["segments"][0]["name"]}
        for capture in (True, False):
            with (
                patch.object(audit_snapshot, "_leased", return_value=nullcontext(42)),
                patch.object(
                    audit_snapshot,
                    "_read",
                    side_effect=[(manifest, [4, 5]), (chunks[0], [1, 2]), (manifest, [4, 5])],
                ),
                patch.object(audit_snapshot, "_names", return_value=names),
            ):
                result = (
                    audit_snapshot.capture_closed(Path("owned"))
                    if capture
                    else audit_snapshot.read_closed(Path("owned"))
                )
            self.assertEqual(result, (manifest, tuple(chunks)) if capture else chunks)

    def test_unsupported_platform_does_not_create_packet_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary).resolve() / "archive"
            with patch.object(audit_snapshot.os, "name", "nt"), self.assertRaises(Rejected):
                audit_snapshot.store_packet(target, b"private")
            self.assertFalse(target.exists())


@unittest.skipUnless(
    os.name == "posix", "native Linux ownership and directory descriptors required"
)
class PrivatePacketIOContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.target = self.root / "archive"

    def test_real_http_packet_remains_verifiable_after_source_journal_cleanup(self):
        engine_fixture = core.ServingCoreContracts()
        engine_fixture.setUp()
        self.addCleanup(engine_fixture.doCleanups)
        engine_fixture.loaded.audit_context = serving_context.QualificationTrace(
            "a" * 64,
            "a" * 64,
            engine_fixture.loaded.subject_sha256,
            engine_fixture.loaded.model_sha256,
            lineage=lineage(),
        )
        context = asdict(engine_fixture.loaded.audit_context)
        ledger, saved, sources = Ledger(), {}, []

        def retain(path):
            sources.append(path)
            saved.update(
                audit_evidence_probe.retain(
                    path, self.target, ledger, binding=binding(), expected_context=context
                )
            )

        with serving_native.site(
            engine_fixture.engine, http_ledger=ledger, audit_export=retain
        ) as request:
            self.assertEqual(request("/readyz")[0], 200)
            self.assertEqual(request("/readyz", authorized=False)[0], 401)
            self.assertEqual(request("/unknown")[0], 404)
        self.assertFalse(sources[0].exists())
        checked = audit_evidence.verify(
            audit_snapshot.load_packet(self.target), binding=binding(), expected_context=context
        )
        self.assertEqual(checked, saved)
        self.assertEqual(checked["observed_responses"], 3)
        self.assertEqual(checked["correlation"]["correlated_requests"], 1)

    def test_exact_private_packet_survives_source_removal_and_is_not_overwritten(self):
        content = packet()
        audit_snapshot.store_packet(self.target, content)
        self.assertEqual(audit_snapshot.load_packet(self.target), content)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.target / "packet.json").stat().st_mode & 0o777, 0o600)
        with self.assertRaises(Rejected):
            audit_snapshot.store_packet(self.target, b"replacement")
        self.assertEqual(audit_snapshot.load_packet(self.target), content)
        self.assertFalse((self.target / ".lease").exists())

    def test_partial_write_and_fsync_failure_never_return_success(self):
        original = os.write
        for fault in ("short", "zero", "sync"):
            target = self.root / fault
            calls = [0]

            def write(descriptor, content):
                calls[0] += 1
                if fault == "zero" and calls[0] > 1:
                    return 0
                return original(descriptor, content[:3] if fault == "short" else content)

            with (
                patch.object(audit_snapshot.os, "write", side_effect=write),
                patch.object(
                    audit_snapshot.os,
                    "fsync",
                    side_effect=OSError("controlled failure") if fault == "sync" else os.fsync,
                ),
            ):
                if fault == "short":
                    audit_snapshot.store_packet(target, b"bounded-private-content")
                else:
                    with self.assertRaises(Rejected):
                        audit_snapshot.store_packet(target, b"bounded-private-content")
            if fault == "short":
                self.assertEqual(audit_snapshot.load_packet(target), b"bounded-private-content")

    def test_symlinks_hardlinks_modes_extra_files_and_active_lease_reject(self):
        for fault in ("directory-mode", "file-mode", "symlink", "hardlink", "extra", "lease"):
            target = self.root / fault
            audit_snapshot.store_packet(target, canonical({"private": digest(b"synthetic")}))
            path = target / "packet.json"
            if fault == "directory-mode":
                target.chmod(0o755)
            elif fault == "file-mode":
                path.chmod(0o644)
            elif fault == "symlink":
                replacement = target / "original"
                path.rename(replacement)
                path.symlink_to(replacement)
            elif fault == "hardlink":
                os.link(path, self.root / "duplicate")
            elif fault == "extra":
                (target / "extra").write_bytes(b"unexpected")
            else:
                (target / ".lease").write_bytes(b"active")
            with self.subTest(fault=fault), self.assertRaises(Rejected):
                audit_snapshot.load_packet(target)

    def test_missing_oversized_empty_relative_and_linked_destinations_reject(self):
        for content in (b"", "text", b"x" * (audit_snapshot.MAX_PACKET + 1)):
            with self.assertRaises(Rejected):
                audit_snapshot.store_packet(self.target, content)
        with self.assertRaises(Rejected):
            audit_snapshot.load_packet(self.target)
        with self.assertRaises(Rejected):
            audit_snapshot.store_packet(Path("relative"), b"private")
        linked = self.root / "linked"
        linked.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(Rejected):
            audit_snapshot.store_packet(linked / "unsafe", b"private")
        self.assertFalse((self.root / "unsafe").exists())


if __name__ == "__main__":
    unittest.main()
