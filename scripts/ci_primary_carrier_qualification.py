"""Disk-based qualification of the private primary carrier, without live services."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mlsecops import final_evidence as final
from mlsecops.contracts import Rejected, canonical, digest
from scripts import ci_primary_carrier as carrier
from scripts import ci_serving_retention as serving
from scripts import frozen_candidate_transfer as transfer
from scripts import m18_shared_retention as shared

ROOT = Path(__file__).resolve().parents[1]
MAGIC = b"MLSCAS\x00\x01"


class CarrierTests(unittest.TestCase):
    def setUp(self):
        runtime = ROOT / ".runtime"
        runtime.mkdir(exist_ok=True)
        self.root = Path(self.enterContext(TemporaryDirectory(dir=runtime)))
        self.runtime = self.root / ".runtime"
        self.source = self.runtime / "source"
        self.target = self.runtime / "received"
        self.objects = {
            final.retain(self.source, raw): raw for raw in (b"\xff\x00a\n", b"\x00\x01b\n")
        }
        self.one = next(iter(self.objects))
        self.files = {"model.bin": self.one, "copy.bin": self.one}

    def authority(self, role):
        common = dict(
            freeze_pin=self.one,
            expected=dict(
                dict.fromkeys(transfer.IDENTITY, self.one),
                source_revision="a" * 40,
                image_id="sha256:" + self.one,
            ),
            freeze=dict.fromkeys(transfer.delivery.FILES, self.one),
            run_owner=dict(
                repository="example/project", producer_job="producer", run_id=1, run_attempt=1
            ),
        )
        if role == "shared":
            return dict(
                common,
                report_pins=dict.fromkeys(shared.GATES, self.one),
                actual_pin=self.one,
                native_pin=self.one,
            )
        nodes = [
            dict(namespace=digest(bytes([i])), volume=digest(bytes([i + 3]))) for i in range(3)
        ]
        return dict(
            common,
            report_pins=dict.fromkeys(serving.campaign.GATES, self.one),
            admission_pins=dict.fromkeys(serving.serving.GATES, self.one),
            transitions=[
                dict(before=nodes[i], after=nodes[i + 1], source_sql=self.one) for i in range(2)
            ],
            consumer_storage_pin=self.one,
        )

    def record(self, role):
        if role == "shared":
            scope = shared.SCOPE
            extra = self.authority(role)
        else:
            scope = serving.SCOPE
            extra = dict(authority=self.authority(role), serving_pin=self.one)
        return dict(
            schema_version=1,
            scope=scope,
            classification=transfer.CLASSIFICATION,
            files=self.files,
            objects={pin: len(raw) for pin, raw in self.objects.items()},
            **extra,
        )

    def archive(self, role="shared"):
        raw = canonical(self.record(role)) + b"\n"
        pin = final.retain(self.source, raw)
        body = b"".join(self.objects[key] for key in sorted(self.objects))
        return pin, MAGIC + len(raw).to_bytes(4, "big") + raw + body

    def pack(self, pin, role="shared"):
        return carrier.pack(self.root, self.source, role=role, index_pin=pin)

    def unpack(self, data, pin, role="shared"):
        return carrier.unpack(self.root, self.target, data, role=role, index_pin=pin)

    def test_wrong_role_pin_and_corrupt_frames_leave_no_destination(self):
        pin, frame = self.archive()
        for data, role, expected in (
            (frame, "serving", pin),
            (frame, "unknown", pin),
            (frame, "shared", digest(b"other index")),
            (frame, "shared", "../outside"),
            (frame[:-1], "shared", pin),
            (frame + b"\x00", "shared", pin),
            (frame[:-1] + b"X", "shared", pin),
            (frame[:-8] + frame[-4:] * 2, "shared", pin),
            (frame[:-8] + frame[-4:] + frame[-8:-4], "shared", pin),
        ):
            with self.subTest(role=role, length=len(data)), self.assertRaises(Rejected):
                self.unpack(data, expected, role)
            self.assertEqual(list(self.runtime.iterdir()), [self.source])

    def test_portable_bytes_and_exact_disk_roundtrip(self):
        foreign = final.retain(self.source, b"foreign unindexed payload")
        for role in ("shared", "serving"):
            with self.subTest(role=role):
                pin, expected = self.archive(role)
                data = self.pack(pin, role)
                self.assertIs(type(data), bytes)
                self.assertEqual(data, expected)
                self.target = self.runtime / role
                self.assertIsNone(self.unpack(data, pin, role))
                cas = self.target / transfer.CAS
                self.assertEqual({p.name for p in cas.iterdir()}, {*self.objects, pin})
                self.assertFalse((cas / foreign).exists())
                for key in (*self.objects, pin):
                    self.assertEqual((cas / key).read_bytes(), final.blob(self.source, key))
                self.assertEqual(
                    carrier.pack(self.root, self.target, role=role, index_pin=pin), data
                )
                # Match the host's private temp directory and retained-file modes.
                self.assertEqual(
                    self.target.stat().st_mode & 0o077, self.root.stat().st_mode & 0o077
                )
                original = self.source / transfer.CAS / pin
                self.assertEqual(
                    (cas / pin).stat().st_mode & 0o077, original.stat().st_mode & 0o077
                )

    def test_real_retention_writers_and_restored_disk_indexes(self):
        # Keep the two ordinary index writers/readers. Supply controlled inventory
        # and semantic results so this contract exercises only portable storage.
        for role, retention, last in (("shared", shared, {}), ("serving", serving, self.one)):
            owner = self.authority(role)
            with (
                self.subTest(role=role),
                patch.object(final, "clean"),
                patch.object(retention, "inventory", return_value=(self.files, self.objects, last)),
                patch.object(retention, "verify", return_value={}),
            ):
                with TemporaryDirectory(dir=ROOT / ".runtime") as name:
                    archive = Path(name)
                    archive.rmdir()  # retain owns creation; the context owns test cleanup.
                    result = retention.retain(ROOT, self.source, archive, **owner)
                    pin = result if role == "shared" else result["index_pin"]
                    expected = final.blob(archive, pin)
                    data = carrier.pack(ROOT, archive, role=role, index_pin=pin)
                restored = self.runtime / role
                carrier.unpack(self.root, restored, data, role=role, index_pin=pin)
                retention.replay(self.root, restored, index_pin=pin, **owner)
                self.assertEqual(final.blob(restored, pin), expected)

    def test_malformed_header_and_frame_budget(self):
        pin, data = self.archive()
        for bad in (
            bytearray(data),
            b"",
            data[:11],
            b"X" + data[1:],
            data[:7] + b"\x02" + data[8:],
            MAGIC + bytes(4),
            MAGIC + (final.LIMIT + 1).to_bytes(4, "big"),
            MAGIC + (100).to_bytes(4, "big") + b"x",
        ):
            with self.subTest(length=len(bad)), self.assertRaises(Rejected):
                self.unpack(bad, pin)
        with (
            patch.object(shared, "TOTAL", 1),
            patch.object(serving, "TOTAL", 1),
            self.assertRaises(Rejected),
        ):
            self.unpack(data, pin)
        self.assertEqual(list(self.runtime.iterdir()), [self.source])

    def test_malformed_rehashed_disk_indexes(self):
        record = self.record("shared")
        raw = canonical(record)
        # Exercise duplicate JSON keys even when the malformed bytes have their own pin.
        duplicate = raw.replace(b'"objects":{', b'"objects":{"' + self.one.encode() + b'":4,')
        for bad in (raw, raw + b"\n\n", b"{", duplicate + b"\n", b" " * (final.LIMIT + 1)):
            pin = final.retain(self.source, bad)
            with self.subTest(length=len(bad)), self.assertRaises(Rejected):
                self.pack(pin)
        for changes in (
            dict(schema_version=True),
            dict(scope=serving.SCOPE),
            dict(classification="public"),
            dict(extra=True),
            dict(files=[]),
            dict(files={}),
            dict(objects=[]),
            dict(objects={}),
            dict(files={"file": digest(b"absent")}),
            dict(files={"file": []}),
            dict(files={str(i): self.one for i in range(shared.MAX_FILES + 1)}),
            dict(objects={f"{i:064x}": 1 for i in range(shared.MAX_FILES + 3)}),
            dict(objects={"../outside": 1}),
            dict(objects={self.one.upper(): 4}),
            *(dict(objects={self.one: size}) for size in (0, -1, True, 4.0, shared.LIMIT + 1)),
        ):
            pin = final.retain(self.source, canonical(record | changes) + b"\n")
            with self.subTest(field=next(iter(changes))), self.assertRaises(Rejected):
                self.pack(pin)

    def test_counts_and_total_at_inclusive_boundary_for_each_role(self):
        for role, retention in (("shared", shared), ("serving", serving)):
            pin, data = self.archive(role)
            budget = len(data) - 12
            with (
                self.subTest(role=role),
                patch.multiple(retention, LIMIT=4, TOTAL=budget, MAX_FILES=2),
            ):
                self.assertEqual(self.pack(pin, role), data)
                with patch.object(retention, "TOTAL", budget - 1), self.assertRaises(Rejected):
                    self.pack(pin, role)
        with patch.object(serving, "MAX_OBJECTS", 1), self.assertRaises(Rejected):
            self.pack(pin, "serving")

    def test_missing_corrupt_or_wrong_length_files_on_disk(self):
        pin, _ = self.archive()
        cas = self.source / transfer.CAS
        obj = cas / self.one
        obj.unlink()
        with self.assertRaises(Rejected):
            self.pack(pin)
        for content in (b"bad!", b"x", b"extra"):
            obj.write_bytes(content)
            with self.assertRaises(Rejected):
                self.pack(pin)
        obj.write_bytes(self.objects[self.one])
        record = self.record("shared")
        record["objects"][self.one] += 1
        bigger = final.retain(self.source, canonical(record) + b"\n")
        with self.assertRaisesRegex(Rejected, "carrier-object-length"):
            self.pack(bigger)
        (cas / pin).write_bytes(b"forged index")
        with self.assertRaisesRegex(Rejected, "carrier-index-pin"):
            self.pack(pin)

    def test_runtime_boundary_and_linked_paths(self):
        pin, data = self.archive()
        for path in (
            self.root,
            self.runtime,
            self.runtime / ".." / "escape",
            self.root / "outside",
        ):
            with self.subTest(path=path.name), self.assertRaises(Rejected):
                carrier.unpack(self.root, path, data, role="shared", index_pin=pin)
            with self.assertRaises(Rejected):
                carrier.pack(self.root, path, role="shared", index_pin=pin)
        alias = self.runtime / "alias"
        alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(Rejected):
            carrier.unpack(self.root, alias / "new", data, role="shared", index_pin=pin)
        with self.assertRaises(Rejected):
            carrier.pack(self.root, alias, role="shared", index_pin=pin)
        obj = self.source / transfer.CAS / self.one
        other = self.root / "elsewhere"
        obj.rename(other)
        obj.symlink_to(other)
        with self.assertRaises(Rejected):
            self.pack(pin)

    def test_existing_targets_and_mid_unpack_empty_directory_collision(self):
        pin, data = self.archive()
        self.target.write_bytes(b"existing")
        with self.assertRaises(Rejected):
            self.unpack(data, pin)
        self.assertEqual(self.target.read_bytes(), b"existing")
        self.target.unlink()
        self.target.mkdir()
        with self.assertRaises(Rejected):
            self.unpack(data, pin)
        self.target.rmdir()
        write = carrier.atomic_write

        def claim(path, content):
            write(path, content)
            if path.name == pin:
                self.target.mkdir()

        with patch.object(carrier, "atomic_write", claim), self.assertRaises(FileExistsError):
            self.unpack(data, pin)
        self.assertEqual(list(self.target.iterdir()), [])
        self.assertEqual(set(self.runtime.iterdir()), {self.source, self.target})

    def test_partial_write_and_publication_failure_clean_only_owned_paths(self):
        pin, data = self.archive()
        write = carrier.atomic_write

        def fail_after_one(path, content):
            if path.name == max(self.objects):
                self.assertTrue((path.parent / min(self.objects)).is_file())
                self.assertFalse(self.target.exists())
                raise OSError("controlled partial write")
            write(path, content)

        with patch.object(carrier, "atomic_write", fail_after_one), self.assertRaises(OSError):
            self.unpack(data, pin)
        with (
            patch.object(Path, "rename", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            self.unpack(data, pin)
        self.assertEqual(list(self.runtime.iterdir()), [self.source])
        self.unpack(data, pin)
        self.assertEqual(final.blob(self.target, pin), final.blob(self.source, pin))


if __name__ == "__main__":
    unittest.main()
