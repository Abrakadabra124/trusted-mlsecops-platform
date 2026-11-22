import gzip
import io
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import image_bpftool_materials as m


def tar_bytes(name, payload, *, kind=tarfile.REGTYPE, count=1):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for _ in range(count):
            entry = tarfile.TarInfo(name)
            entry.type = kind
            entry.size = len(payload)
            tf.addfile(entry, io.BytesIO(payload))
    return buf.getvalue()


def elf(kind, machine=62):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    header[16:20] = kind.to_bytes(2, "little") + machine.to_bytes(2, "little")
    return bytes(header)


def ar_member(name, obj):
    header = f"{name:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(obj):<10}`\n"
    return header.encode() + obj + b"\n" * (len(obj) % 2)


class MaterialsQualification(unittest.TestCase):
    def setUp(self):
        self.witness = b"witness at known offsets"
        self.obj = elf(1) + self.witness
        self.archive = b"!<arch>\n" + ar_member("member.o/", self.obj)
        self.donor = elf(2) + b"padding" + self.witness
        self.material = replace(
            m._MATERIALS["libc6-dev"],
            archive_name="libc.a",
            archive_size=len(self.archive),
            archive_sha=digest(self.archive),
            member="member.o",
            member_start=68,
            member_sha=digest(self.obj),
            object_offset=64,
            elf_offset=71,
            length=len(self.witness),
            witness_sha=digest(self.witness),
        )

    def test_four_coordinates_including_epoch_and_donor_identity(self):
        self.assertEqual(
            m.PACKAGES,
            {
                "libc6-dev": ("glibc", "2.39-0ubuntu8.3"),
                "libelf-dev": ("elfutils", "0.190-1.1build4"),
                "zlib1g-dev": ("zlib", "1:1.3.dfsg-3.1ubuntu2.1"),
                "libzstd-dev": ("libzstd", "1.5.5+dfsg2-2build1.1"),
            },
        )
        self.assertEqual(m.PACKAGES.keys(), m._MATERIALS.keys())
        self.assertEqual(
            m.BINARY_SHA256, "023276e781975b6e4ca5ab3ac39855f831f6132eb57e6e0b141018e92c2aabed"
        )

    def test_witness_requires_named_archive_member_full_hash_and_both_exact_ranges(self):
        m._verify_witness(self.material, self.archive, self.donor)
        for changes in (
            {"archive_sha": "0" * 64},
            {"member": "another.o"},
            {"member_start": 69},
            {"member_sha": "0" * 64},
            {"object_offset": 65},
            {"elf_offset": 70},
            {"length": len(self.witness) + 1},
            {"witness_sha": "0" * 64},
        ):
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                m._verify_witness(replace(self.material, **changes), self.archive, self.donor)
        with self.assertRaises(Rejected):
            m._verify_witness(self.material, self.archive, self.donor[:-1] + b"!")

    def test_machine_and_type_independent_of_otherwise_matching_object_hash(self):
        for wrong in (elf(1, 183), elf(2), elf(1).replace(b"ELF", b"XYZ")):
            obj = wrong + self.witness
            archive = b"!<arch>\n" + ar_member("member.o/", obj)
            pinned = replace(self.material, member_sha=digest(obj), archive_sha=digest(archive))
            with self.assertRaises(Rejected):
                m._verify_witness(pinned, archive, self.donor)
        with self.assertRaises(Rejected):
            m._check_elf(elf(2, 183), 2)

    def test_tar_member_requires_unique_exact_regular_file(self):
        for name, kind, count in (
            ("other/libc.a", tarfile.REGTYPE, 1),
            ("./usr/lib/libc.a", tarfile.SYMTYPE, 1),
            ("usr/lib/libc.a", tarfile.REGTYPE, 2),
        ):
            with self.subTest(name=name, kind=kind, count=count), self.assertRaises(Rejected):
                m._tar_file(tar_bytes(name, b"data", kind=kind, count=count), "usr/lib/libc.a", 4)

    def test_donor_rejects_descriptor_platform_and_uncompressed_layer_substitution(self):
        config = {"digest": "sha256:" + m._CONFIG, "size": 846}
        layer = {"digest": "sha256:" + m._LAYER, "size": 2815864}
        manifest = canonical({"config": config, "layers": [layer]})
        platform = {
            "os": "linux",
            "architecture": "amd64",
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + m._DIFF_ID]},
        }
        for reason, responses in (
            ("descriptor", [canonical({"config": config, "layers": [layer, layer]})]),
            ("descriptor", [canonical({"config": {**config, "size": 847}, "layers": [layer]})]),
            ("config", [manifest, canonical({**platform, "architecture": "arm64"})]),
            ("config", [manifest, canonical({**platform, "rootfs": {"diff_ids": []}})]),
            ("diff_id", [manifest, canonical(platform), gzip.compress(b"other layer")]),
        ):
            with (
                self.subTest(reason=reason),
                patch.object(m, "_fetch", side_effect=responses),
                self.assertRaisesRegex(Rejected, reason),
            ):
                m._read_donor()

    def test_fetch_checks_size_and_sha(self):
        for body in (b"abc", b"ab", b"abcd", b"xyz"):
            with patch.object(m.urllib.request, "urlopen", return_value=io.BytesIO(body)):
                if body == b"abc":
                    self.assertEqual(m._fetch("https://example.invalid/", 3, digest(b"abc")), body)
                else:
                    with self.assertRaises(Rejected):
                        m._fetch("https://example.invalid/", 3, digest(b"abc"))

    @staticmethod
    def control(name):
        source, version = m.PACKAGES[name]
        return (
            f"Package: {name}\nSource: {source}\nVersion: {version}\nArchitecture: amd64\n"
            "Description: first line\n .\n  second line\n"
        ).encode()

    def test_control_rejects_identity_substitution_and_extra_stanza(self):
        name = "libc6-dev"
        valid = self.control(name)
        for bad in (
            valid.replace(b"amd64", b"arm64"),
            valid.replace(b"Source: glibc", b"Source: libc"),
            valid.replace(b"Package: libc6-dev", b"Package: libc6"),
            valid.replace(b"2.39-0ubuntu8.3", b"2.39-0ubuntu8.2"),
            valid + b"Architecture: amd64\n",
            valid + b"Status: install ok installed\n",
            valid + b"\n" + valid,
        ):
            with self.subTest(bad=bad), self.assertRaises(Rejected):
                m._installed_stanza(name, bad)

    @unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb unavailable on this host")
    def test_native_dpkg_deb_control_and_payload_readback(self):
        name = "libc6-dev"
        control = self.control(name) + b"Maintainer: Fixture <fixture@example.invalid>\n"
        path = "usr/lib/x86_64-linux-gnu/libc.a"
        deb = (
            b"!<arch>\n"
            + ar_member("debian-binary", b"2.0\n")
            + ar_member("control.tar.gz", gzip.compress(tar_bytes("./control", control)))
            + ar_member("data.tar.gz", gzip.compress(tar_bytes("./" + path, self.archive)))
        )
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "sample.deb"
            file.write_bytes(deb)
            stanza = m._installed_stanza(name, subprocess.check_output(["dpkg-deb", "-f", file]))
            self.assertIn("Architecture: amd64\n", stanza)
            payload = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", file])
            archive = m._tar_file(payload, path, self.material.archive_size)
            m._verify_witness(self.material, archive, self.donor)

    def test_prepare_emits_only_two_files_after_all_four_bindings_pass(self):
        archive_tar = tar_bytes("./usr/lib/x86_64-linux-gnu/libc.a", self.archive)
        materials = {
            k: replace(self.material, deb_path=v.deb_path) for k, v in m._MATERIALS.items()
        }

        def dpkg(argv, **kwargs):
            self.assertEqual(argv[0], "dpkg-deb")
            self.assertEqual(Path(argv[2]).read_bytes(), b"verified deb fixture")
            if argv[1] == "-f":
                return self.control(Path(argv[2]).stem)
            self.assertEqual(argv[1], "--fsys-tarfile")
            return archive_tar

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(m, "_MATERIALS", materials),
            patch.object(m, "_read_donor", return_value=self.donor),
            patch.object(m, "_fetch", return_value=b"verified deb fixture"),
            patch.object(m.subprocess, "check_output", side_effect=dpkg) as reader,
        ):
            run = Path(tmp)
            root = m.prepare(run)
            self.assertEqual(reader.call_count, 8)
            self.assertEqual(
                {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()},
                {"etc/os-release", "var/lib/dpkg/status"},
            )
            os_release = (root / "etc/os-release").read_text()
            self.assertIn('VERSION_ID="24.04"', os_release)
            self.assertIn("VERSION_CODENAME=noble", os_release)
            self.assertIn("ID=ubuntu", os_release.splitlines())
            stanzas = (root / "var/lib/dpkg/status").read_bytes().strip().split(b"\n\n")
            self.assertEqual(len(stanzas), 4)
            for name, stanza in zip(materials, stanzas, strict=True):
                self.assertEqual(
                    set(stanza.splitlines()),
                    set(self.control(name).splitlines()) | {b"Status: install ok installed"},
                )
            materials["libzstd-dev"] = replace(self.material, elf_offset=72)
            with self.assertRaises(Rejected):
                m.prepare(run)
            self.assertEqual(list(run.iterdir()), [root])


if __name__ == "__main__":
    unittest.main()
