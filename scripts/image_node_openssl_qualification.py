import contextlib
import copy
import gzip
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import image_node_openssl as subject


class OpenSSLQualification(unittest.TestCase):
    def setUp(self):
        self.source = {
            "image_id": subject.CONFIG,
            "packages": [
                {
                    "name": name,
                    "type": "deb",
                    "version": subject.OLD,
                    "paths": ["/var/lib/dpkg/status"],
                }
                for name in subject.DEB
            ]
            + [{"name": "keep", "version": "1", "type": "go-module", "paths": ["/usr/bin/x"]}]
            * 875,
        }
        self.candidate_id = "sha256:" + "a" * 64
        self.candidate = copy.deepcopy(self.source)
        self.candidate["image_id"] = self.candidate_id
        for row in self.candidate["packages"][:3]:
            row["version"] = subject.NEW
            row["paths"].insert(0, f"/usr/share/doc/{row['name']}/copyright")
        self.rows = [
            {
                "package": name,
                "installed": subject.OLD,
                "type": "deb",
                "id": cve,
                "severity": "Critical",
                "fix": {"state": "fixed", "versions": [subject.FIX]},
            }
            for cve in subject.CVES
            for name in subject.DEB
        ]

    def inventory(self):
        checksum = digest(
            canonical({**self.source, "packages": sorted(self.source["packages"], key=canonical)})
        )
        with patch.object(subject, "OBSERVATION", checksum):
            subject.check_inventory(self.source, self.candidate, self.candidate_id)

    def test_only_three_versions_and_license_paths_move(self):
        self.candidate["packages"].reverse()
        self.inventory()

    def test_exact_license_and_dpkg_paths_required(self):
        for paths in (
            ["/var/lib/dpkg/status"],
            ["/usr/share/doc/openssl/copyright", "/var/lib/dpkg/status"],
            ["/usr/share/doc/libssl3t64/copyright"],
            ["/additional", "/usr/share/doc/libssl3t64/copyright", "/var/lib/dpkg/status"],
            ["/usr/share/doc/libssl3t64/copyright"] * 2 + ["/var/lib/dpkg/status"],
        ):
            with self.subTest(paths=paths), self.assertRaises(Rejected):
                self.candidate["packages"][0]["paths"] = paths
                self.inventory()

    def test_inventory_drift_is_rejected(self):
        for change in ("path", "missing", "extra", "old", "config", "source"):
            with self.subTest(change=change):
                self.setUp()
                if change == "path":
                    self.candidate["packages"][-1]["paths"] = ["/elsewhere"]
                elif change == "missing":
                    self.candidate["packages"].pop()
                elif change == "extra":
                    self.candidate["packages"][0] = self.candidate["packages"][1]
                elif change == "old":
                    self.candidate["packages"][0]["version"] = subject.OLD
                elif change == "config":
                    self.candidate["image_id"] = subject.CONFIG
                else:
                    self.source["image_id"] = self.candidate_id
                with self.assertRaises(Rejected):
                    self.inventory()

    def test_six_positive_controls(self):
        subject.check_findings(self.rows, [])

    def test_pkg_overlay_rejects_embedded_oci_or_opaque_directory(self):
        for path in ("usr/bin/openssl", "var/lib/containerd/index.json", "usr/.wh..wh..opq", "usr"):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:gz") as layer:
                layer.addfile(tarfile.TarInfo(path))
            stream.seek(0)
            with (
                patch.object(subject, "LICENSE_PATHS", {}),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                if path == "usr/bin/openssl":
                    subject.check_overlay(stream, {path}, {}, {})
                else:
                    with self.assertRaises(Rejected):
                        subject.check_overlay(stream, {"usr/bin/openssl"}, {}, {})

    def test_document_opacity_requires_empty_lower_view_and_exact_signed_contents(self):
        parent = "usr/share/doc/openssl"
        directory = tarfile.TarInfo(parent)
        directory.type = tarfile.DIRTYPE
        marker = tarfile.TarInfo(parent + "/.wh..wh..opq")
        license_file = tarfile.TarInfo(parent + "/copyright")
        license_file.size = 3
        signed = {parent: subject.directory_record(directory)[0]}

        def check(entries, inherited):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as tar:
                for member, data in entries:
                    tar.addfile(member, io.BytesIO(data))
            stream.seek(0)
            with (
                patch.object(subject, "LICENSE_PATHS", {"openssl": license_file.name}),
                patch.object(subject, "COPYRIGHT", (3, digest(b"abc"))),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                subject.check_overlay(stream, {license_file.name}, signed, inherited)
            return output.getvalue()

        valid = [(marker, b""), (directory, b""), (license_file, b"abc")]
        for inherited in ({}, {parent: (signed[parent], {})}):
            self.assertIn('"inherited_entries": 0', check(valid, inherited))
        nonempty = {parent + "/old/nested": ({"type": "0"}, {})}
        bad_marker = copy.deepcopy(marker)
        bad_marker.type = tarfile.SYMTYPE
        bad_marker.linkname = "copyright"
        payload_marker = copy.deepcopy(marker)
        payload_marker.size = 1
        xattr_marker = copy.deepcopy(marker)
        xattr_marker.pax_headers = {"SCHILY.xattr.user.extra": "value"}
        wrong_owner = copy.deepcopy(marker)
        wrong_owner.uid = 1000
        for entries, inherited in (
            (valid, nonempty),
            (valid, {parent: ({"type": "2"}, {})}),
            (valid, {"usr/share/doc": ({"type": "2"}, {})}),
            (valid[::2], {}),
            (valid[:-1], {}),
            ([(bad_marker, b""), *valid[1:]], {}),
            ([(payload_marker, b"x"), *valid[1:]], {}),
            ([(xattr_marker, b""), *valid[1:]], {}),
            ([(wrong_owner, b""), *valid[1:]], {}),
            ([(tarfile.TarInfo(parent + "/.wh.copyright"), b""), *valid[1:]], {}),
            (valid + [(marker, b"")], {}),
            (valid + [(tarfile.TarInfo(parent + "/extra"), b"")], {}),
        ):
            with self.subTest(members=len(entries), inherited=list(inherited)):
                with self.assertRaisesRegex(Rejected, "node_overlay_mismatch"):
                    check(entries, inherited)

    def test_existing_directory_requires_bound_metadata(self):
        def layer(*members):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as tar:
                for member in members:
                    tar.addfile(member)
            stream.seek(0)
            return stream

        original = tarfile.TarInfo("tmp")
        original.type, original.mode, original.mtime = tarfile.DIRTYPE, 0o1777, 1
        original.pax_headers = {"SCHILY.xattr.user.test": "private-value"}
        base = {}
        subject.apply_base_layer(base, layer(original))
        changed = copy.deepcopy(original)
        changed.mtime = 2
        with (
            patch.object(subject, "LICENSE_PATHS", {}),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            subject.check_overlay(layer(changed), set(), {}, base)
            self.assertIn('"tmp"', output.getvalue())
            self.assertNotIn("private-value", output.getvalue())
            for field, value in (
                ("mode", 0o777),
                ("uid", 1),
                ("gid", 1),
                ("type", tarfile.SYMTYPE),
                ("pax_headers", {}),
                ("name", "renamed"),
            ):
                item = copy.deepcopy(changed)
                setattr(item, field, value)
                with self.subTest(field=field), self.assertRaises(Rejected):
                    subject.check_overlay(layer(item), set(), {}, base)
            with self.assertRaises(Rejected):
                subject.check_overlay(layer(changed), set(), {}, {})
            signed = {"tmp": subject.directory_record(changed)[0]}
            subject.check_overlay(layer(changed), set(), signed, {})
            old_mode = copy.deepcopy(changed)
            old_mode.mode = 0o700
            previous = {"tmp": subject.directory_record(old_mode)}
            with self.assertRaises(Rejected):
                subject.check_overlay(layer(changed), set(), signed, previous)
            with self.assertRaises(Rejected):
                subject.check_overlay(
                    layer(changed, tarfile.TarInfo("tmp/new"), tarfile.TarInfo("tmp/other")),
                    set(),
                    {},
                    base,
                )
            self.assertIn("tmp/new", output.getvalue())
            self.assertIn("tmp/other", output.getvalue())
            for marker in (".wh.tmp", ".wh..wh..opq"):
                removed = base.copy()
                subject.apply_base_layer(removed, layer(tarfile.TarInfo(marker)))
                with self.assertRaises(Rejected):
                    subject.check_overlay(layer(changed), set(), {}, removed)
            subject.apply_base_layer(base, layer(changed, tarfile.TarInfo(".wh.tmp")))
            self.assertIn("tmp", base)

    def test_license_members_match_type_content_and_multiplicity(self):
        def check(entries):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:gz") as tar:
                for name, kind, data in entries:
                    member = tarfile.TarInfo(subject.LICENSE_PATHS[name])
                    member.type = kind
                    member.size = len(data)
                    tar.addfile(member, io.BytesIO(data))
            stream.seek(0)
            with (
                patch.object(subject, "COPYRIGHT", (3, digest(b"abc"))),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                subject.check_overlay(stream, set(subject.LICENSE_PATHS.values()), {}, {})

        valid = [(name, tarfile.REGTYPE, b"abc") for name in subject.DEB]
        check(valid)
        for entries in (
            valid[:-1],
            valid + valid[:1],
            [("libssl3t64", tarfile.REGTYPE, b"abd"), *valid[1:]],
            [("libssl3t64", tarfile.SYMTYPE, b""), *valid[1:]],
            [("libssl3t64", tarfile.LNKTYPE, b""), *valid[1:]],
        ):
            with self.assertRaises(Rejected):
                check(entries)

    def test_docker_archive_replays_pinned_plain_and_gzip_layers(self):
        def tar_bytes(entries):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as tar:
                for entry, data in entries:
                    entry.size = len(data)
                    tar.addfile(entry, io.BytesIO(data))
            return stream.getvalue()

        directory = tarfile.TarInfo("tmp")
        directory.type, directory.mode = tarfile.DIRTYPE, 0o1777
        first = tar_bytes([(directory, b"")])
        directory.uid = 17
        second = tar_bytes([(directory, b"")])
        directory.mtime += 1
        top = tar_bytes([(directory, b"")])
        base_ids = ["sha256:" + digest(data) for data in (first, second)]
        config = {"rootfs": {"diff_ids": base_ids + ["sha256:" + digest(top)]}}
        manifest = canonical([{"Layers": ["base0", "base1", "top"]}])

        def archive(a, b, c):
            return tar_bytes(
                [
                    (tarfile.TarInfo(k), v)
                    for k, v in [
                        ("manifest.json", manifest),
                        ("base0", a),
                        ("base1", b),
                        ("top", c),
                    ]
                ]
            )

        with (
            tempfile.TemporaryDirectory() as directory_name,
            patch.object(subject, "LAYERS", base_ids),
            patch.object(subject, "LICENSE_PATHS", {}),
            patch.object(subject, "package_files", return_value=(set(), {})),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            path = Path(directory_name) / "candidate.tar"
            path.write_bytes(archive(first, gzip.compress(second), gzip.compress(top)))
            subject.verify_archive_overlay(path, config, path.parent)
            for data in (archive(second, second, top), archive(first, second, first)):
                path.write_bytes(data)
                with self.assertRaisesRegex(Rejected, "diff_id"):
                    subject.verify_archive_overlay(path, config, path.parent)

    def test_other_rows_diff_counts_duplicates_and_bounds_samples(self):
        rows = subject.other_rows(self.source)
        self.assertEqual(len(rows), 875)
        self.assertEqual(subject.bounded_delta(rows, rows[2:])["sample"][0]["count"], 2)
        diff = subject.bounded_delta([canonical(i) for i in range(12)], [])
        self.assertEqual((diff["count"], len(diff["sample"])), (12, 8))
        long_row = canonical("x" * 2000)
        self.assertEqual(
            subject.bounded_delta([long_row], [])["sample"][0]["row"], {"sha256": digest(long_row)}
        )

    def test_wrong_debian_bytes_or_index_binding(self):
        with patch("urllib.request.urlopen", return_value=io.BytesIO(b"wrong")):
            with self.assertRaises(Rejected):
                subject.fetch("https://example.invalid/", (5, digest(b"input")))
        with self.assertRaises(Rejected):
            subject.package_paths(b"wrong suite metadata", b"")

    def test_missing_duplicate_or_changed_control_and_residual(self):
        for rows, residual in (
            (self.rows[1:], []),
            (self.rows + self.rows[:1], []),
            ([{**self.rows[0], "severity": "Unknown"}, *self.rows[1:]], []),
            (self.rows, [{**self.rows[0], "installed": subject.NEW, "severity": "Low"}]),
        ):
            with self.subTest(rows=len(rows), residual=bool(residual)), self.assertRaises(Rejected):
                subject.check_findings(rows, residual)

    def test_oci_config_and_layer_drift(self):
        base = {
            "config": {"Entrypoint": ["/init"]},
            "rootfs": {"type": "layers", "diff_ids": list(subject.LAYERS)},
        }
        candidate = copy.deepcopy(base)
        candidate["rootfs"]["diff_ids"].append(self.candidate_id)
        subject.check_oci(base, candidate)
        for key in ("config", "rootfs"):
            changed = copy.deepcopy(candidate)
            changed[key] = {} if key == "config" else base[key]
            with self.assertRaises(Rejected):
                subject.check_oci(base, changed)
