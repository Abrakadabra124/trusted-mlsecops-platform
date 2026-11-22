import copy
import io
import tarfile
import unittest
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
            with patch.object(subject, "LICENSE_PATHS", {}):
                if path == "usr/bin/openssl":
                    subject.check_overlay(stream, {path}, {"usr"})
                else:
                    with self.assertRaises(Rejected):
                        subject.check_overlay(stream, {"usr/bin/openssl"}, {"usr"})

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
            with patch.object(subject, "COPYRIGHT", (3, digest(b"abc"))):
                subject.check_overlay(stream, set(subject.LICENSE_PATHS.values()), set())

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
