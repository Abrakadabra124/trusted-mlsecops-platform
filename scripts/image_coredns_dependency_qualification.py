import copy
import gzip
import io
import tarfile
import unittest
from hashlib import sha256

from mlsecops.contracts import Rejected
from scripts import image_coredns_dependency as qualify
from scripts.image_package_observation_qualification import coredns_observation


class DependencyTests(unittest.TestCase):
    def test_complete_candidate_observation(self):
        original = coredns_observation()
        config = "sha256:" + "1" * 64
        original["image_id"] = config
        for row in original["packages"]:
            if row["name"] in qualify.UPDATES:
                row["version"] = qualify.UPDATES[row["name"]][1]
        self.assertTrue(qualify.inventory_matches(original, config))
        for key, value in (("version", "UNKNOWN"), ("paths", ["/other"]), ("foundBy", "other")):
            edited = copy.deepcopy(original)
            edited["packages"][0][key] = value
            self.assertFalse(qualify.inventory_matches(edited, config))
        self.assertFalse(qualify.inventory_matches(original, qualify.COREDNS_CONFIG))
        original["packages"].pop()
        self.assertFalse(qualify.inventory_matches(original, config))

    def test_findings_and_unknown(self):
        findings = [
            dict(id=id_, package=name, installed=ver, severity=severity, type="go-module")
            for id_, name, ver, severity in qualify.BASELINE
        ]
        candidate = {"status": "pass", "findings": []}
        self.assertTrue(qualify.accepted(findings, candidate))
        self.assertFalse(qualify.accepted(findings[:-1], candidate))
        for status in ("fail", "inconclusive"):
            self.assertFalse(qualify.accepted(findings, {**candidate, "status": status}))
        downgraded = {**findings[0], "severity": "Low"}
        self.assertFalse(qualify.accepted(findings, {**candidate, "findings": [downgraded]}))

    def test_final_layer_exact_bytes_and_metadata(self):
        elf = b"\x7fELF" + bytes(80)
        elf_hash = sha256(elf).hexdigest()
        for error in ("", "missing-cap", "extra-cap", "wrong-mode", "link", "duplicate", "extra"):
            with self.subTest(error=error):
                buf = io.BytesIO()
                with tarfile.open(fileobj=buf, mode="w") as layer:
                    member = tarfile.TarInfo("coredns")
                    member.size = len(elf)
                    member.mode = 0o755 if error != "wrong-mode" else 0o777
                    if error != "missing-cap":
                        attr = qualify.CAPABILITY if error != "extra-cap" else bytes(20)
                        member.pax_headers["SCHILY.xattr.security.capability"] = attr.decode()
                    if error == "link":
                        member.type = tarfile.SYMTYPE
                    layer.addfile(member, io.BytesIO(elf))
                    if error in ("duplicate", "extra"):
                        layer.addfile(tarfile.TarInfo("other" if error == "extra" else "coredns"))
                raw = buf.getvalue()
                diff_id = "sha256:" + sha256(raw).hexdigest()
                if error:
                    with self.assertRaises(Rejected):
                        qualify.read_layer(io.BytesIO(raw), diff_id, elf_hash)
                else:
                    for contents in (raw, gzip.compress(raw)):
                        self.assertEqual(
                            qualify.read_layer(io.BytesIO(contents), diff_id, elf_hash), elf_hash
                        )
                    for wrong_diff, wrong_elf in (
                        (diff_id, "0" * 64),
                        ("sha256:" + "0" * 64, elf_hash),
                    ):
                        with self.assertRaises(Rejected):
                            qualify.read_layer(io.BytesIO(raw), wrong_diff, wrong_elf)
