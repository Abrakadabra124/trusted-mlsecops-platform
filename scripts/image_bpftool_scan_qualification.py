import copy
import unittest
from datetime import UTC, datetime

from mlsecops.contracts import Rejected
from scripts import image_bpftool_scan as scan
from scripts.image_audit_contract import GRYPE_VERSION, SYFT_VERSION


class NobleScanTests(unittest.TestCase):
    def setUp(self):
        stamp = datetime.now(UTC).isoformat()
        self.expected = {"libc6-dev": ("glibc", "2.39-0ubuntu8.3")}
        self.database = {"built": stamp, "schema_version": "v6.1.10"}
        self.pkg = dict(
            id="abcdef",
            name="libc6-dev",
            version="2.39-0ubuntu8.3",
            type="deb",
            foundBy="dpkg-db-cataloger",
            metadata=dict(architecture="amd64", source="glibc", sourceVersion=""),
            locations=[{"path": "/var/lib/dpkg/status"}],
        )
        self.sbom = {
            "descriptor": {"name": "syft", "version": SYFT_VERSION},
            "artifacts": [self.pkg],
            "distro": {"id": "ubuntu", "versionID": "24.04"},
            "source": {"type": "directory", "metadata": {"path": "/input"}},
        }
        self.match = {
            "artifact": {k: self.pkg[k] for k in ("id", "name", "version", "type")},
            "vulnerability": {
                "id": "CVE-2025-0395",
                "namespace": "ubuntu:distro:ubuntu:24.04",
                "severity": "Medium",
                "fix": {"state": "fixed", "versions": ["2.39-0ubuntu8.4"]},
            },
        }
        self.report = {
            "descriptor": {
                "name": "grype",
                "version": GRYPE_VERSION,
                "db": {"status": {"schemaVersion": "v6.1.10", "built": stamp, "valid": True}},
            },
            "source": {"type": "directory", "target": "/input"},
            "distro": {"name": "ubuntu", "version": "24.04"},
            "matches": [self.match],
        }

    def result(self):
        return scan.assess(self.sbom, self.report, 0, self.expected, self.database)

    def test_findings_are_bound_to_source_package_and_exact_revision(self):
        findings = self.result()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source_package"], "glibc")
        self.assertEqual(findings[0]["installed"], "2.39-0ubuntu8.3")
        proof = scan.control(findings, [])
        self.assertEqual(proof["observed_matches"], 1)
        self.assertEqual(proof["fixed_matches"], 0)

    def test_changed_evidence_rejected(self):
        for change in (
            lambda: self.sbom["artifacts"].append(self.pkg),
            lambda: self.pkg["metadata"].update(architecture="arm64"),
            lambda: self.pkg["metadata"].update(source="other"),
            lambda: self.pkg["metadata"].update(sourceVersion="9:2.39"),
            lambda: self.sbom["distro"].update(id="debian"),
            lambda: self.report["distro"].update(version="22.04"),
            lambda: self.match["artifact"].update(id="unknown"),
            lambda: self.match["vulnerability"].update(namespace="nvd:cpe"),
            lambda: self.report.update(ignoredMatches=[self.match]),
            lambda: self.match["vulnerability"].update(severity="High"),
            lambda: self.report["descriptor"]["db"]["status"].update(valid=False),
        ):
            self.setUp()
            change()
            with self.assertRaises(Rejected):
                self.result()

    def test_control_both_sides_required(self):
        findings = self.result()
        wrong_fix = copy.deepcopy(findings)
        wrong_fix[0]["fix"]["versions"] = ["2.39"]
        for old, new in (([], []), (wrong_fix, []), (findings, findings)):
            with self.assertRaises(Rejected):
                scan.control(old, new)
