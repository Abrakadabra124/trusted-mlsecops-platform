import copy
import unittest

from mlsecops.contracts import Rejected
from scripts.image_audit_contract import assess
from scripts.image_audit_qualification import fixtures


class DiagnosticScanContracts(unittest.TestCase):
    def test_bound_minimal_ubuntu_and_unknown_distro_never_grant_coverage(self):
        for declared, observed in (
            ({"id": "debian", "versionID": "12.14"}, {"name": "debian", "version": "12"}),
            ({"id": "ubuntu", "versionID": "26.04"}, {"name": "ubuntu", "version": "26.04"}),
            ({}, None),
            (None, {"name": "", "version": ""}),
        ):
            sbom, report, _, image, timestamp = fixtures()
            sbom["distro"], report["distro"] = declared, observed
            sbom["artifacts"] = [
                {
                    "id": "main",
                    "name": "example.org/app",
                    "version": "UNKNOWN",
                    "type": "go-module",
                    "foundBy": "go-module-binary-cataloger",
                }
            ]
            with self.subTest(distro=declared):
                result = assess(sbom, report, image, set(), 0, timestamp, diagnostic_only=True)
                self.assertEqual(result["status"], "inconclusive")
                self.assertEqual(result["packages"], 1)

    def test_real_blocking_findings_stay_fail_without_application_approval(self):
        sbom, report, match, image, timestamp = fixtures()
        report["matches"] = [match]
        for severity, code, expected in (
            ("Critical", 2, "fail"),
            ("High", 2, "fail"),
            ("Unknown", 0, "inconclusive"),
            ("Low", 0, "inconclusive"),
        ):
            report["matches"][0]["vulnerability"]["severity"] = severity
            with self.subTest(severity=severity):
                result = assess(sbom, report, image, set(), code, timestamp, diagnostic_only=True)
                self.assertEqual(result["status"], expected)
                self.assertEqual(result["findings"][0]["severity"], severity)

    def test_diagnostics_still_reject_foreign_malformed_or_suppressed_reports(self):
        original, original_report, match, image, timestamp = fixtures()
        for mutate in (
            lambda s, r: s.update(artifacts=[]),
            lambda s, r: s["source"]["metadata"].update(imageID="sha256:" + "b" * 64),
            lambda s, r: r["source"]["target"].update(imageID="sha256:" + "b" * 64),
            lambda s, r: r.update(distro={"name": "ubuntu", "version": "12"}),
            lambda s, r: r.update(distro={"name": "debian", "version": "13"}),
            lambda s, r: r.update(distro=False),
            lambda s, r: r.update(ignoredMatches=[{}]),
            lambda s, r: r.update(alertsByPackage={"missing": [{}]}),
            lambda s, r: r["descriptor"]["db"]["status"].update(valid=False),
            lambda s, r: r.update(
                matches=[{**match, "artifact": {**match["artifact"], "id": "foreign"}}]
            ),
        ):
            sbom, report = copy.deepcopy(original), copy.deepcopy(original_report)
            mutate(sbom, report)
            with self.subTest(mutation=mutate), self.assertRaises(Rejected):
                assess(sbom, report, image, set(), 0, timestamp, diagnostic_only=True)

    def test_normal_coverage_contract_is_not_weakened(self):
        sbom, report, _, image, timestamp = fixtures()
        with self.assertRaises(Rejected):
            assess(sbom, report, image, set(), 0, timestamp)


if __name__ == "__main__":
    unittest.main()
