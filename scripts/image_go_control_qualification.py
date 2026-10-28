import copy
import unittest

from mlsecops.contracts import Rejected
from scripts.image_audit_contract import go_detection_control
from scripts.image_audit_qualification import fixtures


class GoDetectionContracts(unittest.TestCase):
    def sample(self, kind):
        _, report, match, _, timestamp = fixtures()
        name, version = (
            ("golang.org/x/net", "v0.16.0") if kind == "module" else ("stdlib", "go1.20.9")
        )
        match["artifact"].update(name=name, version=version, type="go-module")
        match["vulnerability"].update(id="GO-2023-2102", severity="High")
        report["matches"] = [match]
        return report, timestamp

    def test_module_and_stdlib_must_detect_same_documented_advisory(self):
        for kind in ("module", "stdlib"):
            for advisory in ("GO-2023-2102", "CVE-2023-39325", "GHSA-4374-p667-p6c8"):
                report, timestamp = self.sample(kind)
                report["matches"][0]["vulnerability"]["id"] = advisory
                with self.subTest(kind=kind, advisory=advisory):
                    go_detection_control(report, 2, kind, timestamp)

    def test_missing_wrong_or_suppressed_detection_cannot_pass(self):
        for kind in ("module", "stdlib"):
            original, timestamp = self.sample(kind)
            for mutation in (
                lambda r: r.update(matches=[]),
                lambda r: r.update(matches=None),
                lambda r: r["matches"][0]["artifact"].update(name="other"),
                lambda r: r["matches"][0]["artifact"].update(version="fixed"),
                lambda r: r["matches"][0]["artifact"].update(type="deb"),
                lambda r: r["matches"][0]["vulnerability"].update(id="unrelated"),
                lambda r: r["matches"][0]["vulnerability"].update(severity="Medium"),
                lambda r: r["matches"][0].pop("artifact"),
                lambda r: r.update(ignoredMatches=[{}]),
                lambda r: r.update(alertsByPackage={"unscanned": [{}]}),
                lambda r: r["descriptor"].update(version="other"),
                lambda r: r["descriptor"]["db"]["status"].update(valid=False),
            ):
                report = copy.deepcopy(original)
                mutation(report)
                with self.subTest(kind=kind, mutation=mutation), self.assertRaises(Rejected):
                    go_detection_control(report, 2, kind, timestamp)
            for code in (0, 1, True, "2"):
                with self.subTest(kind=kind, code=code), self.assertRaises(Rejected):
                    go_detection_control(original, code, kind, timestamp)
        with self.assertRaises(Rejected):
            go_detection_control(original, 2, "unknown", timestamp)


if __name__ == "__main__":
    unittest.main()
