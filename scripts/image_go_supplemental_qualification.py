"""Controlled pinned-format fixtures, not additional native scanner evidence."""

import copy
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta

from mlsecops.contracts import Rejected
from scripts import image_go_supplemental_contract as contract
from scripts.image_audit_contract import SEVERITIES

MODULE = "k8s.io/streaming"
VERSION = "v0.36.4"
PURL = f"pkg:golang/{MODULE}@{VERSION}"
THRESHOLD = "discovered vulnerabilities at or above the severity threshold"
STAMP = datetime(2026, 11, 20, 4, tzinfo=UTC)


def fixture(severities=(), timestamp=STAMP):
    findings = [
        {
            "artifact": {
                "id": "package-1",
                "name": MODULE,
                "version": VERSION,
                "type": "go-module",
                "purl": PURL,
            },
            "vulnerability": {
                "id": f"GO-2026-{index + 1000}",
                "severity": severity,
                "fix": {"state": "not-fixed", "versions": []},
            },
        }
        for index, severity in enumerate(severities)
    ]
    blocked = bool(set(severities) & {"High", "Critical"})
    report = {
        "source": {"type": "purl", "target": PURL},
        "descriptor": {
            "name": "grype",
            "version": "0.120.1",
            "db": {
                "status": {
                    "schemaVersion": "v6.1.3",
                    "built": timestamp.isoformat(),
                    "valid": True,
                }
            },
        },
        "matches": findings,
    }
    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "library",
                "name": MODULE,
                "version": VERSION,
                "purl": PURL,
                "properties": [{"name": "syft:package:type", "value": "go-module"}],
            }
        ],
    }
    trace = (
        "[0000] DEBUG config:\n  fail-on-severity: high\n  quiet: false\n"
        f"[0000] TRACE searching for vulnerability matches package={PURL}\n"
    )
    if not blocked:
        trace += f"[0001]  INFO found {len(findings)} vulnerability matches across 1 packages\n"
    trace += "[0001]  INFO found vulnerability matches time=1ms\n"
    trace += "[0001] TRACE wrote vulnerability report time=1ms\n"
    if blocked:
        trace += f"[0001] ERROR {THRESHOLD}\n"
    return dict(
        module=MODULE,
        version=VERSION,
        report=report,
        cdx=cdx,
        trace=trace.encode(),
        returncode=2 if blocked else 0,
        expected_database={"schema_version": "v6.1.3", "built": timestamp.isoformat()},
        timestamp=timestamp,
    )


class SupplementalContracts(unittest.TestCase):
    def test_blank_fix_state_retains_finding_and_severity_decision(self):
        # Grype's serialized Fix.State may be the empty Go string. This was
        # also observed for GO-2025-3547 in the saved Kubernetes image reports.
        for severity, expected in (
            ("Low", "pass"),
            ("High", "fail"),
            ("Critical", "fail"),
            ("Unknown", "inconclusive"),
        ):
            inputs = fixture([severity])
            inputs["report"]["matches"][0]["vulnerability"]["fix"]["state"] = ""
            with self.subTest(severity=severity):
                result = contract.assess(**inputs)
                self.assertEqual(result["status"], expected)
                self.assertEqual(result["matches"], 1)
                self.assertEqual(result["findings"][0]["fix"], {"state": "", "versions": []})
                self.assertEqual(result["severity_counts"][severity], 1)

    def rejected(self, inputs):
        with self.assertRaises(Rejected) as caught:
            contract.assess(**inputs)
        self.assertEqual(str(caught.exception), "image_go_supplemental_rejected")

    def test_rejects_coordinate_bypass_before_report_interpretation(self):
        for field, values in {
            "module": (
                None,
                True,
                "",
                "k8s.io/../streaming",
                "k8s.io//streaming",
                "/k8s.io/a",
                "K8S.io/streaming",
                "k8s.io/a?x=1",
                "k8s.io/%73treaming",
                "k8s.io/a@v1",
                "x" * 513,
            ),
            "version": (
                None,
                False,
                "not-a-version",
                "v01.2.3",
                "v1.02.3",
                "1.2.3",
                "v1.2",
                "v1.2.3-rc.1",
                "v1.2.3+incompatible",
                "v0.0.0-20260101000000-abcdef123456",
                "v1.2.3\n",
            ),
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    inputs = fixture()
                    inputs[field] = value
                    self.rejected(inputs)
        inputs = fixture()
        inputs["version"] = "not-a-version"
        foreign = PURL.replace(VERSION, "not-a-version")
        inputs["report"]["source"]["target"] = foreign
        inputs["cdx"]["components"][0].update(version="not-a-version", purl=foreign)
        inputs["trace"] = inputs["trace"].replace(PURL.encode(), foreign.encode())
        self.rejected(inputs)

    def test_wrapper_pseudo_version_is_bound_to_one_module_and_revision(self):
        wrapper = "github.com/kubernetes-sigs/iptables-wrappers"
        pinned = "v0.0.0-20260420133543-bfef9e5087a1"
        for module, version in ((wrapper, pinned), (MODULE, pinned), (wrapper, pinned[:-1] + "2")):
            with self.subTest(module=module, version=version):
                inputs = fixture()
                purl = f"pkg:golang/{module}@{version}"
                inputs.update(module=module, version=version)
                inputs["report"]["source"]["target"] = purl
                inputs["cdx"]["components"][0].update(name=module, version=version, purl=purl)
                inputs["trace"] = inputs["trace"].replace(PURL.encode(), purl.encode())
                if (module, version) == (wrapper, pinned):
                    self.assertEqual(contract.assess(**inputs)["purl"], purl)
                else:
                    self.rejected(inputs)

    def test_rejects_source_cdx_or_component_binding_changes(self):
        for mutate in (
            lambda x: x["report"]["source"].update(type="image"),
            lambda x: x["report"]["source"].update(target=PURL + "-other"),
            lambda x: x["report"]["source"].update(extra=True),
            lambda x: x["cdx"].update(bomFormat="other"),
            lambda x: x["cdx"].update(components=[]),
            lambda x: x["cdx"]["components"].append(copy.deepcopy(x["cdx"]["components"][0])),
            lambda x: x["cdx"].update(components=[None]),
            lambda x: x["cdx"]["components"][0].update(name="k8s.io/foreign"),
            lambda x: x["cdx"]["components"][0].update(version="v0.36.3"),
            lambda x: x["cdx"]["components"][0].update(purl=PURL + "?x=1"),
            lambda x: x["cdx"]["components"][0].update(type="application"),
            lambda x: x["cdx"]["components"][0].update(properties=[]),
            lambda x: x["cdx"]["components"][0].update(properties=[None]),
            lambda x: x["cdx"]["components"][0]["properties"][0].update(value="deb"),
            lambda x: x["cdx"]["components"][0]["properties"].append(
                {"name": "syft:package:type", "value": "go-module"}
            ),
            lambda x: x["cdx"]["components"][0].update(components=[{}]),
        ):
            with self.subTest(mutate=mutate):
                inputs = fixture()
                mutate(inputs)
                self.rejected(inputs)

    def test_rejects_foreign_or_malformed_findings(self):
        for field, value in (
            ("name", "foreign"),
            ("version", "v1.2.3"),
            ("type", "deb"),
            ("purl", PURL + "#x"),
        ):
            inputs = fixture(["High"])
            inputs["report"]["matches"][0]["artifact"][field] = value
            self.rejected(inputs)
        for mutate in (
            lambda m: m.pop("artifact"),
            lambda m: m.update(artifact=[]),
            lambda m: m.update(vulnerability=None),
            lambda m: m["vulnerability"].update(id=""),
            lambda m: m["vulnerability"].update(id=True),
            lambda m: m["vulnerability"].update(severity="Unrecognized"),
            lambda m: m["vulnerability"].update(fix=None),
            lambda m: m["vulnerability"].update(fix={"state": True}),
            lambda m: m["vulnerability"].update(fix={"versions": "v1.0.0"}),
            lambda m: m["vulnerability"].update(fix={"versions": [False]}),
        ):
            inputs = fixture(["High"])
            mutate(inputs["report"]["matches"][0])
            self.rejected(inputs)

    def test_rejects_ignores_alerts_invalid_exit_and_policy_disagreement(self):
        for field in ("ignoredMatches", "alertsByPackage"):
            for value in ([{}], {}, None, False, ""):
                inputs = fixture()
                inputs["report"][field] = value
                self.rejected(inputs)
        for code in (True, False, "0", 0.0, None, 1, 125, -9, 2):
            inputs = fixture()
            inputs["returncode"] = code
            self.rejected(inputs)
        inputs = fixture(["High"])
        inputs["returncode"] = 0
        self.rejected(inputs)

    def test_rejects_stale_future_or_changed_database(self):
        for delta in (timedelta(hours=120, microseconds=1), -timedelta(microseconds=1)):
            inputs = fixture()
            inputs["timestamp"] += delta
            self.rejected(inputs)
        for mutate in (
            lambda x: x["report"]["descriptor"].update(version="0.120.0"),
            lambda x: x["report"]["descriptor"]["db"]["status"].update(valid=False),
            lambda x: x["report"]["descriptor"]["db"]["status"].update(error="PRIVATE_CANARY"),
            lambda x: x["expected_database"].update(built="other"),
            lambda x: x["expected_database"].update(extra=True),
            lambda x: x.update(expected_database=[]),
            lambda x: x.update(timestamp=False),
            lambda x: x.update(timestamp=STAMP.replace(tzinfo=None)),
        ):
            inputs = fixture()
            mutate(inputs)
            self.rejected(inputs)

    def test_rejects_missing_foreign_duplicate_or_early_trace(self):
        original = fixture()["trace"]
        search = f"[0000] TRACE searching for vulnerability matches package={PURL}\n".encode()
        summary = b"[0001]  INFO found 0 vulnerability matches across 1 packages\n"
        for trace in (
            b"",
            original.decode(),
            bytearray(original),
            b"x" * (2 * 1024**2 + 1),
            b"\xff",
            original[:-1],
            original.replace(search, b""),
            original + search,
            original.replace(PURL.encode(), (PURL + "-foreign").encode()),
            original.replace(b"TRACE searching", b"INFO searching"),
            original.replace(summary, b""),
            original + summary,
            original.replace(b"across 1 packages", b"across 2 packages"),
            original.replace(b"found 0 vulnerability", b"found 1 vulnerability"),
            summary + search,
            original + b"unexpected raw failure\n",
            original + b"\x00\n",
            original + b"\x1b[2J\n",
        ):
            inputs = fixture()
            inputs["trace"] = trace
            self.rejected(inputs)

    def test_rejects_operational_errors_and_one_error_shortcut(self):
        for line in (
            "[0002] ERROR PRIVATE_CANARY",
            "[0002] WARN matcher returned error package=PRIVATE_CANARY",
            "[0002] DEBUG error(s) returned from searchDBForMatches",
            "[0002] FATAL crash",
            "[0002] PANIC crash",
            "[0002] WARN unknown warning",
            "[0002] DEBUG operation failed",
        ):
            inputs = fixture(["High"])
            inputs["trace"] += (line + "\n").encode()
            self.rejected(inputs)
        for replacement in ("PRIVATE_CANARY", THRESHOLD + " extra", "prefix " + THRESHOLD):
            inputs = fixture(["High"])
            inputs["trace"] = inputs["trace"].replace(THRESHOLD.encode(), replacement.encode())
            self.rejected(inputs)
        for severity in ((), ("High",)):
            inputs = fixture(severity)
            inputs["trace"] += f"[0003] ERROR {THRESHOLD}\n".encode()
            self.rejected(inputs)
        inputs = fixture(["High"])
        inputs["trace"] = inputs["trace"].replace(f"[0001] ERROR {THRESHOLD}\n".encode(), b"")
        self.rejected(inputs)

    def test_rejects_malformed_and_oversized_documents(self):
        for key in ("report", "cdx"):
            for value in (None, [], False, "PRIVATE_CANARY"):
                inputs = fixture()
                inputs[key] = value
                self.rejected(inputs)
        for value in (None, {}, [None], [False], [0] * 10001):
            inputs = fixture()
            inputs["report"]["matches"] = value
            self.rejected(inputs)
        for value in (object(), float("nan"), float("inf"), 2**100, "x" * 65537):
            inputs = fixture()
            inputs["report"]["extra"] = value
            self.rejected(inputs)
        inputs = fixture()
        inputs["report"][False] = "invalid key"
        self.rejected(inputs)
        inputs = fixture()
        inputs["cdx"]["extra"] = ["x" * 60000] * 20
        self.rejected(inputs)
        inputs = fixture()
        inputs["report"]["extra"] = inputs["report"]
        self.rejected(inputs)

    def test_zero_and_all_severities_preserve_result_shape(self):
        for severity in (None, *SEVERITIES):
            inputs = fixture(() if severity is None else (severity,))
            before = copy.deepcopy(inputs)
            result = contract.assess(**inputs)
            self.assertEqual(inputs, before)
            self.assertEqual(
                set(result),
                {
                    "status",
                    "matches",
                    "unique_vulnerabilities",
                    "severity_counts",
                    "findings",
                    "database",
                    "scanner_exit_code",
                    "purl",
                    "package_identity_bound",
                    "matching_completed",
                },
            )
            self.assertEqual(
                result["status"],
                "fail"
                if severity in ("High", "Critical")
                else "inconclusive"
                if severity == "Unknown"
                else "pass",
            )
            self.assertEqual(result["matches"], int(severity is not None))
            self.assertEqual(result["unique_vulnerabilities"], int(severity is not None))
            self.assertEqual(result["severity_counts"], {s: int(s == severity) for s in SEVERITIES})
            self.assertTrue(result["package_identity_bound"])
            self.assertTrue(result["matching_completed"])
            self.assertEqual(result["database"], inputs["expected_database"])
            self.assertEqual(result["purl"], PURL)

    def test_all_findings_unknown_and_unfixed_survive_without_aliasing(self):
        inputs = fixture(["Low", "High", "Unknown", "High"])
        inputs["report"]["matches"][3]["vulnerability"]["id"] = "GO-2026-1001"
        inputs["report"]["matches"][0]["vulnerability"]["fix"] = {
            "state": "fixed",
            "versions": ["v0.36.5"],
        }
        result = contract.assess(**inputs)
        self.assertEqual(result["matches"], 4)
        self.assertEqual(result["unique_vulnerabilities"], 3)
        self.assertEqual(
            result["findings"][0],
            {
                "id": "GO-2026-1000",
                "severity": "Low",
                "package": MODULE,
                "installed": VERSION,
                "type": "go-module",
                "fix": {"state": "fixed", "versions": ["v0.36.5"]},
            },
        )
        self.assertEqual(result["findings"][2]["severity"], "Unknown")
        self.assertEqual(result["findings"][3]["fix"]["state"], "not-fixed")
        result["findings"][0]["fix"]["versions"].append("foreign")
        self.assertEqual(
            inputs["report"]["matches"][0]["vulnerability"]["fix"]["versions"], ["v0.36.5"]
        )

    def test_optional_fix_metadata_sgr_and_actual_default_clock(self):
        inputs = fixture(["Medium"], datetime.now(UTC))
        inputs["timestamp"] = None
        inputs["report"]["matches"][0]["vulnerability"].pop("fix")
        inputs["report"].update(
            ignoredMatches=[], alertsByPackage=[], extra={"float": 0.5, "bool": False, "none": None}
        )
        inputs["cdx"]["components"][0]["properties"].append(
            {"name": "syft:package:language", "value": "go"}
        )
        inputs["trace"] = (
            inputs["trace"].replace(b"TRACE", b"\x1b[35mTRACE\x1b[0m").replace(b"\n", b"\r\n")
        )
        result = contract.assess(**inputs)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["findings"][0]["fix"], {"state": None, "versions": []})
        inputs = fixture()
        inputs["timestamp"] += timedelta(hours=120)
        self.assertEqual(contract.assess(**inputs)["status"], "pass")

    def test_control_sized_findings_and_private_error_do_not_escape(self):
        # Source-shaped log records, not a copy of the unretained native raw trace.
        inputs = fixture(["High"] * 23)
        search = f"[0000] TRACE searching for vulnerability matches package={PURL}\n"
        detail = (
            f"[0000] DEBUG found 23 vulnerabilities package={PURL}\n"
            "[0000] TRACE   \u251c\u2500\u2500 namespace=github:language:go vuln=GHSA-example\n\n"
        )
        inputs["trace"] = inputs["trace"].replace(search.encode(), (search + detail).encode())
        result = contract.assess(**inputs)
        self.assertEqual(result["matches"], 23)
        self.assertEqual(result["scanner_exit_code"], 2)
        self.assertEqual(result["severity_counts"]["High"], 23)
        private = b"PRIVATE_CANARY_credential_and_path"
        inputs["trace"] += b"[0002] ERROR " + private + b"\n"
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.rejected(inputs)
        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", ""))

    def test_structural_and_utf8_budgets_include_unused_metadata(self):
        for value in (
            {str(index): None for index in range(10001)},
            [[None] * 10000 for _ in range(11)],
            ["x" * 60000] * 280,
            "\u00e9" * 40000,
            "\ud800",
        ):
            inputs = fixture()
            inputs["report"]["unused"] = value
            self.rejected(inputs)
        inputs = fixture()
        inputs["trace"] += b"\n" * (2 * 1024**2 - len(inputs["trace"]))
        self.assertEqual(contract.assess(**inputs)["status"], "pass")
        inputs["trace"] += b"\n"
        self.rejected(inputs)


if __name__ == "__main__":
    unittest.main()
