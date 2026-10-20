import copy
from datetime import UTC, datetime, timedelta

from mlsecops.contracts import Rejected, canonical
from scripts.image_audit_contract import assess, detection_control, wolfi_detection_control


def fixtures():
    image_id = "sha256:" + "a" * 64
    packages = [
        {"id": name, "name": name, "version": "1", "type": "deb", "foundBy": "dpkg-db-cataloger"}
        for name in ("libc6", "postgresql-18")
    ]
    sbom = {
        "descriptor": {"name": "syft", "version": "1.54.1"},
        "source": {"type": "image", "metadata": {"imageID": image_id}},
        "distro": {"id": "debian", "versionID": "12.15"},
        "artifacts": packages,
    }
    timestamp = datetime(2026, 10, 8, 20, tzinfo=UTC)
    report = {
        "descriptor": {
            "name": "grype",
            "version": "0.120.1",
            "db": {
                "status": {
                    "valid": True,
                    "schemaVersion": "v6.1.10",
                    "built": timestamp.isoformat(),
                },
                "providers": {},
            },
        },
        "source": {"type": "image", "target": {"imageID": image_id}},
        "distro": {"name": "debian", "version": "12"},
        "matches": [],
    }
    match = {
        "artifact": {key: packages[0][key] for key in ("id", "name", "version", "type")},
        "vulnerability": {
            "id": "CVE-2026-12345",
            "severity": "High",
            "fix": {"state": "not-fixed", "versions": []},
        },
    }
    return sbom, report, match, image_id, timestamp


def qualify():
    cases = []

    def confirmed(name, condition):
        if not condition:
            raise Rejected(f"image_audit_contract_failed:{name}")
        cases.append({"id": name, "status": "pass", "expected": True, "actual": True})

    sbom, report, match, image_id, timestamp = fixtures()
    required = {"libc6", "postgresql-18"}
    result = assess(sbom, report, image_id, required, 0, timestamp)
    confirmed("covered-empty-matches", result["status"] == "pass" and result["packages"] == 2)
    for severity, expected, returncode in (
        ("Negligible", "pass", 0),
        ("Low", "pass", 0),
        ("Medium", "pass", 0),
        ("High", "fail", 2),
        ("Critical", "fail", 2),
        ("Unknown", "inconclusive", 0),
    ):
        document = copy.deepcopy(report)
        document["matches"] = [copy.deepcopy(match)]
        document["matches"][0]["vulnerability"]["severity"] = severity
        confirmed(
            f"severity:{severity}",
            assess(sbom, document, image_id, required, returncode, timestamp)["status"] == expected,
        )
    for name, change in (
        ("empty-inventory", lambda inputs: inputs[0].update(artifacts=[])),
        ("missing-inventory", lambda inputs: inputs[0].pop("artifacts")),
        ("missing-required-package", lambda inputs: inputs[0]["artifacts"].pop()),
        (
            "duplicate-package-id",
            lambda inputs: inputs[0]["artifacts"].append(inputs[0]["artifacts"][0]),
        ),
        ("uncatalogued-package", lambda inputs: inputs[0]["artifacts"][0].update(foundBy="")),
        ("wrong-syft-version", lambda inputs: inputs[0]["descriptor"].update(version="old")),
        ("wrong-sbom-image", lambda inputs: inputs[0]["source"]["metadata"].update(imageID="old")),
        ("wrong-report-image", lambda inputs: inputs[1]["source"]["target"].update(imageID="old")),
        ("missing-image", lambda inputs: inputs[1].pop("source")),
        ("wrong-grype-version", lambda inputs: inputs[1]["descriptor"].update(version="old")),
        ("bad-db", lambda inputs: inputs[1]["descriptor"]["db"]["status"].update(valid=False)),
        (
            "truthy-db-valid",
            lambda inputs: inputs[1]["descriptor"]["db"]["status"].update(valid="true"),
        ),
        (
            "db-error",
            lambda inputs: inputs[1]["descriptor"]["db"]["status"].update(error="corrupted"),
        ),
        ("missing-db", lambda inputs: inputs[1]["descriptor"].pop("db")),
        (
            "old-schema",
            lambda inputs: inputs[1]["descriptor"]["db"]["status"].update(schemaVersion="5"),
        ),
        (
            "stale-db",
            lambda inputs: inputs[1]["descriptor"]["db"]["status"].update(
                built=(timestamp - timedelta(hours=121)).isoformat()
            ),
        ),
        (
            "future-db",
            lambda inputs: inputs[1]["descriptor"]["db"]["status"].update(
                built=(timestamp + timedelta(hours=1)).isoformat()
            ),
        ),
        (
            "naive-db-date",
            lambda inputs: inputs[1]["descriptor"]["db"]["status"].update(
                built="2026-10-08T20:00:00"
            ),
        ),
        (
            "invalid-db-date",
            lambda inputs: inputs[1]["descriptor"]["db"]["status"].update(built="yesterday"),
        ),
        ("unsupported-distro", lambda inputs: inputs[0]["distro"].update(id="unknown")),
        ("wrong-distro", lambda inputs: inputs[1]["distro"].update(version="13")),
        ("ignored-matches", lambda inputs: inputs[1].update(ignoredMatches=[match])),
        ("coverage-alert", lambda inputs: inputs[1].update(alertsByPackage=[{"alerts": ["eol"]}])),
        ("null-matches", lambda inputs: inputs[1].update(matches=None)),
        ("crashed-scanner", lambda inputs: inputs.__setitem__(4, 1)),
        ("empty-threshold-exit", lambda inputs: inputs.__setitem__(4, 2)),
        ("boolean-exit", lambda inputs: inputs.__setitem__(4, False)),
    ):
        inputs = [copy.deepcopy(sbom), copy.deepcopy(report), image_id, required, 0, timestamp]
        change(inputs)
        try:
            assess(*inputs)
        except Rejected:
            confirmed(name, True)
        else:
            confirmed(name, False)
    for name, change in (
        (
            "unknown-artifact",
            lambda document: document["matches"][0]["artifact"].update(id="other"),
        ),
        (
            "changed-artifact-version",
            lambda document: document["matches"][0]["artifact"].update(version="2"),
        ),
        (
            "invalid-severity",
            lambda document: document["matches"][0]["vulnerability"].update(severity="safe"),
        ),
        ("high-with-zero-exit", lambda document: None),
    ):
        document = copy.deepcopy(report)
        document["matches"] = [copy.deepcopy(match)]
        change(document)
        try:
            assess(sbom, document, image_id, required, 0, timestamp)
        except Rejected:
            confirmed(name, True)
        else:
            confirmed(name, False)
    control = copy.deepcopy(report)
    control["matches"] = [copy.deepcopy(match)]
    control["matches"][0]["artifact"].update(name="urllib3", version="1.26.7")
    control["matches"][0]["vulnerability"]["id"] = "GHSA-v845-jxx5-vc9f"
    detection_control(control, 2, timestamp)
    confirmed("known-vulnerable-package-detected", True)
    for name, mutate in (
        ("no-matches", lambda value: value.update(matches=[])),
        ("malformed-match", lambda value: value.update(matches=[{}])),
        (
            "wrong-vulnerability",
            lambda value: value["matches"][0]["vulnerability"].update(id="other"),
        ),
        (
            "wrong-control-package",
            lambda value: value["matches"][0]["artifact"].update(name="other"),
        ),
    ):
        invalid = copy.deepcopy(control)
        mutate(invalid)
        try:
            detection_control(invalid, 2, timestamp)
        except Rejected:
            confirmed(f"detection:{name}", True)
        else:
            confirmed(f"detection:{name}", False)
    wolfi_sbom, wolfi_report, wolfi_match, image_id, timestamp = fixtures()
    wolfi_sbom["distro"] = {"id": "wolfi", "versionID": "20230201"}
    wolfi_report["distro"] = {"name": "wolfi", "version": "20230201"}
    for package in wolfi_sbom["artifacts"]:
        if package["name"] == "libc6":
            package["name"] = "glibc-2.44"
        package.update(type="apk", foundBy="apk-db-cataloger")
    required = {"glibc-2.44", "postgresql-18"}
    confirmed(
        "wolfi-explicit-profile",
        assess(wolfi_sbom, wolfi_report, image_id, required, 0, timestamp, distro="wolfi")["status"]
        == "pass",
    )
    confirmed(
        "wolfi-installed-package-versions-retained",
        assess(wolfi_sbom, wolfi_report, image_id, required, 0, timestamp, distro="wolfi")[
            "apk_packages"
        ]
        == [
            {"name": "glibc-2.44", "version": "1"},
            {"name": "postgresql-18", "version": "1"},
        ],
    )
    try:
        assess(wolfi_sbom, wolfi_report, image_id, required, 0, timestamp)
    except Rejected:
        confirmed("wolfi-is-not-default-debian", True)
    else:
        confirmed("wolfi-is-not-default-debian", False)
    wolfi_match["artifact"] = {
        key: wolfi_sbom["artifacts"][0][key] for key in ("id", "name", "version", "type")
    }
    for severity, expected, code in (("High", "fail", 2), ("Unknown", "inconclusive", 0)):
        observed = copy.deepcopy(wolfi_report)
        observed["matches"] = [copy.deepcopy(wolfi_match)]
        observed["matches"][0]["vulnerability"]["severity"] = severity
        confirmed(
            f"wolfi-unmodified-policy:{severity}",
            assess(wolfi_sbom, observed, image_id, required, code, timestamp, distro="wolfi")[
                "status"
            ]
            == expected,
        )
    for name, mutate in (
        ("sbom-distro", lambda sbom, report: sbom["distro"].update(id="alpine")),
        ("sbom-version", lambda sbom, report: sbom["distro"].update(versionID="foreign")),
        (
            "sbom-version-suffix",
            lambda sbom, report: sbom["distro"].update(versionID="20230201.99"),
        ),
        ("report-distro", lambda sbom, report: report["distro"].update(name="debian")),
        ("report-version", lambda sbom, report: report["distro"].update(version="rolling")),
        ("package-type", lambda sbom, report: sbom["artifacts"][0].update(type="python")),
        (
            "package-cataloger",
            lambda sbom, report: sbom["artifacts"][0].update(foundBy="python-package-cataloger"),
        ),
        ("missing-libc", lambda sbom, report: sbom["artifacts"].pop(0)),
        ("ignored-match", lambda sbom, report: report.update(ignoredMatches=[{}])),
    ):
        invalid_sbom, invalid_report = copy.deepcopy(wolfi_sbom), copy.deepcopy(wolfi_report)
        mutate(invalid_sbom, invalid_report)
        try:
            assess(invalid_sbom, invalid_report, image_id, required, 0, timestamp, distro="wolfi")
        except Rejected:
            confirmed(f"wolfi-rejected:{name}", True)
        else:
            confirmed(f"wolfi-rejected:{name}", False)
    wolfi_control = copy.deepcopy(wolfi_report)
    wolfi_control["matches"] = [copy.deepcopy(wolfi_match)]
    wolfi_control["matches"][0]["artifact"].update(name="openssl", version="3.0.7-r0")
    wolfi_control["matches"][0]["vulnerability"].update(id="CVE-2023-0286")
    wolfi_detection_control(wolfi_control, 2, timestamp)
    confirmed("wolfi-vulnerable-apk-detected", True)
    for name, mutate in (
        ("missing", lambda value: value.update(matches=[])),
        ("malformed", lambda value: value.update(matches=[{}])),
        ("distro", lambda value: value["distro"].update(name="alpine")),
        ("version", lambda value: value["distro"].update(version="13")),
        ("package", lambda value: value["matches"][0]["artifact"].update(name="other")),
        ("installed", lambda value: value["matches"][0]["artifact"].update(version="3.1.0-r0")),
        ("type", lambda value: value["matches"][0]["artifact"].update(type="python")),
        ("id", lambda value: value["matches"][0]["vulnerability"].update(id="other")),
        ("severity", lambda value: value["matches"][0]["vulnerability"].update(severity="Low")),
        ("medium", lambda value: value["matches"][0]["vulnerability"].update(severity="Medium")),
    ):
        invalid = copy.deepcopy(wolfi_control)
        mutate(invalid)
        try:
            wolfi_detection_control(invalid, 2, timestamp)
        except Rejected:
            confirmed(f"wolfi-control-rejected:{name}", True)
        else:
            confirmed(f"wolfi-control-rejected:{name}", False)
    for code in (0, True):
        try:
            wolfi_detection_control(wolfi_control, code, timestamp)
        except Rejected:
            confirmed(f"wolfi-control-exit:{code}", True)
        else:
            confirmed(f"wolfi-control-exit:{code}", False)
    return {
        "status": "pass",
        "scope": "image-audit-contracts-only",
        "cases": cases,
        "checks": len(cases),
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
