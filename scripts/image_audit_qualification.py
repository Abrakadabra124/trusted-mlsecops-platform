import copy
from datetime import UTC, datetime, timedelta

from mlsecops.contracts import Rejected, canonical
from scripts.image_audit_contract import assess, detection_control


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
            "db": {"valid": True, "schemaVersion": "6.1.10", "built": timestamp.isoformat()},
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
        ("bad-db", lambda inputs: inputs[1]["descriptor"]["db"].update(valid=False)),
        ("truthy-db-valid", lambda inputs: inputs[1]["descriptor"]["db"].update(valid="true")),
        ("db-error", lambda inputs: inputs[1]["descriptor"]["db"].update(error="corrupted")),
        ("missing-db", lambda inputs: inputs[1]["descriptor"].pop("db")),
        ("old-schema", lambda inputs: inputs[1]["descriptor"]["db"].update(schemaVersion="5")),
        (
            "stale-db",
            lambda inputs: inputs[1]["descriptor"]["db"].update(
                built=(timestamp - timedelta(hours=121)).isoformat()
            ),
        ),
        (
            "future-db",
            lambda inputs: inputs[1]["descriptor"]["db"].update(
                built=(timestamp + timedelta(hours=1)).isoformat()
            ),
        ),
        (
            "naive-db-date",
            lambda inputs: inputs[1]["descriptor"]["db"].update(built="2026-10-08T20:00:00"),
        ),
        ("invalid-db-date", lambda inputs: inputs[1]["descriptor"]["db"].update(built="yesterday")),
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
    return {
        "status": "pass",
        "scope": "image-audit-contracts-only",
        "cases": cases,
        "checks": len(cases),
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
