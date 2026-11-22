"""Match four proven static build inputs of the pinned bpftool against Ubuntu Noble."""

import json
import re
from datetime import UTC, datetime

from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest
from scripts.image_audit_contract import SEVERITIES, SYFT_VERSION, database

# Ubuntu USN-7259-1, 2025-02-06. A version-bound scanner control, not a runtime fixture.
ADVISORY = "CVE-2025-0395"
FIXED = "2.39-0ubuntu8.4"
NAMESPACE = "ubuntu:distro:ubuntu:24.04"


def assess(sbom, report, exit_code, expected, expected_database):
    try:
        if (
            database(report, datetime.now(UTC)) != expected_database
            or sbom["descriptor"]["name"] != "syft"
            or sbom["descriptor"]["version"] != SYFT_VERSION
            or sbom["source"]["type"] != "directory"
            or sbom["source"]["metadata"]["path"] != "/input"
            or sbom["distro"]["id"] != "ubuntu"
            or sbom["distro"]["versionID"] != "24.04"
            or report["source"] != {"type": "directory", "target": "/input"}
            or (report["distro"]["name"], report["distro"]["version"]) != ("ubuntu", "24.04")
            or any(report.get(key, []) != [] for key in ("ignoredMatches", "alertsByPackage"))
            or type(report["matches"]) is not list
        ):
            raise Rejected("bpftool_noble_scan_binding")
        by_id, names = {}, set()
        for pkg in sbom["artifacts"]:
            name, version = pkg["name"], pkg["version"]
            source, wanted = expected[name]
            meta = pkg["metadata"]
            if (
                pkg["id"] in by_id
                or name in names
                or not pkg["id"]
                or version != wanted
                or pkg["foundBy"] != "dpkg-db-cataloger"
                or pkg["type"] != "deb"
                or meta["source"] != source
                or meta["architecture"] != "amd64"
                or meta["sourceVersion"] not in ("", wanted)
                or not any(p["path"] == "/var/lib/dpkg/status" for p in pkg["locations"])
            ):
                raise Rejected("bpftool_noble_package_mismatch")
            names.add(name)
            by_id[pkg["id"]] = pkg
        if names != expected.keys():
            raise Rejected("bpftool_noble_package_set")
        findings = []
        for match in report["matches"]:
            artifact, vuln = match["artifact"], match["vulnerability"]
            pkg = by_id[artifact["id"]]
            if (
                any(artifact[k] != pkg[k] for k in ("name", "version", "type"))
                or vuln["namespace"] != NAMESPACE
                or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", vuln["id"])
                or vuln["severity"] not in SEVERITIES
            ):
                raise Rejected("bpftool_noble_match_mismatch")
            fix = vuln["fix"]
            if (
                type(fix["state"]) is not str
                or type(fix["versions"]) is not list
                or any(
                    type(v) is not str or not re.fullmatch(r"[0-9a-zA-Z:.~+_-]{1,160}", v)
                    for v in fix["versions"]
                )
            ):
                raise Rejected("bpftool_noble_fix_mismatch")
            findings.append(
                {
                    "package": pkg["name"],
                    "installed": pkg["version"],
                    "type": "deb",
                    "source_package": expected[pkg["name"]][0],
                    "namespace": NAMESPACE,
                    "id": vuln["id"],
                    "severity": vuln["severity"],
                    "fix": {"state": fix["state"], "versions": fix["versions"]},
                }
            )
        blocked = any(f["severity"] in ("High", "Critical") for f in findings)
        if type(exit_code) is not int or exit_code != (2 if blocked else 0):
            raise Rejected("bpftool_noble_exit_mismatch")
        return sorted(findings, key=canonical)
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise Rejected("bpftool_noble_report_malformed") from error


def control(actual, reference):
    observed = [f for f in actual if f["id"] == ADVISORY and f["package"] == "libc6-dev"]
    if (
        len(observed) != 1
        or observed[0]["installed"] != "2.39-0ubuntu8.3"
        or observed[0]["fix"] != {"state": "fixed", "versions": [FIXED]}
        or any(f["id"] == ADVISORY for f in reference)
    ):
        raise Rejected("bpftool_noble_version_control_failed")


def verified_findings(receipt, mapping, db):
    from scripts import image_bpftool_materials as materials

    donors = [
        g["binary_sha256"]
        for g in mapping["uncovered_native_applications"]
        if g["binary_path"] == "/usr/local/bin/bpftool"
    ]
    if (
        donors != [materials.BINARY_SHA256]
        or receipt["binary_sha256"] != donors[0]
        or receipt["scope"] != "static-build-inputs-ubuntu-noble"
        or receipt["release_ready"] is not False
        or receipt["database"] != db
        or not re.fullmatch(r"[0-9a-f]{64}", receipt["db_sha256"])
        or receipt["packages"] != {k: list(v) for k, v in materials.PACKAGES.items()}
        or receipt["control_advisory"] != ADVISORY
    ):
        raise Rejected("bpftool_static_subject_mismatch")
    for key in ("materials", "fixed_metadata_control"):
        inputs = receipt[key]
        if (
            type(inputs["exit_code"]) is not int
            or inputs["exit_code"] not in (0, 2)
            or any(
                not re.fullmatch(r"[0-9a-f]{64}", inputs[k])
                for k in ("sbom_sha256", "grype_sha256", "log_sha256")
            )
        ):
            raise Rejected("bpftool_scan_evidence_mismatch")
    if receipt["materials"]["sbom_sha256"] == receipt["fixed_metadata_control"]["sbom_sha256"]:
        raise Rejected("bpftool_control_input_reused")
    findings = receipt["findings"]
    for row in findings:
        source, version = materials.PACKAGES[row["package"]]
        if (row["type"], row["installed"], row["source_package"], row["namespace"]) != (
            "deb",
            version,
            source,
            NAMESPACE,
        ) or row["severity"] not in SEVERITIES:
            raise Rejected("bpftool_static_coordinate_mismatch")
    if receipt["materials"]["exit_code"] != (
        2 if any(row["severity"] in ("Critical", "High") for row in findings) else 0
    ):
        raise Rejected("bpftool_static_exit_mismatch")
    control(findings, [])
    return findings


def scan(run, label, root, cache, expected, expected_database):
    from scripts import image_audit as audit

    code, sbom = audit.scanner(
        run,
        label + "-packages",
        audit.SYFT_IMAGE,
        ["dir:/input", "--override-default-catalogers", "dpkg-db-cataloger", "-o", "syft-json"],
        [(root, "/input", False)],
    )
    if code:
        raise Rejected("bpftool_syft_failed")
    raw = bounded_read(sbom, audit.LIMIT)
    code, path = audit.scanner(
        run,
        label + "-ubuntu",
        audit.GRYPE_IMAGE,
        ["sbom:/input/sbom.json", "--fail-on", "high", "-o", "json", "-v"],
        [(sbom, "/input/sbom.json", False), (cache, "/cache", False)],
    )
    report_raw = bounded_read(path, audit.LIMIT)
    report = decode(report_raw, audit.LIMIT)
    packages = decode(raw, audit.LIMIT)
    # A small diagnostic remains available even when a new scanner format is rejected.
    print(
        json.dumps(
            {
                "scope": "bpftool-scanner-input",
                "role": label,
                "exit": code,
                "sbom_type": packages.get("source", {}).get("type"),
                "grype_source": report.get("source"),
                "grype_distro": report.get("distro"),
                "packages": [
                    [
                        p["name"],
                        p["version"],
                        p["metadata"].get("source"),
                        p["metadata"].get("sourceVersion"),
                        p["locations"][0].get("path") if p["locations"] else None,
                    ]
                    for p in packages["artifacts"][:5]
                ],
                "namespaces": sorted(
                    {m["vulnerability"]["namespace"] for m in report.get("matches", [])}
                )[:5],
            },
            sort_keys=True,
        ),
        flush=True,
    )
    if digest(raw) != audit.file_hash(sbom):
        raise Rejected("bpftool_sbom_changed")
    log = bounded_read(path.with_suffix(".log"), 2 * 1024**2).decode()
    for line in log.splitlines():
        severity = re.search(r"\]\s+(WARN|ERROR|FATAL|PANIC)\s+(.*)", line)
        if severity and not (
            code == 2
            and severity.groups()
            == ("ERROR", "discovered vulnerabilities at or above the severity threshold")
        ):
            raise Rejected("bpftool_grype_diagnostic")
    result = assess(packages, report, code, expected, expected_database)
    return result, {
        "sbom_sha256": digest(raw),
        "grype_sha256": digest(report_raw),
        "log_sha256": digest(log.encode()),
        "exit_code": code,
    }


def collect(run, cache, db_files, expected_database):
    from scripts import image_audit as audit
    from scripts import image_bpftool_materials as materials

    run.mkdir(mode=0o700)
    root = materials.prepare(run)
    ref = run / "fixed-control"
    (ref / "etc").mkdir(parents=True)
    (ref / "etc/os-release").write_bytes((root / "etc/os-release").read_bytes())
    dpkg = ref / "var/lib/dpkg"
    dpkg.mkdir(parents=True)
    (dpkg / "status").write_text(
        "Package: libc6-dev\nStatus: install ok installed\nArchitecture: amd64\nSource: glibc\n"
        f"Version: {FIXED}\nDescription: controlled fixed-version metadata\n\n",
        encoding="utf-8",
    )
    actual, measured = scan(run, "materials", root, cache, materials.PACKAGES, expected_database)
    reference, checked = scan(
        run, "reference", ref, cache, {"libc6-dev": ("glibc", FIXED)}, expected_database
    )
    control(actual, reference)
    if audit.snapshot(cache) != db_files:
        raise Rejected("bpftool_db_changed")
    return {
        "scope": "static-build-inputs-ubuntu-noble",
        "release_ready": False,
        "binary_sha256": materials.BINARY_SHA256,
        "database": expected_database,
        "db_sha256": db_files["6/vulnerability.db"],
        "materials": measured,
        "fixed_metadata_control": checked,
        "control_advisory": ADVISORY,
        "packages": {k: list(v) for k, v in materials.PACKAGES.items()},
        "findings": actual,
    }
