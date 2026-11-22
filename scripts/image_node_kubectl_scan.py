"""Offline scans of the observed kubectl and its nine proven staging coordinates."""

from collections import Counter
from datetime import UTC, datetime

from mlsecops.contracts import bounded_read, canonical, decode, digest
from mlsecops.inventory import command
from scripts import image_audit as audit
from scripts import image_go_supplemental_contract as single
from scripts import image_node_kubectl_inventory as inv
from scripts.image_audit_contract import GO_CONTROLS, SEVERITIES, database, go_detection_control
from scripts.image_kubernetes_scans import confirm_absent

DATABASE = {"schema_version": "v6.1.10", "built": "2026-11-22T06:19:59Z"}
DB_SHA = "08b302c006875468fc087630ba33be9d814a2585047ddc874c8cd7a8bfab0d1b"
DB_ARCHIVE = "vulnerability-db_v6.1.10_2026-11-22T00:23:04Z_1795328399.tar.zst"
DB_ARCHIVE_SHA = "baa591108fd0fafa273503769dea65bf0334ad337e84aeb7f08197849cea9f87"
# Historical canonical audit SHA 705778a343723a6c932a01fb95567733f963f82ef8336d2d5faba70edc4f124d.
# For the eight PURLs take these fields from kubernetes_supplemental.scans, require identical
# repeats across components, then hash the canonical JSON array ordered by module.
FIELDS = (
    "purl",
    "findings",
    "status",
    "matches",
    "database",
    "severity_counts",
    "matching_completed",
    "package_identity_bound",
    "scanner_exit_code",
)
PREVIOUS_SHA = "00a68f32fabda476c791ca1d02d9db01ca71c702d1523f95c31d7ce6c964b068"


def compare_previous(results):
    inv.need(set(results) == set(inv.MODULES), "scan_set")
    rows = [
        {k: results[m][k] for k in FIELDS} for m in sorted(results) if m != "k8s.io/cli-runtime"
    ]
    actual = digest(canonical(rows))
    return dict(
        count=len(rows),
        sha256=actual,
        expected_sha256=PREVIOUS_SHA,
        matches_previous=actual == PREVIOUS_SHA,
    )


def check_db(cache):
    snapshot = audit.snapshot(cache)
    inv.need(snapshot.get("6/vulnerability.db") == DB_SHA, "database_bytes")
    return snapshot


def scanner(run, label, image, args, mounts):
    try:
        return audit.scanner(run, label, image, args, mounts)
    finally:
        confirm_absent(run / (label + ".cid"))


def raw_report(path):
    return decode(bounded_read(path, audit.LIMIT), audit.LIMIT)


def assess_original(raw, code, by_id):
    inv.need(
        database(raw, datetime.now(UTC)) == DATABASE
        and raw["source"] == {"type": "directory", "target": "/input"}
        and raw.get("ignoredMatches", []) == []
        and raw.get("alertsByPackage", []) == []
        and type(raw["matches"]) is list,
        "original_scan_binding",
    )
    counts = Counter()
    for hit in raw["matches"]:
        a = hit["artifact"]
        inv.need(
            a["type"] == "go-module"
            and by_id.get(a["id"]) == (a["name"], a["version"])
            and hit["vulnerability"]["severity"] in SEVERITIES,
            "original_match_identity",
        )
        counts[hit["vulnerability"]["severity"]] += 1
    inv.need(code == (2 if counts["Critical"] or counts["High"] else 0), "original_exit")
    return {s: counts[s] for s in SEVERITIES}


def qualify(run, root, versions, report):
    for image in (audit.SYFT_IMAGE, audit.GRYPE_IMAGE):
        command(["docker", "pull", "--platform", "linux/amd64", image], timeout=360)
    report["stage"] = "kubectl-sbom"
    code, sbom = scanner(
        run,
        "kubectl-sbom",
        audit.SYFT_IMAGE,
        ["dir:/input", "--override-default-catalogers", inv.CATALOGER, "-o", "syft-json"],
        [(root, "/input", False)],
    )
    inv.need(code == 0, "syft_failed")
    by_id = inv.check_sbom(raw_report(sbom), versions)
    report["sbom_sha256"] = audit.file_hash(sbom)
    report["stage"] = "database-import"
    bundle = run / DB_ARCHIVE
    inv.download("https://grype.anchore.io/databases/v6/" + DB_ARCHIVE, bundle, 512 * 1024**2)
    inv.need(audit.file_hash(bundle) == DB_ARCHIVE_SHA, "database_archive")
    cache = run / "cache"
    cache.mkdir(mode=0o700)
    code, _ = scanner(
        run,
        "db-import",
        audit.GRYPE_IMAGE,
        ["db", "import", "/input/db.tar.zst"],
        [(bundle, "/input/db.tar.zst", False), (cache, "/cache", True)],
    )
    inv.need(code == 0, "database_import")
    snapshot = check_db(cache)
    mounts = [(cache, "/cache", False)]
    report.update(
        database=DATABASE,
        db_sha256=DB_SHA,
        db_archive_sha256=DB_ARCHIVE_SHA,
        syft=audit.SYFT_IMAGE,
        grype=audit.GRYPE_IMAGE,
        controls={},
    )
    for kind, (package, version) in GO_CONTROLS.items():
        label = "control-" + kind
        report["stage"] = label
        purl = f"pkg:golang/{package}@{version}"
        code, path = scanner(
            run, label, audit.GRYPE_IMAGE, [purl, "--fail-on", "high", "-o", "json"], mounts
        )
        raw = raw_report(path)
        go_detection_control(raw, code, kind)
        inv.need(
            raw["source"] == {"type": "purl", "target": purl}
            and database(raw, datetime.now(UTC)) == DATABASE,
            "control_binding",
        )
        report["controls"][kind] = dict(
            purl=purl, report_sha256=audit.file_hash(path), matches=len(raw["matches"])
        )

    report["stage"] = "original-kubectl-scan"
    code, path = scanner(
        run,
        "original",
        audit.GRYPE_IMAGE,
        ["sbom:/input/sbom.json", "--fail-on", "high", "-o", "json"],
        [*mounts, (sbom, "/input/sbom.json", False)],
    )
    raw = raw_report(path)
    report["original_matches"] = raw["matches"]
    report["original_report_sha256"] = audit.file_hash(path)
    counts = assess_original(raw, code, by_id)
    report["original_severities"] = counts
    inv.need(audit.file_hash(sbom) == report["sbom_sha256"], "sbom_changed")
    results = report["supplemental"] = {}
    for index, module in enumerate(inv.coordinates()):
        version = "v0.36.4"
        purl = f"pkg:golang/{module}@{version}"
        label = f"module-{index:02d}"
        report["stage"] = purl
        out = run / label
        out.mkdir(mode=0o700)
        code, path = scanner(
            run,
            label,
            audit.GRYPE_IMAGE,
            [
                purl,
                "--fail-on",
                "high",
                "-o",
                "json",
                "-o",
                "cyclonedx-json=/output/report.json",
                "-vvv",
            ],
            [*mounts, (out, "/output", True)],
        )
        raw = raw_report(path)
        result = results[module] = dict(
            raw_matches=raw["matches"], report_sha256=audit.file_hash(path)
        )
        cdx = bounded_read(out / "report.json", audit.LIMIT)
        trace = bounded_read(path.with_suffix(".log"), 2 * 1024**2)
        result.update(
            single.assess(module, version, raw, decode(cdx, audit.LIMIT), trace, code, DATABASE),
            cdx_sha256=digest(cdx),
            trace_sha256=digest(trace),
        )
    inv.need(check_db(cache) == snapshot, "database_changed")
    previous = compare_previous(results)
    report["previous_eight"] = previous
    statuses = {s["status"] for s in results.values()}
    if counts["Critical"] or counts["High"] or "fail" in statuses:
        status = "fail"
    elif counts["Unknown"] or "inconclusive" in statuses or not previous["matches_previous"]:
        status = "inconclusive"
    else:
        status = "diagnostic-clear"
    report.update(stage="complete", status=status)
    if not previous["matches_previous"]:
        report["reason"] = "kubectl_prior_eight_differ"
