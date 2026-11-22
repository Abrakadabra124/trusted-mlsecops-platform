"""Hosted, two-image comparison of the previously observed CoreDNS Critical findings."""

import json
import os
from pathlib import Path

from mlsecops.contracts import Rejected, bounded_read, decode, digest
from scripts import image_audit as audit
from scripts.image_audit_contract import (
    COREDNS_CONFIG,
    COREDNS_REFERENCE,
    COREDNS_REPOSITORY,
    assess,
    coredns_inventory_matches,
    observe_packages,
)

OLD_CONFIG = "sha256:97efff2babf85310d6f87bd969ac64d7006bbbadb147c90579d68d57634750f4"
OLD_REFERENCE = (
    COREDNS_REPOSITORY + "@sha256:2329f5f0e7e79fbe56dcdf11ecc4337ee2476bb251095bc275fe9461cb88a55b"
)
_REQUIRED = {"github.com/coredns/coredns", "stdlib", "golang.org/x/net", "base-files"}
_BASELINE_CRITICAL = {
    ("GO-2026-6604", "stdlib", "go1.26.6"),
    ("GO-2026-6612", "stdlib", "go1.26.6"),
    ("GO-2026-6612", "golang.org/x/net", "v0.57.0"),
}
_TARGET_IDS = {advisory for advisory, _, _ in _BASELINE_CRITICAL}
_DB_FILE = "6/vulnerability.db"


def target_removed(old_findings, new_findings):
    old = {
        (f["id"], f["package"], f["installed"])
        for f in old_findings
        if f["severity"] == "Critical" and f["type"] == "go-module"
    }
    return _BASELINE_CRITICAL <= old and not any(
        f["severity"] == "Critical" and f["id"] in _TARGET_IDS for f in new_findings
    )


def scan_image(
    run,
    cache,
    label,
    reference,
    config,
    *,
    inventory_matches=coredns_inventory_matches,
    archive_tag=None,
):
    details = audit.inspect_image(reference)
    if details["Id"] != config:
        raise Rejected("coredns_pair_config_mismatch")
    archive = run / f"{label}.tar"
    if archive_tag:
        audit.command(["docker", "tag", config, archive_tag])
    audit.command(
        ["docker", "image", "save", "--output", str(archive), archive_tag or config], timeout=300
    )
    if audit.identity(archive, details) != config:
        raise Rejected("coredns_pair_archive_mismatch")
    archive_sha = audit.file_hash(archive) if archive_tag else None
    code, sbom_path = audit.scanner(
        run,
        label + "-sbom",
        audit.SYFT_IMAGE,
        ["docker-archive:/input/image.tar", "-o", "syft-json"],
        [(archive, "/input/image.tar", False)],
    )
    if code:
        raise Rejected("coredns_pair_syft_failed")
    sbom_bytes = bounded_read(sbom_path, audit.LIMIT)
    sbom = decode(sbom_bytes, audit.LIMIT)
    observation = observe_packages(sbom, config)
    if not inventory_matches(observation, reference):
        raise Rejected("coredns_pair_inventory_mismatch")
    code, report_path = audit.scanner(
        run,
        label + "-scan",
        audit.GRYPE_IMAGE,
        ["sbom:/input/sbom.json", "--fail-on", "high", "-o", "json"],
        [(cache, "/cache", False), (sbom_path, "/input/sbom.json", False)],
    )
    sbom_hash = digest(sbom_bytes)
    if audit.file_hash(sbom_path) != sbom_hash:
        raise Rejected("coredns_pair_sbom_changed")
    raw = bounded_read(report_path, audit.LIMIT)
    result = assess(sbom, decode(raw, audit.LIMIT), config, _REQUIRED, code)
    if archive_tag and audit.file_hash(archive) != archive_sha:
        raise Rejected("coredns_archive_changed_during_scan")
    return {
        **result,
        **({"archive_sha256": archive_sha} if archive_tag else {}),
        "reference": reference,
        "sbom_sha256": sbom_hash,
        "report_sha256": digest(raw),
        "go_versions": {
            p["name"]: p["version"]
            for p in observation["packages"]
            if p["type"] == "go-module" and p["name"] in _REQUIRED
        },
    }


def compare(run):
    for reference in (audit.SYFT_IMAGE, audit.GRYPE_IMAGE, OLD_REFERENCE, COREDNS_REFERENCE):
        audit.command(["docker", "pull", "--platform", "linux/amd64", reference], timeout=300)
        audit.inspect_image(reference)
    cache = run / "cache"
    cache.mkdir(mode=0o700)
    code, _ = audit.scanner(
        run,
        "db-update",
        audit.GRYPE_IMAGE,
        ["db", "update"],
        [(cache, "/cache", True)],
        network=True,
    )
    if code:
        raise Rejected("coredns_pair_database_update_failed")
    before = audit.snapshot(cache)
    if _DB_FILE not in before:
        raise Rejected("coredns_pair_database_missing")
    scans = {}
    for label, ref, config in (
        ("old", OLD_REFERENCE, OLD_CONFIG),
        ("new", COREDNS_REFERENCE, COREDNS_CONFIG),
    ):
        scans[label] = scan_image(run, cache, label, ref, config)
        after = audit.snapshot(cache)
        if after != before:
            raise Rejected("coredns_pair_database_changed")
    if scans["old"]["database"] != scans["new"]["database"]:
        raise Rejected("coredns_pair_database_descriptor_mismatch")
    return {
        "scope": "coredns-two-critical-advisories",
        "advisory_ids": sorted(_TARGET_IDS),
        "target_criticals_removed": target_removed(
            scans["old"]["findings"], scans["new"]["findings"]
        ),
        "release_ready": False,
        "scanners": {"syft": audit.SYFT_IMAGE, "grype": audit.GRYPE_IMAGE},
        "db_file": _DB_FILE,
        "db_sha256_before": before[_DB_FILE],
        "db_sha256_after": after[_DB_FILE],
        **scans,
    }


if __name__ == "__main__":
    run = Path(os.environ["RUNNER_TEMP"]) / "coredns-pair"
    run.mkdir(mode=0o700)
    summary = compare(run)
    print(json.dumps(summary, indent=2, sort_keys=True))
    raise SystemExit(0 if summary["target_criticals_removed"] else 1)
