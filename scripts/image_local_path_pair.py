"""Same-database image diagnostic. Only the pinned scanner containers are executed."""

import json
import os
import platform
import re
import tempfile
from collections import Counter
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.inventory import command
from scripts import image_audit as audit
from scripts.image_audit_contract import LOCAL_PATH_CONFIG, SEVERITIES, local_path_inventory_matches
from scripts.image_node_openssl import measure

STOCK = (
    "kindest/local-path-provisioner@sha256:77ab4466418c90f8a651cdec58ef864977eeb755c3ec83791c1d4b0d9259c938",
    LOCAL_PATH_CONFIG,
)
PROPOSAL = (
    "rancher/local-path-provisioner@sha256:c3f2c60ee2490eb83ac00101d7e239fd8c20a5b8b4038e2dfc36a7e66fe99c08",
    "sha256:683316f41426e4fc774e1cd7388e3bcbd5d4d63837753a789d929d64365c399a",
)
APP = "github.com/rancher/local-path-provisioner"
ADVISORY = "GHSA-7fxv-8wr2-mfc4"
# Two scratch layers contain ca-certificates.crt and /usr/bin/local-path-provisioner.
# ELF b569eb78b7ab812c649dfd8a7948d60a4f94ab6835b33104bf830619a3442727:
# 1 main + 52 dep (no replaces) + stdlib from Go build info. Hash the complete
# Syft projection (name, version, type, foundBy, paths), sorted by canonical JSON.
_PROPOSAL_PACKAGES = "fd939457d4893b0e3cd292a1ce26b10c17dacbacb0dec822232802b93dc7e2dc"
GO_COMPONENTS = {
    APP,
    "stdlib",
    "golang.org/x/net",
    "golang.org/x/text",
    "github.com/klauspost/compress",
}


def inventory_matches(spec, obs):
    if spec == STOCK:
        return local_path_inventory_matches(obs)
    distro = obs["distro"]
    unknown_distro = distro is None or (
        isinstance(distro, dict)
        and set(distro) == {"id", "versionID"}
        and all(value in ("", None) for value in distro.values())
    )
    return (
        spec == PROPOSAL
        and obs["image_id"] == PROPOSAL[1]
        and unknown_distro
        and len(obs["packages"]) == 54
        and digest(canonical(sorted(obs["packages"], key=canonical))) == _PROPOSAL_PACKAGES
    )


def _rows(counts):
    return [
        {"id": identifier, "package": package, "severity": severity, "count": count}
        for (identifier, package, severity), count in sorted(counts.items())
    ]


def _summary(spec, observation, result):
    if result["image_id"] != spec[1] or observation["image_id"] != spec[1]:
        raise Rejected("local_path_scan_identity_mismatch")
    rows = observation["packages"]
    counts = Counter((r["id"], r["package"], r["severity"]) for r in result["findings"])
    severities = Counter(f["severity"] for f in result["findings"])
    if result["matches"] != counts.total() or result["severity_counts"] != {
        severity: severities[severity] for severity in SEVERITIES
    }:
        raise Rejected("local_path_scan_count_mismatch")
    summary = {
        "reference": spec[0],
        "config": spec[1],
        "distro": observation["distro"],
        "inventory_verified": inventory_matches(spec, observation),
        "package_count": len(rows),
        "package_types": dict(Counter(row["type"] for row in rows)),
        "packages_sha256": digest(canonical(sorted(rows, key=canonical))),
        "go_packages": [r for r in rows if r["name"] in GO_COMPONENTS],
        **{
            k: result[k]
            for k in (
                "severity_counts",
                "matches",
                "unique_vulnerabilities",
                "scanner_exit_code",
                "sbom_sha256",
                "grype_sha256",
            )
        },
    }
    return summary, counts


def compare(before, source, after, candidate, db_files):
    db_sha = db_files.get("6/vulnerability.db", "")
    if not re.fullmatch("[0-9a-f]{64}", db_sha) or source["database"] != candidate["database"]:
        raise Rejected("local_path_scan_database_mismatch")
    stock, left = _summary(STOCK, before, source)
    proposal, right = _summary(PROPOSAL, after, candidate)
    original = [f for f in source["findings"] if f["id"] == ADVISORY and f["package"] == APP]
    remaining = sum(n for (i, _, _), n in right.items() if i == ADVISORY)
    control = (
        bool(original)
        and all(
            f["type"] == "go-module"
            and f["installed"] == "v0.0.34"
            and f["severity"] == "High"
            and f["fix"]["state"] == "fixed"
            and isinstance(f["fix"]["versions"], list)
            and "0.0.36" in f["fix"]["versions"]
            for f in original
        )
        and remaining == 0
    )
    severity = proposal["severity_counts"]
    if not stock["inventory_verified"] or not proposal["inventory_verified"] or not control:
        status = "inconclusive"
    elif severity["High"] or severity["Critical"]:
        status = "fail"
    elif severity["Unknown"] or stock["severity_counts"]["Unknown"]:
        status = "inconclusive"
    else:
        status = "diagnostic-clear"
    return {
        "scope": "local-path-provisioner-image-pair",
        "release_ready": False,
        "status": status,
        "database": source["database"],
        "database_files": db_files,
        "db_sha256": db_sha,
        "syft": audit.SYFT_IMAGE,
        "grype": audit.GRYPE_IMAGE,
        "stock": stock,
        "proposal": proposal,
        "app_advisory": {
            "id": ADVISORY,
            "stock_occurrences": len(original),
            "proposal_occurrences": remaining,
            "verified": control,
        },
        "removed": _rows(left - right),
        "retained": _rows(left & right),
        "added": _rows(right - left),
    }


def qualify(run):
    for reference, config in (STOCK, PROPOSAL):
        command(["docker", "pull", "--platform", "linux/amd64", reference], timeout=360)
        if command(["docker", "image", "inspect", "--format", "{{.Id}}", reference]) != config:
            raise Rejected("local_path_pulled_config_mismatch")
    for image in (audit.SYFT_IMAGE, audit.GRYPE_IMAGE):
        command(["docker", "pull", "--platform", "linux/amd64", image], timeout=360)

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
        raise Rejected("local_path_db_update_failed")
    db = audit.snapshot(cache)
    # measure verifies the exported config, both scanner reports, the SBOM hash
    # and the read-only cache snapshot after each scan.
    _, before, source = measure(run, cache, db, "source", STOCK[1])
    _, after, candidate = measure(run, cache, db, "candidate", PROPOSAL[1])
    report = compare(before, source, after, candidate, db)
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report["status"] == "diagnostic-clear" else 1


def main():
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or platform.system() != "Linux"
        or platform.machine() != "x86_64"
    ):
        raise SystemExit("GitHub-hosted Linux x86_64 runner required")
    with tempfile.TemporaryDirectory(prefix="local-path-pair-") as tmp:
        try:
            return qualify(Path(tmp))
        except Rejected as error:
            print(
                json.dumps(
                    {
                        "scope": "local-path-provisioner-image-pair",
                        "status": "inconclusive",
                        "release_ready": False,
                        "reason": str(error),
                    }
                ),
                flush=True,
            )
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
