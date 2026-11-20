"""Fixed Kubernetes module scans and additive joins with original image findings.

Receipts refer to private artifacts in an exclusively created directory. Public
projections are integrity checks under the existing trusted-host model, not signed
attestations. A version mapping alone never authorizes application coverage.
"""

import copy
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, safe_child
from scripts import image_go_supplemental_contract as single
from scripts import image_kubernetes_aliases as aliases
from scripts import image_kubernetes_export
from scripts.image_audit_contract import SEVERITIES, assess, observe_packages

LIMIT = 64 * 1024**2
SUFFIXES = (".json", ".cdx.json", ".log", ".cid")


@dataclass(frozen=True)
class Receipt:
    module: str
    version: str
    returncode: int
    hashes: tuple


@dataclass(frozen=True)
class Batch:
    directory: Path
    proof: str
    database: dict
    receipts: tuple


def confirm_absent(cidfile):
    """Do not interpret missing identity or an unavailable daemon as cleanup."""
    try:
        cid = bounded_read(cidfile, 128).decode("ascii").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", cid):
            raise Rejected("kubernetes_scan_cleanup_identity")
        result = subprocess.run(
            [
                "docker",
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--quiet",
                "--filter",
                f"id={cid}",
            ],
            capture_output=True,
            timeout=15,
            check=False,
        )
        if result.returncode or result.stdout.strip():
            raise Rejected("kubernetes_scan_cleanup_unconfirmed")
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        raise Rejected("kubernetes_scan_cleanup_unavailable") from error


def artifacts(directory, index):
    contents = tuple(
        bounded_read(safe_child(directory, f"module-{index:02d}{suffix}"), limit)
        for suffix, limit in zip(SUFFIXES, (LIMIT, LIMIT, 2 * 1024**2, 128), strict=True)
    )
    return contents, tuple(digest(content) for content in contents)


def run_batch(run, cache, expected_database, db_files):
    from scripts import image_audit as audit

    coordinates = aliases.coordinates()
    # Validate the entire allowlist before the first scanner process starts.
    purls = tuple(aliases.validate_coordinate(*pair) for pair in coordinates)
    proof = aliases.proof_digest()
    directory = safe_child(run, "kubernetes-modules")
    directory.mkdir(mode=0o700)
    cache = safe_child(cache, ".")
    if audit.snapshot(cache) != db_files:
        raise Rejected("kubernetes_scan_database_changed")
    receipts = []
    for index, ((module, version), purl) in enumerate(zip(coordinates, purls, strict=True)):
        name = f"module-{index:02d}"
        # The only writable bind contains this invocation's reports, never the DB.
        output_dir = directory / f"output-{index:02d}"
        output_dir.mkdir(mode=0o700)
        try:
            code, path = audit.scanner(
                directory,
                name,
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
                [(cache, "/cache", False), (output_dir, "/output", True)],
            )
        finally:
            # scanner() removes its exact CID even on failure; prove final absence.
            confirm_absent(directory / f"{name}.cid")
        if path != directory / f"{name}.json":
            raise Rejected("kubernetes_scan_output_path_changed")
        cdx = bounded_read(output_dir / "report.json", LIMIT)
        with (directory / f"{name}.cdx.json").open("xb") as target:
            target.write(cdx)
        contents, hashes = artifacts(directory, index)
        single.assess(
            module,
            version,
            decode(contents[0], LIMIT),
            decode(contents[1], LIMIT),
            contents[2],
            code,
            expected_database,
        )
        if audit.snapshot(cache) != db_files:
            raise Rejected("kubernetes_scan_database_changed")
        receipts.append(Receipt(module, version, code, hashes))
    if aliases.proof_digest() != proof or aliases.coordinates() != coordinates:
        raise Rejected("kubernetes_scan_registry_changed")
    return Batch(directory, proof, copy.deepcopy(expected_database), tuple(receipts))


def read_batch(batch, expected_database, timestamp=None):
    if batch.proof != aliases.proof_digest() or batch.database != expected_database:
        raise Rejected("kubernetes_scan_batch_binding")
    if tuple((r.module, r.version) for r in batch.receipts) != aliases.coordinates():
        raise Rejected("kubernetes_scan_batch_incomplete")
    results = []
    for index, receipt in enumerate(batch.receipts):
        contents, hashes = artifacts(batch.directory, index)
        if hashes != receipt.hashes:
            raise Rejected("kubernetes_scan_artifact_changed")
        result = single.assess(
            receipt.module,
            receipt.version,
            decode(contents[0], LIMIT),
            decode(contents[1], LIMIT),
            contents[2],
            receipt.returncode,
            expected_database,
            timestamp,
        )
        results.append(
            {
                **result,
                "module": receipt.module,
                "version": receipt.version,
                "artifact_digests": dict(zip(SUFFIXES, hashes, strict=True)),
                "cleanup_verified": True,
            }
        )
    return results


def joined_result(original, supplemental):
    """Keep every occurrence, including original raw UNKNOWN-version findings."""
    findings = copy.deepcopy(original["findings"])
    for result in supplemental:
        findings.extend(copy.deepcopy(result["findings"]))
    counts = {severity: sum(f["severity"] == severity for f in findings) for severity in SEVERITIES}
    return {
        "status": "fail"
        if counts["Critical"] or counts["High"]
        else "inconclusive"
        if counts["Unknown"]
        else "pass",
        "findings": findings,
        "severity_counts": counts,
        "matches": len(findings),
        "unique_vulnerabilities": len({f["id"] for f in findings}),
        "database": copy.deepcopy(original["database"]),
    }


def join(
    component,
    sbom_path,
    report_path,
    returncode,
    batch,
    reference,
    expected_database,
    timestamp=None,
):
    # Only the specifically resolved inventory diagnostic may be cleared. A
    # successful supplement cannot erase an unrelated earlier failure.
    if (
        "reason" in component
        and component["reason"] != "image_audit_kubernetes_module_versions_unresolved"
    ):
        raise Rejected("kubernetes_scan_unrelated_original_failure")
    sbom_raw = bounded_read(sbom_path, LIMIT)
    report_raw = bounded_read(report_path, LIMIT)
    if (
        digest(sbom_raw) != component["sbom_digest"]
        or digest(report_raw) != component["report_digest"]
    ):
        raise Rejected("kubernetes_scan_original_changed")
    sbom = decode(sbom_raw, LIMIT)
    observation = observe_packages(sbom, component["image_config_id"])
    if observation != component["package_observation"]:
        raise Rejected("kubernetes_scan_observation_changed")
    mapping = aliases.resolve(observation, reference)
    if mapping is None:
        raise Rejected("kubernetes_scan_unknown_image")
    original = assess(
        sbom,
        decode(report_raw, LIMIT),
        component["image_config_id"],
        set(),
        returncode,
        timestamp,
        distro="debian",
        diagnostic_only=True,
    )
    if original["database"] != expected_database:
        raise Rejected("kubernetes_scan_original_database_changed")
    if component.get("status") != original["status"]:
        raise Rejected("kubernetes_scan_original_decision_changed")
    if canonical(component.get("findings")) != canonical(original["findings"]):
        raise Rejected("kubernetes_scan_original_findings_changed")
    all_results = read_batch(batch, expected_database, timestamp)
    required = {tuple(pair) for pair in mapping["coordinates"]}
    supplemental = [r for r in all_results if (r["module"], r["version"]) in required]
    if {(r["module"], r["version"]) for r in supplemental} != required:
        raise Rejected("kubernetes_scan_join_incomplete")
    result = copy.deepcopy(component)
    result.update(joined_result(original, supplemental))
    result.update(
        coverage_profile="kubernetes-supplemental",
        sbom_validated=True,
        scan_executed=True,
        diagnostic_only=False,
        vulnerability_count=result["unique_vulnerabilities"],
        kubernetes_supplemental={
            "mapping": mapping,
            "original_result": original,
            "scans": supplemental,
        },
    )
    result.pop("reason", None)
    if "containerd_export" in component:
        result["kubernetes_supplemental"]["containerd_export_sha256"] = (
            image_kubernetes_export.evidence_pin(component)
        )
    return result


def coverage_valid(component, target):
    """Reconcile complete public joins; profile names/booleans are insufficient."""
    try:
        if "reason" in component:
            return False
        evidence = component["kubernetes_supplemental"]
        pin = (
            image_kubernetes_export.evidence_pin(component)
            if "containerd_export" in component
            else None
        )
        if evidence.get("containerd_export_sha256") != pin:
            return False
        reference = image_kubernetes_export.binding_reference(component, target)
        mapping = aliases.resolve(component["package_observation"], reference)
        if (
            mapping is None
            or mapping != evidence["mapping"]
            or mapping["image_config_id"] != target["config_id"]
        ):
            return False
        scans = evidence["scans"]
        if [(r["module"], r["version"]) for r in scans] != [
            tuple(pair) for pair in mapping["coordinates"]
        ]:
            return False
        original = evidence["original_result"]
        if original["image_id"] != target["config_id"] or original["diagnostic_only"] is not True:
            return False
        for result in scans:
            if (
                result["purl"] != aliases.validate_coordinate(result["module"], result["version"])
                or result["database"] != original["database"]
                or result["package_identity_bound"] is not True
                or result["matching_completed"] is not True
                or result["cleanup_verified"] is not True
                or set(result["artifact_digests"]) != set(SUFFIXES)
                or any(
                    not re.fullmatch(r"[0-9a-f]{64}", value)
                    for value in result["artifact_digests"].values()
                )
            ):
                return False
        expected = joined_result(original, scans)
        return all(component.get(key) == value for key, value in expected.items())
    except (Rejected, KeyError, TypeError, ValueError, AttributeError):
        return False
