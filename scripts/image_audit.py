import hashlib
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.storage_bootstrap import IMAGE as STORAGE_IMAGE
from scripts.image_archive import identity
from scripts.image_audit_contract import assess, database, detection_control, inventory

SYFT_IMAGE = (
    "anchore/syft:v1.54.1@sha256:3eb5379ba7b409c3f4069b686110527af0c47df993fa5c10d13e7cf34f49b1aa"
)
GRYPE_IMAGE = (
    "anchore/grype:v0.120.1@sha256:7bb1480f73d9a23b8e6137669c9b780389492778dc2da5c818d0add7e828ed45"
)
REPORT = ".runtime/evidence/image-audit.json"
LIMIT = 64 * 1024 * 1024
POLICY = {
    "id": "worker-storage-v1",
    "threshold": "High",
    "db_max_age_hours": 120,
    "unknown_severity": "inconclusive",
    "ignored_matches": "inconclusive",
    "coverage_alerts": "inconclusive",
    "allow_exceptions": False,
    "scope": ["worker", "storage"],
    "catalogue_scope": "squashed",
}


def file_hash(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024**3:
        raise Rejected("image_audit_file_invalid")
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def execute(arguments, output, timeout, cidfile=None):
    process = None
    log = output.with_suffix(".log")
    deadline = time.monotonic() + timeout

    def check_size():
        if output.stat().st_size > LIMIT or log.stat().st_size > 2 * 1024**2:
            raise Rejected("image_audit_output_too_large")

    try:
        with output.open("xb") as stdout, log.open("xb") as stderr:
            process = subprocess.Popen(
                arguments, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr
            )
            while process.poll() is None:
                check_size()
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(arguments, timeout)
                time.sleep(0.1)
        check_size()
        return process.returncode
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Rejected("image_audit_command_unavailable_or_timeout") from error
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if cidfile is not None and cidfile.is_file():
            container_id = bounded_read(cidfile, 128).decode("ascii").strip()
            if not re.fullmatch(r"[0-9a-f]{64}", container_id):
                raise Rejected("image_audit_cleanup_identity_invalid")
            result = subprocess.run(
                ["docker", "rm", "-f", container_id], capture_output=True, timeout=30, check=False
            )
            if result.returncode:
                raise Rejected("image_audit_cleanup_failed")


def scanner(run, name, image, arguments, mounts=(), network=False):
    user, group = (os.getuid(), os.getgid()) if hasattr(os, "getuid") else (65532, 65532)
    if user == 0:
        raise Rejected("image_audit_nonroot_host_required")
    cidfile = run / f"{name}.cid"
    output = run / f"{name}.json"
    command_line = [
        "docker",
        "run",
        "--cidfile",
        str(cidfile),
        "--pull=never",
        "--platform",
        "linux/amd64",
        "--network",
        "bridge" if network else "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        f"{user}:{group}",
        "--pids-limit",
        "256",
        "--cpus",
        "2",
        "--memory",
        "2g",
        "--memory-swap",
        "2g",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size=1g,uid={user},gid={group},mode=0700",
        "--workdir",
        "/tmp",
    ]
    environment = {
        "HOME": "/tmp",
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
        "GRYPE_DB_CACHE_DIR": "/cache",
        "GRYPE_DB_AUTO_UPDATE": "true" if network else "false",
        "GRYPE_DB_VALIDATE_AGE": "true",
        "GRYPE_DB_VALIDATE_BY_HASH_ON_START": "true",
        "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": "120h",
        "GRYPE_EXTERNAL_SOURCES_ENABLE": "false",
        "GRYPE_DB_UPDATE_URL": "https://grype.anchore.io/databases",
        "GRYPE_DB_REQUIRE_UPDATE_CHECK": "true",
        "GRYPE_ONLY_FIXED": "false",
        "GRYPE_ONLY_NOTFIXED": "false",
    }
    for name, value in environment.items():
        command_line.extend(["--env", f"{name}={value}"])
    for source, target, writable in mounts:
        if "," in str(source) or source.is_symlink():
            raise Rejected("image_audit_mount_invalid")
        command_line.extend(
            [
                "--mount",
                f"type=bind,source={source},target={target}" + ("" if writable else ",readonly"),
            ]
        )
    return execute(command_line + [image, *arguments], output, 300, cidfile), output


def inspect_image(reference):
    details = decode(command(["docker", "image", "inspect", reference]).encode())[0]
    if (
        details["Os"] != "linux"
        or details["Architecture"] != "amd64"
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", details["Id"])
        or not 0 < details["Size"] <= 4 * 1024**3
        or (
            "@sha256:" in reference
            and reference.split("@")[0].rsplit(":", 1)[0] + "@" + reference.split("@")[1]
            not in details["RepoDigests"]
        )
    ):
        raise Rejected("image_audit_image_identity_invalid")
    return details


def snapshot(cache):
    paths = sorted(path for path in cache.rglob("*") if not path.is_dir())
    if not paths or len(paths) > 20 or any(path.is_symlink() for path in cache.rglob("*")):
        raise Rejected("image_audit_database_snapshot_invalid")
    return {path.relative_to(cache).as_posix(): file_hash(path) for path in paths}


def audit(root):
    if shutil.disk_usage(root).free < 8 * 1024**3:
        raise Rejected("image_audit_disk_headroom_required")
    run_id = uuid.uuid4().hex
    run = safe_child(root, f".runtime/image-audit/{run_id}")
    run.mkdir(parents=True, mode=0o700)
    fingerprint = source_fingerprint(root)
    report = {
        "schema_version": 1,
        "status": "inconclusive",
        "release_ready": False,
        "scope": "worker-storage-image-audit-only",
        "run_id": run_id,
        "started_at": now(),
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "source_dirty": bool(command(["git", "-C", str(root), "status", "--porcelain"])),
        "source_fingerprint": fingerprint,
        "policy": POLICY,
        "policy_digest": digest(canonical(POLICY)),
        "scanner_images": {"syft": SYFT_IMAGE, "grype": GRYPE_IMAGE},
        "runner_materials": {
            path.name: file_hash(path) for path in sorted((root / "scripts").glob("image_*.py"))
        },
        "components": [],
        "detection_control": "inconclusive",
        "vulnerability_count": None,
        "limitations": [
            "Not full M01, M21 or R1 acceptance; control-plane images are outside this slice",
            "Scanner signatures not independently verified; digest pinning is not publisher identity",
            "Package matching is not exploitability analysis or complete vulnerability coverage",
            "Host administrator is trusted; reports are not a signed trusted audit sink",
            "Fresh DB can change findings; exact reproduction requires recorded DB and image snapshots",
        ],
    }
    write_json(safe_child(root, REPORT), report)
    for image in (SYFT_IMAGE, GRYPE_IMAGE, STORAGE_IMAGE):
        try:
            inspect_image(image)
        except Rejected:
            command(["docker", "pull", "--platform", "linux/amd64", image], timeout=300)
            inspect_image(image)
    sboms = {}
    required = {
        "worker": {"libc6", "scikit-learn", "onnxruntime", "cryptography"},
        "storage": {"libc6", "postgresql-18"},
    }
    for name, reference in (("worker", "trusted-mlsecops:dev"), ("storage", STORAGE_IMAGE)):
        component = {
            "name": name,
            "status": "inconclusive",
            "scan_executed": False,
            "vulnerability_count": None,
        }
        report["components"].append(component)
        archive = run / f"{name}.tar"
        try:
            details = inspect_image(reference)
            if (
                name == "worker"
                and details["Config"]
                .get("Labels", {})
                .get("org.trusted-mlsecops.source-fingerprint")
                != fingerprint
            ):
                raise Rejected("image_audit_worker_source_mismatch")
            component["runtime_image_id"] = details["Id"]
            command(
                ["docker", "image", "save", "--output", str(archive), details["Id"]], timeout=300
            )
            config_id = identity(archive, details)
            component.update(image_config_id=config_id, archive_digest=file_hash(archive))
            exit_code, path = scanner(
                run,
                f"{name}-sbom",
                SYFT_IMAGE,
                ["docker-archive:/input/image.tar", "-o", "syft-json"],
                [(archive, "/input/image.tar", False)],
            )
            if exit_code:
                raise Rejected("image_audit_sbom_failed")
            packages = inventory(
                decode(bounded_read(path, LIMIT), LIMIT), config_id, required[name]
            )
            component["catalogued_packages"] = len(packages)
            component["sbom_validated"] = True
            sboms[name] = path
            component["sbom_digest"] = file_hash(path)
        except Rejected as error:
            component["reason"] = str(error)
        finally:
            if archive.is_file() and not archive.is_symlink() and archive.resolve().parent == run:
                archive.unlink()
        write_json(safe_child(root, REPORT), report)
    if not sboms:
        raise Rejected("image_audit_no_sboms")
    cache = run / "cache"
    cache.mkdir(mode=0o700)
    exit_code, unused = scanner(
        run, "db-update", GRYPE_IMAGE, ["db", "update"], [(cache, "/cache", True)], network=True
    )
    if exit_code:
        raise Rejected("image_audit_database_update_failed")
    db_files = snapshot(cache)
    report["database_files"] = db_files
    exit_code, control_path = scanner(
        run,
        "detection-control",
        GRYPE_IMAGE,
        ["pkg:pypi/urllib3@1.26.7", "--fail-on", "high", "-o", "json"],
        [(cache, "/cache", False)],
    )
    control = decode(bounded_read(control_path, LIMIT), LIMIT)
    detection_control(control, exit_code)
    report["detection_control"] = "pass"
    report["detection_control_digest"] = file_hash(control_path)
    control_database = database(control, datetime.now(UTC))
    for component in report["components"]:
        name = component["name"]
        if name not in sboms:
            continue
        try:
            path = sboms[name]
            exit_code, scan_path = scanner(
                run,
                f"{name}-scan",
                GRYPE_IMAGE,
                ["sbom:/input/sbom.json", "--fail-on", "high", "-o", "json"],
                [(cache, "/cache", False), (path, "/input/sbom.json", False)],
            )
            result = assess(
                decode(bounded_read(path, LIMIT), LIMIT),
                decode(bounded_read(scan_path, LIMIT), LIMIT),
                component["image_config_id"],
                required[name],
                exit_code,
            )
            if (
                result["database"] != control_database
                or file_hash(path) != component["sbom_digest"]
                or snapshot(cache) != db_files
            ):
                raise Rejected("image_audit_snapshot_changed")
            component.update(
                result,
                scan_executed=True,
                vulnerability_count=result["unique_vulnerabilities"],
                report_digest=file_hash(scan_path),
            )
        except Rejected as error:
            component["reason"] = str(error)
        write_json(safe_child(root, REPORT), report)
    if snapshot(cache) != db_files or source_fingerprint(root) != fingerprint:
        raise Rejected("image_audit_materials_changed")
    statuses = {component["status"] for component in report["components"]}
    report["status"] = (
        "fail" if "fail" in statuses else "inconclusive" if "inconclusive" in statuses else "pass"
    )
    if all(component["scan_executed"] for component in report["components"]):
        report["vulnerability_count"] = len(
            {
                finding["id"]
                for component in report["components"]
                for finding in component["findings"]
            }
        )
    report["completed_at"] = now()
    return report


def main(root=None):
    root = Path(root or Path(__file__).resolve().parents[1]).resolve()
    output = safe_child(root, REPORT)
    write_json(
        output,
        {
            "status": "inconclusive",
            "release_ready": False,
            "reason": "audit_started",
            "started_at": now(),
            "vulnerability_count": None,
        },
    )
    try:
        report = audit(root)
    except Exception as error:
        report = read_json(output)
        report.update(
            status="inconclusive",
            release_ready=False,
            completed_at=now(),
            reason=str(error) if isinstance(error, Rejected) else "image_audit_internal_error",
        )
    write_json(output, report)
    print(canonical(report).decode())
    return 0 if report["status"] == "pass" else 1 if report["status"] == "fail" else 2


if __name__ == "__main__":
    sys.exit(main())
