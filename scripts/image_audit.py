import argparse
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
from mlsecops.kube_worker import image_document
from mlsecops.storage_bootstrap import IMAGE as STORAGE_IMAGE
from scripts import image_candidates, image_scope, tracking_spike
from scripts.image_archive import identity
from scripts.image_audit_contract import (
    assess,
    database,
    detection_control,
    inventory,
    observe_packages,
    wolfi_detection_control,
)
from scripts.image_audit_publication import render
from scripts.image_comparison import compare

SYFT_IMAGE = (
    "anchore/syft:v1.54.1@sha256:3eb5379ba7b409c3f4069b686110527af0c47df993fa5c10d13e7cf34f49b1aa"
)
GRYPE_IMAGE = (
    "anchore/grype:v0.120.1@sha256:7bb1480f73d9a23b8e6137669c9b780389492778dc2da5c818d0add7e828ed45"
)
REPORT = ".runtime/evidence/image-audit.json"
LIMIT = 64 * 1024 * 1024
POLICY = {
    "id": "worker-storage-tracking-v2",
    "threshold": "High",
    "db_max_age_hours": 120,
    "unknown_severity": "inconclusive",
    "ignored_matches": "inconclusive",
    "coverage_alerts": "inconclusive",
    "allow_exceptions": False,
    "scope": ["worker", "storage", "tracking"],
    "catalogue_scope": "squashed",
}


def file_hash(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024**3:
        raise Rejected("image_audit_file_invalid")
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def execute(arguments, output, timeout, cidfile=None, *, output_limit=None):
    process = None
    log = output.with_suffix(".log")
    deadline = time.monotonic() + timeout

    def check_size():
        if (
            output.stat().st_size > (LIMIT if output_limit is None else output_limit)
            or log.stat().st_size > 2 * 1024**2
        ):
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


def export_local_image(target, archive):
    config_id = image_scope.image_digest(target["config_id"])
    reference = target["reference"]
    if "@" in reference:
        image_scope.registry_reference(reference)
        observed_config = image_scope.image_config(reference.split("@", 1)[1])
    else:
        observed_config = reference
    if observed_config != config_id:
        raise Rejected("image_audit_local_target_invalid")
    alias = image_scope.local_reference(target["containerd_reference"])
    config = image_document(config_id)
    details = {
        "Id": config_id,
        "Os": config["os"],
        "Architecture": config["architecture"],
        "RootFS": {"Layers": config["rootfs"]["diff_ids"]},
        "Config": config["config"],
    }
    code = execute(
        [
            "docker",
            "exec",
            image_scope.NODE,
            "ctr",
            "-n",
            "k8s.io",
            "images",
            "export",
            "--local",
            "--platform",
            "linux/amd64",
            "-",
            alias,
        ],
        archive,
        300,
        output_limit=4 * 1024**3,
    )
    if code:
        raise Rejected("image_audit_local_export_failed")
    if identity(archive, details) != config_id:
        raise Rejected("image_audit_runtime_config_mismatch")
    return details


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
    return execute(
        command_line + [image, *arguments], output, 600 if network else 300, cidfile
    ), output


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


def audit(root, include_candidates=False, runtime_state=None):
    if shutil.disk_usage(root).free < 8 * 1024**3:
        raise Rejected("image_audit_disk_headroom_required")
    run_id = uuid.uuid4().hex
    run = safe_child(root, f".runtime/image-audit/{run_id}")
    run.mkdir(parents=True, mode=0o700)
    fingerprint = source_fingerprint(root)
    policy = (
        POLICY
        if runtime_state is None
        else {
            **POLICY,
            "id": "observed-runtime-images-v1",
            "scope": [*POLICY["scope"], "owned-runtime"],
        }
    )
    report = {
        "schema_version": 1,
        "status": "inconclusive",
        "release_ready": False,
        "scope": "worker-storage-tracking-image-audit-only"
        if runtime_state is None
        else "observed-runtime-image-audit-only",
        "run_id": run_id,
        "started_at": now(),
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "source_dirty": bool(command(["git", "-C", str(root), "status", "--porcelain"])),
        "source_fingerprint": fingerprint,
        "policy": policy,
        "policy_digest": digest(canonical(policy)),
        "scanner_images": {"syft": SYFT_IMAGE, "grype": GRYPE_IMAGE},
        "runner_materials": {
            path.name: file_hash(path)
            for path in [
                *sorted((root / "scripts").glob("image_*.py")),
                root / "scripts/tracking_spike.py",
            ]
        },
        "components": [],
        "includes_candidates": include_candidates,
        "detection_control": "inconclusive",
        "vulnerability_count": None,
        "limitations": [
            "Not full M01, M21 or R1 acceptance; unapproved system application coverage remains inconclusive"
            if runtime_state is not None
            else "Not full M01, M21 or R1 acceptance; deployed controller/system inventory reconciliation is still required",
            "Scanner signatures not independently verified; digest pinning is not publisher identity",
            "Package matching is not exploitability analysis or complete vulnerability coverage",
            "Host administrator is trusted; reports are not a signed trusted audit sink",
            "Fresh DB can change findings; exact reproduction requires recorded DB and image snapshots",
        ],
    }
    observed = None
    if runtime_state is not None:
        report["runtime_scope"] = {
            "status": "inconclusive",
            "expected_images": None,
            "covered_images": 0,
        }
    write_json(safe_child(root, REPORT), report)
    if runtime_state is not None:
        observed = image_scope.collect(root, runtime_state)
        if any(observed[key] != report[key] for key in ("source_revision", "source_fingerprint")):
            raise Rejected("image_audit_runtime_source_mismatch")
        write_json(run / "runtime-before.json", observed)
        report["runtime_scope"]["expected_images"] = len(observed["targets"])
        write_json(safe_child(root, REPORT), report)
    tracking_materials = tracking_spike.materials(root)
    for image in (SYFT_IMAGE, GRYPE_IMAGE, STORAGE_IMAGE):
        try:
            inspect_image(image)
        except Rejected:
            command(["docker", "pull", "--platform", "linux/amd64", image], timeout=300)
            inspect_image(image)
    sboms = {}
    required = {
        ("debian", "worker"): {"libc6", "scikit-learn", "onnxruntime", "cryptography"},
        ("debian", "storage"): {"libc6", "postgresql-18"},
        ("debian", "tracking"): {"libc6", "mlflow", "mlflow-skinny", "psycopg", "uvicorn"},
        ("debian", "system"): {"libc6"},
        ("wolfi", "system"): {"glibc-2.44"},
        ("wolfi", "worker"): {
            "glibc-2.44",
            "python-3.12",
            "scikit-learn",
            "onnxruntime",
            "cryptography",
        },
        ("wolfi", "storage"): {"glibc-2.44", "postgresql-18"},
        ("wolfi", "tracking"): {
            "glibc-2.44",
            "python-3.12",
            "mlflow",
            "mlflow-skinny",
            "mlflow-tracing",
            "psycopg",
            "uvicorn",
        },
    }
    targets = [
        ("worker", "worker", "trusted-mlsecops:dev", "wolfi"),
        ("storage", "storage", STORAGE_IMAGE, "wolfi"),
        ("tracking", "tracking", tracking_spike.TAG, "wolfi"),
    ]
    if include_candidates:
        targets.extend(
            (role + "-candidate", role, spec["reference"], "wolfi")
            for role, spec in image_candidates.SPECS.items()
        )
    expected_configs, local_exports = {}, {}
    if observed is not None:
        targets.extend(
            (item["name"], "system", item["reference"], None) for item in observed["targets"]
        )
        expected_configs = {item["name"]: item["config_id"] for item in observed["targets"]}
        local_exports = {
            item["name"]: item for item in observed["targets"] if "containerd_reference" in item
        }
    for name, role, reference, distro in targets:
        component = {
            "name": name,
            "role": role,
            "distro": distro,
            "status": "inconclusive",
            "scan_executed": False,
            "vulnerability_count": None,
            "coverage_profile": role if role != "system" else "unapproved-system",
        }
        report["components"].append(component)
        archive = run / f"{name}.tar"
        expected_distro = None
        try:
            try:
                details = (
                    export_local_image(local_exports[name], archive)
                    if name in local_exports
                    else inspect_image(reference)
                )
            except Rejected:
                if role != "system" or "@sha256:" not in reference:
                    raise
                command(["docker", "pull", "--platform", "linux/amd64", reference], timeout=300)
                details = inspect_image(reference)
            if role == "system" and expected_configs[name] is None and details["Id"] != reference:
                raise Rejected("image_audit_runtime_image_mismatch")
            if (
                role == "worker"
                and details["Config"]
                .get("Labels", {})
                .get("org.trusted-mlsecops.source-fingerprint")
                != fingerprint
            ):
                raise Rejected("image_audit_worker_source_mismatch")
            if name.endswith("-candidate"):
                component["recipe_digest"] = image_candidates.validate(root, role, details)[
                    "recipe_digest"
                ]
            if role == "tracking":
                if (
                    details["Config"].get("User") != "65532:65532"
                    or details["Config"].get("Labels", {}).get(tracking_spike.LABEL)
                    != tracking_materials
                ):
                    raise Rejected("image_audit_tracking_materials_mismatch")
                component["recipe_digest"] = tracking_materials
            component["runtime_image_id"] = details["Id"]
            if name not in local_exports:
                command(
                    ["docker", "image", "save", "--output", str(archive), details["Id"]],
                    timeout=300,
                )
            config_id = identity(archive, details)
            if (
                role == "system"
                and expected_configs[name] is not None
                and config_id != expected_configs[name]
            ):
                raise Rejected("image_audit_runtime_config_mismatch")
            if role == "system":
                known = [
                    item
                    for item in report["components"]
                    if item["name"] in POLICY["scope"]
                    and item.get("image_config_id") == config_id
                    and item.get("sbom_validated") is True
                ]
                if len(known) == 1:
                    component["coverage_profile"] = known[0]["role"]
                    expected_distro = known[0]["distro"]
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
            sbom = decode(bounded_read(path, LIMIT), LIMIT)
            if role == "system":
                component["package_observation"] = observe_packages(sbom, config_id)
                component["observed_reference"] = reference
                if name in local_exports:
                    component["local_alias"] = local_exports[name]["containerd_reference"]
                component["host_roles"] = sorted(
                    {
                        item["role"]
                        for item in observed["containers"]
                        if item["image_id"] in {reference, config_id}
                    }
                )
                declared = sbom.get("distro")
                distro = declared.get("id") if isinstance(declared, dict) else None
                component["distro"] = distro
                if (distro, role) not in required:
                    raise Rejected("image_audit_runtime_distro_unsupported")
                if expected_distro is not None and distro != expected_distro:
                    raise Rejected("image_audit_runtime_distro_mismatch")
            packages = inventory(
                sbom,
                config_id,
                required[(distro, component["coverage_profile"])]
                if component["coverage_profile"] != "unapproved-system"
                else required[(distro, role)],
                distro=distro,
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
    write_json(safe_child(root, REPORT), report)
    exit_code, control_path = scanner(
        run,
        "detection-control",
        GRYPE_IMAGE,
        ["pkg:pypi/urllib3@1.26.7", "--fail-on", "high", "-o", "json"],
        [(cache, "/cache", False)],
    )
    control = decode(bounded_read(control_path, LIMIT), LIMIT)
    descriptor = control.get("descriptor", {})
    report["control_observation"] = {
        "exit_code": exit_code,
        "scanner_name": descriptor.get("name"),
        "scanner_version": descriptor.get("version"),
        "database": {
            key: descriptor.get("db", {}).get("status", {}).get(key)
            for key in ("schemaVersion", "built", "valid")
        },
        "database_error_present": bool(descriptor.get("db", {}).get("status", {}).get("error")),
    }
    write_json(safe_child(root, REPORT), report)
    detection_control(control, exit_code)
    report["detection_control"] = "pass"
    report["detection_control_digest"] = file_hash(control_path)
    control_database = database(control, datetime.now(UTC))
    if any(distro == "wolfi" for unused, role, reference, distro in targets):
        report["wolfi_detection_control"] = "inconclusive"
        write_json(safe_child(root, REPORT), report)
        exit_code, wolfi_path = scanner(
            run,
            "wolfi-detection-control",
            GRYPE_IMAGE,
            [
                "pkg:apk/wolfi/openssl@3.0.7-r0?arch=x86_64&distro=wolfi-20230201",
                "--fail-on",
                "high",
                "-o",
                "json",
            ],
            [(cache, "/cache", False)],
        )
        wolfi_control = decode(bounded_read(wolfi_path, LIMIT), LIMIT)
        report["wolfi_control_observation"] = {
            "exit_code": exit_code,
            "distro": {
                key: wolfi_control.get("distro", {}).get(key) for key in ("name", "version")
            },
            "expected_matches": [
                {key: match["vulnerability"].get(key) for key in ("id", "severity")}
                for match in wolfi_control.get("matches", [])
                if match.get("vulnerability", {}).get("id")
                in {"CVE-2023-0286", "CGA-6vj8-747q-h83f"}
            ],
        }
        report["wolfi_detection_control_digest"] = file_hash(wolfi_path)
        write_json(safe_child(root, REPORT), report)
        wolfi_detection_control(wolfi_control, exit_code)
        if database(wolfi_control, datetime.now(UTC)) != control_database:
            raise Rejected("image_audit_wolfi_database_changed")
        report["wolfi_detection_control"] = "pass"
        write_json(safe_child(root, REPORT), report)
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
                required[(component["distro"], component["coverage_profile"])]
                if component["coverage_profile"] != "unapproved-system"
                else required[(component["distro"], component["role"])],
                exit_code,
                distro=component["distro"],
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
            if component["coverage_profile"] == "unapproved-system":
                component["reason"] = "image_audit_runtime_application_coverage_unapproved"
                if component["status"] == "pass":
                    component["status"] = "inconclusive"
        except Rejected as error:
            component["reason"] = str(error)
        write_json(safe_child(root, REPORT), report)
    if (
        snapshot(cache) != db_files
        or source_fingerprint(root) != fingerprint
        or tracking_spike.materials(root) != tracking_materials
    ):
        raise Rejected("image_audit_materials_changed")
    statuses = {component["status"] for component in report["components"]}
    if observed is not None:
        repeated = image_scope.collect(root, runtime_state)
        write_json(run / "runtime-after.json", repeated)
        if canonical(repeated) != canonical(observed):
            raise Rejected("image_audit_runtime_changed")
        report["runtime_scope"] = image_scope.coverage(observed, report["components"])
        if report["runtime_scope"]["status"] != "pass":
            statuses.add("inconclusive")
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
    if include_candidates:
        report["comparison"] = compare(
            [
                component
                for component in report["components"]
                if component["name"]
                in {"worker", "storage", "worker-candidate", "storage-candidate"}
            ]
        )
    return report


def main(root=None, include_candidates=False, runtime_state=None):
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
        report = audit(root, include_candidates=include_candidates, runtime_state=runtime_state)
    except Exception as error:
        report = read_json(output)
        report.update(
            status="inconclusive",
            release_ready=False,
            completed_at=now(),
            reason=str(error) if isinstance(error, Rejected) else "image_audit_internal_error",
        )
    write_json(output, report)
    print(render(report))
    return 0 if report["status"] == "pass" else 1 if report["status"] == "fail" else 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Audit baseline images and optional separate candidates"
    )
    parser.add_argument("--compare-candidates", action="store_true")
    parser.add_argument(
        "--runtime-state", type=Path, help="Owned complete lab state for observed image coverage"
    )
    arguments = parser.parse_args()
    sys.exit(
        main(include_candidates=arguments.compare_candidates, runtime_state=arguments.runtime_state)
    )
