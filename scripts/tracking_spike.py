import argparse
import re
import subprocess
import uuid
from pathlib import Path

from mlsecops.bootstrap import initialize
from mlsecops.contracts import (
    Rejected,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.qualification import qualify as qualify_worker
from scripts.tracking_records import export_records

TAG = "trusted-mlsecops:tracking-candidate"
LABEL = "org.trusted-mlsecops.tracking-materials"
RUN_LABEL = "org.trusted-mlsecops.tracking-probe"


def materials(root):
    paths = (
        "Dockerfile",
        "Dockerfile.dockerignore",
        "requirements.in",
        "requirements.lock",
        "probe.py",
    )
    return digest(
        canonical(
            {
                name: digest(safe_child(root, "images/tracking/" + name).read_bytes())
                for name in paths
            }
        )
    )


def inspect_image(root):
    observed = decode(command(["docker", "image", "inspect", TAG]).encode())[0]
    if (
        not re.fullmatch(r"sha256:[0-9a-f]{64}", observed["Id"])
        or observed["Os"] != "linux"
        or observed["Architecture"] != "amd64"
        or observed["Config"]["User"] != "65532:65532"
        or observed["Config"].get("Labels", {}).get(LABEL) != materials(root)
    ):
        raise Rejected("tracking_image_binding_invalid_rebuild_required")
    return observed["Id"]


def build(root):
    command(
        [
            "docker",
            "build",
            "--platform",
            "linux/amd64",
            "--file",
            "images/tracking/Dockerfile",
            "--build-arg",
            "MATERIALS_DIGEST=" + materials(root),
            "--tag",
            TAG,
            str(root),
        ],
        timeout=900,
    )
    return {
        "status": "pass",
        "scope": "tracking-image-build-only",
        "release_ready": False,
        "image_id": inspect_image(root),
        "materials_digest": materials(root),
    }


def dispose(name, image, identity):
    observed = decode(command(["docker", "container", "inspect", name]).encode())[0]
    if (
        observed["Config"]["Image"] != image
        or observed["Image"] != image
        or observed["Config"].get("Labels", {}).get(RUN_LABEL) != identity
    ):
        raise Rejected("tracking_probe_cleanup_identity_changed")
    command(["docker", "rm", "--force", observed["Id"]])
    if command(
        ["docker", "container", "ls", "--all", "--quiet", "--filter", "id=" + observed["Id"]]
    ):
        raise Rejected("tracking_probe_cleanup_incomplete")


def qualify(root, worker_image):
    output = safe_child(root, ".runtime/evidence/tracking-spike.json")
    write_json(output, {"status": "inconclusive", "release_ready": False, "started_at": now()})
    image = inspect_image(root)
    identity = uuid.uuid4().hex
    state = safe_child(root, ".runtime/tracking/" + identity)
    initialize(root, state)
    training = qualify_worker(root, state, worker_image)
    records = export_records(training, read_json(root / "policies/local-cpu.json"))
    name = "tml-tracking-probe-" + identity
    arguments = [
        "docker",
        "run",
        "--interactive",
        "--name",
        name,
        "--label",
        RUN_LABEL + "=" + identity,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--cpus",
        "2",
        "--memory",
        "2g",
        "--memory-swap",
        "2g",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=384m",
        "--log-driver",
        "none",
        image,
        "/app/probe.py",
    ]
    try:
        result = subprocess.run(
            arguments, input=canonical(records), capture_output=True, timeout=240
        )
        if len(result.stdout) > 256 * 1024 or len(result.stderr) > 256 * 1024:
            raise Rejected("tracking_probe_output_limit")
        report = decode(result.stdout)
        if result.returncode or report.get("status") != "pass":
            write_json(state / "evidence/tracking-probe.json", report)
            raise Rejected("tracking_probe_failed:" + str(report.get("reason", "unknown")))
        if (
            report.get("release_ready") is not False
            or report.get("scope") != "mlflow-offline-auth-sqlite-spike-not-T08-M06"
            or report.get("version") != "3.17.0"
            or report.get("record_digests") != [digest(canonical(record)) for record in records]
            or len(set(report["tracking_run_ids"])) != 3
            or report["checks"] < 53
            or report["checks"] != len(report["cases"])
            or len({case["id"] for case in report["cases"]}) != report["checks"]
            or not all(case["status"] == "pass" for case in report["cases"])
            or inspect_image(root) != image
        ):
            raise Rejected("tracking_probe_binding_invalid")
        write_json(state / "evidence/tracking-probe.json", report)
    finally:
        dispose(name, image, identity)
    summary = {
        **report,
        "completed_at": now(),
        "image_id": image,
        "materials_digest": materials(root),
        "source_fingerprint": source_fingerprint(root),
        "worker_checks": len(training["cases"]),
        "worker_image": training["runs"][0]["image_id"],
        "training_metrics": training["metrics"],
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "source_dirty": bool(command(["git", "-C", str(root), "status", "--porcelain"])),
        "limitations": [
            "Offline throwaway SQLite auth/API spike, not separate PostgreSQL or TLS deployment",
            "Metadata projections only; MLflow cannot approve releases or select runtime models",
            "Container OS vulnerabilities and full T08/M06 remain unaccepted",
            "Input mutation contracts are fixtures, not the complete native M06 mutation campaign",
        ],
    }
    write_json(output, summary)
    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Isolated MLflow compatibility spike, not deployment"
    )
    parser.add_argument("action", choices=("build", "qualify"))
    parser.add_argument("--worker-image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        result = (
            build(root) if arguments.action == "build" else qualify(root, arguments.worker_image)
        )
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError, subprocess.TimeoutExpired) as error:
        result = {
            "status": "inconclusive",
            "release_ready": False,
            "reason": type(error).__name__
            if isinstance(error, subprocess.TimeoutExpired)
            else str(error),
            "completed_at": now(),
        }
        write_json(root / ".runtime/evidence/tracking-spike.json", result)
        print(canonical(result).decode())
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
