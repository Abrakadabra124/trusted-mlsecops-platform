"""Build an isolated Kubernetes patch candidate on disposable hosted runners only."""

import hashlib
import os
import platform
import shutil
import urllib.request
import uuid
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, digest, now, read_json, safe_child, write_json
from mlsecops.inventory import command, source_fingerprint
from scripts.image_audit import file_hash, inspect_image

ARCHIVE_URL = "https://dl.k8s.io/release/v1.36.6/kubernetes-server-linux-amd64.tar.gz"
PINS = {
    "kubernetes": "v1.36.6",
    "kind": "v0.33.0",
    "archive_url": ARCHIVE_URL,
    "archive_sha256": "702d6529b5eb7bfb919dab3542cd420ccf316fca6aa7c506b69169bd12b26a7c",
    "base": "kindest/base:v20260820-69b56db7@sha256:8098fa3cae05bc15d9c4b93a566d19e1f8e65a25e26ebeb993b6cb41142cf791",
}
IMAGES = {
    "baseline": "kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed",
    "candidate": "trusted-mlsecops:node-v1.36.6-candidate",
}
REPORT = ".runtime/evidence/node-candidate-build.json"


def materials(root):
    return digest(
        canonical(
            {
                "runtime": source_fingerprint(root),
                **{
                    name: file_hash(safe_child(root, name))
                    for name in (
                        "scripts/image_node_candidate.py",
                        "scripts/install_ci_tools.py",
                        "infra/kind.yaml",
                    )
                },
            }
        )
    )


def download(target, expected, limit=2 * 1024**3):
    hasher, size = hashlib.sha256(), 0
    with target.open("xb") as output, urllib.request.urlopen(ARCHIVE_URL, timeout=90) as response:
        while chunk := response.read(1024**2):
            size += len(chunk)
            if size > limit:
                raise Rejected("node_candidate_archive_oversize")
            hasher.update(chunk)
            output.write(chunk)
    if not size or hasher.hexdigest() != expected:
        raise Rejected("node_candidate_archive_digest_mismatch")


def validate(root):
    report = read_json(safe_child(root, REPORT))
    try:
        if (
            report["status"] != "pass"
            or report["scope"] != "node-candidate-build-only"
            or report["release_ready"] is not False
            or report["materials"] != PINS
            or report["source_materials"] != materials(root)
            or report["source_revision"] != command(["git", "-C", str(root), "rev-parse", "HEAD"])
            or set(report["images"]) != set(IMAGES)
        ):
            raise Rejected("node_candidate_binding_invalid")
        for role, reference in IMAGES.items():
            if report["images"][role] != {
                "reference": reference,
                "config_id": inspect_image(reference)["Id"],
            }:
                raise Rejected("node_candidate_binding_invalid")
    except (KeyError, TypeError) as error:
        raise Rejected("node_candidate_binding_invalid") from error
    return report


def build(root):
    if (
        platform.system() != "Linux"
        or platform.machine() != "x86_64"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise Rejected("node_candidate_disposable_hosted_runner_required")
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("node_candidate_clean_checkout_required")
    if shutil.disk_usage(root).free < 12 * 1024**3:
        raise Rejected("node_candidate_disk_headroom_required")
    if PINS["kind"] not in command(["kind", "version"]):
        raise Rejected("node_candidate_kind_version_mismatch")
    source = materials(root)
    report = {
        "status": "inconclusive",
        "scope": "node-candidate-build-only",
        "release_ready": False,
        "materials": PINS,
        "source_materials": source,
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "started_at": now(),
        "images": {},
        "limitations": [
            "Build success is not functional, scanner coverage or release acceptance",
            "The pinned base is unchanged and retains existing OS/runtime vulnerabilities",
            "Kind imports ancillary images by upstream tags; resulting bytes need separate inventory",
            "Pinned archive checksum is not independent publisher-signature verification",
            "Kind docker-commit output is not claimed bit-for-bit reproducible",
        ],
    }
    output = safe_child(root, REPORT)
    write_json(output, report)
    run = safe_child(root, f".runtime/node-candidate/{uuid.uuid4().hex}")
    run.mkdir(parents=True, mode=0o700)
    archive = run / "kubernetes-server-linux-amd64.tar.gz"
    download(archive, PINS["archive_sha256"])
    command(["docker", "pull", "--platform", "linux/amd64", PINS["base"]], timeout=300)
    report["base_config_id"] = inspect_image(PINS["base"])["Id"]
    command(
        [
            "kind",
            "build",
            "node-image",
            "--type",
            "file",
            "--arch",
            "amd64",
            "--base-image",
            PINS["base"],
            "--image",
            IMAGES["candidate"],
            str(archive),
        ],
        timeout=1200,
    )
    command(["docker", "pull", "--platform", "linux/amd64", IMAGES["baseline"]], timeout=300)
    report["images"] = {
        role: {"reference": reference, "config_id": inspect_image(reference)["Id"]}
        for role, reference in IMAGES.items()
    }
    if materials(root) != source or file_hash(archive) != PINS["archive_sha256"]:
        raise Rejected("node_candidate_materials_changed")
    report.update(status="pass", completed_at=now())
    write_json(output, report)
    return validate(root)


if __name__ == "__main__":
    try:
        print(canonical(build(Path(__file__).resolve().parents[1])).decode())
    except (Rejected, OSError) as error:
        raise SystemExit(f"Node candidate refused: {error}") from error
