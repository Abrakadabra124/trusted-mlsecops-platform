import argparse
import math
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, decode, digest, now, read_json, write_json
from mlsecops.inventory import command, source_fingerprint
from scripts import image_audit, image_candidates

REPOSITORY = "Abrakadabra124/trusted-mlsecops-platform"
REGISTRY = "ghcr.io/abrakadabra124/trusted-mlsecops-platform-postgres"
REPORT = ".runtime/evidence/storage-publication.json"


def permit(audit, worker, storage, identities, revision, fingerprint, timestamp, repeat_tolerance):
    try:
        for report in (audit, worker, storage):
            completed = datetime.fromisoformat(report["completed_at"])
            if (
                report["release_ready"] is not False
                or completed.tzinfo is None
                or not timedelta(0) <= timestamp - completed <= timedelta(hours=2)
            ):
                raise Rejected("storage_publication_evidence_invalid")
        if (
            audit["scope"] != "worker-storage-tracking-image-audit-only"
            or audit["status"] not in {"pass", "fail"}
            or audit["source_dirty"] is not False
            or audit["source_revision"] != revision
            or audit["source_fingerprint"] != fingerprint
            or audit["includes_candidates"] is not True
            or audit["detection_control"] != "pass"
            or audit["wolfi_detection_control"] != "pass"
            or audit["policy"] != image_audit.POLICY
            or audit["policy_digest"] != digest(canonical(image_audit.POLICY))
            or worker["status"] != "pass"
            or worker["scope"] != "candidate-developer-profile-only"
            or any(worker[key] != value for key, value in identities["worker"].items())
            or storage["status"] != "pass"
            or storage["scope"] != "candidate-storage-compatibility-not-adoption"
            or storage["source_dirty"] is not False
            or storage["source_revision"] != revision
            or storage["identities"] != identities
            or storage["source_resources_removed"] is not True
            or storage["golden_rows"] != 1000
            or not math.isfinite(storage["golden_max_error"])
            or not 0 <= storage["golden_max_error"] <= repeat_tolerance
        ):
            raise Rejected("storage_publication_evidence_invalid")
        components = audit["components"]
        if (
            len(components) != 5
            or {component["name"] for component in components}
            != {"worker", "storage", "tracking", "worker-candidate", "storage-candidate"}
            or any(
                component["scan_executed"] is not True
                or component["sbom_validated"] is not True
                or component["status"] not in {"pass", "fail"}
                for component in components
            )
        ):
            raise Rejected("storage_publication_evidence_invalid")
        indexed = {component["name"]: component for component in components}
        for role, identity in identities.items():
            component = indexed[role + "-candidate"]
            if (
                component["status"] != "pass"
                or component["distro"] != "wolfi"
                or component["image_config_id"] != identity["image_id"]
                or component["recipe_digest"] != identity["recipe_digest"]
                or any(
                    type(component["severity_counts"][severity]) is not int
                    or component["severity_counts"][severity] != 0
                    for severity in ("Critical", "High", "Unknown")
                )
            ):
                raise Rejected("storage_publication_evidence_invalid")
    except (KeyError, TypeError, ValueError) as error:
        raise Rejected("storage_publication_evidence_invalid") from error
    return {
        "status": "pass",
        "scope": "qualified-storage-artifact-not-runtime-adoption",
        "release_ready": False,
        "source_revision": revision,
        "source_fingerprint": fingerprint,
        "baseline_audit_status": audit["status"],
        "identity": identities["storage"],
        "evidence_digests": {
            name: digest(canonical(report))
            for name, report in (("audit", audit), ("worker", worker), ("storage", storage))
        },
    }


def destination(environment, revision):
    expected = {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": revision,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
    }
    run, attempt = (environment.get(key, "") for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    if (
        not re.fullmatch(r"[0-9a-f]{40}", revision)
        or any(environment.get(key) != value for key, value in expected.items())
        or not all(re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (run, attempt))
    ):
        raise Rejected("storage_publication_dispatch_invalid")
    return f"{REGISTRY}:candidate-{revision}-{run}-{attempt}"


def publication_context(root):
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("storage_publication_dirty_source")
    return revision, destination(os.environ, revision)


def qualification(root):
    revision, target = publication_context(root)
    identities = {role: image_candidates.inspect(root, role) for role in ("worker", "storage")}
    report = permit(
        read_json(root / image_audit.REPORT),
        read_json(root / ".runtime/evidence/image-candidate-worker.json"),
        read_json(root / ".runtime/evidence/storage-candidate.json"),
        identities,
        revision,
        source_fingerprint(root),
        datetime.now(UTC),
        read_json(root / "policies/local-cpu.json")["repeat_tolerance"],
    )
    return {**report, "target": target}


def registry_readback(root, target, identity):
    descriptor = decode(
        command(
            ["docker", "buildx", "imagetools", "inspect", target, "--format", "{{json .Manifest}}"]
        ).encode()
    )
    try:
        manifest_digest = descriptor["digest"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_digest):
            raise Rejected("storage_publication_manifest_invalid")
        reference = f"{REGISTRY}@{manifest_digest}"
        manifest = decode(
            command(["docker", "buildx", "imagetools", "inspect", "--raw", reference]).encode()
        )
        if manifest["schemaVersion"] != 2 or manifest["config"]["digest"] != identity["image_id"]:
            raise Rejected("storage_publication_config_mismatch")
        command(["docker", "pull", "--platform", "linux/amd64", reference], timeout=300)
        actual = decode(command(["docker", "image", "inspect", reference]).encode())
        if (
            len(actual) != 1
            or actual[0]["Id"] != identity["image_id"]
            or image_candidates.inspect(root, "storage") != identity
        ):
            raise Rejected("storage_publication_readback_mismatch")
        return reference
    except (KeyError, TypeError) as error:
        raise Rejected("storage_publication_manifest_invalid") from error


def prepare(root):
    publication_context(root)
    report = image_audit.audit(root, include_candidates=True)
    write_json(root / image_audit.REPORT, report)
    return qualification(root)


def publish(root):
    report = qualification(root)
    command(["docker", "tag", report["identity"]["image_id"], report["target"]])
    command(["docker", "push", report["target"]], timeout=900)
    reference = registry_readback(root, report["target"], report["identity"])
    return {**report, "registry_reference": reference, "public_access_verified": False}


def main(action=None, root=None):
    if action is None:
        parser = argparse.ArgumentParser()
        parser.add_argument("action", choices=("prepare", "publish"))
        action = parser.parse_args().action
    root = Path(root or Path(__file__).resolve().parents[1]).resolve()
    pending = {
        "status": "inconclusive",
        "release_ready": False,
        "phase": action,
        "started_at": now(),
    }
    write_json(root / REPORT, pending)
    try:
        if action not in {"prepare", "publish"}:
            raise Rejected("storage_publication_action_invalid")
        report = (prepare if action == "prepare" else publish)(root)
    except (Rejected, OSError) as error:
        pending.update(
            reason=str(error) if isinstance(error, Rejected) else "storage_publication_io_failed",
            completed_at=now(),
        )
        write_json(root / REPORT, pending)
        print(canonical(pending).decode())
        return 2
    report.update(phase=action, completed_at=now())
    write_json(root / REPORT, report)
    print(canonical(report).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
