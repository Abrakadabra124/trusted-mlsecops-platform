import argparse
import re
import sys
import uuid
from pathlib import Path

from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    safe_child,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint

SPECS = {
    "worker": {
        "reference": "trusted-mlsecops:worker-candidate",
        "recipe": "images/candidates/worker/Dockerfile",
    },
    "storage": {
        "reference": "trusted-mlsecops:storage-candidate",
        "recipe": "images/candidates/storage/Dockerfile",
    },
}


def recipe_digest(root, role):
    return digest(bounded_read(safe_child(root, SPECS[role]["recipe"]), 65536))


def validate(root, role, image):
    try:
        labels = image["Config"]["Labels"]
        recipe = recipe_digest(root, role)
        fingerprint = source_fingerprint(root)
        if (
            image["Os"] != "linux"
            or image["Architecture"] != "amd64"
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", image["Id"])
            or labels["org.trusted-mlsecops.source-fingerprint"] != fingerprint
            or labels["org.trusted-mlsecops.candidate-recipe"] != recipe
            or labels["org.trusted-mlsecops.candidate-role"] != role
        ):
            raise Rejected("candidate_image_binding_invalid")
        return {
            "role": role,
            "image_id": image["Id"],
            "source_fingerprint": fingerprint,
            "recipe_digest": recipe,
            "release_ready": False,
        }
    except (KeyError, TypeError) as error:
        raise Rejected("candidate_image_binding_invalid") from error


def inspect(root, role):
    return validate(
        root,
        role,
        decode(command(["docker", "image", "inspect", SPECS[role]["reference"]]).encode())[0],
    )


def build(root):
    output = safe_child(root, ".runtime/evidence/image-candidate-build.json")
    report = {
        "status": "inconclusive",
        "scope": "image-candidate-build-only",
        "release_ready": False,
        "started_at": now(),
        "images": [],
    }
    write_json(output, report)
    fingerprint = source_fingerprint(root)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    for role, spec in SPECS.items():
        command(
            [
                "docker",
                "build",
                "--platform",
                "linux/amd64",
                "--tag",
                spec["reference"],
                "--file",
                str(safe_child(root, spec["recipe"])),
                "--label",
                f"org.opencontainers.image.revision={revision}",
                "--label",
                f"org.trusted-mlsecops.source-fingerprint={fingerprint}",
                "--label",
                f"org.trusted-mlsecops.candidate-recipe={recipe_digest(root, role)}",
                "--label",
                f"org.trusted-mlsecops.candidate-role={role}",
                str(root),
            ],
            timeout=900,
        )
        report["images"].append(inspect(root, role))
        write_json(output, report)
    report.update(status="pass", completed_at=now())
    write_json(output, report)
    return report


def qualify_worker(root):
    from mlsecops.qualification import qualify

    output = safe_child(root, ".runtime/evidence/image-candidate-worker.json")
    write_json(output, {"status": "inconclusive", "release_ready": False, "started_at": now()})
    identity = inspect(root, "worker")
    state = safe_child(root, f".runtime/image-candidates/{uuid.uuid4().hex}")
    state.mkdir(parents=True, mode=0o700)
    result = qualify(root, state, identity["image_id"])
    if inspect(root, "worker") != identity:
        raise Rejected("candidate_changed_during_qualification")
    report = {
        "status": "pass",
        "scope": "candidate-developer-profile-only",
        **identity,
        "checks": len(result["cases"]),
        "metrics": result["metrics"],
        "report_digest": digest(canonical(result)),
        "completed_at": now(),
    }
    write_json(output, report)
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Build or qualify separate images; never replace running storage"
    )
    parser.add_argument("action", choices=("build", "qualify-worker"))
    arguments = parser.parse_args()
    try:
        root = Path(__file__).resolve().parents[1]
        result = build(root) if arguments.action == "build" else qualify_worker(root)
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        print(f"Candidate operation rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
