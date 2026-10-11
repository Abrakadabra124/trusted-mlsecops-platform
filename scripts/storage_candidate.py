import sys
import uuid
from pathlib import Path

from mlsecops import storage_bootstrap, storage_recovery_qualification
from mlsecops.bootstrap import initialize
from mlsecops.contracts import Rejected, canonical, digest, now, read_json, safe_child, write_json
from mlsecops.inventory import command
from scripts.image_candidates import inspect

REPORT = ".runtime/evidence/storage-candidate.json"


def dispose(root, state, expected):
    parent = safe_child(root, ".runtime/image-candidates")
    if state.is_symlink() or state.resolve().parent != parent:
        raise Rejected("candidate_storage_cleanup_path_invalid")
    marker = storage_bootstrap.validate(state)
    if marker != expected:
        raise Rejected("candidate_storage_cleanup_identity_changed")
    storage_bootstrap.docker(["rm", "--force", marker["container_id"]])
    storage_bootstrap.docker(["network", "rm", marker["network"]])
    storage_bootstrap.docker(["volume", "rm", marker["volume"]])
    if any(
        storage_bootstrap.inspect(kind, marker[key], required=False) is not None
        for kind, key in (("container", "name"), ("network", "network"), ("volume", "volume"))
    ):
        raise Rejected("candidate_storage_cleanup_incomplete")


def rehearse(root):
    output = safe_child(root, REPORT)
    write_json(output, {"status": "inconclusive", "release_ready": False, "started_at": now()})
    identities = {role: inspect(root, role) for role in ("worker", "storage")}
    state = safe_child(root, f".runtime/image-candidates/{uuid.uuid4().hex}")
    initialize(root, state)
    storage_bootstrap.bootstrap(state, 15442)
    source = storage_bootstrap.validate(state)
    result = storage_recovery_qualification.qualify(
        root,
        state,
        identities["worker"]["image_id"],
        15443,
        experimental_image_id=identities["storage"]["image_id"],
    )
    if (
        result["status"] != "pass"
        or result["release_ready"] is not False
        or result["target_image"] != identities["storage"]["image_id"]
        or result["source_image"] != source["image"]
        or any(inspect(root, role) != identity for role, identity in identities.items())
    ):
        raise Rejected("candidate_storage_qualification_binding_invalid")
    write_json(state / "evidence/storage-candidate-full.json", result)
    dispose(root, state, source)
    report = {
        "status": "pass",
        "scope": "candidate-storage-compatibility-not-adoption",
        "release_ready": False,
        "completed_at": now(),
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "source_dirty": bool(command(["git", "-C", str(root), "status", "--porcelain"])),
        "identities": identities,
        "source_image": source["image"],
        "checks": result["checks"],
        "report_digest": digest(canonical(result)),
        "golden_rows": result["golden_rows"],
        "golden_max_error": result["golden_max_error"],
        "storage_restore_seconds": result["storage_restore_seconds"],
        "restore_to_golden_seconds": result["restore_to_golden_seconds"],
        "database_profiles": result["database_profiles"],
        "source_resources_removed": True,
        "limitations": [
            "Fresh synthetic source, not backup of working cluster history",
            "Known High/Critical findings remain blocking; compatibility does not authorize adoption",
            "SQL restore and limited collation sample, not complete M17 release/serving recovery",
            "Host, source administrator and backup signer remain trusted",
        ],
    }
    write_json(output, report)
    return report


def main():
    root = Path(__file__).resolve().parents[1]
    try:
        report = rehearse(root)
        print(canonical(report).decode())
        return 0
    except (Rejected, OSError) as error:
        report = read_json(safe_child(root, REPORT))
        report.update(
            status="inconclusive", release_ready=False, reason=str(error), completed_at=now()
        )
        write_json(safe_child(root, REPORT), report)
        print(canonical(report).decode())
        return 2


if __name__ == "__main__":
    sys.exit(main())
