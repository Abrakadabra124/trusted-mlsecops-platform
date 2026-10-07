import argparse
import re
import sys
from pathlib import Path

from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.datasets import generate, source_approval, validate_rows, verify_dataset
from mlsecops.intake import approve, snapshot_statement, submit
from mlsecops.signing import sign, verify

SOURCE = "source/records.json"
INPUTS = (
    "mlsecops/contracts.py",
    "mlsecops/data_source.py",
    "mlsecops/datasets.py",
    "mlsecops/intake.py",
    "mlsecops/signing.py",
    "policies/local-cpu.json",
    "uv.lock",
)


def inputs(root):
    return {
        name: {"sha256": digest(content), "bytes": len(content)}
        for name in INPUTS
        for content in (bounded_read(safe_child(root, name)),)
    }


def generated(root):
    policy = read_json(Path(root) / "policies/local-cpu.json")
    rows = generate(policy["data_seed"], policy["rows"])
    validate_rows(rows, policy["rows"])
    return canonical(rows)


def validate_lock(root):
    lock = read_json(safe_child(root, "data.lock"))
    require_fields(lock, ("schema_version", "stage", "inputs", "output"))
    require_fields(lock["output"], ("sha256", "bytes"))
    if (
        type(lock["schema_version"]) is not int
        or lock["schema_version"] != 1
        or lock["stage"] != "synthetic-source-v1"
        or canonical(lock["inputs"]) != canonical(inputs(root))
        or not isinstance(lock["output"]["sha256"], str)
        or not re.fullmatch("[0-9a-f]{64}", lock["output"]["sha256"])
        or type(lock["output"]["bytes"]) is not int
        or not 0 < lock["output"]["bytes"] <= 16 * 1024 * 1024
    ):
        raise Rejected("source_lock_mismatch_explicit_update_required")
    return lock


def reproduce(root, state, update_lock=False, fresh=False):
    root, state = Path(root), Path(state)
    if read_json(safe_child(state, "workspace.json")).get("product") != "trusted-mlsecops":
        raise Rejected("source_requires_owned_workspace")
    if update_lock:
        content = generated(root)
        lock = {
            "schema_version": 1,
            "stage": "synthetic-source-v1",
            "inputs": inputs(root),
            "output": {"sha256": digest(content), "bytes": len(content)},
        }
        write_json(safe_child(root, "data.lock"), lock)
        mode = "generated-lock-update"
    else:
        lock = validate_lock(root)
        cached = safe_child(state, f"source-cache/{lock['output']['sha256']}.json")
        content = generated(root) if fresh or not cached.exists() else bounded_read(cached)
        mode = "generated" if fresh or not cached.exists() else "verified-cache"
    if {"sha256": digest(content), "bytes": len(content)} != lock["output"]:
        raise Rejected("source_content_does_not_match_lock")
    validate_rows(decode(content), read_json(root / "policies/local-cpu.json")["rows"])
    cache = safe_child(state, f"source-cache/{digest(content)}.json")
    if cache.exists() and bounded_read(cache) != content:
        raise Rejected("source_cache_corrupted")
    if not cache.exists():
        atomic_write(cache, content)
    atomic_write(safe_child(state, SOURCE), content)
    return {**lock["output"], "mode": mode, "lock_sha256": digest(bounded_read(root / "data.lock"))}


def verify_source(root, state):
    lock = validate_lock(root)
    content = bounded_read(safe_child(state, SOURCE))
    if {"sha256": digest(content), "bytes": len(content)} != lock["output"]:
        raise Rejected("source_content_does_not_match_lock")
    policy = read_json(Path(root) / "policies/local-cpu.json")
    validate_rows(decode(content), policy["rows"])
    return content, digest(bounded_read(Path(root) / "data.lock"))


def authorize_source(root, state):
    content, lock_digest = verify_source(root, state)
    policy = read_json(Path(root) / "policies/local-cpu.json")
    approval = source_approval(state, policy, create=True)
    statement = snapshot_statement(content, policy, approval)
    target = safe_child(state, f"source-attestations/{digest(content)}.json")
    public = read_json(Path(state) / "trusted-keys.json")["curator"]
    if target.exists():
        if canonical(verify(read_json(target), "source-snapshot", public)) != canonical(statement):
            raise Rejected("source_attestation_requires_explicit_renewal")
    else:
        write_json(target, sign(statement, "source-snapshot", Path(state) / "keys/curator.pem"))
    return {"source_sha256": digest(content), "lock_sha256": lock_digest}


def prepare_versioned(root, state):
    root, state = Path(root), Path(state)
    policy = read_json(root / "policies/local-cpu.json")
    authorization = authorize_source(root, state)
    content, lock_digest = verify_source(root, state)
    report = submit(state, safe_child(state, SOURCE), policy["source"], "dataset", policy)
    if report["status"] != "validated-not-approved":
        raise Rejected("versioned_source_intake_failed")
    receipt = approve(state, report["intake_id"], policy)
    if (
        receipt["source_sha256"] != authorization["source_sha256"]
        or lock_digest != authorization["lock_sha256"]
    ):
        raise Rejected("versioned_source_changed_during_publication")
    lineage = {
        "schema_version": 1,
        "dataset_id": receipt["dataset_id"],
        "source_sha256": digest(content),
        "policy_digest": digest(canonical(policy)),
        "lock_sha256": lock_digest,
        "inputs": inputs(root),
        "classification": "synthetic-only",
        "curator": "lab-curator",
    }
    identifier = digest(canonical(lineage))
    target = safe_child(state, f"lineage/{identifier}.json")
    if not target.exists():
        write_json(target, sign(lineage, "data-lineage", state / "keys/curator.pem"))
    verify_lineage(state, identifier, receipt["dataset_id"], policy)
    result = {"dataset_id": receipt["dataset_id"], "lineage_id": identifier}
    write_json(state / "source/prepared.json", result)
    return result


def verify_lineage(state, identifier, dataset_id, policy):
    state = Path(state)
    if not isinstance(identifier, str) or not re.fullmatch("[0-9a-f]{64}", identifier):
        raise Rejected("invalid_lineage_id")
    public = read_json(state / "trusted-keys.json")["curator"]
    lineage = verify(
        read_json(safe_child(state, f"lineage/{identifier}.json")), "data-lineage", public
    )
    require_fields(
        lineage,
        (
            "schema_version",
            "dataset_id",
            "source_sha256",
            "policy_digest",
            "lock_sha256",
            "inputs",
            "classification",
            "curator",
        ),
    )
    if (
        digest(canonical(lineage)) != identifier
        or type(lineage["schema_version"]) is not int
        or lineage["schema_version"] != 1
        or lineage["dataset_id"] != dataset_id
        or lineage["policy_digest"] != digest(canonical(policy))
        or lineage["classification"] != "synthetic-only"
        or lineage["curator"] != "lab-curator"
        or not isinstance(lineage["inputs"], dict)
        or set(lineage["inputs"]) != set(INPUTS)
    ):
        raise Rejected("invalid_data_lineage_binding")
    for material in lineage["inputs"].values():
        require_fields(material, ("sha256", "bytes"))
        if (
            not isinstance(material["sha256"], str)
            or not re.fullmatch("[0-9a-f]{64}", material["sha256"])
            or type(material["bytes"]) is not int
            or material["bytes"] < 0
        ):
            raise Rejected("invalid_lineage_material")
    if not isinstance(lineage["lock_sha256"], str) or not re.fullmatch(
        "[0-9a-f]{64}", lineage["lock_sha256"]
    ):
        raise Rejected("invalid_lineage_lock")
    splits, manifest = verify_dataset(state, dataset_id, policy)
    rows = [record for name in ("train", "validation", "holdout") for record in splits[name]]
    if digest(canonical(rows)) != lineage["source_sha256"]:
        raise Rejected("lineage_dataset_content_mismatch")
    return lineage


def main():
    parser = argparse.ArgumentParser(description="Reproduce and attest the fixed synthetic source")
    parser.add_argument("action", choices=["repro", "verify", "authorize", "prepare"])
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--update-lock", action="store_true")
    parser.add_argument("--fresh", action="store_true")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        if arguments.action == "repro":
            result = reproduce(root, arguments.state, arguments.update_lock, arguments.fresh)
        elif arguments.action == "verify":
            content, lock_digest = verify_source(root, arguments.state)
            result = {"sha256": digest(content), "lock_sha256": lock_digest}
        elif arguments.action == "authorize":
            result = authorize_source(root, arguments.state)
        else:
            result = prepare_versioned(root, arguments.state)
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        print(f"Data source rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
