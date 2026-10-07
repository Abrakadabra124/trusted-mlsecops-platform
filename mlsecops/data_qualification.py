import argparse
import copy
import shutil
import sys
import tempfile
from pathlib import Path

from mlsecops.bootstrap import initialize
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.data_source import (
    INPUTS,
    SOURCE,
    authorize_source,
    prepare_versioned,
    reproduce,
    validate_lock,
    verify_lineage,
    verify_source,
)
from mlsecops.datasets import source_approval, verify_dataset
from mlsecops.intake import approve, submit
from mlsecops.signing import sign


def qualify(root, state):
    root, state = Path(root), Path(state)
    initialize(root, state)
    policy = read_json(root / "policies/local-cpu.json")
    cases = []

    def confirmed(identifier, condition):
        if not condition:
            raise Rejected(f"data_qualification_failed:{identifier}")
        cases.append({"id": identifier, "status": "pass", "expected": True, "actual": True})

    def rejected(identifier, operation):
        try:
            operation()
        except Rejected as error:
            cases.append(
                {"id": identifier, "status": "pass", "expected": "reject", "actual": str(error)}
            )
        else:
            raise Rejected(f"data_qualification_bypass:{identifier}")

    with tempfile.TemporaryDirectory(
        prefix="data-qualification-", dir=state / "evidence"
    ) as temporary:
        workspace = Path(temporary)
        initialize(root, workspace)
        first = reproduce(root, workspace, fresh=True)
        content = bounded_read(workspace / SOURCE)
        second = reproduce(root, workspace, fresh=True)
        confirmed(
            "fresh-source-byte-identical",
            first["sha256"] == second["sha256"] and content == bounded_read(workspace / SOURCE),
        )
        source_path = safe_child(workspace, SOURCE)
        source_path.unlink()
        restored = reproduce(root, workspace)
        confirmed(
            "missing-source-restored-from-verified-cache",
            restored["mode"] == "verified-cache" and bounded_read(source_path) == content,
        )
        cache = safe_child(workspace, f"source-cache/{first['sha256']}.json")
        atomic_write(cache, b"tampered")
        rejected("cache-tamper", lambda: reproduce(root, workspace))
        atomic_write(cache, content)
        atomic_write(source_path, b"tampered")
        rejected("source-tamper", lambda: verify_source(root, workspace))
        atomic_write(source_path, content)
        authorize_source(root, workspace)
        fixture = workspace / "input.json"
        records = decode(content)
        for name in (
            "missing-field",
            "extra-field",
            "boolean-id",
            "boolean-label",
            "boolean-feature",
            "duplicate-id",
            "out-of-range",
            "wrong-count",
            "nonfinite",
            "invalid-json",
            "unexpected-root",
        ):
            modified = copy.deepcopy(records)
            if name == "missing-field":
                modified[0].pop("label")
            elif name == "extra-field":
                modified[0]["untrusted"] = "not-permitted"
            elif name == "boolean-id":
                modified[0]["entity_id"] = True
            elif name == "boolean-label":
                modified[0]["label"] = True
            elif name == "boolean-feature":
                modified[0]["features"][0] = True
            elif name == "duplicate-id":
                modified[1]["entity_id"] = modified[0]["entity_id"]
            elif name == "out-of-range":
                modified[0]["features"][0] = 1.01
            elif name == "wrong-count":
                modified.pop()
            elif name == "unexpected-root":
                modified = {"records": modified}
            payload = canonical(modified)
            if name == "nonfinite":
                payload = payload.replace(b'"label":', b'"label":NaN,"discard":', 1)
            elif name == "invalid-json":
                payload = b"[broken"
            atomic_write(fixture, payload)
            result = submit(workspace, fixture, policy["source"], "dataset", policy)
            confirmed(
                f"intake-{name}-reject-before-approved",
                result["status"] == "rejected"
                and result["rows"] == 0
                and not any((workspace / "approved").iterdir()),
            )
            rejected(
                f"curator-refuses-{name}", lambda: approve(workspace, result["intake_id"], policy)
            )
        atomic_write(fixture, content)
        for name, source, kind in (
            ("unknown-source", "unapproved-source", "dataset"),
            ("forged-feedback", policy["source"], "feedback"),
        ):
            result = submit(workspace, fixture, source, kind, policy)
            confirmed(
                name, result["status"] == "rejected" and not any((workspace / "approved").iterdir())
            )
        mutated = copy.deepcopy(records)
        mutated[0]["label"] = 1 - mutated[0]["label"]
        atomic_write(fixture, canonical(mutated))
        result = submit(workspace, fixture, policy["source"], "dataset", policy)
        confirmed(
            "same-source-name-without-signed-snapshot",
            result["status"] == "rejected" and not any((workspace / "approved").iterdir()),
        )
        atomic_write(fixture, content)
        permission_path = workspace / "source-approval.json"
        original_permission = bounded_read(permission_path)
        permission = source_approval(workspace, policy)
        for name, changed, key in (
            (
                "expired-source",
                {**permission, "expires_at": "2000-01-01T00:00:00+00:00"},
                "curator",
            ),
            ("forged-source", permission, "approver"),
            ("source-schema-boolean", {**permission, "schema_version": True}, "curator"),
        ):
            write_json(permission_path, sign(changed, "source", workspace / f"keys/{key}.pem"))
            result = submit(workspace, fixture, policy["source"], "dataset", policy)
            confirmed(
                name, result["status"] == "rejected" and not any((workspace / "approved").iterdir())
            )
        atomic_write(permission_path, original_permission)
        valid = submit(workspace, fixture, policy["source"], "dataset", policy)
        confirmed(
            "intake-alone-cannot-publish",
            valid["status"] == "validated-not-approved"
            and not any((workspace / "approved").iterdir()),
        )
        quarantined = safe_child(workspace, f"quarantine/intake-{valid['intake_id']}/records.json")
        atomic_write(quarantined, canonical(mutated))
        rejected(
            "mutation-between-intake-and-curator",
            lambda: approve(workspace, valid["intake_id"], policy),
        )
        confirmed(
            "post-validation-mutation-zero-approved", not any((workspace / "approved").iterdir())
        )
        atomic_write(quarantined, content)
        receipt = approve(workspace, valid["intake_id"], policy)
        dataset_id = receipt["dataset_id"]
        approved_manifest = workspace / "approved" / dataset_id / "manifest.json"
        before = bounded_read(approved_manifest)
        confirmed(
            "curator-idempotent",
            approve(workspace, valid["intake_id"], policy) == receipt
            and bounded_read(approved_manifest) == before,
        )
        splits, manifest = verify_dataset(workspace, dataset_id, policy)
        confirmed(
            "approved-disjoint-splits",
            [len(splits[name]) for name in ("train", "validation", "holdout")]
            == policy["split_counts"],
        )
        prepared = prepare_versioned(root, workspace)
        confirmed(
            "lineage-roundtrip",
            verify_lineage(workspace, prepared["lineage_id"], dataset_id, policy)["source_sha256"]
            == digest(content),
        )
        confirmed("lineage-repeat-stable", prepare_versioned(root, workspace) == prepared)
        rejected(
            "lineage-wrong-dataset",
            lambda: verify_lineage(workspace, prepared["lineage_id"], "0" * 64, policy),
        )
        rejected(
            "lineage-traversal", lambda: verify_lineage(workspace, "../outside", dataset_id, policy)
        )
        approved_data = workspace / "approved" / dataset_id / "train.json"
        previous = bounded_read(approved_data)
        atomic_write(approved_data, previous[:-1] + b"x")
        rejected("approved-byte-tamper", lambda: verify_dataset(workspace, dataset_id, policy))
        atomic_write(approved_data, previous)
        shadow = workspace / "isolated-source-fixture"
        shadow.mkdir()
        for name in (*INPUTS, "data.lock"):
            destination = safe_child(shadow, name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, destination)
        frozen = bounded_read(shadow / "data.lock")
        atomic_write(shadow / INPUTS[0], b"changed-source")
        rejected("changed-input-cannot-hit-cache", lambda: validate_lock(shadow))
        confirmed(
            "failed-repro-does-not-rewrite-lock", bounded_read(shadow / "data.lock") == frozen
        )
        source_sha256 = digest(content)
    report = {
        "schema_version": 1,
        "scope": "data-intake-M02-and-lineage-components",
        "status": "pass",
        "observed_at": now(),
        "cases": cases,
        "source_sha256": source_sha256,
        "rows": policy["rows"],
        "policy_digest": digest(canonical(policy)),
        "source_lock_digest": digest(bounded_read(root / "data.lock")),
        "limitations": [
            "Synthetic source only",
            "Storage ACL M03/M04 not covered",
            "Host curator trusted",
            "Not semantic poisoning detection",
            "Not full R1 acceptance",
        ],
    }
    write_json(state / "evidence/data-qualification.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description="Qualify source and quarantine boundaries")
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    arguments = parser.parse_args()
    try:
        result = qualify(Path(__file__).resolve().parents[1], arguments.state)
        print(
            canonical(
                {
                    "status": result["status"],
                    "cases": len(result["cases"]),
                    "scope": result["scope"],
                }
            ).decode()
        )
        return 0
    except (Rejected, OSError) as error:
        print(f"Data qualification rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
