import argparse
import re
import sys
import uuid
from pathlib import Path

from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.datasets import publish_records, source_approval, validate_rows, verify_dataset
from mlsecops.signing import sign, verify


def validate_submission(content, source, kind, policy, state):
    if kind != "dataset":
        raise Rejected("feedback_requires_separate_verified_label_process")
    approval = source_approval(state, policy)
    if source != approval["source"]:
        raise Rejected("unapproved_input_source")
    rows = decode(content)
    validate_rows(rows, policy["rows"])
    public = read_json(Path(state) / "trusted-keys.json")["curator"]
    attestation = verify(
        read_json(safe_child(state, f"source-attestations/{digest(content)}.json")),
        "source-snapshot",
        public,
    )
    expected = snapshot_statement(content, policy, approval)
    if canonical(attestation) != canonical(expected):
        raise Rejected("source_snapshot_mismatch")
    return rows, approval


def snapshot_statement(content, policy, approval):
    return {
        "schema_version": 1,
        "source": policy["source"],
        "kind": "dataset",
        "bytes": len(content),
        "sha256": digest(content),
        "policy_digest": digest(canonical(policy)),
        "source_approval_digest": digest(canonical(approval)),
    }


def submit(state, path, source, kind, policy):
    state = Path(state)
    if not isinstance(source, str) or len(source) > 128 or not isinstance(kind, str):
        raise Rejected("invalid_intake_parameters")
    identifier = uuid.uuid4().hex
    location = safe_child(state, f"quarantine/intake-{identifier}")
    location.mkdir(parents=True, exist_ok=False)
    report = {
        "schema_version": 1,
        "intake_id": identifier,
        "source": source,
        "kind": kind,
        "created_at": now(),
        "policy_digest": digest(canonical(policy)),
        "status": "rejected",
        "rows": 0,
        "bytes": 0,
        "sha256": None,
        "source_approval_digest": None,
        "reason": None,
    }
    try:
        content = bounded_read(path)
        report.update(bytes=len(content), sha256=digest(content))
        atomic_write(location / "records.json", content)
        rows, approval = validate_submission(content, source, kind, policy, state)
        report.update(
            status="validated-not-approved",
            rows=len(rows),
            source_approval_digest=digest(canonical(approval)),
        )
    except Rejected as error:
        report["reason"] = str(error)
    write_json(location / "intake.json", report)
    return report


def approve(state, identifier, policy):
    state = Path(state)
    if not isinstance(identifier, str) or not re.fullmatch("[0-9a-f]{32}", identifier):
        raise Rejected("invalid_intake_id")
    location = safe_child(state, f"quarantine/intake-{identifier}")
    report = read_json(location / "intake.json")
    require_fields(
        report,
        (
            "schema_version",
            "intake_id",
            "source",
            "kind",
            "created_at",
            "policy_digest",
            "status",
            "rows",
            "bytes",
            "sha256",
            "source_approval_digest",
            "reason",
        ),
    )
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] != 1
        or report["intake_id"] != identifier
        or report["status"] != "validated-not-approved"
        or report["policy_digest"] != digest(canonical(policy))
        or report["reason"] is not None
        or type(report["rows"]) is not int
        or report["rows"] != policy["rows"]
        or type(report["bytes"]) is not int
    ):
        raise Rejected("intake_not_eligible")
    content = bounded_read(safe_child(location, "records.json"))
    if digest(content) != report["sha256"] or len(content) != report["bytes"]:
        raise Rejected("intake_content_changed")
    rows, approval = validate_submission(content, report["source"], report["kind"], policy, state)
    if digest(canonical(approval)) != report["source_approval_digest"]:
        raise Rejected("intake_source_approval_changed")
    dataset_id = publish_records(state, policy, rows)
    receipt = {
        "schema_version": 1,
        "intake_id": identifier,
        "intake_digest": digest(canonical(report)),
        "dataset_id": dataset_id,
        "source_sha256": digest(content),
        "policy_digest": digest(canonical(policy)),
        "curator": "lab-curator",
    }
    target = safe_child(state, f"intake-approvals/{identifier}.json")
    if target.exists():
        public = read_json(state / "trusted-keys.json")["curator"]
        if canonical(verify(read_json(target), "intake-approval", public)) != canonical(receipt):
            raise Rejected("intake_receipt_conflict")
    else:
        write_json(target, sign(receipt, "intake-approval", state / "keys/curator.pem"))
    verify_dataset(state, dataset_id, policy)
    return receipt


def main():
    parser = argparse.ArgumentParser(description="Quarantine input, then explicit curator approval")
    parser.add_argument("action", choices=["submit", "approve"])
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--file", type=Path)
    parser.add_argument("--source")
    parser.add_argument("--kind", choices=["dataset", "feedback"], default="dataset")
    parser.add_argument("--intake")
    arguments = parser.parse_args()
    policy = read_json(Path(__file__).resolve().parents[1] / "policies/local-cpu.json")
    try:
        if arguments.action == "submit":
            if arguments.file is None:
                raise Rejected("input_file_required")
            result = submit(
                arguments.state, arguments.file, arguments.source, arguments.kind, policy
            )
        else:
            result = approve(arguments.state, arguments.intake, policy)
        print(canonical(result).decode())
        return 1 if result.get("status") == "rejected" else 0
    except (Rejected, OSError) as error:
        print(f"Intake rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
