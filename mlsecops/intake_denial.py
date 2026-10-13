import argparse
import sys
from pathlib import Path

from mlsecops import artifact_intake, evaluation_quality, holdout_budget, storage
from mlsecops.contracts import Rejected, canonical, decode, digest, read_json, require_fields
from mlsecops.signing import sign, verify

MAX_BYTES = 65536


class RecordedDenial(Rejected):
    def __init__(self, reference, status):
        storage.object_id(reference)
        if status not in ("fail", "inconclusive"):
            raise Rejected("intake_denial_status_invalid")
        super().__init__(f"model_intake_{status}:denial={reference}")
        self.reference = reference
        self.status = status


def _context(client, candidate, policy):
    from mlsecops.storage_pipeline import load_candidate

    evaluation_quality.freeze(policy)
    return load_candidate(client, candidate, policy)


def _payload(candidate, record, metadata, policy, access, report):
    return {
        "schema_version": 1,
        "candidate_reference": candidate,
        "dataset_reference": record["dataset_reference"],
        "lineage_id": metadata["lineage_id"],
        "run_id": metadata["run_id"],
        "policy_digest": digest(canonical(policy)),
        "holdout_access": access,
        "intake": report,
        "decision": "deny-evaluation",
        "release_ready": False,
    }


def _validate(client, payload, candidate, record, metadata, model, policy):
    require_fields(
        payload,
        (
            "schema_version",
            "candidate_reference",
            "dataset_reference",
            "lineage_id",
            "run_id",
            "policy_digest",
            "holdout_access",
            "intake",
            "decision",
            "release_ready",
        ),
    )
    expected = _payload(
        candidate, record, metadata, policy, payload["holdout_access"], payload["intake"]
    )
    if canonical(payload) != canonical(expected):
        raise Rejected("intake_denial_subject_mismatch")
    artifact_intake.validate_failure(payload["intake"], model, metadata["image_id"])
    access = payload["holdout_access"]
    require_fields(access, ("holdout_digest", "slot", "reservation", "policy_digest"))
    reserved = holdout_budget.reservation(access["holdout_digest"], access["slot"])
    try:
        holdout = metadata["materials"]["holdout.json"]["sha256"]
    except (KeyError, TypeError):
        raise Rejected("intake_denial_holdout_missing") from None
    storage.object_id(holdout)
    if (
        access["holdout_digest"] != holdout
        or access["policy_digest"] != digest(canonical(holdout_budget.policy()))
        or access["reservation"] != digest(reserved)
        or storage.get(client, "evaluations", access["reservation"]) != reserved
    ):
        raise Rejected("intake_denial_reservation_mismatch")
    return payload


def read(client, reference, candidate, policy, trust):
    record, metadata, model = _context(client, candidate, policy)
    content = storage.get(client, "evaluations", reference)
    if len(content) > MAX_BYTES or digest(content) != reference:
        raise Rejected("intake_denial_envelope_invalid")
    payload = verify(decode(content, MAX_BYTES), "intake-denial", trust["evaluator"])
    return _validate(client, payload, candidate, record, metadata, model, policy)


def publish(client, candidate, policy, trust, signing_key, access, report):
    record, metadata, model = _context(client, candidate, policy)
    payload = _payload(candidate, record, metadata, policy, access, report)
    _validate(client, payload, candidate, record, metadata, model, policy)
    envelope = sign(payload, "intake-denial", signing_key)
    if verify(envelope, "intake-denial", trust["evaluator"]) != payload:
        raise Rejected("intake_denial_signer_mismatch")
    content = canonical(envelope)
    if len(content) > MAX_BYTES:
        raise Rejected("intake_denial_envelope_limit")
    reference = storage.put(client, "evaluations", content)
    if reference != digest(content) or read(client, reference, candidate, policy, trust) != payload:
        raise Rejected("intake_denial_persistence_mismatch")
    return reference


def main():
    parser = argparse.ArgumentParser(description="Read a signed denial, never authorize a release")
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--denial", required=True)
    parser.add_argument("--trust", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        policy = read_json(Path(__file__).resolve().parents[1] / "policies/local-cpu.json")
        result = read(
            arguments.client,
            arguments.denial,
            arguments.candidate,
            policy,
            read_json(arguments.trust),
        )
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError):
        print("Intake denial could not be verified", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
