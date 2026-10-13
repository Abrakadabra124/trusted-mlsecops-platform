import argparse
import re
import sys
from datetime import datetime
from functools import partial
from pathlib import Path

from mlsecops import artifact_intake, evaluation_quality, holdout_budget, storage, storage_dataset
from mlsecops.bootstrap import initialize
from mlsecops.contracts import (
    Rejected,
    canonical,
    decode,
    digest,
    read_json,
    require_fields,
    write_json,
)
from mlsecops.data_source import prepare_versioned, reproduce
from mlsecops.datasets import source_approval
from mlsecops.pipeline import evaluate_verified_candidate, train_verified_dataset
from mlsecops.prediction_protocol import validate_scan
from mlsecops.sandbox import run_worker
from mlsecops.signing import sign, verify


def train(client, reference, policy, image, trust, executor=run_worker, provenance=None):
    splits, manifest, statement = storage_dataset.read_dataset(
        client,
        reference,
        policy,
        trust["curator"],
        trust["source_approval_digest"],
        ("train", "validation"),
    )
    metadata, model, scores = train_verified_dataset(
        statement["dataset_id"],
        statement["lineage_id"],
        splits,
        manifest,
        policy,
        image,
        executor,
        provenance,
    )
    record = {
        "schema_version": 1,
        "dataset_reference": reference,
        "model_object": storage.put(client, "candidates", model),
        "metadata_object": storage.put(client, "candidates", canonical(metadata)),
        "scores_object": storage.put(client, "candidates", canonical(scores)),
    }
    candidate = storage.put(client, "candidates", canonical(record))
    load_candidate(client, candidate, policy)
    return {"candidate_reference": candidate, "metadata": metadata}


def load_candidate(client, reference, policy, *, reader=None):
    read = storage.get if reader is None else reader
    record = decode(read(client, "candidates", reference))
    require_fields(
        record,
        ("schema_version", "dataset_reference", "model_object", "metadata_object", "scores_object"),
    )
    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
        raise Rejected("stored_candidate_schema_invalid")
    for name, value in record.items():
        if name != "schema_version":
            storage.object_id(value)
    metadata = decode(read(client, "candidates", record["metadata_object"]))
    model = read(client, "candidates", record["model_object"])
    require_fields(
        metadata,
        (
            "schema_version",
            "run_id",
            "created_at",
            "dataset_id",
            "lineage_id",
            "model_digest",
            "policy_digest",
            "input_digest",
            "image_id",
            "execution",
            "versions",
            "validation_parity_max_error",
            "validation_probability_digest",
            "materials",
            "status",
            "source_fingerprint",
            "source_revision",
        ),
    )
    if (
        type(metadata["schema_version"]) is not int
        or metadata["schema_version"] != 1
        or not isinstance(metadata["run_id"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", metadata["run_id"])
        or metadata.get("model_digest") != digest(model)
        or metadata.get("policy_digest") != digest(canonical(policy))
        or not 0 < len(model) <= policy["model_limit_bytes"]
        or metadata.get("status") != "unapproved-candidate"
        or type(metadata["validation_parity_max_error"]) not in (int, float)
        or not 0 <= metadata["validation_parity_max_error"] <= policy["parity_tolerance"]
        or not isinstance(metadata["image_id"], str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", metadata["image_id"])
    ):
        raise Rejected("stored_candidate_material_mismatch")
    for name in (
        "dataset_id",
        "lineage_id",
        "input_digest",
        "validation_probability_digest",
        "source_fingerprint",
    ):
        storage.object_id(metadata[name])
    return record, metadata, model


def read_evaluation(
    client, evaluation_reference, candidate_reference, policy, trust, *, reader=None
):
    read = storage.get if reader is None else reader
    evaluation_quality.freeze(policy)
    record, metadata, model = load_candidate(client, candidate_reference, policy, reader=read)
    bound = verify(
        decode(read(client, "evaluations", evaluation_reference)),
        "stored-evaluation",
        trust["evaluator"],
    )
    require_fields(
        bound,
        (
            "schema_version",
            "candidate_reference",
            "dataset_reference",
            "lineage_id",
            "holdout_access",
            "report",
        ),
    )
    if (
        type(bound["schema_version"]) is not int
        or bound["schema_version"] != 1
        or bound["candidate_reference"] != candidate_reference
        or bound["dataset_reference"] != record["dataset_reference"]
        or bound["lineage_id"] != metadata["lineage_id"]
    ):
        raise Rejected("stored_evaluation_subject_mismatch")
    report = bound["report"]
    require_fields(
        report,
        (
            "schema_version",
            "run_id",
            "created_at",
            "model_digest",
            "dataset_id",
            "policy_digest",
            "image_id",
            "holdout_digest",
            *evaluation_quality.SUMMARY_FIELDS,
            "validation_parity_max_error",
            "release_status",
            "scan",
            "intake",
            "prediction_protocol",
            "prediction_execution",
            "limitations",
        ),
    )
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] != 2
        or any(
            report[name] != metadata[name]
            for name in ("run_id", "model_digest", "dataset_id", "policy_digest", "image_id")
        )
        or report["policy_digest"] != digest(canonical(policy))
    ):
        raise Rejected("stored_evaluation_subject_mismatch")
    if (
        not evaluation_quality.number(
            report["validation_parity_max_error"], 0, policy["parity_tolerance"]
        )
        or report["validation_parity_max_error"] != metadata["validation_parity_max_error"]
        or report["release_status"] != "unapproved"
    ):
        raise Rejected("stored_evaluation_state_invalid")
    try:
        if datetime.fromisoformat(report["created_at"]).tzinfo is None:
            raise ValueError
    except (ValueError, TypeError):
        raise Rejected("stored_evaluation_time_invalid") from None
    evaluation_quality.validate_summary(
        {name: report[name] for name in evaluation_quality.SUMMARY_FIELDS}
    )
    validate_scan(report["scan"])
    artifact_intake.validate_receipt(report["intake"], model, metadata["image_id"])
    proof = report["prediction_protocol"]
    require_fields(
        proof,
        ("schema_version", "batch_id", "model_digest", "request_digest", "response_digest", "rows"),
    )
    for name in ("model_digest", "request_digest", "response_digest"):
        storage.object_id(proof[name])
    if (
        type(proof["schema_version"]) is not int
        or proof["schema_version"] != 2
        or not isinstance(proof["batch_id"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", proof["batch_id"])
        or type(proof["rows"]) is not int
        or proof["rows"] != report["rows"]
        or proof["model_digest"] != metadata["model_digest"]
    ):
        raise Rejected("stored_evaluation_protocol_mismatch")
    execution = report["prediction_execution"]
    if (
        not isinstance(execution, dict)
        or execution.get("image_id") != metadata["image_id"]
        or ("input_digest" in execution and execution["input_digest"] != proof["request_digest"])
    ):
        raise Rejected("stored_evaluation_execution_mismatch")
    access = bound["holdout_access"]
    require_fields(access, ("holdout_digest", "slot", "reservation", "policy_digest"))
    reserved = holdout_budget.reservation(report["holdout_digest"], access["slot"])
    if (
        access["holdout_digest"] != report["holdout_digest"]
        or access["reservation"] != digest(reserved)
        or access["policy_digest"] != digest(canonical(holdout_budget.policy()))
    ):
        raise Rejected("stored_evaluation_reservation_mismatch")
    if read(client, "evaluations", access["reservation"]) != reserved:
        raise Rejected("stored_evaluation_reservation_missing")
    return bound


def evaluate(client, reference, policy, image, trust, signing_key, executor=run_worker):
    evaluation_quality.freeze(policy)
    record, metadata, model = load_candidate(client, reference, policy)
    manifest, statement = storage_dataset.read_manifest(
        client,
        record["dataset_reference"],
        policy,
        trust["curator"],
        trust["source_approval_digest"],
    )
    if (
        metadata.get("dataset_id") != statement["dataset_id"]
        or metadata.get("lineage_id") != statement["lineage_id"]
    ):
        raise Rejected("stored_candidate_dataset_binding_mismatch")
    access = holdout_budget.reserve(client, manifest["objects"]["holdout.json"]["sha256"])
    splits, manifest, statement = storage_dataset.read_dataset(
        client,
        record["dataset_reference"],
        policy,
        trust["curator"],
        trust["source_approval_digest"],
        ("holdout",),
    )
    report = evaluate_verified_candidate(
        metadata, model, splits["holdout"], manifest, policy, image, executor
    )
    bound = {
        "schema_version": 1,
        "candidate_reference": reference,
        "dataset_reference": record["dataset_reference"],
        "lineage_id": statement["lineage_id"],
        "holdout_access": access,
        "report": report,
    }
    envelope = sign(bound, "stored-evaluation", signing_key)
    if verify(envelope, "stored-evaluation", trust["evaluator"]) != bound:
        raise Rejected("stored_evaluation_signer_mismatch")
    result = storage.put(client, "evaluations", canonical(envelope))
    if read_evaluation(client, result, reference, policy, trust) != bound:
        raise Rejected("stored_evaluation_persistence_mismatch")
    return {"evaluation_reference": result, "evaluation": bound}


def demo(root, state, image, executor=run_worker):
    root, state = Path(root), Path(state)
    initialize(root, state)
    policy = read_json(root / "policies/local-cpu.json")
    reproduce(root, state)
    source = prepare_versioned(root, state)
    dataset = storage_dataset.publish(state, source["dataset_id"], source["lineage_id"], policy)
    public = read_json(state / "trusted-keys.json")
    trust = {
        "curator": public["curator"],
        "evaluator": public["evaluator"],
        "source_approval_digest": digest(canonical(source_approval(state, policy))),
    }
    write_json(state / "storage-trust.json", trust)
    candidate = train(
        state / "storage-clients/publisher",
        dataset["dataset_reference"],
        policy,
        image,
        trust,
        executor,
    )
    evaluation = evaluate(
        state / "storage-clients/scorer",
        candidate["candidate_reference"],
        policy,
        image,
        trust,
        state / "keys/evaluator.pem",
        executor,
    )
    result = {
        "dataset": dataset,
        "candidate": candidate,
        **evaluation,
        "status": "role-restricted-storage-preview-not-R1-accepted",
        "limitations": [
            "Host demo orchestrator retains administrator access; scoped controllers use the same scorer path",
            "Synthetic data and known generator do not establish business utility or secret labels",
            "Persistent query budget is a component, not full M07; promotion and serving remain pending",
        ],
    }
    write_json(state / "storage-demo.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Run training/evaluation with role-restricted SQL storage"
    )
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    parser.add_argument("--backend", choices=["docker", "kubernetes"], default="docker")
    arguments = parser.parse_args()
    executor = run_worker
    if arguments.backend == "kubernetes":
        from mlsecops.kube_worker import run_worker as kube_worker

        executor = partial(kube_worker, arguments.state)
    try:
        print(
            canonical(
                demo(
                    Path(__file__).resolve().parents[1], arguments.state, arguments.image, executor
                )
            ).decode()
        )
        return 0
    except (Rejected, OSError) as error:
        print(f"Storage pipeline rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
