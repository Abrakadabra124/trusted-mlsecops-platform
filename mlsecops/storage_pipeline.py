import argparse
import re
import sys
from functools import partial
from pathlib import Path

from mlsecops import storage, storage_dataset
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
from mlsecops.sandbox import run_worker
from mlsecops.signing import sign, verify


def train(client, reference, policy, image, trust, executor=run_worker):
    splits, manifest, statement = storage_dataset.read_dataset(
        client,
        reference,
        policy,
        trust["curator"],
        trust["source_approval_digest"],
        ("train", "validation"),
    )
    metadata, model, scores = train_verified_dataset(
        statement["dataset_id"], statement["lineage_id"], splits, manifest, policy, image, executor
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


def load_candidate(client, reference, policy):
    record = decode(storage.get(client, "candidates", reference))
    require_fields(
        record,
        ("schema_version", "dataset_reference", "model_object", "metadata_object", "scores_object"),
    )
    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
        raise Rejected("stored_candidate_schema_invalid")
    for name, value in record.items():
        if name != "schema_version":
            storage.object_id(value)
    metadata = decode(storage.get(client, "candidates", record["metadata_object"]))
    model = storage.get(client, "candidates", record["model_object"])
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


def evaluate(client, reference, policy, image, trust, signing_key, executor=run_worker):
    record, metadata, model = load_candidate(client, reference, policy)
    splits, manifest, statement = storage_dataset.read_dataset(
        client,
        record["dataset_reference"],
        policy,
        trust["curator"],
        trust["source_approval_digest"],
        ("holdout",),
    )
    if (
        metadata.get("dataset_id") != statement["dataset_id"]
        or metadata.get("lineage_id") != statement["lineage_id"]
    ):
        raise Rejected("stored_candidate_dataset_binding_mismatch")
    report = evaluate_verified_candidate(
        metadata, model, splits["holdout"], manifest, policy, image, executor
    )
    bound = {
        "schema_version": 1,
        "candidate_reference": reference,
        "dataset_reference": record["dataset_reference"],
        "lineage_id": statement["lineage_id"],
        "report": report,
    }
    envelope = sign(bound, "stored-evaluation", signing_key)
    if verify(envelope, "stored-evaluation", trust["evaluator"]) != bound:
        raise Rejected("stored_evaluation_signer_mismatch")
    result = storage.put(client, "evaluations", canonical(envelope))
    persisted = decode(storage.get(client, "evaluations", result))
    if verify(persisted, "stored-evaluation", trust["evaluator"]) != bound:
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
            "Host orchestrator retains administrator access; independent controller identities are pending",
            "Synthetic data and known generator do not establish business utility or secret labels",
            "MLflow, query budget, full M04/M20, promotion and serving remain pending; M03 runs separately",
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
