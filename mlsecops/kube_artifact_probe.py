import argparse
from pathlib import Path

from mlsecops import storage, storage_dataset, storage_pipeline
from mlsecops.contracts import Rejected, canonical, decode, digest, read_json, require_fields
from mlsecops.pipeline import validate_scores
from mlsecops.signing import encode64, verify


def inspect(request, client):
    require_fields(
        request,
        (
            "schema_version",
            "role",
            "candidate_reference",
            "evaluation_reference",
            "trust",
            "policy_digest",
        ),
    )
    if (
        type(request["schema_version"]) is not int
        or request["schema_version"] != 1
        or request["role"] not in {"publisher", "scorer"}
    ):
        raise Rejected("migration_artifact_request_invalid")
    require_fields(request["trust"], ("curator", "evaluator", "source_approval_digest"))
    policy = read_json(Path(__file__).resolve().parents[1] / "policies/local-cpu.json")
    if digest(canonical(policy)) != request["policy_digest"]:
        raise Rejected("migration_artifact_policy_mismatch")
    if read_json(client / "connection.json")["role"] != request["role"]:
        raise Rejected("migration_artifact_role_mismatch")
    for field in ("candidate_reference", "evaluation_reference"):
        storage.object_id(request[field])
    record, metadata, model = storage_pipeline.load_candidate(
        client, request["candidate_reference"], policy
    )
    selected = ("train", "validation") if request["role"] == "publisher" else ("holdout",)
    splits, _, lineage = storage_dataset.read_dataset(
        client,
        record["dataset_reference"],
        policy,
        request["trust"]["curator"],
        request["trust"]["source_approval_digest"],
        selected,
    )
    if (
        metadata["dataset_id"] != lineage["dataset_id"]
        or metadata["lineage_id"] != lineage["lineage_id"]
    ):
        raise Rejected("migration_artifact_dataset_binding_mismatch")
    result = {
        "schema_version": 1,
        "role": request["role"],
        "candidate_reference": request["candidate_reference"],
        "dataset_reference": record["dataset_reference"],
        "dataset_id": lineage["dataset_id"],
        "lineage_id": lineage["lineage_id"],
        "model_digest": digest(model),
        "image_id": metadata["image_id"],
        "rows": {name: len(rows) for name, rows in splits.items()},
    }
    if request["role"] == "publisher":
        scores = decode(storage.get(client, "candidates", record["scores_object"]))
        validate_scores(scores, len(splits["validation"]))
        if (
            digest(canonical(scores)) != metadata["validation_probability_digest"]
            or len(scores) < 1000
        ):
            raise Rejected("migration_artifact_saved_scores_invalid")
        result["golden"] = {
            "model": encode64(model),
            "features": [row["features"] for row in splits["validation"][:1000]],
            "expected_scores": scores[:1000],
        }
    else:
        envelope = decode(storage.get(client, "evaluations", request["evaluation_reference"]))
        evaluation = verify(envelope, "stored-evaluation", request["trust"]["evaluator"])
        if (
            evaluation.get("candidate_reference") != request["candidate_reference"]
            or evaluation.get("dataset_reference") != record["dataset_reference"]
            or evaluation.get("lineage_id") != lineage["lineage_id"]
        ):
            raise Rejected("migration_artifact_evaluation_binding_mismatch")
        result["evaluation"] = envelope
    return result


def main():
    parser = argparse.ArgumentParser(description="Read migrated artifacts using a single SQL role")
    parser.add_argument("--request", type=Path, required=True)
    arguments = parser.parse_args()
    print(canonical(inspect(read_json(arguments.request), Path("/client"))).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
