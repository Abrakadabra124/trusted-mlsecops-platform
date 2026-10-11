import re
from datetime import datetime

from mlsecops import asset_graph, storage, storage_dataset, storage_pipeline
from mlsecops.contracts import Rejected, canonical, digest, require_fields

OWNER_KINDS = ("dataset", "run", "model", "runtime", "policy")


def reconcile(
    read,
    *,
    candidate_reference,
    evaluation_reference,
    policy,
    trust,
    expected,
    owners,
    known_owners,
):
    require_fields(expected, ("image_id", "source_fingerprint", "source_revision"))
    require_fields(owners, OWNER_KINDS)
    require_fields(trust, ("curator", "evaluator", "source_approval_digest"))
    storage.object_id(candidate_reference)
    storage.object_id(evaluation_reference)
    storage.object_id(expected["source_fingerprint"])
    storage.object_id(trust["source_approval_digest"])
    for key, pattern in (
        ("image_id", r"sha256:[a-f0-9]{64}"),
        ("source_revision", r"[a-f0-9]{40}"),
    ):
        if not isinstance(expected[key], str) or re.fullmatch(pattern, expected[key]) is None:
            raise Rejected("inventory_expected_build_invalid")
    if trust["curator"] == trust["evaluator"]:
        raise Rejected("inventory_signer_roles_not_separated")
    record, metadata, _ = storage_pipeline.load_candidate(
        "review", candidate_reference, policy, reader=read
    )
    manifest, statement = storage_dataset.read_manifest(
        "metadata",
        record["dataset_reference"],
        policy,
        trust["curator"],
        trust["source_approval_digest"],
        reader=read,
    )
    if any(metadata[name] != statement[name] for name in ("dataset_id", "lineage_id")):
        raise Rejected("inventory_candidate_dataset_binding")
    if metadata["materials"] != manifest["objects"]:
        raise Rejected("inventory_candidate_materials_binding")
    if any(metadata[name] != value for name, value in expected.items()):
        raise Rejected("inventory_candidate_build_binding")
    if (
        not isinstance(metadata["execution"], dict)
        or metadata["execution"].get("image_id") != expected["image_id"]
    ):
        raise Rejected("inventory_candidate_execution_binding")
    evaluation = storage_pipeline.read_evaluation(
        "review", evaluation_reference, candidate_reference, policy, trust, reader=read
    )
    report = evaluation["report"]
    holdout = manifest["objects"]["holdout.json"]
    if report["holdout_digest"] != holdout["sha256"] or report["rows"] != holdout["rows"]:
        raise Rejected("inventory_evaluation_holdout_binding")
    try:
        trained_at = datetime.fromisoformat(metadata["created_at"])
        evaluated_at = datetime.fromisoformat(report["created_at"])
        if trained_at.tzinfo is None or trained_at > evaluated_at:
            raise ValueError
    except (TypeError, ValueError):
        raise Rejected("inventory_candidate_time_binding") from None
    materials = {
        "dataset": metadata["dataset_id"],
        "runtime": expected["image_id"].removeprefix("sha256:"),
        "policy": digest(canonical(policy)),
        "run": record["metadata_object"],
        "model": metadata["model_digest"],
    }
    dependencies = {
        "dataset": (),
        "runtime": (),
        "policy": (),
        "run": ("dataset", "runtime", "policy"),
        "model": ("run",),
    }
    identifiers = {kind: f"{kind}-{material}" for kind, material in materials.items()}
    identifiers["model"] = f"model-{candidate_reference}"
    graph = {
        "schema_version": 1,
        "assets": [
            {
                "asset_id": identifiers[kind],
                "kind": kind,
                "sha256": material,
                "owner": owners[kind],
                "environment": policy["environment"],
                "dependencies": [
                    {"asset_id": identifiers[parent], "sha256": materials[parent]}
                    for parent in dependencies[kind]
                ],
            }
            for kind, material in materials.items()
        ],
    }
    snapshot = {
        "schema_version": 1,
        "environment": policy["environment"],
        "graph_sha256": digest(canonical(graph)),
        "deployments": [],
    }
    return {
        "schema_version": 1,
        "scope": "verified-candidate-lineage-not-deployment-inventory",
        "full_M19": "inconclusive",
        "release_ready": False,
        "candidate_state": metadata["status"],
        "quality_component": report["quality_component"],
        "graph": graph,
        "assessment": asset_graph.assess(graph, known_owners, policy["environment"], snapshot, []),
        "bindings": {
            "candidate_reference": candidate_reference,
            "evaluation_reference": evaluation_reference,
            "dataset_reference": record["dataset_reference"],
            "lineage_id": statement["lineage_id"],
            "lineage_object": statement["lineage_object"],
            "source_approval_digest": trust["source_approval_digest"],
            "holdout_reservation": evaluation["holdout_access"]["reservation"],
            **expected,
        },
    }


def collect(metadata_client, review_client, *, material_sink=None, **context):
    clients = {"metadata": metadata_client, "review": review_client}
    allowed = {"metadata": {"manifests", "lineage"}, "review": {"candidates", "evaluations"}}
    for client, role in ((metadata_client, "ml_publisher"), (review_client, "ml_promoter")):
        if storage.connection_parameters(client)["user"] != role:
            raise Rejected("inventory_reader_identity_mismatch")

    def read(role, table, reference):
        if role not in allowed or table not in allowed[role]:
            raise Rejected("inventory_reader_scope")
        content = storage.get(clients[role], table, reference)
        if material_sink is not None:
            material_sink(table, reference, content)
        return content

    return reconcile(read, **context)
