from pathlib import Path

from mlsecops import storage
from mlsecops.contracts import (
    Rejected,
    canonical,
    decode,
    digest,
    read_json,
    require_fields,
    safe_child,
)
from mlsecops.data_source import verify_lineage, verify_lineage_statement
from mlsecops.datasets import source_approval, validate_rows, verify_dataset, verify_manifest
from mlsecops.signing import sign, verify

SPLITS = ("train", "validation", "holdout")


def publish(state, dataset_id, lineage_id, policy):
    state = Path(state)
    splits, manifest = verify_dataset(state, dataset_id, policy)
    lineage = verify_lineage(state, lineage_id, dataset_id, policy)
    approval = source_approval(state, policy)
    source = canonical([row for name in SPLITS for row in splits[name]])
    ingestor, curator = state / "storage-clients/ingestor", state / "storage-clients/curator"
    source_id = storage.put(ingestor, "quarantine", source)
    received = storage.get(curator, "quarantine", source_id)
    if digest(received) != lineage["source_sha256"] or received != source:
        raise Rejected("storage_quarantine_lineage_mismatch")
    validate_rows(decode(received), policy["rows"])
    for name in SPLITS:
        content = canonical(splits[name])
        if storage.put(curator, name, content) != manifest["objects"][f"{name}.json"]["sha256"]:
            raise Rejected("storage_dataset_persistence_mismatch")
    manifest_id = storage.put(
        curator,
        "manifests",
        canonical(read_json(safe_child(state, f"approved/{dataset_id}/manifest.json"))),
    )
    approval_id = storage.put(
        curator, "manifests", canonical(read_json(state / "source-approval.json"))
    )
    lineage_object = storage.put(
        curator, "lineage", canonical(read_json(safe_child(state, f"lineage/{lineage_id}.json")))
    )
    statement = {
        "schema_version": 1,
        "dataset_id": dataset_id,
        "lineage_id": lineage_id,
        "policy_digest": digest(canonical(policy)),
        "source_approval_digest": digest(canonical(approval)),
        "manifest_object": manifest_id,
        "approval_object": approval_id,
        "lineage_object": lineage_object,
        "quarantine_object": source_id,
    }
    envelope = sign(statement, "stored-dataset", state / "keys/curator.pem")
    reference = storage.put(curator, "manifests", canonical(envelope))
    read_dataset(
        curator,
        reference,
        policy,
        read_json(state / "trusted-keys.json")["curator"],
        digest(canonical(approval)),
        SPLITS,
    )
    return {
        "dataset_id": dataset_id,
        "lineage_id": lineage_id,
        "dataset_reference": reference,
        "source_approval_digest": statement["source_approval_digest"],
    }


def read_dataset(client, reference, policy, curator_public, expected_approval_digest, selected):
    if (
        not isinstance(selected, tuple)
        or not selected
        or any(not isinstance(name, str) for name in selected)
        or len(set(selected)) != len(selected)
        or any(name not in SPLITS for name in selected)
    ):
        raise Rejected("storage_split_selection_invalid")
    envelope = decode(storage.get(client, "manifests", reference))
    statement = verify(envelope, "stored-dataset", curator_public)
    require_fields(
        statement,
        (
            "schema_version",
            "dataset_id",
            "lineage_id",
            "policy_digest",
            "source_approval_digest",
            "manifest_object",
            "approval_object",
            "lineage_object",
            "quarantine_object",
        ),
    )
    if type(statement["schema_version"]) is not int or statement["schema_version"] != 1:
        raise Rejected("storage_dataset_schema_invalid")
    for name, value in statement.items():
        if name != "schema_version":
            storage.object_id(value)
    if (
        statement["policy_digest"] != digest(canonical(policy))
        or statement["source_approval_digest"] != expected_approval_digest
    ):
        raise Rejected("storage_dataset_policy_or_source_stale")
    approval = decode(storage.get(client, "manifests", statement["approval_object"]))
    manifest = verify_manifest(
        decode(storage.get(client, "manifests", statement["manifest_object"])),
        statement["dataset_id"],
        policy,
        approval,
        curator_public,
    )
    if manifest["source_approval_digest"] != expected_approval_digest:
        raise Rejected("storage_dataset_source_mismatch")
    lineage = verify_lineage_statement(
        decode(storage.get(client, "lineage", statement["lineage_object"])),
        statement["lineage_id"],
        statement["dataset_id"],
        policy,
        curator_public,
    )
    if lineage["source_sha256"] != statement["quarantine_object"]:
        raise Rejected("storage_dataset_lineage_mismatch")
    splits, identifiers = {}, set()
    for name in selected:
        metadata = manifest["objects"][f"{name}.json"]
        content = storage.get(client, name, metadata["sha256"])
        if len(content) != metadata["bytes"]:
            raise Rejected("storage_dataset_size_mismatch")
        rows = decode(content)
        current = validate_rows(rows, metadata["rows"])
        if identifiers.intersection(current):
            raise Rejected("storage_dataset_selected_split_leakage")
        identifiers.update(current)
        splits[name] = rows
    return splits, manifest, statement
