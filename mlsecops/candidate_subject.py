"""Read an evaluated candidate through signed lineage and owned storage."""

from mlsecops import candidate_lineage, storage_pipeline
from mlsecops.contracts import Rejected, bounded_read, digest, read_json, safe_child
from mlsecops.inventory import command, source_fingerprint
from mlsecops.storage_bootstrap import validate
from scripts.candidate_lineage_native import KNOWN_OWNERS, OWNERS


def subject(root, state, image):
    marker = validate(state)
    files = {
        name: digest(bounded_read(safe_child(state, name)))
        for name in ("storage-demo.json", "storage-trust.json", "trusted-keys.json")
    }
    demo, trust, keys = (read_json(safe_child(state, name)) for name in files)
    if trust["curator"] != keys["curator"] or trust["evaluator"] != keys["evaluator"]:
        raise Rejected("candidate_subject_trust_changed")
    policy = read_json(root / "policies/local-cpu.json")
    expected = {
        "image_id": image,
        "source_fingerprint": source_fingerprint(root),
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
    }
    reference = demo["candidate"]["candidate_reference"]
    projection = candidate_lineage.collect(
        safe_child(state, "storage-clients/publisher"),
        safe_child(state, "storage-clients/promoter"),
        candidate_reference=reference,
        evaluation_reference=demo["evaluation_reference"],
        policy=policy,
        trust=trust,
        expected=expected,
        owners=OWNERS,
        known_owners=KNOWN_OWNERS,
    )
    record, metadata, model = storage_pipeline.load_candidate(
        safe_child(state, "storage-clients/promoter"),
        reference,
        policy,
    )
    assets = {asset["kind"]: asset["sha256"] for asset in projection["graph"]["assets"]}
    if (
        assets["model"] != digest(model)
        or assets["run"] != record["metadata_object"]
        or any(metadata[name] != value for name, value in expected.items())
        or projection["bindings"]["dataset_reference"] != record["dataset_reference"]
    ):
        raise Rejected("candidate_subject_readback_changed")
    return {
        "model": model,
        "metadata": metadata,
        "record": record,
        "policy": policy,
        "bindings": projection["bindings"],
        "files": files,
        "marker": marker,
    }
