"""Prepare three real SQL-backed release proposals before pinning the hosted fleet inputs."""

from pathlib import Path

from mlsecops import data_source, datasets, intake, signing, storage_dataset, storage_pipeline
from mlsecops.contracts import atomic_write, canonical, digest, read_json, safe_child, write_json
from mlsecops.inventory_gate import require
from scripts import canary_rollout_native as rollout
from scripts import release_native

FILE = "evidence/M19-fleet-inputs.json"
KEY = "keys/M19-qualification.pem"


def independent_source(root, state, policy):
    # Domain-separated stream under the frozen synthetic profile's master seed.
    stream = {"master_seed": policy["data_seed"], "stream": "T25-independent-v1"}
    seed = int(digest(canonical(stream))[:8], 16)
    rows = datasets.generate(seed, policy["rows"])
    for row in rows:
        row["entity_id"] += policy["rows"]
    content = canonical(rows)
    pin = digest(content)
    directory = safe_child(state, "source/M19-independent")
    directory.mkdir(mode=0o700, exist_ok=False)
    path = directory / "records.json"
    atomic_write(path, content)
    lock = {
        **stream,
        "generator_seed": seed,
        "first_entity_id": policy["rows"],
        "source_sha256": pin,
    }
    atomic_write(directory / "stream.lock", canonical(lock))
    key = state / "keys/curator.pem"
    statement = intake.snapshot_statement(content, policy, datasets.source_approval(state, policy))
    write_json(
        state / f"source-attestations/{pin}.json", signing.sign(statement, "source-snapshot", key)
    )
    submitted = intake.submit(state, path, policy["source"], "dataset", policy)
    require(submitted["status"] == "validated-not-approved")
    receipt = intake.approve(state, submitted["intake_id"], policy)
    require(receipt["source_sha256"] == pin)
    lineage = dict(
        schema_version=1,
        dataset_id=receipt["dataset_id"],
        source_sha256=pin,
        policy_digest=digest(canonical(policy)),
        lock_sha256=digest(canonical(lock)),
        inputs=data_source.inputs(root),
        classification="synthetic-only",
        curator="lab-curator",
    )
    identifier = digest(canonical(lineage))
    write_json(state / f"lineage/{identifier}.json", signing.sign(lineage, "data-lineage", key))
    return storage_dataset.publish(state, receipt["dataset_id"], identifier, policy)


def prepare(root, state):
    rollout.hosted()
    require(state.resolve() == safe_child(root, ".runtime") and not state.is_symlink())
    current = read_json(state / "storage-demo.json")
    policy = read_json(root / "policies/local-cpu.json")
    trust = read_json(state / "storage-trust.json")
    reports = {}
    for name in ("previous", "independent"):
        dataset = (
            current["dataset"] if name == "previous" else independent_source(root, state, policy)
        )
        candidate = storage_pipeline.train(
            state / "storage-clients/publisher",
            dataset["dataset_reference"],
            policy,
            rollout.IMAGE,
            trust,
            previous_half_sample=name == "previous",
        )
        evaluated = storage_pipeline.evaluate(
            state / "storage-clients/scorer",
            candidate["candidate_reference"],
            policy,
            rollout.IMAGE,
            trust,
            state / "keys/evaluator.pem",
        )
        demo_file = f"evidence/M19-{name}-demo.json"
        write_json(state / demo_file, dict(dataset=dataset, candidate=candidate, **evaluated))
        reports[name] = release_native.qualify(root, state, rollout.IMAGE, demo_file=demo_file)
    reports["current"] = release_native.qualify(root, state, rollout.IMAGE, sequence=2)
    require(len({r["model_sha256"] for r in reports.values()}) == 3)
    write_json(state / "evidence/release-native.json", reports["current"])
    return dict(reports=reports, qualification_root=signing.create_key(safe_child(state, KEY)))


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    state = root / ".runtime"
    rollout.publish_pin(state, FILE, prepare(root, state))
