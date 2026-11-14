"""Prepare three real SQL-backed release proposals before pinning the hosted fleet inputs."""

import argparse
import math
import time
from pathlib import Path

from mlsecops import (
    data_source,
    datasets,
    intake,
    release_bundle,
    signing,
    storage,
    storage_dataset,
    storage_pipeline,
)
from mlsecops import inventory_gate as gate
from mlsecops.contracts import (
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.inventory_gate import require
from mlsecops.sandbox import resolve_image
from mlsecops.security_events import hexadecimal
from scripts import canary_rollout_native as rollout
from scripts import release_native
from scripts.candidate_serving_reader import bind_proposal

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


def scenarios(root, state, current, policy, trust):
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
    return reports


def prepare(root, state):
    rollout.hosted()
    require(state.resolve() == safe_child(root, ".runtime") and not state.is_symlink())
    reports = scenarios(
        root,
        state,
        read_json(state / "storage-demo.json"),
        read_json(root / "policies/local-cpu.json"),
        read_json(state / "storage-trust.json"),
    )
    reports["current"] = release_native.qualify(root, state, rollout.IMAGE, sequence=2)
    require(len({r["model_sha256"] for r in reports.values()}) == 3)
    write_json(state / "evidence/release-native.json", reports["current"])
    return dict(reports=reports, qualification_root=signing.create_key(safe_child(state, KEY)))


def check_clients(state, marker):
    """Bind every SQL client used by this adapter to the validated owner's loopback store."""
    pins = {}
    for role in ("ingestor", "curator", "publisher", "scorer", "promoter", "serving"):
        params, files = storage.connection_materials(safe_child(state, "storage-clients/" + role))
        require(
            (params["host"], params["port"], params["user"])
            == ("127.0.0.1", marker["port"], "ml_" + role)
        )
        for file, original in (
            ("ca.crt", "ca.crt"),
            ("client.crt", "ml_" + role + ".crt"),
            ("client.key", "ml_" + role + ".key"),
        ):
            require(
                files[file]
                == digest(bounded_read(safe_child(state, "storage-pki/" + original), 4096))
            )
        pins[role] = files
    return pins


def original(root, state, owner, marker, files):
    require(
        gate.storage_bootstrap.inspect("container", marker["container_id"])["State"]["Running"]
        is True
    )
    report = files["evidence/release-native.json"]
    public = files["trusted-keys.json"]
    trust = files["storage-trust.json"]
    demo = files["storage-demo.json"]
    policy = read_json(root / "policies/local-cpu.json")
    require(all(trust[k] == public[k] for k in ("curator", "evaluator")))
    expected = {**owner["source"], "image_id": resolve_image(rollout.IMAGE)}
    package = release_bundle.load(
        state / "storage-clients/serving",
        report["proposal_reference"],
        publisher_public=public["approver"],
    )
    context, verified = bind_proposal(
        report,
        package,
        policy=policy,
        source_trust=trust,
        publisher_public=public["approver"],
        expected=expected,
        clock=math.ceil(time.time()),
    )
    manifest = verified["manifest"]
    projection = decode(package["documents"]["asset_projection"])
    bindings = projection["bindings"]
    require(
        demo["candidate"]["candidate_reference"]
        == context["candidate_reference"]
        == demo["evaluation"]["candidate_reference"]
        and demo["evaluation_reference"] == context["evaluation_reference"]
        and demo["dataset"]["dataset_reference"]
        == bindings["dataset_reference"]
        == demo["evaluation"]["dataset_reference"]
        and demo["dataset"]["dataset_id"]
        == demo["candidate"]["metadata"]["dataset_id"]
        == manifest["materials"]["split_manifest"]
        and digest(canonical(demo["candidate"]["metadata"])) == manifest["materials"]["provenance"]
        and demo["dataset"]["source_approval_digest"] == trust["source_approval_digest"]
        and demo["dataset"]["lineage_id"]
        == bindings["lineage_id"]
        == demo["candidate"]["metadata"]["lineage_id"]
        and report["campaign_id"] == manifest["release_id"]
    )
    policy_path = safe_child(
        state,
        "release-proposals/" + hexadecimal(report["campaign_id"], 32) + "/policy-envelope.json",
    )
    policy_pin = digest(bounded_read(policy_path))
    return policy, policy_path, policy_pin


def existing(root, state):
    """Create only the previous and independent scenarios around a pre-existing pinned proposal."""
    before = gate.inputs(root, state)
    owner, marker, files = before
    require("delivery" in files)
    clients = check_clients(state, marker)
    policy, policy_path, policy_pin = original(root, state, owner, marker, files)
    try:
        reports = scenarios(
            root, state, files["storage-demo.json"], policy, files["storage-trust.json"]
        )
        reports["current"] = files["evidence/release-native.json"]
        require(len({r["model_sha256"] for r in reports.values()}) == 3)
        return dict(
            reports=reports,
            qualification_root=signing.create_key(safe_child(state, KEY)),
            delivery=files["delivery"],
        )
    finally:
        require(
            before == gate.inputs(root, state)
            and clients == check_clients(state, marker)
            and policy_pin == digest(bounded_read(policy_path))
        )


def main(root, arguments=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--existing", action="store_true", help="Reuse the original delivery pins and proposal"
    )
    options = parser.parse_args(arguments)
    state = root / ".runtime"
    rollout.publish_pin(state, FILE, (existing if options.existing else prepare)(root, state))


if __name__ == "__main__":
    main(Path(__file__).resolve().parents[1])
