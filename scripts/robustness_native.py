import argparse
import re
import sys
import uuid
from pathlib import Path

from mlsecops import advisory, artifact_intake
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.data_source import generated, validate_lock
from mlsecops.datasets import generate, validate_rows
from mlsecops.inventory import command, source_fingerprint
from mlsecops.pipeline import train_verified_dataset
from mlsecops.prediction_protocol import PredictionBatch, validate_scores
from mlsecops.sandbox import resolve_image, run_worker
from scripts.robustness import attack, compare, outside_support, policy, select

MATERIAL_FILES = {
    "campaign.json",
    "train.json",
    "validation.json",
    "probes.json",
    "model.onnx",
    "metadata.json",
    "intake.json",
    "clean.json",
    "attack.json",
    "metrics.json",
    "abstain.json",
    "executions.json",
} | {f"{kind}-{index}.json" for index in range(8) for kind in ("request", "response")}


def host_source(root):
    return digest(
        canonical(
            {
                name: digest(bounded_read(root / "scripts" / name))
                for name in ("robustness.py", "robustness_native.py")
            }
        )
    )


def materials(root):
    profile = read_json(root / "policies/local-cpu.json")
    lock = validate_lock(root)
    content = generated(root)
    if {"sha256": digest(content), "bytes": len(content)} != lock["output"]:
        raise Rejected("robustness_source_lock")
    records = decode(content)
    rules = policy()
    probes = generate(rules["probe_seed"], rules["probe_rows"])
    for record in probes:
        record["entity_id"] += rules["probe_entity_offset"]
    if (
        profile["training_seed"] != rules["training_seed"]
        or profile["split_counts"] != [14000, 3000, 3000]
        or len(records) != 20000
        or validate_rows(records).intersection(validate_rows(probes))
        or {tuple(record["features"]) for record in records}.intersection(
            tuple(record["features"]) for record in probes
        )
    ):
        raise Rejected("robustness_materials_not_disjoint")
    return profile, records[:14000], records[14000:17000], probes


def owned(state):
    if state.is_symlink():
        raise Rejected("robustness_symlink_state")
    marker = read_json(state / "workspace.json")
    if (
        not isinstance(marker, dict)
        or set(marker) != {"product", "schema_version", "workspace_id"}
        or marker.get("product") != "trusted-mlsecops"
        or type(marker.get("schema_version")) is not int
        or marker["schema_version"] != 1
        or not isinstance(marker.get("workspace_id"), str)
        or not re.fullmatch(r"[0-9a-f]{32}", marker.get("workspace_id", ""))
    ):
        raise Rejected("robustness_unowned_state")


def reconcile(campaign, expected_hashes, model_digest):
    if not isinstance(expected_hashes, dict) or expected_hashes.keys() != MATERIAL_FILES:
        raise Rejected("robustness_incomplete_material_set")
    for name, expected in expected_hashes.items():
        if digest(bounded_read(safe_child(campaign, name))) != expected:
            raise Rejected("robustness_persisted_material_changed")
    if digest(bounded_read(campaign / "model.onnx")) != model_digest:
        raise Rejected("robustness_model_binding")
    probes = read_json(campaign / "probes.json")
    clean = read_json(campaign / "clean.json")
    mutated = read_json(campaign / "attack.json")
    calculated = select([row["features"] for row in probes], clean, mutated["corner_scores"])
    if canonical(calculated) != canonical(mutated):
        raise Rejected("robustness_selection_binding")
    calculated_metrics = compare(probes, clean, calculated["scores"])
    if canonical(calculated_metrics) != canonical(read_json(campaign / "metrics.json")):
        raise Rejected("robustness_metrics_binding")
    return calculated_metrics


def qualify(root, state, image):
    root, state = Path(root).resolve(), Path(state)
    owned(state)
    image = resolve_image(image)
    profile, train, validation, probes = materials(root)
    identity, started = uuid.uuid4().hex, now()
    campaign = safe_child(state, "robustness/" + identity)
    campaign.mkdir(parents=True, exist_ok=False)
    fingerprint, scripts = source_fingerprint(root), host_source(root)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    split_objects = {
        name + ".json": {
            "sha256": digest(canonical(rows)),
            "rows": len(rows),
            "bytes": len(canonical(rows)),
        }
        for name, rows in (("train", train), ("validation", validation))
    }
    inputs = {
        "source_fingerprint": fingerprint,
        "host_scripts": scripts,
        "image_id": image,
        "protocol": digest(canonical(policy())),
        "data_lock": digest(bounded_read(root / "data.lock")),
        "training_materials": digest(canonical(split_objects)),
        "probes": digest(canonical(probes)),
    }
    hashes, executions, parity = {}, [], {}

    def save(name, value):
        path = safe_child(campaign, name)
        write_json(path, value)
        hashes[name] = digest(bounded_read(path))

    save(
        "campaign.json",
        {
            "campaign_id": identity,
            "started_at": started,
            "policy": policy(),
            "inputs": inputs,
            "status": "inconclusive",
            "release_ready": False,
        },
    )
    save("train.json", train)
    save("validation.json", validation)
    save("probes.json", probes)

    def execute(selected_image, request):
        if selected_image != image:
            raise Rejected("robustness_worker_image")
        output, execution = run_worker(image, request)
        if execution["image_id"] != image:
            raise Rejected("robustness_worker_image")
        index = len(executions)
        save(f"request-{index}.json", request)
        save(f"response-{index}.json", output)
        executions.append({"action": request["action"], **execution})
        if request["action"] == "train":
            expected = validate_scores(output["python_scores"], len(validation))
            observed = validate_scores(output["onnx_scores"], len(validation))
            outside = abs(expected - 0.5) > profile["parity_tolerance"]
            mismatches = int(((expected[outside] >= 0.5) != (observed[outside] >= 0.5)).sum())
            parity.update(
                rows=len(validation),
                max_error=float(abs(expected - observed).max()),
                label_mismatches=mismatches,
            )
            if mismatches:
                raise Rejected("robustness_parity_labels")
        return output, execution

    metadata, content, _ = train_verified_dataset(
        inputs["training_materials"],
        inputs["protocol"],
        {"train": train, "validation": validation},
        {"objects": split_objects},
        profile,
        image,
        execute,
    )
    atomic_write(campaign / "model.onnx", content)
    hashes["model.onnx"] = digest(content)
    save("metadata.json", metadata)
    receipt = artifact_intake.inspect_candidate(content, digest(content), image, image, execute)
    save("intake.json", receipt)

    def predict(features):
        batch = PredictionBatch(content, features)
        output, execution = execute(image, batch.request)
        scores, _, _ = batch.consume(output)
        return scores.tolist()

    features = [record["features"] for record in probes]
    clean = predict(features)
    mutated = attack(features, clean, predict)
    metrics = compare(probes, clean, mutated["scores"])
    before = len(executions)
    decisions = advisory.decide(outside_support(), predict)
    if len(executions) != before or any(
        item["decision"] != "abstain" or item["score"] is not None for item in decisions
    ):
        raise Rejected("robustness_outside_support_executed")
    mixed = advisory.decide([outside_support()[0], features[0], outside_support()[-1]], predict)
    if (
        mixed[0] != decisions[0]
        or mixed[2] != decisions[-1]
        or mixed[1]["decision"] != "score"
        or abs(mixed[1]["score"] - clean[0]) > profile["repeat_tolerance"]
    ):
        raise Rejected("robustness_mixed_positions")
    if [item["action"] for item in executions] != ["train", "inspect", *(["predict"] * 6)]:
        raise Rejected("robustness_execution_count")
    save("clean.json", clean)
    save("attack.json", mutated)
    save("metrics.json", metrics)
    save("abstain.json", {"outside_support": decisions, "mixed": mixed})
    save("executions.json", executions)
    metrics = reconcile(campaign, hashes, digest(content))
    if (
        fingerprint != source_fingerprint(root)
        or scripts != host_source(root)
        or revision != command(["git", "-C", str(root), "rev-parse", "HEAD"])
        or inputs["data_lock"] != digest(bounded_read(root / "data.lock"))
        or any(name in sys.modules for name in ("onnx", "onnxruntime"))
    ):
        raise Rejected("robustness_source_or_host_parser_boundary")
    result = {
        "schema_version": 1,
        "scope": "native-evasion-and-domain-guard-not-full-M09",
        "status": metrics["status"],
        "execution_status": "complete",
        "release_ready": False,
        "full_M09": "inconclusive",
        "campaign_id": identity,
        "started_at": started,
        "finished_at": now(),
        "source_revision": revision,
        "source_dirty": bool(command(["git", "-C", str(root), "status", "--porcelain"])),
        "input_digests": {**inputs, "model": digest(content)},
        "protocol": policy(),
        "metrics": metrics,
        "parity": parity,
        "worker_executions": len(executions),
        "outside_support_abstentions": len(decisions),
        "mixed_batch_score_error": abs(mixed[1]["score"] - clean[0]),
        "primary_reconciliation": "pass",
        "artifact_hashes": hashes,
        "limitations": [
            "Known synthetic feature-space probes; not independent reviewer challenges or final holdout approval",
            "Outside-support guard cannot detect joint distribution shifts inside the allowed cube",
            "No public serving endpoint, release authorization or full M09 acceptance integration",
            "Trusted research host; hashes and readback do not establish independent attestation",
        ],
    }
    write_json(campaign / "report.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Frozen evasion probes and bounded domain-support guard"
    )
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    output = None
    try:
        owned(arguments.state)
        output = safe_child(arguments.state, "evidence/robustness.json")
        write_json(output, {"status": "inconclusive", "release_ready": False, "started_at": now()})
        result = qualify(Path(__file__).resolve().parents[1], arguments.state, arguments.image)
    except (Rejected, OSError) as error:
        reason = (
            str(error)
            if isinstance(error, Rejected) and re.fullmatch(r"[a-z_]{1,100}", str(error))
            else "robustness_execution_incomplete"
        )
        if output is not None:
            write_json(output, {"status": "fail", "reason": reason, "release_ready": False})
        print(canonical({"status": "fail", "reason": reason, "release_ready": False}).decode())
        return 1
    write_json(output, result)
    print(canonical(result).decode())
    return {"pass": 0, "fail": 1, "inconclusive": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
