import argparse
import re
import subprocess
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
from mlsecops.data_source import generated
from mlsecops.inventory import command, source_fingerprint
from mlsecops.prediction_protocol import PredictionBatch
from mlsecops.sandbox import resolve_image, run_worker
from scripts import robust_training_experiment as experiment
from scripts import robustness, robustness_native

ARMS = {"baseline": "train", "candidate": "research-robust-train"}
MATERIAL_FILES = (
    {"campaign.json", "train.json", "validation.json", "probes.json", "executions.json"}
    | {
        f"{arm}-{name}"
        for arm in ARMS
        for name in (
            "model.onnx",
            "parity.json",
            "intake.json",
            "clean.json",
            "attack.json",
            "summary.json",
            "abstain.json",
        )
    }
    | {f"{kind}-{index}.json" for index in range(14) for kind in ("request", "response")}
)


def host_source(root):
    return digest(
        canonical(
            {
                name: digest(bounded_read(root / "scripts" / name))
                for name in (
                    "robust_training_native.py",
                    "robust_training_experiment.py",
                    "robustness.py",
                    "robustness_native.py",
                )
            }
        )
    )


def check_abstentions(decisions, before, after):
    expected = [
        {"decision": "abstain", "reason": "outside-support", "score": None}
        for _ in robustness.outside_support()
    ]
    if before != after or canonical(decisions) != canonical(expected):
        raise Rejected("robust_training_abstain_contract")
    return len(decisions)


def reconcile_training(campaign, arm, index, content, profile, image):
    request = read_json(campaign / f"request-{index}.json")
    expected = {
        "action": ARMS[arm],
        "train": read_json(campaign / "train.json"),
        "features": [row["features"] for row in read_json(campaign / "validation.json")],
        "seed": profile["training_seed"],
    }
    if canonical(request) != canonical(expected):
        raise Rejected("robust_training_persisted_request_binding")
    actual, parity = experiment.training_response(
        request, read_json(campaign / f"response-{index}.json"), profile
    )
    if actual != content or canonical(parity) != canonical(
        read_json(campaign / f"{arm}-parity.json")
    ):
        raise Rejected("robust_training_persisted_response_binding")
    receipt = read_json(campaign / f"{arm}-intake.json")
    artifact_intake.validate_receipt(receipt, content, image)
    inspect_request = read_json(campaign / f"request-{index + 1}.json")
    expected_request = artifact_intake.request_for(content, receipt["inspection_id"])
    if canonical(inspect_request) != canonical(expected_request):
        raise Rejected("robust_training_persisted_intake_binding")
    inspected = artifact_intake.checked_response(
        read_json(campaign / f"response-{index + 1}.json"), inspect_request
    )
    if digest(canonical(inspected)) != receipt["response_digest"]:
        raise Rejected("robust_training_persisted_intake_binding")


def reconcile(campaign, hashes, models, profile):
    if hashes.keys() != MATERIAL_FILES or models.keys() != ARMS.keys():
        raise Rejected("robust_training_incomplete_material_set")
    for name, expected in hashes.items():
        if digest(bounded_read(safe_child(campaign, name))) != expected:
            raise Rejected("robust_training_persisted_material_changed")
    probes = read_json(campaign / "probes.json")
    recorded = read_json(campaign / "campaign.json")
    if canonical(recorded["protocol"]) != canonical(experiment.protocol()):
        raise Rejected("robust_training_persisted_protocol")
    features = [row["features"] for name in experiment.PROBES for row in probes[name]]
    summaries = {}
    variants = [features, *robustness.corners(features)]
    for arm_index, arm in enumerate(ARMS):
        content = bounded_read(campaign / f"{arm}-model.onnx")
        if digest(content) != models[arm]:
            raise Rejected("robust_training_model_binding")
        reconcile_training(
            campaign, arm, arm_index * 7, content, profile, recorded["inputs"]["image_id"]
        )
        check_abstentions(read_json(campaign / f"{arm}-abstain.json"), 0, 0)
        clean = read_json(campaign / f"{arm}-clean.json")
        mutated = read_json(campaign / f"{arm}-attack.json")
        raw = [
            experiment.replay_scores(
                read_json(campaign / f"request-{arm_index * 7 + query_index + 2}.json"),
                read_json(campaign / f"response-{arm_index * 7 + query_index + 2}.json"),
                content,
                values,
            )
            for query_index, values in enumerate(variants)
        ]
        if canonical(raw) != canonical([clean, *mutated["corner_scores"]]):
            raise Rejected("robust_training_raw_scores_binding")
        selected = robustness.select(features, clean, mutated["corner_scores"])
        if canonical(selected) != canonical(mutated):
            raise Rejected("robust_training_selection_binding")
        summary = experiment.summarize(probes, clean, selected["scores"])
        if canonical(summary) != canonical(read_json(campaign / f"{arm}-summary.json")):
            raise Rejected("robust_training_summary_binding")
        summaries[arm] = summary
    return summaries, experiment.decide(summaries["baseline"], summaries["candidate"])


def qualify(root, state, image):
    root, state = Path(root).resolve(), Path(state)
    robustness_native.owned(state)
    image = resolve_image(image)
    profile, train, validation, known = robustness_native.materials(root)
    probes = experiment.probes(decode(generated(root)))
    if canonical(probes["known-73041"]) != canonical(known):
        raise Rejected("robust_training_known_probe_changed")
    identity, started = uuid.uuid4().hex, now()
    campaign = safe_child(state, "robust-training/" + identity)
    campaign.mkdir(parents=True, exist_ok=False)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    inputs = {
        "source_fingerprint": source_fingerprint(root),
        "host_scripts": host_source(root),
        "image_id": image,
        "protocol": digest(canonical(experiment.protocol())),
        "data_lock": digest(bounded_read(root / "data.lock")),
        "train": digest(canonical(train)),
        "validation": digest(canonical(validation)),
        "probes": {name: digest(canonical(rows)) for name, rows in probes.items()},
    }
    hashes, executions, models, parities, optimization, counts = {}, [], {}, {}, {}, {}

    def save(name, value):
        path = safe_child(campaign, name)
        write_json(path, value)
        hashes[name] = digest(bounded_read(path))

    save(
        "campaign.json",
        {
            "campaign_id": identity,
            "started_at": started,
            "inputs": inputs,
            "protocol": experiment.protocol(),
            "status": "inconclusive",
            "release_ready": False,
        },
    )
    save("train.json", train)
    save("validation.json", validation)
    save("probes.json", probes)

    def execute(selected_image, request):
        if selected_image != image:
            raise Rejected("robust_training_worker_image")
        index = len(executions)
        save(f"request-{index}.json", request)
        output, execution = run_worker(image, request)
        if execution["image_id"] != image:
            raise Rejected("robust_training_worker_image")
        save(f"response-{index}.json", output)
        executions.append({"action": request["action"], **execution})
        return output, execution

    features = [row["features"] for name in experiment.PROBES for row in probes[name]]
    for arm, action in ARMS.items():
        request = {
            "action": action,
            "train": train,
            "seed": profile["training_seed"],
            "features": [row["features"] for row in validation],
        }
        output, _ = execute(image, request)
        content, parity = experiment.training_response(request, output, profile)
        if "optimization" in output:
            optimization[arm] = output["optimization"]
        models[arm], parities[arm] = digest(content), parity
        atomic_write(campaign / f"{arm}-model.onnx", content)
        hashes[f"{arm}-model.onnx"] = digest(content)
        save(f"{arm}-parity.json", parity)
        intake = artifact_intake.inspect_candidate(content, digest(content), image, image, execute)
        save(f"{arm}-intake.json", intake)

        def predict(values):
            batch = PredictionBatch(content, values)
            response, _ = execute(image, batch.request)
            scores, _, _ = batch.consume(response)
            return scores.tolist()

        clean = predict(features)
        mutated = robustness.attack(features, clean, predict)
        summary = experiment.summarize(probes, clean, mutated["scores"])
        before = len(executions)
        abstentions = advisory.decide(robustness.outside_support(), predict)
        counts[arm] = check_abstentions(abstentions, before, len(executions))
        save(f"{arm}-clean.json", clean)
        save(f"{arm}-attack.json", mutated)
        save(f"{arm}-summary.json", summary)
        save(f"{arm}-abstain.json", abstentions)
    expected_actions = [
        action
        for train_action in ARMS.values()
        for action in (train_action, "inspect", *(["predict"] * 5))
    ]
    if [item["action"] for item in executions] != expected_actions:
        raise Rejected("robust_training_execution_count")
    save("executions.json", executions)
    summaries, decision = reconcile(campaign, hashes, models, profile)
    if (
        inputs["source_fingerprint"] != source_fingerprint(root)
        or inputs["host_scripts"] != host_source(root)
        or inputs["data_lock"] != digest(bounded_read(root / "data.lock"))
        or revision != command(["git", "-C", str(root), "rev-parse", "HEAD"])
        or any(name in sys.modules for name in ("onnx", "onnxruntime"))
    ):
        raise Rejected("robust_training_source_or_host_parser_boundary")
    result = {
        "schema_version": 1,
        "scope": "paired-robust-training-not-adoption-not-full-M09",
        **decision,
        "execution_status": "complete",
        "campaign_id": identity,
        "started_at": started,
        "finished_at": now(),
        "source_revision": revision,
        "source_dirty": bool(command(["git", "-C", str(root), "status", "--porcelain"])),
        "input_digests": {**inputs, "models": models},
        "protocol": experiment.protocol(),
        "summaries": summaries,
        "parity": parities,
        "optimization": optimization,
        "worker_executions": len(executions),
        "outside_support_abstentions_per_arm": counts,
        "primary_reconciliation": "pass",
        "artifact_hashes": hashes,
        "limitations": [
            "Same-agent synthetic research, not independent reviewer challenges or final holdout approval",
            "No policy adoption, poisoning requalification, signed release or serving integration",
            "Numerical optimization receipt is worker-reported, not independent mathematical certification",
            "Trusted research host; hashes and readback do not establish independent attestation",
        ],
    }
    write_json(campaign / "report.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description="Frozen paired robust training research")
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    output = None
    try:
        robustness_native.owned(arguments.state)
        output = safe_child(arguments.state, "evidence/robust-training.json")
        write_json(output, {"status": "inconclusive", "release_ready": False, "started_at": now()})
        result = qualify(Path(__file__).resolve().parents[1], arguments.state, arguments.image)
    except (Rejected, OSError, subprocess.TimeoutExpired) as error:
        reason = (
            str(error)
            if isinstance(error, Rejected) and re.fullmatch(r"[a-z_]{1,100}", str(error))
            else "robust_training_execution_incomplete"
        )
        result = {
            "status": "fail",
            "execution_status": "incomplete",
            "reason": reason,
            "release_ready": False,
        }
        if output is not None:
            write_json(output, result)
        print(canonical(result).decode())
        return 1
    write_json(output, result)
    print(canonical(result).decode())
    return {"pass": 0, "fail": 1, "inconclusive": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
