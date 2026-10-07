import uuid
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score, recall_score

from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    digest,
    now,
    read_json,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.datasets import verify_dataset
from mlsecops.inventory import command, source_fingerprint
from mlsecops.sandbox import run_worker
from mlsecops.signing import decode64, encode64, sign, verify


def validate_scores(scores, count):
    if not isinstance(scores, list) or len(scores) != count:
        raise Rejected("prediction_count_mismatch")
    if any(
        type(score) not in (float, int) or not np.isfinite(score) or not 0 <= score <= 1
        for score in scores
    ):
        raise Rejected("invalid_probability")
    return np.asarray(scores, dtype=float)


def train_candidate(state, dataset_id, policy, image, executor=run_worker):
    state = Path(state)
    splits, manifest = verify_dataset(state, dataset_id, policy)
    request = {
        "action": "train",
        "train": splits["train"],
        "seed": policy["training_seed"],
        "features": [row["features"] for row in splits["validation"]],
    }
    output, execution = executor(image, request)
    require_fields(
        output,
        (
            "schema_version",
            "action",
            "model",
            "model_digest",
            "input_digest",
            "python_scores",
            "onnx_scores",
            "scan",
            "seed",
            "versions",
        ),
    )
    if output["action"] != "train" or output["input_digest"] != digest(canonical(request)):
        raise Rejected("training_protocol_mismatch")
    content = decode64(output["model"])
    if digest(content) != output["model_digest"] or len(content) > policy["model_limit_bytes"]:
        raise Rejected("candidate_digest_or_size_mismatch")
    python_scores = validate_scores(output["python_scores"], len(splits["validation"]))
    onnx_scores = validate_scores(output["onnx_scores"], len(splits["validation"]))
    parity = float(np.max(np.abs(python_scores - onnx_scores)))
    if parity > policy["parity_tolerance"]:
        raise Rejected("parity_threshold_failed")
    run_id = uuid.uuid4().hex
    location = state / "candidates" / run_id
    location.mkdir()
    metadata = {
        "schema_version": 1,
        "run_id": run_id,
        "created_at": now(),
        "dataset_id": dataset_id,
        "model_digest": digest(content),
        "policy_digest": digest(canonical(policy)),
        "input_digest": output["input_digest"],
        "image_id": execution["image_id"],
        "execution": execution,
        "versions": output["versions"],
        "validation_parity_max_error": parity,
        "validation_probability_digest": digest(canonical(output["onnx_scores"])),
        "materials": manifest["objects"],
        "status": "unapproved-candidate",
        "source_fingerprint": source_fingerprint(Path(__file__).resolve().parents[1]),
        "source_revision": command(
            ["git", "-C", str(Path(__file__).resolve().parents[1]), "rev-parse", "HEAD"]
        ),
    }
    atomic_write(location / "model.onnx", content)
    write_json(location / "run.json", metadata)
    write_json(location / "validation-scores.json", output["onnx_scores"])
    return metadata


def load_candidate(state, run_id, policy):
    if (
        not isinstance(run_id, str)
        or len(run_id) != 32
        or any(character not in "0123456789abcdef" for character in run_id)
    ):
        raise Rejected("invalid_run_id")
    location = safe_child(Path(state) / "candidates", run_id)
    metadata = read_json(location / "run.json")
    content = bounded_read(location / "model.onnx", policy["model_limit_bytes"])
    if (
        metadata.get("model_digest") != digest(content)
        or metadata.get("policy_digest") != digest(canonical(policy))
        or metadata.get("run_id") != run_id
    ):
        raise Rejected("candidate_material_mismatch")
    return metadata, content


def evaluate_candidate(state, run_id, policy, image, executor=run_worker):
    state = Path(state)
    metadata, content = load_candidate(state, run_id, policy)
    splits, manifest = verify_dataset(state, metadata["dataset_id"], policy)
    holdout = splits["holdout"]
    batch_id = uuid.uuid4().hex
    output, execution = executor(
        image,
        {
            "action": "predict",
            "model": encode64(content),
            "batch_id": batch_id,
            "features": [row["features"] for row in holdout],
        },
    )
    require_fields(
        output, ("schema_version", "action", "batch_id", "model_digest", "scores", "scan")
    )
    if (
        output["batch_id"] != batch_id
        or output["model_digest"] != digest(content)
        or output["action"] != "predict"
        or execution["image_id"] != metadata["image_id"]
    ):
        raise Rejected("evaluation_protocol_mismatch")
    scores = validate_scores(output["scores"], len(holdout))
    labels = np.array([row["label"] for row in holdout])
    positives = int(labels.sum())
    auprc = float(average_precision_score(labels, scores))
    dummy_auprc = float(labels.mean())
    slices = {}
    for name, selector in (
        ("low-change", np.array([row["features"][0] < 0.5 for row in holdout])),
        ("high-change", np.array([row["features"][0] >= 0.5 for row in holdout])),
    ):
        slices[name] = {
            "rows": int(selector.sum()),
            "positives": int(labels[selector].sum()),
            "recall": float(recall_score(labels[selector], scores[selector] >= 0.5)),
        }
    quality = (
        positives >= policy["minimum_positives"]
        and auprc >= policy["minimum_auprc"]
        and auprc - dummy_auprc >= policy["minimum_auprc_gain"]
        and all(value["rows"] >= policy["minimum_slice_rows"] for value in slices.values())
    )
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "created_at": now(),
        "model_digest": digest(content),
        "dataset_id": metadata["dataset_id"],
        "policy_digest": digest(canonical(policy)),
        "image_id": execution["image_id"],
        "holdout_digest": manifest["objects"]["holdout.json"]["sha256"],
        "rows": len(holdout),
        "positives": positives,
        "auprc": auprc,
        "dummy_auprc": dummy_auprc,
        "auprc_gain": auprc - dummy_auprc,
        "slices": slices,
        "validation_parity_max_error": metadata["validation_parity_max_error"],
        "quality_component": "pass" if quality else "fail",
        "release_status": "unapproved",
        "scan": output["scan"],
        "limitations": [
            "Synthetic utility only",
            "Full M07 and R1 acceptance not established",
            "Full MLflow, holdout query budget and storage-role acceptance pending",
        ],
    }
    envelope = sign(report, "evaluation", state / "keys/evaluator.pem")
    write_json(state / "evaluations" / f"{run_id}.json", envelope)
    public = read_json(state / "trusted-keys.json")
    if (
        verify(
            read_json(state / "evaluations" / f"{run_id}.json"), "evaluation", public["evaluator"]
        )
        != report
    ):
        raise Rejected("evaluation_persistence_mismatch")
    return report
