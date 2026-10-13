import importlib.metadata
import math
from decimal import Decimal

from mlsecops import evaluation_quality, robust_training
from mlsecops.contracts import Rejected, canonical, digest, require_fields
from mlsecops.datasets import generate, validate_rows
from mlsecops.prediction_protocol import response as prediction_response
from mlsecops.prediction_protocol import validate_request, validate_scan, validate_scores
from mlsecops.signing import decode64
from scripts import robustness

PROBES = {
    "known-73041": (73041, 2000000),
    "new-73043": (73043, 3000000),
    "new-73047": (73047, 4000000),
}


def replay_scores(request, output, content, features):
    if validate_request(request) != content or canonical(request["features"]) != canonical(
        features
    ):
        raise Rejected("robust_training_prediction_material_binding")
    if not isinstance(output, dict) or not isinstance(output.get("predictions"), list):
        raise Rejected("robust_training_prediction_response")
    for record in output["predictions"]:
        require_fields(record, ("row_id", "score"))
    scores = [record["score"] for record in output["predictions"]]
    validate_scan(output.get("scan"))
    if canonical(output) != canonical(prediction_response(request, scores, output["scan"])):
        raise Rejected("robust_training_prediction_response_binding")
    return scores


def training_response(request, response, profile):
    fields = {
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
    }
    research = request["action"] == "research-robust-train"
    require_fields(response, fields | ({"optimization"} if research else set()))
    if (
        type(response["schema_version"]) is not int
        or response["schema_version"] != 1
        or response["action"] != request["action"]
        or response["input_digest"] != digest(canonical(request))
        or type(response["seed"]) is not int
        or response["seed"] != request["seed"]
        or response["versions"]
        != {
            name: importlib.metadata.version(name)
            for name in ("numpy", "scikit-learn", "skl2onnx", "onnx", "onnxruntime")
        }
    ):
        raise Rejected("robust_training_response_binding")
    content = decode64(response["model"])
    if (
        not content
        or digest(content) != response["model_digest"]
        or len(content) > profile["model_limit_bytes"]
    ):
        raise Rejected("robust_training_model_binding")
    validate_scan(response["scan"])
    expected = validate_scores(response["python_scores"], len(request["features"]))
    observed = validate_scores(response["onnx_scores"], len(request["features"]))
    outside = abs(expected - 0.5) > profile["parity_tolerance"]
    parity = {
        "rows": len(expected),
        "max_error": float(abs(expected - observed).max()),
        "label_mismatches": int(((expected[outside] >= 0.5) != (observed[outside] >= 0.5)).sum()),
    }
    if parity["max_error"] > profile["parity_tolerance"] or parity["label_mismatches"]:
        raise Rejected("robust_training_parity")
    if research:
        check_optimization(response["optimization"], len(request["train"]))
    return content, parity


def check_optimization(receipt, rows):
    rules = robust_training.definition()
    fixed = {
        "schema_version": 1,
        "algorithm": rules["algorithm"],
        "policy_digest": digest(canonical(rules)),
        "training_rows": rows,
        "scipy_version": importlib.metadata.version("scipy"),
        "status": "numerically-converged",
    }
    numeric = ("initial_objective", "final_objective", "projected_gradient_inf")
    require_fields(receipt, (*fixed, "iterations", *numeric))
    if (
        canonical({name: receipt[name] for name in fixed}) != canonical(fixed)
        or type(receipt["iterations"]) is not int
        or not 0 <= receipt["iterations"] <= rules["maxiter"]
        or any(
            type(receipt[name]) not in (float, int)
            or not math.isfinite(receipt[name])
            or receipt[name] < 0
            for name in numeric
        )
        or receipt["final_objective"] > receipt["initial_objective"] + 1e-12
        or receipt["projected_gradient_inf"] > rules["accepted_projected_gradient"]
    ):
        raise Rejected("robust_training_optimization_receipt")


def protocol():
    return {
        "schema_version": 1,
        "profile": "paired-robust-training-lab-v1",
        "training": robust_training.definition(),
        "attack": robustness.policy(),
        "quality": evaluation_quality.definition(),
        "probes": PROBES,
        "maximum_clean_ap_loss": 0.03,
        "worker_executions": 14,
        "adoption": "research-only-no-automatic-release",
    }


def probes(original):
    identities = validate_rows(original)
    vectors = {tuple(row["features"]) for row in original}
    result = {}
    for name, (seed, offset) in PROBES.items():
        rows = generate(seed, 3000)
        for row in rows:
            row["entity_id"] += offset
        found = validate_rows(rows)
        features = {tuple(row["features"]) for row in rows}
        if identities.intersection(found) or vectors.intersection(features):
            raise Rejected("robust_training_probe_overlap")
        identities.update(found)
        vectors.update(features)
        result[name] = rows
    return result


def summarize(records, clean, attacked):
    result = {}
    for index, name in enumerate(PROBES):
        selected = slice(index * 3000, (index + 1) * 3000)
        rows = records[name]
        baseline, changed = clean[selected], attacked[selected]
        negatives = sum(row["label"] == 0 for row in rows)
        false_positives = {
            kind: sum(
                row["label"] == 0 and score >= 0.5 for row, score in zip(rows, scores, strict=True)
            )
            for kind, scores in (("clean", baseline), ("attacked", changed))
        }
        result[name] = {
            "quality": evaluation_quality.summarize(
                rows, baseline, evaluation_quality.definition()
            ),
            "evasion": robustness.compare(rows, baseline, changed),
            "negatives": negatives,
            "false_positives": false_positives,
            "false_positive_rates": {
                kind: count / negatives if negatives else None
                for kind, count in false_positives.items()
            },
        }
    return result


def decide(baseline, candidate):
    if baseline.keys() != PROBES.keys() or candidate.keys() != PROBES.keys():
        raise Rejected("robust_training_probe_set")
    statuses, losses = [], {}
    for name in PROBES:
        previous, current = baseline[name]["quality"], candidate[name]["quality"]
        statuses.extend(
            (
                previous["quality_component"],
                current["quality_component"],
                candidate[name]["evasion"]["status"],
            )
        )
        loss = (
            None
            if previous["auprc"] is None or current["auprc"] is None
            else Decimal(str(previous["auprc"])) - Decimal(str(current["auprc"]))
        )
        losses[name] = float(loss) if loss is not None else None
        statuses.append(
            "inconclusive" if loss is None else "fail" if loss > Decimal("0.03") else "pass"
        )
    if any(status not in ("pass", "fail", "inconclusive") for status in statuses):
        raise Rejected("robust_training_unknown_status")
    return {
        "status": "fail"
        if "fail" in statuses
        else "inconclusive"
        if "inconclusive" in statuses
        else "pass",
        "clean_ap_loss": losses,
        "release_ready": False,
        "full_M09": "inconclusive",
    }
