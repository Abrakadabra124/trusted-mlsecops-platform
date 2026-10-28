"""M22 absolute matrix on an actual candidate; no invented independent challenges."""

import copy
import sys
import uuid
from pathlib import Path

import numpy as np

from mlsecops.candidate_subject import subject
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.prediction_protocol import (
    PredictionBatch,
    response,
    validate_request,
    validate_scan,
    validate_scores,
)
from mlsecops.sandbox import resolve_image, run_worker
from scripts import absolute_poisoning as protocol
from scripts import poisoning
from scripts import poisoning_evidence as evidence
from scripts import poisoning_native as native
from scripts.robustness_native import owned

BASE_FILES = (
    "campaign.json",
    "train.json",
    "validation.json",
    "probes.json",
    "triggered.json",
    "candidate-binding.json",
)
CASE_FILES = (
    "model.onnx",
    "metadata.json",
    "mutation.json",
    "validation-scores.json",
    "security-scores.json",
    "prediction.json",
    "result.json",
)


def materials_digest(root):
    names = (
        "scripts/absolute_poisoning.py",
        "scripts/poisoning.py",
        "scripts/poisoning_native.py",
        "scripts/poisoning_evidence.py",
        "scripts/robustness_native.py",
        "scripts/absolute_poisoning_qualification.py",
        "scripts/absolute_poisoning_gate_qualification.py",
    )
    return digest(canonical({n: digest(bounded_read(root / n)) for n in names}))


def primary_hashes(campaign):
    names = [*BASE_FILES, *(c["id"] + "/" + n for c in protocol.matrix() for n in CASE_FILES)]
    return {n: digest(bounded_read(safe_child(campaign, n))) for n in names}


def metrics(probes, control, scores, family):
    count = len(probes)
    position = count if family == "backdoor" else 0
    return poisoning.compare(
        probes,
        control[:count],
        scores[:count],
        control[position : position + count],
        scores[position : position + count],
    )


def reconcile(root, campaign, candidate, inputs, revision, started, finished):
    try:
        return _reconcile(root, campaign, candidate, inputs, revision, started, finished)
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("M22_evidence_shape_invalid") from error


def _reconcile(root, campaign, candidate, inputs, revision, started, finished):
    snapshot = primary_hashes(campaign)
    profile, train, validation, probes, triggered = native.materials(root)
    expected_inputs = {
        "source": source_fingerprint(root),
        "host_scripts": materials_digest(root),
        "protocol": digest(canonical(protocol.policy())),
        "data_lock": digest(bounded_read(root / "data.lock")),
        "image": inputs["image"],
        "train": digest(canonical(train)),
        "validation": digest(canonical(validation)),
        "probes": digest(canonical(probes)),
    }
    evidence.equal(inputs, expected_inputs, "M22_inputs")
    evidence.timestamp(started, "2026-01-01T00:00:00+00:00", now())
    evidence.timestamp(finished, started, now())
    evidence.equal(
        read_json(campaign / "campaign.json"),
        {
            "protocol": protocol.policy(),
            "inputs": inputs,
            "revision": revision,
            "started_at": started,
            "status": "inconclusive",
            "release_ready": False,
        },
        "M22_manifest",
    )
    for name, values in (
        ("train", train),
        ("validation", validation),
        ("probes", probes),
        ("triggered", triggered),
    ):
        evidence.equal(read_json(campaign / (name + ".json")), values, "M22_materials")
    controls, records, score_sets = {}, [], {}
    for case in protocol.matrix():
        record, scores = evidence.case_materials(
            safe_child(campaign, case["id"]),
            case,
            profile,
            train[: case["train_rows"]],
            validation,
            probes,
            triggered,
            inputs,
            revision,
            started,
            finished,
            experiment_policy=protocol.policy(),
        )
        key = (case["train_rows"], case["seed"])
        evidence.equal(record["fraction"], case["count"] / case["train_rows"], "M22_fraction")
        if case["family"] == "clean":
            controls[key] = scores
        evidence.equal(
            record["metrics"], metrics(probes, controls[key], scores, case["family"]), "M22_metrics"
        )
        records.append(record)
        score_sets[case["id"]] = scores
    protocol.summarize(records)
    proof = read_json(campaign / "candidate-binding.json")
    request, output = proof["request"], proof["response"]
    if validate_request(request) != candidate["model"]:
        raise Rejected("M22_candidate_model_binding")
    features = [row["features"] for view in (probes, triggered) for row in view]
    evidence.equal(request["features"], features, "M22_candidate_features")
    scan = output["scan"]
    validate_scan(scan)
    scores = [row["score"] for row in output["predictions"]]
    actual = validate_scores(scores, len(features))
    evidence.equal(output, response(request, scores, scan), "M22_candidate_response")
    evidence.execution(proof["execution"], inputs["image"])
    seed = candidate["policy"]["training_seed"]
    if seed not in protocol.policy()["seeds"]:
        raise Rejected("M22_candidate_seed")
    reference = next(r for r in records if r["id"] == f"14000-clean-0-{seed}")
    if reference["input_digest"] != candidate["metadata"]["input_digest"]:
        raise Rejected("M22_candidate_training_binding")
    expected = validate_scores(score_sets[reference["id"]], len(features))
    error = float(np.max(np.abs(actual - expected)))
    if error > candidate["policy"]["repeat_tolerance"] or not np.array_equal(
        actual >= 0.5, expected >= 0.5
    ):
        raise Rejected("M22_candidate_prediction_binding")
    bound = copy.deepcopy(records)
    for record in bound:
        if record["train_rows"] == 14000 and record["seed"] == seed:
            observed = scores if record["family"] == "clean" else score_sets[record["id"]]
            record["metrics"] = metrics(probes, scores, observed, record["family"])
    evidence.equal(snapshot, primary_hashes(campaign), "M22_primary_changed")
    evidence.equal(revision, command(["git", "-C", str(root), "rev-parse", "HEAD"]), "M22_revision")
    return bound, error, snapshot


def qualify(root, state, image="trusted-mlsecops:dev"):
    try:
        return _qualify(root, state, image)
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("M22_evidence_shape_invalid") from error


def _qualify(root, state, image):
    root, state = Path(root).resolve(), Path(state)
    owned(state)
    state = state.resolve()
    started = now()
    output = safe_child(state, "evidence/absolute-poisoning-gate.json")
    write_json(output, {"status": "inconclusive", "started_at": started, "release_ready": False})
    image = resolve_image(image)
    candidate = subject(root, state, image)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    profile, train, validation, probes, triggered = native.materials(root)
    inputs = {
        "source": source_fingerprint(root),
        "host_scripts": materials_digest(root),
        "protocol": digest(canonical(protocol.policy())),
        "data_lock": digest(bounded_read(root / "data.lock")),
        "image": image,
        "train": digest(canonical(train)),
        "validation": digest(canonical(validation)),
        "probes": digest(canonical(probes)),
    }
    campaign = safe_child(state, "absolute-poisoning/" + uuid.uuid4().hex)
    campaign.mkdir(parents=True, exist_ok=False)
    write_json(
        campaign / "campaign.json",
        {
            "protocol": protocol.policy(),
            "inputs": inputs,
            "revision": revision,
            "started_at": started,
            "status": "inconclusive",
            "release_ready": False,
        },
    )
    for name, values in (
        ("train", train),
        ("validation", validation),
        ("probes", probes),
        ("triggered", triggered),
    ):
        write_json(campaign / (name + ".json"), values)
    controls = {}
    for case in protocol.matrix():
        record, scores = native.execute(
            root,
            campaign / case["id"],
            case,
            train[: case["train_rows"]],
            validation,
            (probes, triggered),
            profile,
            image,
            experiment_policy=protocol.policy(),
        )
        key = (case["train_rows"], case["seed"])
        if case["family"] == "clean":
            controls[key] = scores
        record["metrics"] = metrics(probes, controls[key], scores, case["family"])
        record["fraction"] = case["count"] / case["train_rows"]
        write_json(campaign / case["id"] / "result.json", record)
    batch = PredictionBatch(
        candidate["model"], [r["features"] for view in (probes, triggered) for r in view]
    )
    response_value, execution = run_worker(image, batch.request)
    batch.consume(response_value)
    write_json(
        campaign / "candidate-binding.json",
        {"request": batch.request, "response": response_value, "execution": execution},
    )
    finished = now()
    records, error, snapshot = reconcile(
        root, campaign, candidate, inputs, revision, started, finished
    )
    summary = protocol.summarize(records)
    if (
        subject(root, state, image) != candidate
        or inputs["source"] != source_fingerprint(root)
        or inputs["host_scripts"] != materials_digest(root)
        or inputs["data_lock"] != digest(bounded_read(root / "data.lock"))
        or any(n in sys.modules for n in ("onnx", "onnxruntime"))
    ):
        raise Rejected("M22_subject_or_controller_boundary_changed")
    evidence.equal(snapshot, primary_hashes(campaign), "M22_primary_changed")
    result = {
        "schema_version": 1,
        "scope": "M22-absolute-matrix-with-independent-challenges-pending",
        "status": protocol.full_status(summary),
        "component_status": summary["status"],
        "release_ready": False,
        "started_at": started,
        "finished_at": now(),
        "source_revision": revision,
        "source_dirty": bool(command(["git", "-C", str(root), "status", "--porcelain"])),
        "campaign_id": campaign.name,
        "input_digests": {
            **inputs,
            "candidate_reference": candidate["bindings"]["candidate_reference"],
            "evaluation_reference": candidate["bindings"]["evaluation_reference"],
            "model_digest": digest(candidate["model"]),
        },
        "protocol": protocol.policy(),
        "records": records,
        "metrics": {
            **{key: value for key, value in summary.items() if key != "status"},
            "component_status": summary["status"],
            "candidate_prediction_error": error,
            "primary_files_verified": len(snapshot),
            "independent_challenges": 0,
            "required_independent_challenges": 2,
        },
        "cases": [{"id": r["id"], "status": r["metrics"]["status"]} for r in records]
        + [{"id": "independent-reviewer-challenges", "status": "inconclusive"}],
        "checks": len(records) + 1,
        "artifact_hashes": {"primary_materials": digest(canonical(snapshot))},
        "limitations": [
            "Independent reviewer challenges are absent; M22 cannot pass",
            "Known synthetic probes; conditional per-scenario intervals, not a population guarantee",
            "Other train sizes/seeds test the recipe, not the actual candidate bytes",
            "Trusted controller and source; consistent host forgery is outside this boundary",
        ],
    }
    write_json(campaign / "report.json", result)
    write_json(output, result)
    return result
