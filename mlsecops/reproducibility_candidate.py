"""Compare three verified fresh trainings with the evaluator's exact frozen ONNX request."""

from mlsecops import storage_pipeline
from mlsecops.candidate_subject import subject
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    digest,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.datasets import verify_dataset
from mlsecops.prediction_protocol import response, validate_scores
from mlsecops.sandbox import run_worker
from mlsecops.signing import encode64
from scripts.poisoning_evidence import execution
from scripts.reproducibility_native import record_from


def bind(root, state, evidence, result, demo_pin):
    image = evidence["image_id"]
    candidate = subject(root, state, image)
    if candidate["files"]["storage-demo.json"] != demo_pin:
        raise Rejected("M06_frozen_demo_changed")
    metadata = candidate["metadata"]
    bindings = candidate["bindings"]
    signed = storage_pipeline.read_evaluation(
        state / "storage-clients/promoter",
        bindings["evaluation_reference"],
        bindings["candidate_reference"],
        candidate["policy"],
        read_json(state / "storage-trust.json"),
    )["report"]
    campaign = safe_child(state, "reproducibility/" + evidence["campaign_id"])
    repeats = evidence["records"][:3]
    splits, manifest = verify_dataset(
        campaign, repeats[0]["inputs"]["dataset"], candidate["policy"]
    )
    holdout = splits["holdout"]
    if metadata["materials"] != manifest["objects"] or signed["holdout_digest"] != digest(
        canonical(holdout)
    ):
        raise Rejected("M06_candidate_split_mismatch")
    proof = signed["prediction_protocol"]
    batch_id = proof["batch_id"]
    request = dict(
        schema_version=2,
        action="predict",
        model=encode64(candidate["model"]),
        features=[row["features"] for row in holdout],
        batch_id=batch_id,
        row_ids=[f"{batch_id}:{i}" for i in range(len(holdout))],
    )
    if digest(canonical(request)) != proof["request_digest"]:
        raise Rejected("M06_evaluator_request_mismatch")
    output, boundary = run_worker(image, request)
    execution(boundary, image)
    if digest(canonical(output)) != proof["response_digest"]:
        raise Rejected("M06_evaluator_response_mismatch")
    scores = [row["score"] for row in output["predictions"]]
    if output != response(request, scores, signed["scan"]):
        raise Rejected("M06_evaluator_rows_mismatch")
    actual = record_from(metadata, holdout, scores, evidence["baseline_environment"])
    if actual["auprc"] != signed["auprc"] or actual["run_id"] in {r["run_id"] for r in repeats}:
        raise Rejected("M06_reference_or_evaluation_mismatch")
    max_score, max_auprc = 0.0, 0.0
    for reference in repeats:
        # Each fresh local workspace has a separately signed source approval, hence
        # a different manifest ID. The signed split bytes and actual requests match.
        if any(actual["inputs"][k] != v for k, v in reference["inputs"].items() if k != "dataset"):
            raise Rejected("M06_actual_training_inputs_mismatch")
        vector = read_json(
            safe_child(campaign, "candidates/" + reference["run_id"] + "/golden-scores.json")
        )
        if digest(canonical(vector)) != reference["vector_digest"]:
            raise Rejected("M06_reference_vector_changed")
        other = validate_scores(vector, len(holdout))
        max_score = max(max_score, float(max(abs(other - scores))))
        max_auprc = max(max_auprc, abs(reference["auprc"] - actual["auprc"]))
    if max_score > 1e-6 or max_auprc > 1e-4:
        raise Rejected("M06_actual_repeat_tolerance")
    path = campaign / "candidate-replay.json"
    write_json(
        path,
        dict(
            candidate=actual,
            scores=scores,
            protocol=proof,
            reference_runs=[r["run_id"] for r in repeats],
            split_materials=metadata["materials"],
            execution=boundary,
        ),
    )
    result["artifact_hashes"]["candidate_replay"] = digest(bounded_read(path))
    result["input_digests"].update(
        candidate_reference=bindings["candidate_reference"],
        evaluation_reference=bindings["evaluation_reference"],
        dataset_reference=bindings["dataset_reference"],
        model_digest=digest(candidate["model"]),
        candidate_training_input=metadata["input_digest"],
        frozen_demo=demo_pin,
    )
    result["metrics"].update(
        candidate_probability_difference=max_score, candidate_auprc_difference=max_auprc
    )
    result["cases"].append(
        dict(
            id="signed-candidate-three-fresh-repeats",
            status="pass",
            expected=dict(probability_max=1e-6, auprc_max=1e-4),
            actual=dict(probability=max_score, auprc=max_auprc),
        )
    )
    result["checks"] = len(result["cases"])
