import argparse
import copy
from pathlib import Path
from unittest.mock import patch

from mlsecops import storage, storage_pipeline
from mlsecops.contracts import Rejected, canonical, decode, digest, now, read_json, require_fields
from mlsecops.controller import process_state
from mlsecops.controller_worker import run, validate_profile
from mlsecops.inventory import source_fingerprint
from mlsecops.prediction_protocol import MAX_BYTES, response, validate_request, validate_scan
from mlsecops.signing import verify

MUTATIONS = {
    "raw-text": "unexpected_fields",
    "extra-field": "unexpected_fields",
    "missing-field": "unexpected_fields",
    "missing-row": "prediction_count_mismatch",
    "extra-row": "prediction_count_mismatch",
    "reordered-rows": "prediction_response_row_binding",
    "duplicate-row": "prediction_response_row_binding",
    "boolean-score": "invalid_probability",
    "nan-score": "invalid_json_value",
    "inf-score": "invalid_json_value",
    "negative-score": "invalid_probability",
    "large-score": "invalid_probability",
    "oversized-response": "prediction_response_limit",
    "wrong-version": "prediction_response_binding",
    "wrong-batch": "prediction_response_binding",
    "wrong-model": "prediction_response_binding",
    "wrong-request": "prediction_response_binding",
    "unsupported-scan": "prediction_scan_contract",
    "replayed-response": "prediction_response_binding",
}


def corrupt(name, valid, replay):
    output = copy.deepcopy(valid)
    if name == "raw-text":
        return "arbitrary untrusted output"
    if name == "replayed-response":
        return copy.deepcopy(replay)
    mutations = {
        "extra-field": lambda: output.update(untrusted="extra"),
        "missing-field": lambda: output.pop("request_digest"),
        "missing-row": lambda: output["predictions"].pop(),
        "extra-row": lambda: output["predictions"].append(output["predictions"][0]),
        "reordered-rows": lambda: output["predictions"].reverse(),
        "duplicate-row": lambda: output["predictions"][1].update(
            row_id=output["predictions"][0]["row_id"]
        ),
        "boolean-score": lambda: output["predictions"][0].update(score=True),
        "nan-score": lambda: output["predictions"][0].update(score=float("nan")),
        "inf-score": lambda: output["predictions"][0].update(score=float("inf")),
        "negative-score": lambda: output["predictions"][0].update(score=-0.1),
        "large-score": lambda: output["predictions"][0].update(score=1.1),
        "oversized-response": lambda: output.update(untrusted="x" * MAX_BYTES),
        "wrong-version": lambda: output.update(schema_version=999),
        "wrong-batch": lambda: output.update(batch_id="0" * 32),
        "wrong-model": lambda: output.update(model_digest="0" * 64),
        "wrong-request": lambda: output.update(request_digest="0" * 64),
        "unsupported-scan": lambda: output["scan"].update(unsupported=1),
    }
    if name not in mutations:
        raise Rejected("unknown_authority_fault")
    mutations[name]()
    return output


def evaluation_snapshot(client):
    with storage.connect(client) as connection:
        rows = connection.execute(
            "SELECT sha256 FROM ml.evaluations ORDER BY sha256 LIMIT 10001"
        ).fetchall()
    if len(rows) > 10000:
        raise Rejected("authority_history_fixture_limit")
    return [row[0] for row in rows]


def qualify(request):
    require_fields(request, ("schema_version", "profile", "candidate_reference", "trust"))
    if type(request["schema_version"]) is not int or request["schema_version"] != 1:
        raise Rejected("authority_probe_schema")
    profile = request["profile"]
    validate_profile(profile)
    root = Path(__file__).resolve().parents[1]
    if profile["source_fingerprint"] != source_fingerprint(root):
        raise Rejected("authority_probe_source_stale")
    process_state("scorer")
    client = Path("/client")
    policy = read_json(root / "policies/local-cpu.json")
    candidate = request["candidate_reference"]
    record, metadata, _ = storage_pipeline.load_candidate(client, candidate, policy)
    if metadata["image_id"] != profile["image_id"]:
        raise Rejected("authority_probe_candidate_image")
    cases, executions, positive = [], [], []
    previous = None
    history_before = evaluation_snapshot(client)

    def confirmed(name, condition, expected=True, actual=True):
        if not condition:
            raise Rejected(f"authority_output_failed:{name}")
        cases.append({"id": name, "status": "pass", "expected": expected, "actual": actual})

    for name in ("positive-before", *MUTATIONS, "positive-after"):
        snapshot = evaluation_snapshot(client)
        clean_response = None

        def executor(image, payload):
            nonlocal clean_response
            confirmed(f"{name}:image-bound", image == profile["image_id"])
            validate_request(payload)
            confirmed(f"{name}:features-without-labels-or-credentials", True)
            output, execution = run(profile, "scorer", payload, timeout=60)
            confirmed(
                f"{name}:real-worker-execution",
                execution["backend"] == "scoped-kubernetes-controller"
                and execution["image_id"] == image
                and execution["namespace"] == "ml-eval"
                and execution["input_digest"] == digest(canonical(payload)),
            )
            validate_scan(output["scan"])
            confirmed(
                f"{name}:clean-output-before-injection",
                output
                == response(
                    payload,
                    [row["score"] for row in output["predictions"]],
                    output["scan"],
                ),
            )
            clean_response = output
            executions.append({"case": name, "execution": execution})
            return (corrupt(name, output, previous) if name in MUTATIONS else output), execution

        with (
            patch("mlsecops.storage_pipeline.sign", wraps=storage_pipeline.sign) as signer,
            patch("mlsecops.storage.put", wraps=storage.put) as writer,
        ):
            try:
                evaluated = storage_pipeline.evaluate(
                    client,
                    candidate,
                    policy,
                    profile["image_id"],
                    request["trust"],
                    Path("/signer/key.pem"),
                    executor,
                )
            except Rejected as error:
                confirmed(
                    f"{name}:exact-rejection",
                    name in MUTATIONS and str(error) == MUTATIONS[name],
                    MUTATIONS.get(name),
                    str(error),
                )
                confirmed(f"{name}:no-sign-or-write", signer.call_count == writer.call_count == 0)
                confirmed(f"{name}:history-unchanged", evaluation_snapshot(client) == snapshot)
            else:
                confirmed(f"{name}:positive-only", name not in MUTATIONS)
                confirmed(
                    f"{name}:real-sign-and-write", signer.call_count == writer.call_count == 1
                )
                envelope = decode(
                    storage.get(client, "evaluations", evaluated["evaluation_reference"])
                )
                confirmed(
                    f"{name}:persisted-signature",
                    verify(envelope, "stored-evaluation", request["trust"]["evaluator"])
                    == evaluated["evaluation"],
                )
                confirmed(
                    f"{name}:single-new-row",
                    set(evaluation_snapshot(client)) - set(snapshot)
                    == {evaluated["evaluation_reference"]},
                )
                positive.append(evaluated)
                if previous is None:
                    previous = clean_response
    confirmed("all-native-batches-executed", len(executions) == len(MUTATIONS) + 2)
    confirmed(
        "unique-worker-pods",
        len({item["execution"]["pod_uid"] for item in executions}) == len(executions),
    )
    confirmed(
        "exact-positive-history-delta",
        set(evaluation_snapshot(client))
        == set(history_before) | {item["evaluation_reference"] for item in positive}
        and len(positive) == 2,
    )
    return {
        "schema_version": 1,
        "status": "pass",
        "scope": "native-scorer-receive-boundary-fault-injection",
        "observed_at": now(),
        "source_fingerprint": source_fingerprint(root),
        "image_id": profile["image_id"],
        "candidate_reference": candidate,
        "dataset_reference": record["dataset_reference"],
        "model_digest": metadata["model_digest"],
        "policy_digest": digest(canonical(policy)),
        "process": process_state("scorer"),
        "negative_batches": len(MUTATIONS),
        "positive_evaluations": positive,
        "executions": executions,
        "cases": cases,
        "checks": len(cases),
        "release_ready": False,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Synthetic-only real scorer output fault injection"
    )
    parser.add_argument("--request", type=Path, required=True)
    arguments = parser.parse_args()
    print(canonical(qualify(read_json(arguments.request))).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
