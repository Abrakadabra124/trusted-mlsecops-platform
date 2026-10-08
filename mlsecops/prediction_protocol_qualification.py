import argparse
import copy
import importlib.metadata
import sys
from pathlib import Path
from unittest.mock import patch

from mlsecops import storage_pipeline
from mlsecops.contracts import Rejected, canonical, digest, now, read_json, write_json
from mlsecops.inventory import source_fingerprint
from mlsecops.prediction_protocol import MAX_BYTES, PredictionBatch, response, validate_request


def qualify():
    cases = []
    content = b"protocol-fixture-not-a-loaded-model"
    features = [[value] * 6 for value in (0.1, 0.2, 0.8, 0.9)]
    probabilities = [0.1, 0.9, 0.2, 0.8]
    scan = {
        "format": "onnx",
        "inspected_nodes": 3,
        "unsupported": 0,
        "skipped": 0,
        "errors": 0,
        "policy_version": "linear-onnx-v1",
        "onnx_version": importlib.metadata.version("onnx"),
    }

    def confirmed(name, condition):
        if not condition:
            raise Rejected(f"prediction_protocol_qualification_failed:{name}")
        cases.append({"id": name, "status": "pass"})

    def rejected(name, action):
        try:
            action()
        except Rejected:
            confirmed(name, True)
        else:
            confirmed(name, False)

    def fixture():
        batch = PredictionBatch(content, features)
        return batch, response(batch.request, probabilities, copy.deepcopy(scan))

    batch, valid = fixture()
    scores, observed_scan, proof = batch.consume(valid)
    confirmed("scores-and-scan", scores.tolist() == probabilities and observed_scan == scan)
    confirmed(
        "bound-evidence",
        proof["request_digest"] == digest(canonical(batch.request))
        and proof["response_digest"] == digest(canonical(valid))
        and proof["rows"] == 4
        and proof["schema_version"] == 2,
    )
    rejected("consume-once", lambda: batch.consume(valid))
    another = PredictionBatch(content, features)
    confirmed("fresh-batch-id", batch.request["batch_id"] != another.request["batch_id"])
    rejected("cross-batch-replay", lambda: another.consume(valid))
    batch, valid = fixture()
    copy_of_request = batch.request
    copy_of_request["features"][0][0] = 0.6
    confirmed("immutable-pending-request", batch.request["features"][0][0] == 0.1)

    mutations = [
        ("wrong-version", lambda item: item.update(schema_version=999)),
        ("boolean-version", lambda item: item.update(schema_version=True)),
        ("legacy-version", lambda item: item.update(schema_version=1)),
        ("wrong-action", lambda item: item.update(action="train")),
        ("wrong-batch", lambda item: item.update(batch_id="0" * 32)),
        ("wrong-model", lambda item: item.update(model_digest="0" * 64)),
        ("wrong-request", lambda item: item.update(request_digest="0" * 64)),
        ("extra-field", lambda item: item.update(raw_log="untrusted")),
        ("missing-field", lambda item: item.pop("request_digest")),
        ("missing-row", lambda item: item["predictions"].pop()),
        ("extra-row", lambda item: item["predictions"].append(item["predictions"][0])),
        ("reordered-rows", lambda item: item["predictions"].reverse()),
        (
            "duplicate-row",
            lambda item: item["predictions"][1].update(row_id=item["predictions"][0]["row_id"]),
        ),
        ("row-type", lambda item: item["predictions"].__setitem__(0, "raw text")),
        ("row-extra-field", lambda item: item["predictions"][0].update(explanation="untrusted")),
        ("row-missing-score", lambda item: item["predictions"][0].pop("score")),
        ("boolean-score", lambda item: item["predictions"][0].update(score=True)),
        ("nan-score", lambda item: item["predictions"][0].update(score=float("nan"))),
        ("inf-score", lambda item: item["predictions"][0].update(score=float("inf"))),
        ("negative-score", lambda item: item["predictions"][0].update(score=-0.1)),
        ("large-score", lambda item: item["predictions"][0].update(score=1.1)),
        ("huge-integer-score", lambda item: item["predictions"][0].update(score=10**100)),
        ("string-score", lambda item: item["predictions"][0].update(score="0.1")),
        ("scan-extra-field", lambda item: item["scan"].update(log="untrusted")),
        ("scan-missing-field", lambda item: item["scan"].pop("format")),
        ("scan-format", lambda item: item["scan"].update(format="pickle")),
        ("scan-policy", lambda item: item["scan"].update(policy_version="untrusted")),
        ("scan-version", lambda item: item["scan"].update(onnx_version="untrusted")),
        ("scan-zero", lambda item: item["scan"].update(inspected_nodes=0)),
        ("scan-boolean", lambda item: item["scan"].update(inspected_nodes=True)),
        ("scan-oversized", lambda item: item["scan"].update(inspected_nodes=17)),
        ("scan-unsupported", lambda item: item["scan"].update(unsupported=1)),
        ("scan-skipped", lambda item: item["scan"].update(skipped=1)),
        ("scan-errors", lambda item: item["scan"].update(errors=1)),
    ]
    for name, mutate in mutations:
        pending, output = fixture()
        original = copy.deepcopy(output)
        mutate(output)
        rejected(name, lambda: pending.consume(output))
        rejected(f"{name}:burned-batch", lambda: pending.consume(original))
    for name, invalid in (("raw-text", "arbitrary text"), ("array-response", [])):
        pending, _ = fixture()
        rejected(name, lambda: pending.consume(invalid))
    pending, output = fixture()
    output["untrusted"] = "x" * MAX_BYTES
    rejected("response-byte-limit", lambda: pending.consume(output))
    rejected("request-byte-limit", lambda: PredictionBatch(b"x" * MAX_BYTES, features))
    rejected("model-type", lambda: PredictionBatch("not-bytes", features))
    rejected("worker-score-count", lambda: response(batch.request, [0.1], scan))
    oversized_request = batch.request
    oversized_request["model"] = "A" * MAX_BYTES
    rejected("worker-request-byte-limit", lambda: validate_request(oversized_request))

    for name, mutate in (
        ("request-version", lambda item: item.update(schema_version=1)),
        ("request-boolean-version", lambda item: item.update(schema_version=True)),
        ("request-action", lambda item: item.update(action="train")),
        ("request-id", lambda item: item.update(batch_id="z" * 32)),
        ("request-short-id", lambda item: item.update(batch_id="a")),
        ("request-extra", lambda item: item.update(labels=[0, 1, 0, 1])),
        ("request-row-order", lambda item: item["row_ids"].reverse()),
        ("request-row-count", lambda item: item["row_ids"].pop()),
        ("request-feature-range", lambda item: item["features"][0].__setitem__(0, 2)),
        ("request-feature-type", lambda item: item["features"][0].__setitem__(0, True)),
        ("request-model-base64", lambda item: item.update(model="!invalid!")),
    ):
        invalid = batch.request
        mutate(invalid)
        rejected(name, lambda: validate_request(invalid))
    confirmed("worker-request-bytes", validate_request(batch.request) == content)

    root = Path(__file__).resolve().parents[1]
    policy = read_json(root / "policies/local-cpu.json")
    image = "sha256:" + "1" * 64
    metadata = {
        "image_id": image,
        "dataset_id": "2" * 64,
        "lineage_id": "3" * 64,
        "run_id": "4" * 32,
        "validation_parity_max_error": 0.0,
    }
    manifest = {"objects": {"holdout.json": {"sha256": "5" * 64}}}
    statement = {name: metadata[name] for name in ("dataset_id", "lineage_id")}
    holdout = [{"features": values, "label": index % 2} for index, values in enumerate(features)]

    def resolved_executor(reference, request):
        confirmed("image-alias-reaches-resolver", reference == "local-alias")
        return response(request, probabilities, scan), {"image_id": image}

    report = storage_pipeline.evaluate_verified_candidate(
        metadata, content, holdout, manifest, policy, "local-alias", resolved_executor
    )
    confirmed("observed-digest-not-input-alias", report["image_id"] == image)
    rejected(
        "wrong-observed-image",
        lambda: storage_pipeline.evaluate_verified_candidate(
            metadata,
            content,
            holdout,
            manifest,
            policy,
            "local-alias",
            lambda reference, request: (
                response(request, probabilities, scan),
                {"image_id": "sha256:" + "0" * 64},
            ),
        ),
    )
    for name, mutate in mutations:

        def executor(image, request):
            output = response(request, probabilities, copy.deepcopy(scan))
            mutate(output)
            return output, {"image_id": image}

        with (
            patch.object(
                storage_pipeline,
                "load_candidate",
                return_value=({"dataset_reference": "6" * 64}, metadata, content),
            ),
            patch.object(
                storage_pipeline.storage_dataset,
                "read_dataset",
                return_value=({"holdout": holdout}, manifest, statement),
            ),
            patch.object(storage_pipeline, "sign") as signer,
            patch.object(storage_pipeline.storage, "put") as publish,
        ):
            rejected(
                f"before-signing:{name}",
                lambda: storage_pipeline.evaluate(
                    Path("unused"),
                    "7" * 64,
                    policy,
                    image,
                    {"curator": "fixture", "source_approval_digest": "fixture"},
                    Path("unused.pem"),
                    executor,
                ),
            )
            confirmed(f"no-sign-or-publish:{name}", signer.call_count == publish.call_count == 0)
    return {
        "schema_version": 1,
        "status": "pass",
        "scope": "prediction-protocol-component-not-full-M20",
        "observed_at": now(),
        "source_fingerprint": source_fingerprint(root),
        "checks": len(cases),
        "cases": cases,
        "release_ready": False,
    }


def main():
    parser = argparse.ArgumentParser(description="Single-use ordered prediction contract checks")
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    arguments = parser.parse_args()
    if not (arguments.state / "workspace.json").is_file():
        print(
            "Prediction protocol qualification requires an initialized workspace", file=sys.stderr
        )
        return 2
    path = arguments.state / "evidence/prediction-protocol-qualification.json"
    write_json(path, {"status": "inconclusive", "reason": "running", "release_ready": False})
    try:
        report = qualify()
        write_json(path, report)
        print(canonical(report).decode())
        return 0
    except (Rejected, OSError) as error:
        write_json(path, {"status": "fail", "reason": str(error), "release_ready": False})
        print(f"Prediction protocol qualification rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
