import importlib.metadata
import re
import secrets

import numpy as np

from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.datasets import validate_features
from mlsecops.signing import decode64, encode64

MAX_BYTES = 16 * 1024 * 1024


def validate_scores(scores, count):
    if not isinstance(scores, list) or len(scores) != count:
        raise Rejected("prediction_count_mismatch")
    if any(type(score) not in (float, int) or not 0 <= score <= 1 for score in scores):
        raise Rejected("invalid_probability")
    return np.asarray(scores, dtype=float)


def validate_request(request):
    require_fields(
        request, ("schema_version", "action", "model", "features", "batch_id", "row_ids")
    )
    if len(canonical(request)) > MAX_BYTES:
        raise Rejected("prediction_request_limit")
    if (
        type(request["schema_version"]) is not int
        or request["schema_version"] != 2
        or request["action"] != "predict"
        or not isinstance(request["batch_id"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", request["batch_id"])
    ):
        raise Rejected("prediction_request_contract")
    validate_features(request["features"])
    expected = [f"{request['batch_id']}:{index}" for index in range(len(request["features"]))]
    if request["row_ids"] != expected:
        raise Rejected("prediction_request_row_binding")
    return decode64(request["model"])


def response(request, scores, scan):
    content = validate_request(request)
    validate_scores(scores, len(request["row_ids"]))
    return {
        "schema_version": 2,
        "action": "predict",
        "batch_id": request["batch_id"],
        "request_digest": digest(canonical(request)),
        "model_digest": digest(content),
        "predictions": [
            {"row_id": identifier, "score": score}
            for identifier, score in zip(request["row_ids"], scores, strict=True)
        ],
        "scan": scan,
    }


def validate_scan(scan):
    require_fields(
        scan,
        (
            "format",
            "inspected_nodes",
            "unsupported",
            "skipped",
            "errors",
            "policy_version",
            "onnx_version",
        ),
    )
    if (
        scan["format"] != "onnx"
        or scan["policy_version"] != "linear-onnx-v1"
        or scan["onnx_version"] != importlib.metadata.version("onnx")
        or type(scan["inspected_nodes"]) is not int
        or not 1 <= scan["inspected_nodes"] <= 16
        or any(
            type(scan[name]) is not int or scan[name] != 0
            for name in ("unsupported", "skipped", "errors")
        )
    ):
        raise Rejected("prediction_scan_contract")


class PredictionBatch:
    def __init__(self, model, features):
        if not isinstance(model, bytes) or len(model) > MAX_BYTES:
            raise Rejected("prediction_model_transport_limit")
        validate_features(features)
        batch_id = secrets.token_hex(16)
        request = {
            "schema_version": 2,
            "action": "predict",
            "model": encode64(model),
            "features": features,
            "batch_id": batch_id,
            "row_ids": [f"{batch_id}:{index}" for index in range(len(features))],
        }
        self._request = canonical(request)
        if len(self._request) > MAX_BYTES:
            raise Rejected("prediction_request_limit")
        self._model_digest = digest(model)
        self._consumed = False

    @property
    def request(self):
        return decode(self._request, MAX_BYTES)

    def consume(self, output):
        if self._consumed:
            raise Rejected("prediction_batch_already_consumed")
        self._consumed = True
        content = canonical(output)
        if len(content) > MAX_BYTES:
            raise Rejected("prediction_response_limit")
        output = decode(content, MAX_BYTES)
        require_fields(
            output,
            (
                "schema_version",
                "action",
                "batch_id",
                "request_digest",
                "model_digest",
                "predictions",
                "scan",
            ),
        )
        request = self.request
        request_digest = digest(self._request)
        if (
            type(output["schema_version"]) is not int
            or output["schema_version"] != 2
            or output["action"] != "predict"
            or output["batch_id"] != request["batch_id"]
            or output["request_digest"] != request_digest
            or output["model_digest"] != self._model_digest
        ):
            raise Rejected("prediction_response_binding")
        records = output["predictions"]
        if not isinstance(records, list) or len(records) != len(request["row_ids"]):
            raise Rejected("prediction_count_mismatch")
        for record, identifier in zip(records, request["row_ids"], strict=True):
            require_fields(record, ("row_id", "score"))
            if record["row_id"] != identifier:
                raise Rejected("prediction_response_row_binding")
        scores = validate_scores([record["score"] for record in records], len(records))
        validate_scan(output["scan"])
        return (
            scores,
            output["scan"],
            {
                "schema_version": 2,
                "batch_id": request["batch_id"],
                "model_digest": self._model_digest,
                "request_digest": request_digest,
                "response_digest": digest(content),
                "rows": len(records),
            },
        )
