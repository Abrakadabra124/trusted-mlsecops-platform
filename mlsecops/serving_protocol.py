import importlib.metadata
import re
import secrets

from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.datasets import validate_features
from mlsecops.prediction_protocol import validate_scan, validate_scores
from mlsecops.signing import decode64, encode64

MAX_MODEL = 8 * 1024 * 1024
MAX_LOAD = 12 * 1024 * 1024
MAX_FRAME = 64 * 1024
COMMON = ("schema_version", "action", "session_id", "model_sha256", "request_id")


def frame(source, limit):
    content = source.readline(limit + 1)
    if not content:
        return None
    if len(content) > limit or not content.endswith(b"\n"):
        raise Rejected("serving_frame_limit")
    value = decode(content, limit)
    if content != canonical(value) + b"\n":
        raise Rejected("serving_frame_noncanonical")
    return value


def validate(request):
    if not isinstance(request, dict):
        raise Rejected("serving_request_schema")
    action = request.get("action")
    extra = {"load": ("model",), "predict": ("features",), "ping": ()}
    if not isinstance(action, str) or action not in extra:
        raise Rejected("serving_action_invalid")
    require_fields(request, (*COMMON, *extra[action]))
    if type(request["schema_version"]) is not int or request["schema_version"] != 1:
        raise Rejected("serving_protocol_version")
    for name, width in (("session_id", 32), ("request_id", 32), ("model_sha256", 64)):
        value = request[name]
        if not isinstance(value, str) or re.fullmatch(rf"[a-f0-9]{{{width}}}", value) is None:
            raise Rejected("serving_protocol_binding")
    if len(canonical(request)) + 1 > (MAX_LOAD if action == "load" else MAX_FRAME):
        raise Rejected("serving_frame_limit")
    if action == "load":
        content = decode64(request["model"])
        if not 0 < len(content) <= MAX_MODEL or digest(content) != request["model_sha256"]:
            raise Rejected("serving_model_integrity")
        return content
    if action == "predict":
        try:
            validate_features(request["features"], max_rows=100)
        except (OverflowError, TypeError):
            raise Rejected("serving_feature_type") from None
    return None


def load_request(model):
    if not isinstance(model, bytes) or not 0 < len(model) <= MAX_MODEL:
        raise Rejected("serving_model_size")
    result = {
        "schema_version": 1,
        "action": "load",
        "session_id": secrets.token_hex(16),
        "request_id": secrets.token_hex(16),
        "model_sha256": digest(model),
        "model": encode64(model),
    }
    validate(result)
    return result


def request(binding, action, features=None):
    result = {
        "schema_version": 1,
        "action": action,
        "session_id": binding["session_id"],
        "model_sha256": binding["model_sha256"],
        "request_id": secrets.token_hex(16),
    }
    if action == "predict":
        result["features"] = features
    validate(result)
    return result


def response(request, **fields):
    return {
        **{name: request[name] for name in COMMON},
        "request_sha256": digest(canonical(request)),
        **fields,
    }


def verify_reply(request, reply):
    validate(request)
    action = request["action"]
    extra = {
        "load": ("ready", "scan", "runtime_version"),
        "ping": ("ready",),
        "predict": ("predictions",),
    }
    require_fields(reply, (*COMMON, "request_sha256", *extra[action]))
    expected = response(request)
    if canonical({name: reply[name] for name in expected}) != canonical(expected):
        raise Rejected("serving_reply_binding")
    if action in ("load", "ping"):
        if reply["ready"] is not True:
            raise Rejected("serving_worker_not_ready")
        if action == "load":
            validate_scan(reply["scan"])
            if reply["runtime_version"] != importlib.metadata.version("onnxruntime"):
                raise Rejected("serving_runtime_version")
        return None
    predictions = reply["predictions"]
    if not isinstance(predictions, list) or len(predictions) != len(request["features"]):
        raise Rejected("serving_prediction_count")
    scores = []
    for index, prediction in enumerate(predictions):
        require_fields(prediction, ("row_id", "score"))
        if prediction["row_id"] != f"{request['request_id']}:{index}":
            raise Rejected("serving_prediction_order")
        scores.append(prediction["score"])
    return validate_scores(scores, len(request["features"])).tolist()
