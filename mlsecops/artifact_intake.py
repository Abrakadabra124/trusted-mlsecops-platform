import importlib.metadata
import re
import secrets
import subprocess
from datetime import datetime

from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    require_fields,
    safe_child,
)
from mlsecops.prediction_protocol import MAX_BYTES, validate_scan
from mlsecops.signing import decode64, encode64

REASONS = {
    "model_size_rejected",
    "model_parse_rejected",
    "model_structure_rejected",
    "model_interface_rejected",
    "model_tensor_interface_rejected",
    "model_topology_rejected",
    "model_attribute_contract_rejected",
    "model_parameter_rejected",
    "model_binary_classifier_rejected",
    "model_unknown_fields_rejected",
    "model_check_rejected",
    "model_profile_rejected",
}
RESPONSE_FIELDS = (
    "schema_version",
    "action",
    "inspection_id",
    "model_digest",
    "bytes",
    "request_digest",
    "tool",
    "status",
    "reason",
    "inspected",
    "unsupported",
    "skipped",
    "errors",
    "approved_outputs",
    "scan",
)
REPORT_FIELDS = (
    "schema_version",
    "inspection_id",
    "model_digest",
    "bytes",
    "request_digest",
    "tool",
    "status",
    "reason",
    "inspected",
    "unsupported",
    "skipped",
    "errors",
    "approved_outputs",
    "scan",
    "image_id",
    "origin",
    "response_digest",
    "started_at",
    "finished_at",
)


class IntakeFailure(Rejected):
    def __init__(self, report):
        super().__init__("model_intake_" + report["status"])
        self.report = report


def tool_profile():
    return {
        "name": "onnx-linear-profile",
        "version": importlib.metadata.version("onnx"),
        "policy": "linear-onnx-v2",
    }


def request_for(content, inspection_id):
    if type(content) is not bytes or not 0 < len(content) <= MAX_BYTES:
        raise Rejected("intake_content_limit")
    if type(inspection_id) is not str or not re.fullmatch(r"[0-9a-f]{32}", inspection_id):
        raise Rejected("intake_request_identity")
    request = {
        "schema_version": 1,
        "action": "inspect",
        "inspection_id": inspection_id,
        "model": encode64(content),
        "model_digest": digest(content),
    }
    if len(canonical(request)) > MAX_BYTES:
        raise Rejected("intake_request_limit")
    return request


def validate_request(request):
    require_fields(request, ("schema_version", "action", "inspection_id", "model", "model_digest"))
    if type(request["schema_version"]) is not int or len(canonical(request)) > MAX_BYTES:
        raise Rejected("intake_request_contract")
    content = decode64(request["model"])
    if request != request_for(content, request["inspection_id"]):
        raise Rejected("intake_request_binding")
    return content


def response(request, scan=None, reason=None):
    content = validate_request(request)
    if reason is None:
        validate_scan(scan)
    elif type(reason) is not str or reason not in REASONS:
        raise Rejected("intake_reason_contract")
    passed = reason is None
    return {
        "schema_version": 1,
        "action": "inspect",
        "inspection_id": request["inspection_id"],
        "model_digest": digest(content),
        "bytes": len(content),
        "request_digest": digest(canonical(request)),
        "tool": tool_profile(),
        "status": "pass" if passed else "fail",
        "reason": reason,
        "inspected": 1 if passed else 0,
        "unsupported": 0,
        "skipped": 0,
        "errors": 0 if passed else 1,
        "approved_outputs": [digest(content)] if passed else [],
        "scan": scan if passed else None,
    }


def checked_response(output, request):
    if len(canonical(output)) > 65536:
        raise Rejected("intake_response_limit")
    require_fields(output, RESPONSE_FIELDS)
    if any(
        type(output[name]) is not int
        for name in ("schema_version", "bytes", "inspected", "unsupported", "skipped", "errors")
    ):
        raise Rejected("intake_response_contract")
    expected = response(request, output["scan"], output["reason"])
    if canonical(output) != canonical(expected):
        raise Rejected("intake_response_binding")
    return decode(canonical(output))


def validate_receipt(report, content, image_id):
    require_fields(report, REPORT_FIELDS)
    request = request_for(content, report["inspection_id"])
    expected = response(request, report["scan"])
    return _validate_report(report, expected, image_id, "worker")


def validate_failure(report, content, image_id):
    require_fields(report, REPORT_FIELDS)
    if report["status"] not in ("fail", "inconclusive"):
        raise Rejected("intake_denial_status_invalid")
    request = request_for(content, report["inspection_id"])
    origin = report["origin"]
    if origin == "worker":
        expected = response(request, reason=report["reason"])
    elif origin == "controller":
        outcomes = {
            "scanner_protocol_rejected": "fail",
            "scanner_unavailable": "inconclusive",
            "scanner_timeout": "inconclusive",
            "scanner_crash": "inconclusive",
        }
        if type(report["reason"]) is not str or report["reason"] not in outcomes:
            raise Rejected("intake_denial_reason_invalid")
        expected = response(request, reason="model_profile_rejected")
        expected.update(reason=report["reason"], status=outcomes[report["reason"]], skipped=1)
    else:
        raise Rejected("intake_denial_origin_invalid")
    return _validate_report(report, expected, image_id, origin)


def _validate_report(report, expected, image_id, origin):
    if (
        report["origin"] != origin
        or report["image_id"] != image_id
        or report["response_digest"]
        != (digest(canonical(expected)) if origin == "worker" else None)
        or canonical({name: report[name] for name in RESPONSE_FIELDS if name != "action"})
        != canonical({name: expected[name] for name in RESPONSE_FIELDS if name != "action"})
    ):
        raise Rejected("intake_receipt_binding")
    try:
        started, finished = (
            datetime.fromisoformat(report[name]) for name in ("started_at", "finished_at")
        )
        if started.tzinfo is None or finished.tzinfo is None or started > finished:
            raise ValueError
    except (TypeError, ValueError):
        raise Rejected("intake_receipt_time") from None
    return report


def inspect_candidate(content, expected_digest, image, expected_image, executor):
    request = request_for(content, secrets.token_hex(16))
    if expected_digest != request["model_digest"]:
        raise Rejected("intake_subject_mismatch")
    if type(expected_image) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_image):
        raise Rejected("intake_image_profile")
    started = now()
    report = {
        **response(request, reason="model_profile_rejected"),
        "image_id": expected_image,
        "origin": "controller",
        "response_digest": None,
        "started_at": started,
        "finished_at": started,
    }
    report.pop("action")
    try:
        output, execution = executor(image, decode(canonical(request)))
    except (Rejected, OSError, subprocess.TimeoutExpired) as error:
        report.update(
            status="inconclusive", reason="scanner_unavailable", skipped=1, finished_at=now()
        )
        if isinstance(error, subprocess.TimeoutExpired) or (
            isinstance(error, Rejected)
            and str(error)
            in {
                "worker_deadline",
                "worker_transport_deadline",
                "controller_worker_wait_deadline",
                "controller_worker_deadline",
            }
        ):
            report["reason"] = "scanner_timeout"
        elif isinstance(error, Rejected) and str(error) in {
            "worker_failed",
            "worker_process_failed",
            "controller_worker_failed",
        }:
            report["reason"] = "scanner_crash"
        raise IntakeFailure(report) from None
    try:
        if (
            not isinstance(execution, dict)
            or execution.get("image_id") != expected_image
            or (
                "input_digest" in execution
                and execution["input_digest"] != digest(canonical(request))
            )
        ):
            raise Rejected("intake_execution_binding")
        output = checked_response(output, request)
    except (Rejected, TypeError, ValueError, RecursionError):
        report.update(
            status="fail", reason="scanner_protocol_rejected", skipped=1, finished_at=now()
        )
        raise IntakeFailure(report) from None
    report.update({name: value for name, value in output.items() if name != "action"})
    report.update(origin="worker", response_digest=digest(canonical(output)), finished_at=now())
    if report["status"] != "pass":
        raise IntakeFailure(report)
    validate_receipt(report, content, expected_image)
    return report


def inspect_file(root, relative, expected_digest, image, expected_image, executor):
    path = safe_child(root, relative)
    content = bounded_read(path, MAX_BYTES)
    report = inspect_candidate(content, expected_digest, image, expected_image, executor)
    if bounded_read(safe_child(root, relative), MAX_BYTES) != content:
        raise Rejected("intake_input_changed")
    return content, report
