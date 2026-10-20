import copy
from contextlib import redirect_stderr, redirect_stdout

from mlsecops import worker_transport
from mlsecops.contracts import Rejected, canonical, decode, require_fields
from scripts.serving_privacy_probe import MAX_CAPTURE, LifecycleCapture

SCOPE = "serving-lifecycle-output-privacy-not-full-M13"
CASE = "full-lifecycle-output-privacy"
REPORT_FIELDS = (
    "schema_version",
    "scope",
    "status",
    "release_ready",
    "full_M12",
    "campaign_id",
    "started_at",
    "finished_at",
    "source",
    "source_dirty",
    "cases",
    "proposal_reference",
    "subject_sha256",
    "model_sha256",
    "candidate_reference",
    "evaluation_reference",
    "qualification_permit_sha256",
    "runtime",
    "reference_response_sha256",
    "limitations",
)


def produce(operation):
    needles = []

    def observe(values):
        if (
            needles
            or type(values) is not tuple
            or len(values) != 6
            or any(type(value) is not bytes or not 1 <= len(value) <= 4096 for value in values)
        ):
            raise Rejected("serving_output_observer_invalid")
        needles.extend(values)

    output, diagnostic = LifecycleCapture(), LifecycleCapture()
    with redirect_stdout(output), redirect_stderr(diagnostic):
        try:
            result = operation(observe)
            payload = canonical(result)
        finally:
            output.seal()
            diagnostic.seal()
    if not needles or output.overflow or diagnostic.overflow:
        raise Rejected("serving_output_capture_incomplete")
    streams = (output.getvalue().encode(), diagnostic.getvalue().encode(), payload)
    if any(needle in content for content in streams for needle in needles):
        raise Rejected("serving_output_canary")
    return {
        "native": decode(payload),
        "observation": {
            "schema_version": 1,
            "scope": SCOPE,
            "status": "inconclusive",
            "release_ready": False,
            "canary_count": len(needles),
            "stdout_characters": output.size,
            "stderr_characters": diagnostic.size,
        },
    }


def observe(envelope, expected):
    value, diagnostic = worker_transport.unwrap(envelope)
    require_fields(value, ("native", "observation"))
    summary = value["observation"]
    require_fields(
        summary,
        (
            "schema_version",
            "scope",
            "status",
            "release_ready",
            "canary_count",
            "stdout_characters",
            "stderr_characters",
        ),
    )
    if (
        diagnostic["bytes"] != 0
        or diagnostic["gpu_discovery_warning"]
        or type(summary["schema_version"]) is not int
        or summary["schema_version"] != 1
        or summary["scope"] != SCOPE
        or summary["status"] != "inconclusive"
        or summary["release_ready"] is not False
        or type(summary["canary_count"]) is not int
        or summary["canary_count"] != 6
        or any(
            type(summary[name]) is not int or not 0 <= summary[name] <= MAX_CAPTURE
            for name in ("stdout_characters", "stderr_characters")
        )
    ):
        raise Rejected("serving_output_observation_invalid")
    report = value["native"]
    require_fields(report, REPORT_FIELDS)
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] != 1
        or report["scope"] != "actual-candidate-serving-qualification-not-release-approval"
        or report["status"] != "pass"
        or report["release_ready"] is not False
        or report["source_dirty"] is not False
        or report["source"] != expected
        or report["full_M12"] != "inconclusive"
        or type(report["cases"]) is not list
        or not 1 <= len(report["cases"]) <= 5000
        or any(type(case) is not str for case in report["cases"])
        or len(set(report["cases"])) != len(report["cases"])
        or CASE in report["cases"]
    ):
        raise Rejected("serving_output_report_invalid")
    runtime = report["runtime"]
    if (
        any(
            runtime[name]["status"] != "pass"
            for name in ("http_privacy", "http_correlation", "public_audit_window")
        )
        or runtime["http_privacy"]["request_cases"] != 12
        or runtime["http_privacy"]["audit_events_confirmed"] != 36
        or runtime["http_privacy"]["approved_metric_series"] != 69
        or "output_privacy" in runtime
    ):
        raise Rejected("serving_output_components_incomplete")
    result = copy.deepcopy(report)
    result["cases"].append(CASE)
    result["runtime"]["output_privacy"] = {
        **summary,
        "status": "pass",
        "fd_lifecycle_complete": True,
        "native_stderr_bytes": 0,
    }
    return result
