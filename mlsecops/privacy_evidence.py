import math
import re
from datetime import datetime

from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields

SUBJECT_FIELDS = (
    "proposal_reference",
    "subject_sha256",
    "model_sha256",
    "candidate_reference",
    "evaluation_reference",
)
REQUIRED_CASES = frozenset(
    (
        "original-signed-proposal-bound",
        "actual-release-remains-denied-without-assurance",
        "qualification-permit-is-not-release-approval",
        "source-candidate-loaded-without-resigning",
        "http-missing-auth-401",
        "independent-client-burst-boundary",
        "client-quota-refill-recovers",
        "client-admission-accounting",
        "primary-client-remains-available",
        "foreign-client-identity-401",
        "audit-http-pair-accepted",
        "audit-http-pair-durable",
        "privacy-http-input-and-output-matrix",
        "privacy-owned-audit-input-absent",
        "privacy-native-telemetry-disabled",
        "privacy-approved-metrics-cardinality",
        "closed-audit-private-primary-material-correlation",
        "closed-audit-public-export-schema-counters-and-canaries",
        "closed-audit-export-not-release-approval",
        "qualification-authority-and-private-key-removed",
        "source-cas-budget-envelopes-and-checkout-unchanged",
        "full-lifecycle-output-privacy",
    )
)


def _hex(value, length):
    if type(value) is not str or re.fullmatch(f"[a-f0-9]{{{length}}}", value) is None:
        raise Rejected("privacy_evidence_digest")


def _time(value):
    try:
        if type(value) is not str or len(value) > 64:
            raise ValueError
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError
        return parsed
    except ValueError:
        raise Rejected("privacy_evidence_timestamp") from None


def _count(value, maximum=65536, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise Rejected("privacy_evidence_counter")
    return value


def _fixed(value, constants, dynamic=()):
    require_fields(value, (*constants, *dynamic))
    if canonical({name: value[name] for name in constants}) != canonical(constants):
        raise Rejected("privacy_evidence_component")


def _component(value, scope, constants, dynamic=(), *, schema=False):
    fixed = {"scope": scope, "status": "pass", "release_ready": False, **constants}
    if schema:
        fixed["schema_version"] = 1
    _fixed(value, fixed, dynamic)


def checked_candidate(content, *, expected_source, expected_subject, started_at, observed_at):
    if type(content) is not bytes:
        raise Rejected("privacy_evidence_bytes")
    report = decode(content, 1024 * 1024)
    require_fields(
        report,
        (
            *SUBJECT_FIELDS,
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
            "qualification_permit_sha256",
            "runtime",
            "reference_response_sha256",
            "limitations",
        ),
    )
    require_fields(expected_source, ("image_id", "source_revision", "source_fingerprint"))
    require_fields(expected_subject, SUBJECT_FIELDS)
    _hex(expected_source["source_revision"], 40)
    _hex(expected_source["source_fingerprint"], 64)
    image = expected_source["image_id"]
    if type(image) is not str or not image.startswith("sha256:"):
        raise Rejected("privacy_evidence_image")
    _hex(image[7:], 64)
    for reference in expected_subject.values():
        _hex(reference, 64)
    constants = {
        "schema_version": 1,
        "scope": "actual-candidate-serving-qualification-not-release-approval",
        "status": "pass",
        "release_ready": False,
        "full_M12": "inconclusive",
        "source_dirty": False,
        "source": expected_source,
        **expected_subject,
    }
    if canonical({name: report[name] for name in constants}) != canonical(constants):
        raise Rejected("privacy_evidence_binding")
    _hex(report["campaign_id"], 32)
    _hex(report["qualification_permit_sha256"], 64)
    _hex(report["reference_response_sha256"], 64)
    if not (
        _time(started_at)
        <= _time(report["started_at"])
        <= _time(report["finished_at"])
        <= _time(observed_at)
    ):
        raise Rejected("privacy_evidence_not_fresh")
    cases = report["cases"]
    if (
        type(cases) is not list
        or not 1 <= len(cases) <= 5000
        or any(
            type(name) is not str or re.fullmatch("[A-Za-z0-9][A-Za-z0-9-]{0,127}", name) is None
            for name in cases
        )
        or len(set(cases)) != len(cases)
        or not REQUIRED_CASES <= set(cases)
    ):
        raise Rejected("privacy_evidence_cases")
    limitations = report["limitations"]
    if (
        type(limitations) is not list
        or not 1 <= len(limitations) <= 64
        or any(type(value) is not str or not 1 <= len(value) <= 4096 for value in limitations)
    ):
        raise Rejected("privacy_evidence_limitations")
    runtime = report["runtime"]
    required = {
        "http_audit",
        "http_privacy",
        "client_quota",
        "http_correlation",
        "public_audit_window",
        "output_privacy",
    }
    if type(runtime) is not dict or not required <= runtime.keys():
        raise Rejected("privacy_evidence_runtime")
    _component(
        runtime["http_audit"],
        "actual-candidate-http-audit-pair-not-full-M13",
        {"accepted_delta": 8, "durable_delta": 8},
    )
    _component(
        runtime["http_privacy"],
        "existing-serving-output-privacy-not-full-M13",
        {
            "request_cases": 12,
            "audit_events_confirmed": 36,
            "approved_metric_series": 69,
            "ambient_signals_used": False,
        },
        ("audit_files_scanned",),
    )
    _count(runtime["http_privacy"]["audit_files_scanned"], 66, 1)
    _component(
        runtime["output_privacy"],
        "serving-lifecycle-output-privacy-not-full-M13",
        {"canary_count": 6, "native_stderr_bytes": 0, "fd_lifecycle_complete": True},
        ("stdout_characters", "stderr_characters"),
        schema=True,
    )
    for field in ("stdout_characters", "stderr_characters"):
        _count(runtime["output_privacy"][field])
    _fixed(
        runtime["client_quota"],
        {
            "status": "pass",
            "release_ready": False,
            "boundary_statuses": [422, 429, 422, 429],
            "refill_statuses": [200, 200],
            "admitted_deltas": [2, 2, 4],
        },
        ("window_seconds",),
    )
    elapsed = runtime["client_quota"]["window_seconds"]
    if type(elapsed) not in (int, float) or not 0 <= elapsed < 1 or not math.isfinite(elapsed):
        raise Rejected("privacy_evidence_quota_window")
    correlation, public = runtime["http_correlation"], runtime["public_audit_window"]
    _component(
        correlation,
        "candidate-qualification-private-correlation-not-full-M13",
        {"failed_after_intent": 0},
        ("events", "correlated_requests", "completed_200", "without_context"),
        schema=True,
    )
    _component(
        public,
        "serving-audit-public-window-not-full-M13",
        {},
        ("events", "requests", "routes", "context_kinds"),
        schema=True,
    )
    _fixed(public["requests"], {"aborted": 0, "unresolved": 0}, ("completed",))
    _fixed(
        public["context_kinds"],
        {"release-selection": 0},
        ("candidate-qualification", "none"),
    )
    require_fields(public["routes"], ("predict", "ready"))
    events = _count(correlation["events"], minimum=1)
    correlated = _count(correlation["correlated_requests"], 16384, 7)
    completed = _count(public["requests"]["completed"], 16384, 15)
    predicted = _count(public["routes"]["predict"], 16384, 13)
    ready = _count(public["routes"]["ready"], 16384, 2)
    if (
        _count(public["events"], minimum=1) != events
        or _count(correlation["completed_200"], 16384, 1) != correlated
        or _count(correlation["without_context"], 16384, 8) + correlated != completed
        or _count(public["context_kinds"]["candidate-qualification"], 16384) != correlated
        or _count(public["context_kinds"]["none"], 16384) != completed - correlated
        or predicted + ready != completed
        or events != 4 * completed
    ):
        raise Rejected("privacy_evidence_accounting")
    return {
        "schema_version": 1,
        "scope": "checked-candidate-privacy-evidence-not-full-M13",
        "status": "pass",
        "release_ready": False,
        "receipt_sha256": digest(canonical(report)),
        "request_count": completed,
        "correlated_requests": correlated,
        "events": events,
    }
