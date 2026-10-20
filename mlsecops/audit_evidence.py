import base64
import binascii
import re

from mlsecops import audit_event, audit_export, audit_retention, audit_snapshot
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields

MAX_PACKET = audit_snapshot.MAX_PACKET
SCOPE = "closed-serving-audit-private-primary-packet"


def _encoded(content):
    if type(content) is not bytes:
        raise Rejected("audit_evidence_bytes")
    return base64.b64encode(content).decode()


def _decoded(value, maximum):
    if type(value) is not str or not 1 <= len(value) <= 4 * ((maximum + 2) // 3):
        raise Rejected("audit_evidence_encoding")
    try:
        content = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise Rejected("audit_evidence_encoding") from None
    if not 1 <= len(content) <= maximum or _encoded(content) != value:
        raise Rejected("audit_evidence_encoding")
    return content


def create(manifest, chunks, outcomes, public_export, *, binding):
    return canonical(
        {
            "schema_version": 1,
            "scope": SCOPE,
            "release_ready": False,
            "binding": binding,
            "manifest": _encoded(manifest),
            "segments": [_encoded(chunk) for chunk in chunks],
            "http_outcomes": outcomes,
            "public_export": _encoded(public_export),
        }
    )


def checked_outcome(value):
    require_fields(value, ("exchange", "request_id", "route", "status", "admitted"))
    if (
        type(value["exchange"]) is not int
        or not 1 <= value["exchange"] <= audit_export.MAX_REQUESTS
        or type(value["admitted"]) is not bool
        or type(value["route"]) is not str
        or value["route"] not in {"predict", "ready", "other"}
        or type(value["status"]) is not int
        or not 200 <= value["status"] <= 599
    ):
        raise Rejected("audit_evidence_http_outcome")
    if value["route"] == "other":
        if (value["status"], value["request_id"], value["admitted"]) != (404, None, False):
            raise Rejected("audit_evidence_unknown_route")
    elif (
        type(value["request_id"]) is not str
        or re.fullmatch("[a-f0-9]{32}", value["request_id"]) is None
    ):
        raise Rejected("audit_evidence_http_outcome")
    return value


def verify(content, *, binding, expected_context):
    if type(content) is not bytes:
        raise Rejected("audit_evidence_bytes")
    value = decode(content, MAX_PACKET)
    require_fields(
        value,
        (
            "schema_version",
            "scope",
            "release_ready",
            "binding",
            "manifest",
            "segments",
            "http_outcomes",
            "public_export",
        ),
    )
    require_fields(binding, ("campaign_id", "source"))
    require_fields(binding["source"], ("image_id", "source_revision", "source_fingerprint"))
    for field, pattern in (
        ("image_id", "sha256:[a-f0-9]{64}"),
        ("source_revision", "[a-f0-9]{40}"),
        ("source_fingerprint", "[a-f0-9]{64}"),
    ):
        if (
            type(binding["source"][field]) is not str
            or re.fullmatch(pattern, binding["source"][field]) is None
        ):
            raise Rejected("audit_evidence_binding")
    if (
        type(binding["campaign_id"]) is not str
        or re.fullmatch("[a-f0-9]{32}", binding["campaign_id"]) is None
        or canonical(value) != content
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["scope"] != SCOPE
        or value["release_ready"] is not False
        or canonical(value["binding"]) != canonical(binding)
    ):
        raise Rejected("audit_evidence_binding")
    expected_context = audit_event.checked_context(expected_context)
    if expected_context["schema_version"] != 2 or any(
        expected_context["lineage"][field] != binding["source"][field]
        for field in ("source_revision", "source_fingerprint")
    ):
        raise Rejected("audit_evidence_context")
    saved = audit_snapshot.manifest(_decoded(value["manifest"], audit_retention.MAX_MANIFEST))
    if type(value["segments"]) is not list or len(value["segments"]) != len(saved["segments"]):
        raise Rejected("audit_evidence_segments")
    chunks = []
    for encoded, segment in zip(value["segments"], saved["segments"], strict=True):
        chunk = _decoded(encoded, saved["policy"]["segment_bytes"])
        if len(chunk) != segment["size"] or digest(chunk) != segment["sha256"]:
            raise Rejected("audit_evidence_segment_digest")
        chunks.append(chunk)
    if (
        audit_retention.sequences(chunks[0])[0] != 1
        or audit_retention.sequences(chunks[-1])[1] != saved["sequence"]
    ):
        raise Rejected("audit_evidence_sequence")
    public = audit_export.project(chunks)
    if (
        public["status"] != "pass"
        or public["requests"]["aborted"] != 0
        or _decoded(value["public_export"], 4096) != canonical(public) + b"\n"
    ):
        raise Rejected("audit_evidence_public")
    outcomes = value["http_outcomes"]
    if type(outcomes) is not list or not 1 <= len(outcomes) <= audit_export.MAX_REQUESTS:
        raise Rejected("audit_evidence_http_capacity")
    observed = {}
    for number, item in enumerate(outcomes, 1):
        item = checked_outcome(item)
        if (
            item["exchange"] != number
            or item["request_id"] is not None
            and item["request_id"] in observed
        ):
            raise Rejected("audit_evidence_http_duplicate")
        if item["request_id"] is not None:
            observed[item["request_id"]] = item
    completed, correlated = {}, set()
    for chunk in chunks:
        for line in chunk.splitlines():
            event = decode(line)["event"]
            identifier = event["request_id"]
            if event["context"] is not None:
                if event["context"] != expected_context:
                    raise Rejected("audit_evidence_context")
                correlated.add(identifier)
            if event["stage"] == "response_completed":
                completed[identifier] = {
                    "request_id": identifier,
                    "route": event["route"],
                    "status": event["status"],
                }
    if (
        not correlated
        or any(
            identifier not in observed
            or observed[identifier]["admitted"] is not True
            or any(observed[identifier][field] != item[field] for field in item)
            for identifier, item in completed.items()
        )
        or any(
            identifier not in completed
            and (item["admitted"] or item["status"] not in {401, 429, 503})
            for identifier, item in observed.items()
        )
    ):
        raise Rejected("audit_evidence_http_binding")
    return {
        "schema_version": 1,
        "scope": "private-primary-audit-packet-not-full-M13",
        "status": "pass",
        "release_ready": False,
        "packet_sha256": digest(content),
        "observed_responses": len(outcomes),
        "correlation": {
            "schema_version": 1,
            "scope": expected_context["kind"] + "-private-correlation-not-full-M13",
            "status": "pass",
            "release_ready": False,
            "events": public["events"],
            "correlated_requests": len(correlated),
            "completed_200": sum(item["status"] == 200 for item in completed.values()),
            "failed_after_intent": len(
                correlated - {key for key, item in completed.items() if item["status"] == 200}
            ),
            "without_context": len(completed.keys() - correlated),
        },
        "public": public,
    }
