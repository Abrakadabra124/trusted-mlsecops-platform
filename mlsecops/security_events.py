"""Bounded M23 event contracts. Authentication, persistence and routing are distinct."""

import re
from dataclasses import dataclass

from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, decode, digest

MAX_INTEGER = 2**53 - 1
MAX_ENVELOPE = 4096
MAX_AGE_MS = 300000
CLOCK_SKEW_MS = 5000
DELIVERY_MS = 60000
GAP_MS = 120000
HEARTBEAT_MS = 30000

# kind: action, outcome, allowed reasons, server-selected alert route
RULES = {
    "artifact.rejected": (
        "reject",
        "denied",
        ("integrity", "signature", "unsupported_format"),
        "security.artifacts",
    ),
    "promotion.denied": (
        "promote",
        "denied",
        ("authorization", "trust", "audit_unavailable", "policy"),
        "security.releases",
    ),
    "trust.revoked": ("revoke", "revoked", ("key", "artifact", "policy"), "security.trust"),
    "identity.denied": ("authenticate", "denied", ("credential", "role"), "security.identity"),
    "inventory.mismatch": (
        "verify",
        "denied",
        ("digest", "dangling", "owner", "cycle"),
        "security.inventory",
    ),
    "worker.policy_violation": (
        "evaluate",
        "denied",
        ("isolation", "output_schema", "quota"),
        "security.workers",
    ),
    "telemetry.gap": (
        "observe",
        "missing",
        ("sequence", "heartbeat", "restart"),
        "security.telemetry",
    ),
}
ROLE_KINDS = {
    "intake": ("artifact.rejected",),
    "promoter": ("promotion.denied", "artifact.rejected", "identity.denied", "inventory.mismatch"),
    "trust": ("trust.revoked",),
    "serving": ("identity.denied", "artifact.rejected", "inventory.mismatch"),
    "controller": (
        "worker.policy_violation",
        "artifact.rejected",
        "identity.denied",
        "inventory.mismatch",
    ),
    "collector": ("telemetry.gap",),
}
FIELDS = (
    "schema_version",
    "event_id",
    "kind",
    "producer_id",
    "epoch",
    "sequence",
    "occurred_at_ms",
    "observed_at_ms",
    "correlation_id",
    "asset_sha256",
    "bundle_sha256",
    "policy_sha256",
    "action",
    "outcome",
    "reason",
)
HEARTBEAT_FIELDS = (
    "schema_version",
    "producer_id",
    "epoch",
    "sequence",
    "last_event_sequence",
    "observed_at_ms",
    "policy_sha256",
)
RECEIPT_FIELDS = (
    "schema_version",
    "event_id",
    "config_sha256",
    "producer_id",
    "epoch",
    "sequence",
    "route",
    "ingested_at_ms",
    "routed_at_ms",
    "late",
    "release_ready",
)


def shape(value, fields):
    if type(value) is not dict or value.keys() != set(fields):
        raise Rejected("security_shape")


def version(value):
    if type(value) is not int or value != 1:
        raise Rejected("security_schema")


def integer(value, minimum=1):
    if type(value) is not int or not minimum <= value <= MAX_INTEGER:
        raise Rejected("security_integer")
    return value


def hexadecimal(value, length=64):
    if type(value) is not str or re.fullmatch(r"[a-f0-9]{" + str(length) + "}", value) is None:
        raise Rejected("security_identifier")
    return value


def public_key(value):
    raw = signing.decode64(value)
    if len(raw) != 32 or signing.encode64(raw) != value:
        raise Rejected("security_public_key")
    return value


def signer(envelope, maximum=MAX_ENVELOPE):
    shape(envelope, ("payloadType", "payload", "signatures"))
    signatures = envelope["signatures"]
    if type(signatures) is not list or len(signatures) != 1:
        raise Rejected("security_signature_count")
    shape(signatures[0], ("keyid", "sig"))
    identity = hexadecimal(signatures[0]["keyid"])
    # Reject nested attacker values before recursive JSON serialization.
    values = (envelope["payloadType"], envelope["payload"], signatures[0]["sig"])
    if any(type(value) is not str for value in values):
        raise Rejected("security_envelope_shape") from None
    if any(len(value) > maximum for value in values) or len(canonical(envelope)) > maximum:
        raise Rejected("security_envelope_size")
    return identity


def signed(envelope, kind, public, maximum=MAX_ENVELOPE):
    signer(envelope, maximum)
    value = signing.verify(envelope, kind, public_key(public))
    if signing.decode64(envelope["payload"]) != canonical(value):
        raise Rejected("security_noncanonical_payload")
    return value


def checked(value):
    shape(value, FIELDS)
    version(value["schema_version"])
    for field in ("event_id", "producer_id", "asset_sha256", "policy_sha256"):
        hexadecimal(value[field])
    for field in ("epoch", "correlation_id"):
        hexadecimal(value[field], 32)
    if value["bundle_sha256"] is not None:
        hexadecimal(value["bundle_sha256"])
    for field in ("sequence", "occurred_at_ms", "observed_at_ms"):
        integer(value[field])
    kind = value["kind"]
    if type(kind) is not str or kind not in RULES:
        raise Rejected("security_kind")
    action, outcome, reasons, _ = RULES[kind]
    if (
        value["action"] != action
        or value["outcome"] != outcome
        or value["reason"] not in reasons
        or value["occurred_at_ms"] > value["observed_at_ms"]
    ):
        raise Rejected("security_event_semantics")
    expected = digest(canonical({key: item for key, item in value.items() if key != "event_id"}))
    if value["event_id"] != expected:
        raise Rejected("security_event_identity")
    return decode(canonical(value))


def create(
    *,
    kind,
    producer_id,
    epoch,
    sequence,
    occurred_at_ms,
    observed_at_ms,
    correlation_id,
    asset_sha256,
    bundle_sha256,
    policy_sha256,
    reason,
):
    if type(kind) is not str or kind not in RULES:
        raise Rejected("security_kind")
    action, outcome, _, _ = RULES[kind]
    value = {
        "schema_version": 1,
        "kind": kind,
        "producer_id": producer_id,
        "epoch": epoch,
        "sequence": sequence,
        "occurred_at_ms": occurred_at_ms,
        "observed_at_ms": observed_at_ms,
        "correlation_id": correlation_id,
        "asset_sha256": asset_sha256,
        "bundle_sha256": bundle_sha256,
        "policy_sha256": policy_sha256,
        "action": action,
        "outcome": outcome,
        "reason": reason,
    }
    value["event_id"] = digest(canonical(value))
    return checked(value)


@dataclass(frozen=True, slots=True)
class Event:
    """Immutable schema-checked value; only Registry.verify authenticates its origin."""

    content: bytes

    def __post_init__(self):
        if type(self.content) is not bytes or len(self.content) > 2048:
            raise Rejected("security_event_size")
        if canonical(checked(decode(self.content, 2048))) != self.content:
            raise Rejected("security_event_canonical")

    def document(self):
        return decode(self.content, 2048)

    @property
    def route(self):
        return RULES[self.document()["kind"]][3]


def delivered(event, config_sha256, *, ingested_at_ms, routed_at_ms, late):
    if type(event) is not Event:
        raise Rejected("security_receipt_event")
    hexadecimal(config_sha256)
    integer(ingested_at_ms)
    integer(routed_at_ms)
    if type(late) is not bool or not 0 <= routed_at_ms - ingested_at_ms <= DELIVERY_MS:
        raise Rejected("security_delivery_deadline")
    value = event.document()
    return {
        "schema_version": 1,
        "event_id": value["event_id"],
        "config_sha256": config_sha256,
        "producer_id": value["producer_id"],
        "epoch": value["epoch"],
        "sequence": value["sequence"],
        "route": event.route,
        "ingested_at_ms": ingested_at_ms,
        "routed_at_ms": routed_at_ms,
        "late": late,
        "release_ready": False,
    }
