"""Signed monitoring alerts and receipts. No model release authority."""

import re
import threading
from collections import OrderedDict

from mlsecops import monitoring, signing
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.release_policy import checked

KINDS = ("data_drift", "prediction_drift", "quality_degradation", "telemetry_gap")
DELIVERY_MS = 120000
MAX_RECEIPTS = 128


def epoch_id(value):
    if type(value) is not str or re.fullmatch(r"[a-f0-9]{32}", value) is None:
        raise Rejected("monitor_epoch_invalid")
    return value


def public_key(value):
    raw = signing.decode64(value)
    if len(raw) != 32 or signing.encode64(raw) != value:
        raise Rejected("monitor_public_key_invalid")
    return value


def validate_event(document):
    monitoring.schema(
        document,
        (
            "epoch",
            "sequence",
            "reference_sha256",
            "window_sha256",
            "evidence_sha256",
            "kind",
            "admitted_at_ms",
            "expires_at_ms",
        ),
    )
    epoch_id(document["epoch"])
    monitoring.integer(document["sequence"], 1, 2**53 - 1)
    for field in ("reference_sha256", "window_sha256", "evidence_sha256"):
        monitoring.sha256(document[field])
    admitted = monitoring.integer(document["admitted_at_ms"], 1, 2**53 - 1 - DELIVERY_MS)
    expires = monitoring.integer(document["expires_at_ms"], 1, 2**53 - 1)
    if document["kind"] not in KINDS or expires != admitted + DELIVERY_MS:
        raise Rejected("monitor_alert_profile")


def event(
    *, reference_sha256, window_sha256, evidence_sha256, epoch, sequence, kind, admitted_at_ms
):
    monitoring.integer(admitted_at_ms, 1, 2**53 - 1 - DELIVERY_MS)
    document = {
        "schema_version": 1,
        "reference_sha256": reference_sha256,
        "window_sha256": window_sha256,
        "evidence_sha256": evidence_sha256,
        "epoch": epoch,
        "sequence": sequence,
        "kind": kind,
        "admitted_at_ms": admitted_at_ms,
        "expires_at_ms": admitted_at_ms + DELIVERY_MS,
    }
    validate_event(document)
    return document


def receipt(envelope, expected, public):
    validate_event(expected)
    document = checked(envelope, "monitor-alert-receipt", public_key(public))
    monitoring.schema(
        document, ("event_sha256", "epoch", "sequence", "reference_sha256", "received_at_ms")
    )
    monitoring.integer(document["sequence"], 1, 2**53 - 1)
    received = monitoring.integer(document["received_at_ms"], 1, 2**53 - 1)
    if (
        document["event_sha256"] != digest(canonical(expected))
        or any(
            document[field] != expected[field]
            for field in ("epoch", "sequence", "reference_sha256")
        )
        or not expected["admitted_at_ms"] <= received < expected["expires_at_ms"]
    ):
        raise Rejected("monitor_receipt_binding")
    return document


class Sink:
    def __init__(self, producer_public, receipt_key, *, reference_sha256, epoch):
        self._producer = public_key(producer_public)
        sink_public = signing.encode64(
            signing.load_key(receipt_key).public_key().public_bytes_raw()
        )
        if self._producer == sink_public:
            raise Rejected("monitor_alert_roles_not_separated")
        self._key, self._reference, self._epoch = (
            receipt_key,
            monitoring.sha256(reference_sha256),
            epoch_id(epoch),
        )
        self._last, self._receipts = 0, OrderedDict()
        self._lock = threading.Lock()

    def accept(self, envelope, *, clock_ms):
        document = checked(envelope, "monitor-alert", self._producer)
        validate_event(document)
        clock = monitoring.integer(clock_ms, 1, 2**53 - 1)
        if (document["reference_sha256"], document["epoch"]) != (self._reference, self._epoch):
            raise Rejected("monitor_alert_binding")
        if not document["admitted_at_ms"] <= clock < document["expires_at_ms"]:
            raise Rejected("monitor_alert_expired_or_future")
        sequence, reference = document["sequence"], digest(canonical(document))
        with self._lock:
            if sequence in self._receipts:
                old_reference, original = self._receipts[sequence]
                if old_reference != reference:
                    raise Rejected("monitor_alert_conflict")
                return decode(original)
            if sequence <= self._last:
                raise Rejected("monitor_alert_replay")
            if sequence != self._last + 1:
                raise Rejected("monitor_alert_sequence")
            accepted = {
                "schema_version": 1,
                "event_sha256": reference,
                "epoch": self._epoch,
                "sequence": sequence,
                "reference_sha256": self._reference,
                "received_at_ms": clock,
            }
            acknowledgement = signing.sign(accepted, "monitor-alert-receipt", self._key)
            self._receipts[sequence] = reference, canonical(acknowledgement)
            self._last = sequence
            while len(self._receipts) > MAX_RECEIPTS:
                self._receipts.popitem(last=False)
            return acknowledgement
