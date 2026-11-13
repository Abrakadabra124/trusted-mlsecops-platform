"""Replay private signed delivery evidence against caller-owned authority pins.

This establishes agreement of producer, collector and incident records. It does
not establish the source decision, native elapsed time, cleanup or full M23.
Those observations must be reconciled by the owning campaign, not inferred from
valid signatures or a self-selected registry in an evidence packet.
"""

from mlsecops import security_event_config as config
from mlsecops import security_event_ledger as ledger
from mlsecops import security_event_outbox as outbox
from mlsecops import security_events as events
from mlsecops.contracts import Rejected, canonical, digest

MAX_BYTES = 4 * 1024 * 1024
SUBJECT_FIELDS = ("kind", "reason", "asset_sha256", "bundle_sha256", "producer_id")


def _require(condition):
    if not condition:
        raise Rejected("security_source_evidence_invalid")


def verify_delivery(bundle, *, expected_root, expected_pin, expected_events):
    """Return finite measurements; expected event bindings come from the caller.

    All exported outboxes must have their terminal acknowledgements. The collector
    may also contain auxiliary events (for example telemetry notices); the complete
    incident export must exactly match all routed collector records. Only explicitly
    expected events count toward the caller's source inventory.
    """
    try:
        events.shape(bundle, ("registry", "outboxes", "collector", "incidents"))
        _require(len(canonical(bundle)) <= MAX_BYTES)
        authority = bundle["registry"]
        events.shape(authority, ("envelope", "root", "pin", "clock_ms"))
        _require(authority["root"] == expected_root and authority["pin"] == expected_pin)
        registry = config.Registry(
            authority["envelope"],
            trusted_root=expected_root,
            expected_sha256=expected_pin,
            clock_ms=authority["clock_ms"],
        )
        _require(type(expected_events) is dict and 1 <= len(expected_events) <= ledger.MAX_RECORDS)
        for identity, subject in expected_events.items():
            events.hexadecimal(identity)
            events.shape(subject, SUBJECT_FIELDS)
        book = ledger.Ledger(registry, bundle["collector"])
        document = book.document()
        _require(authority["clock_ms"] >= document["updated_at_ms"] and not book.pending())
        _require(
            type(bundle["incidents"]) is list
            and canonical(bundle["incidents"]) == canonical(document["records"])
        )
        delivered = {}
        for record in document["records"]:
            event = registry.verify(record["envelope"], clock_ms=record["ingested_at_ms"])
            value = event.document()
            receipt = registry.receipt(record["receipt"], event)
            delivered[value["event_id"]] = (record, value, receipt)
        queues = bundle["outboxes"]
        _require(type(queues) is list and len(queues) <= 16)
        producers, sent = set(), set()
        for document in queues:
            producer = document["producer_id"]
            _require(producer not in producers)
            producers.add(producer)
            queue = outbox.Outbox(registry, producer, document)
            _require(authority["clock_ms"] >= document["updated_at_ms"] and not queue.pending())
            for record in queue.document()["records"]:
                value = registry.verify(
                    record["envelope"], clock_ms=record["queued_at_ms"]
                ).document()
                identity = value["event_id"]
                _require(identity not in sent and identity in delivered)
                target = delivered[identity][0]
                _require(
                    record["envelope"] == target["envelope"]
                    and record["receipt"] == target["receipt"]
                )
                sent.add(identity)
        measurements = []
        for identity, subject in sorted(expected_events.items()):
            _require(identity in delivered)
            _, value, receipt = delivered[identity]
            _require({key: value[key] for key in SUBJECT_FIELDS} == subject)
            _require(identity in sent or value["kind"] == "telemetry.gap")
            measurements.append(
                {
                    "event_id": identity,
                    "kind": value["kind"],
                    "route": receipt["route"],
                    "delivery_ms": receipt["routed_at_ms"] - receipt["ingested_at_ms"],
                }
            )
        return {
            "status": "pass",
            "scope": "signed-delivery-not-source-decision-or-M23",
            "events": measurements,
            "primary_sha256": digest(canonical(bundle)),
            "release_ready": False,
        }
    except (Rejected, KeyError, TypeError, ValueError, IndexError, OverflowError, RecursionError):
        raise Rejected("security_source_evidence_invalid") from None
