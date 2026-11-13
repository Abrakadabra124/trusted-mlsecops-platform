"""M23 candidate component. Native capture and offline replay of the two owner pins."""

import os
from collections import Counter
from datetime import datetime
from pathlib import Path

from mlsecops import release_policy, security_outage_packet
from mlsecops import security_events as events
from mlsecops import security_inventory_evidence as inventory
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    safe_child,
    write_json,
)
from mlsecops.security_event_config import Registry
from scripts import kube_security_outage_native as outage
from scripts import security_inventory_events_native as native
from scripts.kube_trust_native import hosted

INVENTORY_PUBLIC = "evidence/security-inventory-public.json"
INVENTORY_PRIMARY = "evidence/security-inventory-primary.json"
INVENTORY_BINDING = "evidence/security-inventory-primary.bindings.json"
PROPOSAL = "evidence/release-native.json"
OUTAGE_LIMIT = security_outage_packet.MAX_PACKET
# Historical qualify emits the same CLI assertion for several distinct invocations.
INVENTORY_CASES = Counter(
    {
        "separate-observer-cli-success": 3,
        "no-release-authority-or-payload-output": 3,
        "private-cli-refusal": 9,
        "actual-trained-candidate-verified-without-event": 1,
        "actual-sql-candidate-build-mismatch-has-receipt": 1,
        "offline-mismatch-durable-before-delivery": 1,
        "pending-outage-prevents-another-observation": 1,
        "same-outbox-retry-delivered-one-event": 1,
        "original-envelope-preserved-after-restart": 1,
        "valid-candidate-retry-adds-no-event": 1,
        "missing-sql-object-not-invented-mismatch": 1,
        "operator-request-pin-refusal-without-event": 1,
        "six-actual-source-decisions-retained": 1,
        **{f"authenticated-inventory-route-{seq}": 1 for seq in range(1, 7)},
        "bounded-reasons-and-source-subjects": 1,
        "private-input-not-in-outbox": 1,
        "exact-receipt-retry-idempotent": 1,
        "collector-process-port-and-private-state-cleanup": 1,
        "source-sql-unchanged-and-owned": 1,
        "runtime-source-and-image-unchanged": 1,
        "inventory-methods-unchanged": 1,
    }
)


def _require(condition, code):
    if not condition:
        raise Rejected("security_gate_candidate_" + code)


def _pin_public(path, summary, limit, *fields):
    raw = bounded_read(path, limit)
    _require(raw == canonical(summary) + b"\n", "public_readback")
    return {
        "public_sha256": digest(raw),
        **{key: events.hexadecimal(summary[key]) for key in fields},
    }


def capture_inventory(root, state):
    hosted()
    # qualify derives its source root from its module, not its caller's cwd.
    _require(Path(root).resolve() == Path(native.__file__).resolve().parents[1], "inventory_root")
    public = native.qualify(state, "trusted-mlsecops:dev")
    path = safe_child(state, INVENTORY_PUBLIC)
    write_json(path, public)
    return _pin_public(path, public, 32768, "primary_sha256", "binding_sha256")


def capture_outage(root, state):
    hosted()
    proposal_sha = events.hexadecimal(os.environ.get("M23_PROPOSAL_SHA256"))
    _proposal(state, proposal_sha)
    public = outage.run(root, state, proposal_pin=proposal_sha)
    pin = _pin_public(safe_child(state, outage.PUBLIC), public, OUTAGE_LIMIT, "primary_sha256")
    return {**pin, "proposal_sha256": proposal_sha}


def _pinned(path, pin, limit, *, canonical_pin=False):
    raw = bounded_read(path, limit)
    # Inventory's existing owner pins hash canonical JSON. Its writer appends one LF.
    if canonical_pin:
        value = decode(raw, limit)
        body = canonical(value)
        _require(raw == body + b"\n" and digest(body) == pin, "inventory_file")
        return value
    _require(digest(raw) == pin, "file_pin")
    return decode(raw, limit)


def _proposal(state, pin):
    report = _pinned(safe_child(state, PROPOSAL), pin, release_policy.MAX_DOCUMENT)
    events.version(report.get("schema_version"))
    _require(
        report.get("status") == "pass"
        and report.get("release_ready") is False
        and report.get("source_dirty") is False
        and report.get("full_M10") == "inconclusive"
        and report.get("scope") == "release-proposal-and-authorization-denial-not-full-M10",
        "proposal_status",
    )
    events.hexadecimal(report.get("campaign_id"), 32)
    events.shape(report.get("source"), ("image_id", "source_revision", "source_fingerprint"))
    try:
        finished = datetime.fromisoformat(report.get("finished_at"))
    except (ValueError, TypeError):
        raise Rejected("security_gate_candidate_proposal_time") from None
    _require(
        finished.utcoffset() is not None and finished.isoformat() == report["finished_at"],
        "proposal_time",
    )
    return report


def _route_ms(registry, records, expected_ids, kind):
    # Only the source-bound events contribute. Outage journals may contain other history.
    delays = {}
    for record in records:
        event = registry.verify(record["envelope"], clock_ms=record["queued_at_ms"])
        value = event.document()
        identity = value["event_id"]
        if identity in expected_ids:
            receipt = registry.receipt(record["receipt"], event)
            _require(value["kind"] == kind and identity not in delays, "route_event")
            delays[identity] = receipt["routed_at_ms"] - receipt["ingested_at_ms"]
    _require(delays.keys() == expected_ids, "route_inventory")
    return max(delays.values())


def _inventory(root, state, pin):
    events.shape(pin, ("public_sha256", "primary_sha256", "binding_sha256"))
    public = _pinned(state / INVENTORY_PUBLIC, pin["public_sha256"], 32768)
    primary = _pinned(
        state / INVENTORY_PRIMARY, pin["primary_sha256"], inventory.MAX_BYTES, canonical_pin=True
    )
    binding = _pinned(state / INVENTORY_BINDING, pin["binding_sha256"], 16384, canonical_pin=True)
    events.shape(
        public,
        (
            "source",
            "fingerprint",
            "cases",
            "status",
            "release_ready",
            "candidate_reference",
            "max_cli_seconds",
            "scope",
            "primary_sha256",
            "binding_sha256",
        ),
    )
    events.shape(binding, ("schema_version", "scope", "expected"))
    events.version(binding["schema_version"])
    expected = binding["expected"]
    events.shape(
        expected,
        (
            "expected_source",
            "expected_fingerprint",
            "expected_methods",
            "expected_candidate",
            "expected_root",
            "expected_pin",
        ),
    )
    _require(
        binding["scope"] == "inventory-owner-inputs-not-new-authority"
        and public["binding_sha256"] == pin["binding_sha256"]
        and public["primary_sha256"] == pin["primary_sha256"]
        and public["status"] == "pass"
        and public["release_ready"] is False
        and public["scope"] == inventory.SCOPE
        and public["source"] == expected["expected_source"]
        and public["fingerprint"] == expected["expected_fingerprint"]
        and public["candidate_reference"] == expected["expected_candidate"]["candidate_reference"],
        "inventory_public",
    )
    _require(
        expected["expected_methods"]
        == {name: digest(bounded_read(root / name)) for name in inventory.METHODS},
        "inventory_methods",
    )
    checked = inventory.verify(primary, **expected)
    labels = public["cases"]
    _require(
        type(labels) is list
        and all(type(label) is str for label in labels)
        and Counter(labels) == INVENTORY_CASES,
        "inventory_cases",
    )
    cases = [
        f"inventory:{label}:{index}" if count > 1 else f"inventory:{label}"
        for label, count in INVENTORY_CASES.items()
        for index in range(1, count + 1)
    ]
    observations = primary["observations"]
    _require(
        type(public["max_cli_seconds"]) in (float, int)
        and public["max_cli_seconds"] == max(row["elapsed_ns"] for row in observations) / 1e9,
        "inventory_cli_time",
    )
    authority = primary["bundle"]["registry"]
    registry = Registry(
        authority["envelope"],
        trusted_root=expected["expected_root"],
        expected_sha256=expected["expected_pin"],
        clock_ms=authority["clock_ms"],
    )
    ids = {row["event_id"] for row in observations if row["event_id"] is not None}
    box = primary["bundle"]["outboxes"][0]
    _require(registry.producer(box["producer_id"]).role == "promoter", "inventory_producer")
    delay = _route_ms(registry, box["records"], ids, "inventory.mismatch")
    return expected["expected_candidate"], cases, delay, checked["event_count"]


def replay(root, state, *, inventory_pin, outage_pin):
    """Replay retained files and source materials after the owner's infrastructure cleanup."""
    root, state = Path(root), Path(state)
    candidate, cases, inventory_ms, count = _inventory(root, state, inventory_pin)
    events.shape(outage_pin, ("public_sha256", "primary_sha256", "proposal_sha256"))
    proposal = _proposal(state, outage_pin["proposal_sha256"])
    public = _pinned(state / outage.PUBLIC, outage_pin["public_sha256"], OUTAGE_LIMIT)
    _require(public["primary_sha256"] == outage_pin["primary_sha256"], "outage_primary")
    primary = _pinned(state / outage.PRIVATE, outage_pin["primary_sha256"], OUTAGE_LIMIT)
    campaign = events.hexadecimal(primary["security_campaign_id"], 32)
    directory = safe_child(state, "evidence/security-outage/" + campaign)
    retained = public["retained_sha256"]
    events.shape(retained, ("binding.json", "operator.json", "packet.json"))
    binding = _pinned(directory / "binding.json", retained["binding.json"], OUTAGE_LIMIT)
    # Replays every window, operator timeline, recovery signatures and owner markers.
    observation = outage.reverify(root, state)
    _require(
        digest(bounded_read(state / outage.PUBLIC, OUTAGE_LIMIT)) == outage_pin["public_sha256"],
        "outage_public_changed",
    )
    _require(canonical(observation) == canonical(public["observation"]), "outage_observation")
    source, context = primary["source"], binding["context"]
    actual = dict(
        candidate_reference=primary["candidate_reference"],
        evaluation_reference=context["lineage"]["evaluation_sha256"],
        model_sha256=primary["model_sha256"],
        image_id=source["image_id"],
        source_revision=source["source_revision"],
        source_fingerprint=source["source_fingerprint"],
    )
    _require(candidate == actual, "shared_candidate")
    subject = primary["subject_sha256"]
    boundary = binding["boundary"]
    _require(
        subject == context["bundle_sha256"] == observation["subject_sha256"]
        and boundary["fixture_bundle_sha256"] != subject,
        "release_subject",
    )
    refusal = primary["actual_refusal"]
    _require(
        refusal["candidate"] == actual["candidate_reference"]
        and refusal["model"] == actual["model_sha256"]
        and refusal["proposal"] == context["proposal_sha256"]
        and refusal["parent_refusal"] == "release_assurance_required"
        and refusal["job_outcome"] == "rejected",
        "actual_refusal",
    )
    _require(
        proposal.get("campaign_id") == refusal["campaign_id"]
        and proposal.get("proposal_reference") == context["proposal_sha256"]
        and proposal.get("model_sha256") == actual["model_sha256"]
        and proposal.get("subject_sha256") == subject
        and proposal.get("source") == source,
        "proposal_binding",
    )

    signed = binding["recovery"]["signed_evidence"]
    box = signed["outbox"]["snapshot"]
    # reverify already checked this retained registry against the owner's runtime markers.
    registry = Registry(
        signed["registry"],
        trusted_root=signed["registry_root"],
        expected_sha256=signed["registry_sha256"],
        clock_ms=box["updated_at_ms"],
    )
    denial_ms = _route_ms(
        registry, box["records"], {boundary["pending"]["event_id"]}, "promotion.denied"
    )
    windows = observation["phase_windows"]
    cases.extend(
        f"outage:{phase}:window:{n}"
        for phase in security_outage_packet.PHASES
        for n in range(1, windows[phase] + 1)
    )
    cases.extend(
        (
            "outage:controlled-authorization-audit-refusal-and-recovery",
            "outage:actual-candidate-assurance-refusal",
            "outage:shared-candidate-after-cleanup",
        )
    )
    return dict(
        candidate=actual,
        release_subject=subject,
        proposal_finished_at=proposal["finished_at"],
        cases=cases,
        routes={"inventory.mismatch": inventory_ms, "promotion.denied": denial_ms},
        artifact_hashes={
            **{"inventory-" + k: v for k, v in inventory_pin.items()},
            **{"outage-" + k: v for k, v in outage_pin.items()},
            **{"outage-" + k: v for k, v in retained.items()},
        },
        metrics=dict(
            observations=observation["observations"], phase_windows=windows, inventory_events=count
        ),
    )
