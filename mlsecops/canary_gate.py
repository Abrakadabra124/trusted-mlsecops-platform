"""Public M16 lab qualification from the two owner-pinned post-cleanup replays."""

import os

from mlsecops.canary_probe import MAX_REQUESTS, STAGES
from mlsecops.contracts import Rejected, require_fields, safe_child
from mlsecops.security_events import hexadecimal, integer
from scripts import canary_rollout_native as native

SCOPE = "bounded-synthetic-canary-traffic-and-controlled-whole-bundle-rollback"


def check_traffic(traffic):
    stages = traffic["stages"]
    if tuple(stage["candidate_percent"] for stage in stages) != STAGES:
        raise Rejected("canary_acceptance_stages")
    baseline = stages[0]
    for stage in stages:
        require_fields(
            stage,
            (
                "candidate_percent",
                "attempts",
                "valid",
                "errors",
                "candidate_attempts",
                "p95_ms",
                "p99_ms",
                "passed",
                "checks",
            ),
        )
        checks = stage["checks"]
        require_fields(checks, ("valid_observations", "golden_responses", "latency", "error_delta"))
        valid, errors = integer(stage["valid"], 100), integer(stage["errors"], 0)
        attempts = integer(stage["attempts"], 100)
        if not (
            valid + errors == attempts <= MAX_REQUESTS
            and 100 * integer(stage["candidate_attempts"], 0)
            == attempts * stage["candidate_percent"]
            and 100 * (errors * baseline["attempts"] - baseline["errors"] * attempts)
            <= attempts * baseline["attempts"]
            and 0 <= stage["p95_ms"] <= 200
            and stage["p95_ms"] <= stage["p99_ms"] <= 500
            and stage["passed"] is True
            and all(value is True for value in checks.values())
        ):
            raise Rejected("canary_acceptance_stage_thresholds")
    require_fields(traffic["audit_completed"], ("stable", "candidate"))
    for count in traffic["audit_completed"].values():
        integer(count)
    if (
        traffic["requests"] != sum(stage["attempts"] for stage in stages)
        or not 0 <= traffic["route_recovery_seconds"] <= 120
    ):
        raise Rejected("canary_acceptance_traffic_totals")


def check_durable(durable):
    references = (
        "from_request_sha256",
        "target_request_sha256",
        "restored_request_sha256",
        "restored_bundle",
        "restored_model",
        "rejected_rollback_event",
        "pending_case_sha256",
    )
    require_fields(
        durable,
        (
            "scope",
            "campaign",
            "release_ready",
            "recovery_ns",
            "refusal_statuses",
            "refusal_attempts",
            *references,
        ),
    )
    for field in references:
        hexadecimal(durable[field])
    if (
        durable["scope"] != "controlled-signed-approvals-disposable-host-recovery"
        or durable["release_ready"] is not False
        or integer(durable["recovery_ns"], 0) > 120_000_000_000
        or durable["refusal_statuses"] != [503, 503]
        or len(durable["refusal_attempts"]) != 2
    ):
        raise Rejected("canary_acceptance_durable_rollback")
    for attempts in durable["refusal_attempts"]:
        integer(attempts)


def qualify(root, state):
    files = ("storage.json", native.PACKET, native.ROLLBACK_PACKET)
    pins = ("T19_PROPOSAL_SHA256", "T19_PRIMARY_SHA256", "T19_ROLLBACK_SHA256")
    if not all(safe_child(state, name).is_file() for name in files) or not all(
        os.environ.get(name) for name in (*pins, "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
    ):
        raise FileNotFoundError("M16 requires the storage marker, both packets and workflow pins")
    proposal_pin, traffic_pin, rollback_pin = (hexadecimal(os.environ[name]) for name in pins)
    packet, traffic, durable = native.measured(root, state)
    owner = native.capture_inputs(root)
    candidate = packet["candidate"]
    if (
        packet["source"] != owner["source"]
        or packet["runner"] != owner["runner"]
        or packet["methods"] != owner["methods"]
        or not packet["proposal_sha256"] == owner["proposal_pin"] == proposal_pin
        or traffic["candidate"] != candidate["candidate_reference"]
        or traffic["model"] != candidate["model_sha256"]
        or traffic["release_subject"] != candidate["subject_sha256"]
        or durable["campaign"] != packet["campaign"]
    ):
        raise Rejected("canary_acceptance_binding")

    # measured() verifies each request, signed selection, HTTP readback and fallback.
    # Only its public summaries and the named capture bindings may enter the report.
    check_traffic(traffic)
    check_durable(durable)
    names = [
        *(f"qualified-traffic-{percent}-percent" for percent in STAGES),
        "qualified-revocation-and-return-to-approved-stable",
        "controlled-compatible-whole-bundle-rollback",
        "controlled-revoked-previous-release-refused",
        "controlled-manual-review-pending-without-ml",
    ]
    cases = [dict(id="M16-" + name, status="pass", expected=True, actual=True) for name in names]
    return dict(
        scope=SCOPE,
        release_ready=False,
        status="pass",
        started_at=packet["started_at"],
        source_dirty=False,
        cases=cases,
        checks=len(cases),
        input_digests={
            **owner["source"],
            "candidate_reference": candidate["candidate_reference"],
            "evaluation_reference": candidate["evaluation_reference"],
            "proposal_reference": candidate["proposal_reference"],
            "qualification_permit_sha256": candidate["permit_sha256"],
            "image_id": candidate["image_id"],
            "qualified_candidate_subject": traffic["release_subject"],
            "qualified_candidate_model": traffic["model"],
            "stable_selection": packet["stable"]["request_sha256"],
            "stable_subject": packet["stable"]["subject_sha256"],
        },
        artifact_hashes=dict(
            proposal_packet=proposal_pin,
            traffic_packet=traffic_pin,
            rollback_packet=rollback_pin,
            method_materials=owner["methods"],
            traffic_rows=traffic["primary_traffic_sha256"],
            stable_journal=packet["journals"]["stable"],
            candidate_journal=packet["journals"]["candidate"],
            candidate_source=candidate["source_evidence_sha256"],
        ),
        metrics=dict(
            stages=traffic["stages"],
            requests=traffic["requests"],
            audit_completed=traffic["audit_completed"],
            route_recovery_seconds=traffic["route_recovery_seconds"],
            controlled_rollback=durable,
        ),
        limitations=[
            "One synthetic input and bounded loopback traffic in the local-cpu lab.",
            "The evaluated candidate served under a qualification permit. Durable rollback used "
            "separate controlled signed approvals and bundles in disposable storage.",
            "Manual review was verified through pending queue readback. M18 and R1 remain open.",
        ],
    )
