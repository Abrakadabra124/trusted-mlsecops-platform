"""Synthetic report shapes for aggregator negatives, never acceptance evidence."""

import copy

from scripts.trust_trace_qualification import dependency, expiry, outage


def ordinary(*cases):
    return {
        "status": "pass",
        "release_ready": False,
        "cases": ["worker-cleanup-confirmed", *cases],
        "max_golden_error": 0.0,
    }


def typed(**cases):
    return [
        {"id": name, "status": "pass", "expected": value, "actual": value}
        for name, value in cases.items()
    ]


def fixture():
    source = {
        "source_revision": "a" * 40,
        "source_fingerprint": "b" * 64,
        "image_id": "sha256:" + "c" * 64,
    }
    refused = {
        "candidate": "d" * 64,
        "proposal": "e" * 64,
        "model": "f" * 64,
        "parent_refusal": "release_assurance_required",
        "job_outcome": "rejected",
    }
    a = {
        "source": source,
        "source_dirty": False,
        "status": "pass",
        "release_ready": False,
        "candidate_reference": refused["candidate"],
        "proposal_reference": refused["proposal"],
        "model_sha256": refused["model"],
        "subject_sha256": "1" * 64,
        "actual_refusal": refused,
        "qualification_permit_sha256": "2" * 64,
        "base_snapshot_sha256": "3" * 64,
        "proposal_issued_at": 90,
        "started_at": "1970-01-01T00:01:40+00:00",
        "finished_at": "1970-01-01T00:03:20+00:00",
    }

    def probe(fault=None, target="primary", cold=False):
        cases = (
            {"cold-worker-absence": 0}
            if cold
            else {
                "initial-worker-absence": 0,
                "final-worker-absence": 0,
                "actual-candidate-not-release": False,
                "golden-model": a["model_sha256"],
                "golden-bundle": a["subject_sha256"],
                "qualification-permit-payload": a["qualification_permit_sha256"],
            }
        )
        value = {
            "status": "pass",
            "release_ready": False,
            "model_sha256": a["model_sha256"],
            "subject_sha256": a["subject_sha256"],
            "authority_target": target,
            "max_golden_error": 0.0,
        }
        if fault:
            cold_fault = "model-revocation" if fault == "revocation" else fault
            cases.update({"no-automatic-reactivation": True, "cold-reader-" + cold_fault: True})
            value["lifecycle"] = {**outage(), "fault": fault}
        value["cases"] = typed(**cases)
        return value

    a["native"] = probe()
    causes = {
        "wall-backward": "trust_clock_invalid",
        "monotonic-backward": "trust_clock_invalid",
        "wall-jump": "trust_clock_invalid",
        "server-skew": "trust_server_clock_skew",
        "invalid-signature": "invalid_signature",
    }
    a["native"]["clock_cache"] = [dependency(f, c) for f, c in causes.items()]
    for fault in causes:
        a["native"]["cases"] += typed(
            **{
                fault + "-generation-fenced": True,
                fault + "-reader-cleared": True,
                fault + "-cache-cleared": True,
            }
        )
    a["trust_lifecycle"] = {
        fault: {"probe": probe(fault), "snapshot_sha256": a["base_snapshot_sha256"]}
        for fault in ("outage", "blackhole", "policy-change")
    }
    replay = dependency("version-replay", "trust_version_replay")
    replay.update(
        recovery_max_golden_error=0.0,
        replay={
            "checked_at_epoch": 100.25,
            "server_epoch": 100,
            "prior_expires_at_epoch": 200,
            "prior_valid_seconds": 99.75,
            "prior_version": 2,
            "current_version": 4,
            "prior_document_sha256": "4" * 64,
            "current_document_sha256": "5" * 64,
        },
    )
    a["trust_lifecycle"]["policy-change"]["probe"]["version_replay"] = replay
    for name, fault, target in (
        ("model_revocation", "revocation", "model-revocation"),
        ("key_revocation", "key-revocation", "primary"),
    ):
        a[name] = probe(fault, target)
        a[name + "_snapshot_sha256"] = a["base_snapshot_sha256"]
    a["revoked_key_sha256"] = "6" * 64
    before = {
        target: {
            "version": 1,
            "policy_sha256": a["qualification_permit_sha256"],
            "revoked_artifacts": [],
            "revoked_keys": [],
            "identity": {
                "target": target,
                "ca_sha256": str(i) * 64,
                "volume_uid_sha256": format(i + 2, "x") * 64,
            },
        }
        for i, target in enumerate(("primary", "model-revocation"), 7)
    }
    after_model = copy.deepcopy(before)
    after_model["model-revocation"].update(version=2, revoked_artifacts=[a["model_sha256"]])
    after_key = copy.deepcopy(after_model)
    after_key["primary"].update(version=2, revoked_keys=[a["revoked_key_sha256"]])
    cold = {}
    for target, fault, cause in (
        ("primary", "key-revocation", "trust_key_revoked"),
        ("model-revocation", "model-revocation", "trust_artifact_revoked"),
    ):
        cold[target] = probe(target=target, cold=True)
        cold[target]["cases"] += typed(**{"cold-" + fault: cause})
    a["independent_authorities"] = {
        "states": {"before": before, "after_model": after_model, "after_key": after_key},
        "cold": cold,
    }
    a["root_rotation"] = {
        "status": "pass",
        "release_ready": False,
        "model_snapshot_sha256": a["base_snapshot_sha256"],
        "permit_sha256": a["qualification_permit_sha256"],
        "probe": probe("root-rotation"),
    }
    renewal = {
        "sequence": 2,
        "release_ready": False,
        "subject_sha256": "7" * 64,
        "request_sha256": "8" * 64,
        "proposal_reference": "9" * 64,
    }
    target = {
        **renewal,
        "sequence": 1,
        "subject_sha256": "a" * 64,
        "request_sha256": "b" * 64,
        "proposal_reference": "c" * 64,
    }
    selected = {**target, "sequence": 3, "request_sha256": "d" * 64}
    result = {
        **source,
        "source_dirty": False,
        "status": "pass",
        "release_ready": False,
        "actual": refused,
        "actual_inference": a,
        "before_approval": ordinary(
            "refused-before-worker-start", "unapproved-or-revoked-ready-503"
        ),
        "approved": ordinary("ordinary-CLI-ready-after-verified-load", "ONNX-golden-parity"),
        "after_revocation": ordinary(
            "refused-before-worker-start", "unapproved-or-revoked-ready-503"
        ),
        "approval_expiry": {
            "active": {**ordinary("approval-expiry-no-reactivation"), "lifecycle": expiry()},
            "cold": ordinary("expected-reader-refusal", "refused-before-worker-start"),
            "retry": {"status": "rejected", "receipt": None, "release_ready": False},
            "expired_retry_ledger_unchanged": True,
            "expired_retry_snapshot_sha256": "e" * 64,
            "renewed_receipt": renewal,
            "recovery": ordinary("ordinary-CLI-ready-after-verified-load", "ONNX-golden-parity"),
        },
        "unexpired_replay": {
            "prior_sequence": 1,
            "current_sequence": 2,
            "prior_valid_at_epoch": 100,
            "prior_expires_at_epoch": 200,
            "journal_unchanged": True,
            "refused": {
                "status": "rejected",
                "receipt": None,
                "release_ready": False,
                "reason": "promotion_sequence_conflict",
            },
            "current_retry": {"receipt": renewal},
        },
        "controlled_model": "0" * 64,
        "controlled_renewed_model": "1" * 64,
        "authorized_rollback": {
            "status": "pass",
            "release_ready": False,
            "sequence_path": [1, 2, 3],
            "from_model": "1" * 64,
            "target_model": "0" * 64,
            "from_receipt": renewal,
            "target_receipt": target,
            "admitted": {"receipt": selected},
            "retry": {"receipt": selected},
            "serving": ordinary("ONNX-golden-parity"),
            "revoked_retry": {"status": "rejected", "receipt": None, "release_ready": False},
            "negative": {
                name: {
                    "outcome": {
                        "status": "rejected",
                        "receipt": None,
                        "release_ready": False,
                        "reason": cause,
                    },
                    "unchanged_snapshot_sha256": "f" * 64,
                }
                for name, cause in (
                    ("from_request_sha256", "rollback_from_history"),
                    ("target_request_sha256", "rollback_target_history"),
                    ("conflicting_same_sequence", "rollback_head_changed"),
                )
            },
        },
        "live_trust": {
            fault: {
                **ordinary("no-automatic-reactivation"),
                "lifecycle": {**outage(), "fault": fault},
            }
            for fault in ("outage", "blackhole", "policy-change", "revocation")
        },
    }
    return result, source
