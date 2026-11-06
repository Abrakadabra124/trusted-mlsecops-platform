"""Fresh M11 evidence reconciliation. A mechanism pass never grants release approval."""

from mlsecops import trust_trace
from mlsecops.contracts import Rejected, canonical, require_fields
from mlsecops.release_policy import integer
from mlsecops.storage import object_id


def require(condition):
    if condition is not True:
        raise Rejected("M11_native_binding")


def passed(value):
    require(value["status"] == "pass" and value["release_ready"] is False)


def ordinary(value, *mandatory):
    passed(value)
    require(isinstance(value["cases"], list) and all(isinstance(c, str) for c in value["cases"]))
    require({"worker-cleanup-confirmed", *mandatory}.issubset(value["cases"]))
    if "ONNX-golden-parity" in mandatory:
        require(0 <= trust_trace.number(value["max_golden_error"]) <= 1e-6)


def typed(value, mandatory):
    passed(value)
    require(isinstance(value["cases"], list) and 0 < len(value["cases"]) <= 10000)
    observed = set()
    for case in value["cases"]:
        require_fields(case, ("id", "status", "expected", "actual"))
        require(isinstance(case["id"], str) and case["status"] == "pass")
        require(canonical(case["expected"]) == canonical(case["actual"]))
        if case["id"] in mandatory:
            require(canonical(case["actual"]) == canonical(mandatory[case["id"]]))
        observed.add(case["id"])
    require(set(mandatory) <= observed)


def rejected(value, reason=None):
    require(
        value["status"] == "rejected"
        and value["receipt"] is None
        and value["release_ready"] is False
    )
    if reason is not None:
        require(value["reason"] == reason)


def probe(actual, value, *, target="primary", fault=None, extra=None, cold=False):
    require(
        value["model_sha256"] == actual["model_sha256"]
        and value["subject_sha256"] == actual["subject_sha256"]
    )
    require(value["authority_target"] == target)
    mandatory = (
        {"cold-worker-absence": 0}
        if cold
        else {
            "initial-worker-absence": 0,
            "final-worker-absence": 0,
            "actual-candidate-not-release": False,
            "golden-model": actual["model_sha256"],
            "golden-bundle": actual["subject_sha256"],
            "qualification-permit-payload": actual["qualification_permit_sha256"],
        }
    )
    if not cold:
        require(0 <= trust_trace.number(value["max_golden_error"]) <= 1e-6)
    if fault:
        cold_fault = "model-revocation" if fault == "revocation" else fault
        mandatory.update({"no-automatic-reactivation": True, "cold-reader-" + cold_fault: True})
    typed(value, {**mandatory, **(extra or {})})
    return trust_trace.refusal(value["lifecycle"], fault) if fault else None


def independent(actual):
    authority = actual["independent_authorities"]
    states = authority["states"]
    require_fields(states, ("before", "after_model", "after_key"))
    for state in states.values():
        require_fields(state, ("primary", "model-revocation"))
    before, model, key = (states[n] for n in ("before", "after_model", "after_key"))
    require(
        before["primary"] == model["primary"]
        and model["model-revocation"] == key["model-revocation"]
    )
    for field in ("ca_sha256", "volume_uid_sha256"):
        require(
            object_id(before["primary"]["identity"][field])
            != object_id(before["model-revocation"]["identity"][field])
        )
    for target, previous, current, field, reference, fault, cause in (
        (
            "model-revocation",
            before,
            model,
            "revoked_artifacts",
            actual["model_sha256"],
            "model-revocation",
            "trust_artifact_revoked",
        ),
        (
            "primary",
            model,
            key,
            "revoked_keys",
            actual["revoked_key_sha256"],
            "key-revocation",
            "trust_key_revoked",
        ),
    ):
        old, new = previous[target], current[target]
        require(integer(new["version"]) == integer(old["version"]) + 1)
        require(old["identity"] == new["identity"] and old["identity"]["target"] == target)
        require(
            old["policy_sha256"] == new["policy_sha256"] == actual["qualification_permit_sha256"]
        )
        for revoked in ("revoked_artifacts", "revoked_keys"):
            require(isinstance(old[revoked], list) and isinstance(new[revoked], list))
            old_set, new_set = (
                {object_id(v) for v in values} for values in (old[revoked], new[revoked])
            )
            require(new_set == old_set | ({reference} if revoked == field else set()))
        require(reference not in old[field] and reference in new[field])
        probe(
            actual,
            authority["cold"][target],
            target=target,
            cold=True,
            extra={"cold-" + fault: cause},
        )


def reconcile(value, source):
    try:
        return _reconcile(value, source)
    except (KeyError, TypeError, ValueError, IndexError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("M11_native_shape") from error


def release_signers(value, source):
    passed(value)
    require(value["source_dirty"] is False and {k: value[k] for k in source} == source)
    require(type(value["workers_removed"]) is int and value["workers_removed"] == 6)
    roles = ("publisher", "assessor", "approver")
    require_fields(value["transitions"], roles)
    expected = {
        "initial-controlled-release-recorded-not-ready",
        "final-three-rotations-four-events",
        "all-retired-keys-stay-revoked",
        "owned-databases-removed",
        "source-state-and-revision-unchanged",
    }
    timings, previous = {}, None
    for sequence, role in enumerate(roles, 2):
        expected.update(
            role + "-" + suffix
            for suffix in (
                "online-policy-denies-old-handoff",
                "cold-before-store-policy-change",
                "old-worker-removed",
                "rotation-preserves-head-not-ready",
                "old-config-after-store",
                "new-policy-with-old-selection",
                "missing-M22-not-approved",
                "denied-release-no-journal-write",
                "new-selection-with-new-subject",
                "no-auto-reactivation",
                "explicit-new-worker",
                "old-instance-remains-fenced",
                "worker-cleanup",
            )
        )
        expected.update(
            role + "-" + phase + "-" + suffix
            for phase in ("before", "after")
            for suffix in ("http-200", "model-and-subject", "prediction-shape", "golden-1e-6")
        )
        transition = value["transitions"][role]
        require(
            transition["release_ready"] is False
            and transition["model_sha256"] == object_id(value["model_sha256"])
        )
        for phase in ("before_golden_error", "after_golden_error"):
            require(0 <= trust_trace.number(transition[phase]) <= 1e-6)
        trace = transition["trace"]
        require_fields(
            trace, ("anchor", "first_503_seconds", "trace", "observations", "trust_receipt")
        )
        timings[role] = trust_trace.refusal(
            {**{k: v for k, v in trace.items() if k != "trust_receipt"}, "fault": "key-revocation"},
            "key-revocation",
        )
        online = trace["trust_receipt"]
        require(integer(online["version"]) == sequence and online["reused"] is False)
        object_id(online["document_sha256"])
        rotation, selection = transition["rotation"], transition["selection"]
        require(
            rotation["release_ready"] is False
            and selection["release_ready"] is False
            and rotation["reused"] is False
        )
        require(
            integer(selection["sequence"]) == sequence
            and integer(rotation["head"]["sequence"]) == sequence - 1
        )
        for receipt in (rotation, selection):
            require(receipt["trust"] == {k: online[k] for k in ("version", "document_sha256")})
        object_id(selection["request_sha256"])
        object_id(selection["subject_sha256"])
        if previous is not None:
            require(
                rotation["head"]["request_sha256"] == previous["request_sha256"]
                and selection["subject_sha256"] != previous["subject_sha256"]
            )
        previous = selection
    typed(value, {name: True for name in expected})
    require(len(value["cases"]) == len(expected))
    return timings


def _reconcile(value, source):
    passed(value)
    require_fields(source, ("source_revision", "source_fingerprint", "image_id"))
    require(value["source_dirty"] is False and {k: value[k] for k in source} == source)
    actual = value["actual_inference"]
    passed(actual)
    require(actual["source_dirty"] is False and actual["source"] == source)
    refusal = value["actual"]
    require(
        actual["actual_refusal"] == refusal
        and refusal["parent_refusal"] == "release_assurance_required"
        and refusal["job_outcome"] == "rejected"
    )
    for left, right in (
        ("candidate", "candidate_reference"),
        ("proposal", "proposal_reference"),
        ("model", "model_sha256"),
    ):
        require(object_id(refusal[left]) == object_id(actual[right]))
    for field in (
        "subject_sha256",
        "qualification_permit_sha256",
        "base_snapshot_sha256",
        "revoked_key_sha256",
    ):
        object_id(actual[field])
    clock_faults = trust_trace.dependency_faults(actual["native"]["clock_cache"])
    probe(
        actual,
        actual["native"],
        extra={
            fault + "-" + suffix: True
            for fault in clock_faults
            for suffix in ("generation-fenced", "reader-cleared", "cache-cleared")
        },
    )
    require_fields(actual["trust_lifecycle"], ("outage", "blackhole", "policy-change"))
    timings = {}
    for fault, report in actual["trust_lifecycle"].items():
        require(report["snapshot_sha256"] == actual["base_snapshot_sha256"])
        timings["actual-" + fault] = probe(actual, report["probe"], fault=fault)
    trust_trace.version_replay(
        actual["trust_lifecycle"]["policy-change"]["probe"]["version_replay"]
    )
    for field, fault, target in (
        ("model_revocation", "revocation", "model-revocation"),
        ("key_revocation", "key-revocation", "primary"),
    ):
        require(actual[field + "_snapshot_sha256"] == actual["base_snapshot_sha256"])
        timings["actual-" + field] = probe(actual, actual[field], target=target, fault=fault)
    independent(actual)
    root = actual["root_rotation"]
    passed(root)
    require(
        root["model_snapshot_sha256"] == actual["base_snapshot_sha256"]
        and root["permit_sha256"] == actual["qualification_permit_sha256"]
    )
    timings["actual-root-rotation"] = probe(actual, root["probe"], fault="root-rotation")
    for name in ("before_approval", "after_revocation"):
        ordinary(value[name], "refused-before-worker-start", "unapproved-or-revoked-ready-503")
    ordinary(value["approved"], "ordinary-CLI-ready-after-verified-load", "ONNX-golden-parity")
    expiry = value["approval_expiry"]
    ordinary(expiry["active"], "approval-expiry-no-reactivation")
    expiry_seconds = trust_trace.approval_expiry(expiry["active"]["lifecycle"])
    ordinary(expiry["cold"], "expected-reader-refusal", "refused-before-worker-start")
    rejected(expiry["retry"])
    require(expiry["expired_retry_ledger_unchanged"] is True)
    object_id(expiry["expired_retry_snapshot_sha256"])
    ordinary(expiry["recovery"], "ordinary-CLI-ready-after-verified-load", "ONNX-golden-parity")
    replay = value["unexpired_replay"]
    require(integer(replay["prior_sequence"]) < integer(replay["current_sequence"]))
    require(
        integer(replay["prior_valid_at_epoch"]) < integer(replay["prior_expires_at_epoch"])
        and replay["journal_unchanged"] is True
    )
    rejected(replay["refused"], "promotion_sequence_conflict")
    require(replay["current_retry"]["receipt"] == expiry["renewed_receipt"])
    rollback = value["authorized_rollback"]
    passed(rollback)
    require(canonical(rollback["sequence_path"]) == canonical([1, 2, 3]))
    require(
        rollback["from_model"]
        == value["controlled_renewed_model"]
        != value["controlled_model"]
        == rollback["target_model"]
    )
    require(rollback["from_receipt"] == expiry["renewed_receipt"])
    negative = rollback["negative"]
    reasons = {
        "from_request_sha256": "rollback_from_history",
        "target_request_sha256": "rollback_target_history",
        "conflicting_same_sequence": "rollback_head_changed",
    }
    require_fields(negative, reasons)
    for name, reason in reasons.items():
        rejected(negative[name]["outcome"], reason)
        object_id(negative[name]["unchanged_snapshot_sha256"])
    selected = rollback["admitted"]["receipt"]
    require(integer(selected["sequence"]) == 3 and selected["release_ready"] is False)
    require(selected == rollback["retry"]["receipt"])
    for field in ("proposal_reference", "subject_sha256"):
        require(selected[field] == rollback["target_receipt"][field])
    ordinary(rollback["serving"], "ONNX-golden-parity")
    rejected(rollback["revoked_retry"])
    require_fields(value["live_trust"], ("outage", "blackhole", "policy-change", "revocation"))
    for fault, report in value["live_trust"].items():
        ordinary(report, "no-automatic-reactivation")
        timings["controlled-" + fault] = trust_trace.refusal(report["lifecycle"], fault)
    return {
        "actual_candidate": actual["candidate_reference"],
        "model": actual["model_sha256"],
        "release_ready": False,
        "first_503_seconds": timings,
        "approval_expiry_seconds": expiry_seconds,
        "clock_cache_faults": clock_faults,
    }
