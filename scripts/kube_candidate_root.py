"""Rotate a live candidate's authority, then explicitly rotate its independent peer."""

import math
import time
from functools import partial

from mlsecops import kube_trust, trust_authority, trust_root_store, trust_rotation
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.trust_targets import Target
from scripts import kube_root_rotation as rotation
from scripts.kube_promotion_snapshot import read as snapshot
from scripts.kube_serving_native import invoke


def checked(report, expected, recovery, permit):
    required = {
        "qualification-permit-payload": permit["payload"],
        "qualification-permit-envelope": permit["envelope"],
        "root-recovery-permit-payload": permit["payload"],
        "root-recovery-permit-envelope": permit["envelope"],
        "golden-status": 200,
        "trust-fault-initial-prediction": True,
        "cold-reader-root-rotation": True,
        "no-automatic-reactivation": True,
        "trust-fault-readiness-503": True,
        "trust-fault-complete-trace": True,
        "root-recovery-golden-status": 200,
        "root-recovery-golden-model": expected["model"],
        "root-recovery-golden-bundle": expected["bundle"],
        "root-recovery-golden-parity-1e-6": True,
        "root-recovery-worker-absence": 0,
        "root-recovery-worker-cleanup": 0,
        "final-worker-absence": 0,
    }
    cases = report.get("cases", [])
    labels = {c["id"]: c for c in cases}
    restored = report.get("root_recovery", {})
    errors = (report.get("max_golden_error"), restored.get("max_golden_error"))
    if (
        report.get("status") != "pass"
        or report.get("release_ready") is not False
        or report.get("authority_target") != Target.PRIMARY.value
        or report.get("model_sha256") != expected["model"]
        or report.get("subject_sha256") != expected["bundle"]
        or restored != {**recovery, "max_golden_error": errors[1]}
        or any(
            type(e) not in (int, float) or not math.isfinite(e) or not 0 <= e <= 1e-6
            for e in errors
        )
        or any(
            c["status"] != "pass" or canonical(c["actual"]) != canonical(c["expected"])
            for c in cases
        )
        or any(
            k not in labels or canonical(labels[k]["actual"]) != canonical(v)
            for k, v in required.items()
        )
    ):
        raise Rejected("candidate_root_probe_binding")
    trace = report.get("lifecycle", {})
    rows = trace.get("trace", [])
    previous, first, denied = 0, None, 0
    for row in rows:
        start, end, status = row["start_seconds"], row["end_seconds"], row["http_status"]
        if (
            any(type(t) not in (int, float) or not math.isfinite(t) for t in (start, end))
            or not previous <= start <= end
            or type(status) is not int
            or status not in (200, 503)
            or (status == 200 and (denied or end >= 60))
        ):
            raise Rejected("candidate_root_trace")
        previous = end
        if status == 503:
            first = end if first is None else first
            denied += 1
    if (
        trace.get("fault") != "root-rotation"
        or trace.get("observations") != len(rows)
        or denied < 2
        or first is None
        or not 0 <= first <= 60
        or trace.get("first_503_seconds") != first
    ):
        raise Rejected("candidate_root_trace")


def exercise(state, profile, config, expected, *, old_key, new_key, expires_at):
    old_public = config["trust_root"]
    if trust_rotation.key_id(old_public) == trust_rotation.key_id(config["permit_public"]):
        raise Rejected("candidate_root_key_separation")
    if expires_at - math.ceil(time.time()) < 180:
        raise Rejected("candidate_root_window")
    models = snapshot(state)
    backends = {target: partial(kube_trust.binding, target=target) for target in Target}
    for backend in backends.values():
        trust_root_store.migrate(state, backend=backend)
    before = {target.value: rotation.snapshot(state, target=target) for target in Target}
    _, current = trust_authority.current(state, backend=backends[Target.PRIMARY])
    package = rotation.prepare(current, old_key, new_key)
    intent = trust_rotation.authorization(package, old_public)
    recovery = {"trust_root": intent["next_root"], "minimum_trust_version": intent["next_version"]}
    arguments = {"current_root": old_public, "next_root": intent["next_root"]}
    phases, receipt = [], None

    def coordinate(phase):
        nonlocal receipt
        if [*phases, phase] != ["ready", "denied"][: len(phases) + 1]:
            raise Rejected("candidate_root_phase")
        if phase == "ready":
            receipt = trust_root_store.rotate(
                state, package, backend=backends[Target.PRIMARY], **arguments
            )
            if (
                receipt.get("state") != "rotated-not-activated"
                or receipt.get("reused") is not False
                or receipt.get("release_ready") is not False
            ):
                raise Rejected("candidate_root_receipt")
        # No old-key restore on denial, interruption or exception.
        phases.append(phase)

    print(canonical({"stage": "actual-candidate-root-rotation"}).decode(), flush=True)
    probe = invoke(
        state,
        profile,
        config,
        {**expected, "fault": "root-rotation", "root_recovery": recovery},
        coordinator=coordinate,
        candidate_probe=True,
    )
    if phases != ["ready", "denied"]:
        raise Rejected("candidate_root_phase")
    permit = {
        "payload": config["expected_permit"],
        "envelope": digest(canonical(config["permit_envelope"])),
    }
    checked(probe, expected, recovery, permit)
    primary = rotation.snapshot(state)
    rotation.transition(before[Target.PRIMARY.value], primary, receipt)
    if (
        rotation.snapshot(state, target=Target.MODEL_REVOCATION)
        != before[Target.MODEL_REVOCATION.value]
    ):
        raise Rejected("candidate_root_peer_changed")
    retry = trust_root_store.rotate(state, package, backend=backends[Target.PRIMARY], **arguments)
    if retry != {**receipt, "reused": True} or rotation.snapshot(state) != primary:
        raise Rejected("candidate_root_retry")
    # The peer is a separate operator action after live primary recovery. Its
    # own history is preserved; this is not an atomic two-authority operation.
    _, peer = trust_authority.current(state, backend=backends[Target.MODEL_REVOCATION])
    peer_package = rotation.prepare(peer, old_key, new_key)
    peer_receipt = trust_root_store.rotate(
        state, peer_package, backend=backends[Target.MODEL_REVOCATION], **arguments
    )
    alternate = rotation.snapshot(state, target=Target.MODEL_REVOCATION)
    rotation.transition(before[Target.MODEL_REVOCATION.value], alternate, peer_receipt)
    if rotation.snapshot(state) != primary or snapshot(state) != models:
        raise Rejected("candidate_root_storage_changed")
    return {
        "status": "pass",
        "release_ready": False,
        "scope": "actual-candidate-live-root-rotation",
        "next_public": intent["next_root"],
        "minimum_trust_version": receipt["version"],
        "permit_sha256": config["expected_permit"],
        "permit_envelope_sha256": permit["envelope"],
        "probe": probe,
        "model_snapshot_sha256": digest(canonical(models)),
        "authorities": {
            Target.PRIMARY.value: {
                "before": before[Target.PRIMARY.value],
                "after": primary,
                "receipt": receipt,
                "retry": retry,
            },
            Target.MODEL_REVOCATION.value: {
                "before": before[Target.MODEL_REVOCATION.value],
                "after": alternate,
                "receipt": peer_receipt,
            },
        },
    }
