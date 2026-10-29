"""Hosted faults on one trained candidate; irreversible revocation runs last."""

import math
import time

from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.kube_candidate_trust import NONTERMINAL
from mlsecops.trust_targets import Target, select
from scripts.kube_promotion_snapshot import read as snapshot
from scripts.kube_serving_faults import Coordinator
from scripts.kube_serving_native import invoke


def exercise(
    state,
    profile,
    config,
    expected,
    *,
    key,
    policy,
    revoked_key,
    faults,
    expires_at,
    target=Target.PRIMARY,
):
    target = select(target)
    allowed = (
        (NONTERMINAL, ("key-revocation",), (*NONTERMINAL, "key-revocation"))
        if target is Target.PRIMARY
        else (("revocation",),)
    )
    if (
        faults not in allowed
        or select(config.get("trust_target", Target.PRIMARY.value)) is not target
    ):
        raise Rejected("candidate_trust_fault_order")
    results = {}
    for fault in faults:
        if expires_at - math.ceil(time.time()) < 180:
            raise Rejected("candidate_trust_window")
        before = snapshot(state)
        label = "model-revocation" if target is Target.MODEL_REVOCATION else fault
        print(canonical({"stage": "actual-candidate-" + label}).decode(), flush=True)
        with Coordinator(
            state, fault, policy, key, expected["model"], revoked_key=revoked_key, target=target
        ) as coordinator:
            report = invoke(
                state,
                profile,
                config,
                {**expected, "fault": fault},
                coordinator=coordinator,
                candidate_probe=True,
                trust_target=target,
            )
        if (
            report.get("status") != "pass"
            or report.get("release_ready") is not False
            or report.get("model_sha256") != expected["model"]
            or report.get("subject_sha256") != expected["bundle"]
            or report.get("lifecycle", {}).get("fault") != fault
            or report.get("authority_target") != target.value
            or snapshot(state) != before
        ):
            raise Rejected("candidate_trust_binding_changed")
        results[fault] = {"probe": report, "snapshot_sha256": digest(canonical(before))}
    return results
