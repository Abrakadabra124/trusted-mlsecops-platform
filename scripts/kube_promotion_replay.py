"""Reject a still-valid previous sequence through the ordinary isolated promoter."""

import time

from mlsecops import kube_promotion, release_authorization
from mlsecops.contracts import Rejected, canonical, digest
from scripts.kube_promotion_native import stage
from scripts.kube_promotion_snapshot import read as snapshot


def exercise(root, state, image, config, previous, current_request, current_receipt):
    prior = release_authorization.verify(**previous, clock=int(time.time()))
    if (
        prior["sequence"] + 1 != current_receipt["sequence"]
        or prior["environment"] != current_receipt["environment"]
    ):
        raise Rejected("kube_promotion_replay_sequence")
    before = snapshot(state)
    old_request = stage(
        state,
        previous["package"],
        previous["policy_envelope"],
        previous["assurance_envelope"],
        previous["approval_envelope"],
        previous["reports"],
    )
    prior_config = {**config, "context": previous["context"]}
    refused = kube_promotion.invoke(root, state, prior_config, old_request, image)
    if refused["status"] != "rejected" or refused.get("reason") != "promotion_sequence_conflict":
        raise Rejected("kube_promotion_replay_reason")
    after = snapshot(state)
    if after["promotion"] != before["promotion"]:
        raise Rejected("kube_promotion_replay_journal")
    observed = int(time.time())
    release_authorization.verify(**previous, clock=observed)
    retried = kube_promotion.invoke(root, state, config, current_request, image)
    # A fresh trust observation is expected; the selected immutable bundle must not change.
    identity = {k: v for k, v in current_receipt.items() if k != "trust"}
    receipt = retried.get("receipt") or {}
    if (
        retried["status"] != "recorded-not-activated"
        or {k: v for k, v in receipt.items() if k != "trust"} != identity
        or snapshot(state) != after
    ):
        raise Rejected("kube_promotion_replay_current_retry")
    return {
        "prior_sequence": prior["sequence"],
        "current_sequence": current_receipt["sequence"],
        "prior_valid_at_epoch": observed,
        "prior_expires_at_epoch": prior["expires_at"],
        "refused": refused,
        "current_retry": retried,
        "journal_unchanged": True,
        "journal_sha256": digest(canonical(before["promotion"])),
        "current_retry_snapshot_sha256": digest(canonical(after)),
        "release_ready": False,
    }
