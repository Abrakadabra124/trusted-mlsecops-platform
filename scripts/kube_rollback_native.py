"""Ordinary isolated promoter rollback of controlled, previously selected bundles."""

import copy
import time

from mlsecops import kube_promotion, release_authorization, release_policy, signing
from mlsecops.contracts import Rejected, canonical, digest
from scripts.kube_promotion_native import stage
from scripts.kube_promotion_snapshot import read as snapshot


def variant(fixture, image, features):
    from mlsecops.datasets import generate
    from mlsecops.worker import train
    from scripts.serving_native import bind_model

    result = train(
        {
            "action": "train",
            "train": generate(seed=73039, rows=1000),
            "seed": 17,
            "features": features,
        }
    )
    content = signing.decode64(result["model"])
    bind_model(fixture, image, content, result)
    return digest(content), result["python_scores"]


def identity(receipt):
    return {name: value for name, value in receipt.items() if name != "trust"}


def exercise(root, state, image, config, previous, target, current, approver):
    prior = release_authorization.verify(**previous, clock=int(time.time()))
    proposal = digest(canonical(previous["package"]["envelope"]))
    if (
        target["sequence"] != prior["sequence"]
        or target["subject_sha256"] != prior["subject_sha256"]
        or target["proposal_reference"] != proposal
        or target["sequence"] + 1 != current["sequence"]
        or target["environment"] != current["environment"]
        or target["environment"] != prior["environment"]
    ):
        raise Rejected("rollback_fixture_history")
    policy = release_policy.checked(
        previous["policy_envelope"], "promotion-policy", previous["trusted_root"]
    )
    old_approval = release_policy.checked(
        previous["approval_envelope"],
        "release-approval",
        policy["identities"]["approver"]["public_key"],
    )
    approval = {
        **old_approval,
        "schema_version": 2,
        "action": "rollback",
        "issued_at": int(time.time()),
        "sequence": current["sequence"] + 1,
        "rollback": {
            "from_sequence": current["sequence"],
            "from_request_sha256": current["request_sha256"],
            "target_request_sha256": target["request_sha256"],
        },
    }

    def request(payload):
        arguments = {
            **previous,
            "approval_envelope": signing.sign(payload, "release-approval", approver),
        }
        # Every negative native request is cryptographically valid. History is
        # checked only by the production promoter and Reader, not by this fixture.
        release_authorization.verify(**arguments, clock=int(time.time()))
        return stage(
            state,
            *(
                arguments[name]
                for name in (
                    "package",
                    "policy_envelope",
                    "assurance_envelope",
                    "approval_envelope",
                    "reports",
                )
            ),
        )

    negatives = {}

    def refused(label, payload, reason):
        submitted = request(payload)
        before = snapshot(state)
        outcome = kube_promotion.invoke(root, state, config, submitted, image)
        if (
            outcome.get("status") != "rejected"
            or outcome.get("receipt") is not None
            or outcome.get("reason") != reason
            or outcome.get("release_ready") is not False
            or snapshot(state) != before
        ):
            raise Rejected("rollback_native_refusal_or_mutation")
        negatives[label] = {
            "outcome": outcome,
            "unchanged_snapshot_sha256": digest(canonical(before)),
        }

    for field, reason in (
        ("from_request_sha256", "rollback_from_history"),
        ("target_request_sha256", "rollback_target_history"),
    ):
        payload = copy.deepcopy(approval)
        payload["rollback"][field] = "0" * 64
        refused(field, payload, reason)
    selected_request = request(approval)
    before = snapshot(state)
    accepted = kube_promotion.invoke(root, state, config, selected_request, image)
    receipt = accepted.get("receipt") or {}
    if (
        accepted.get("status") != "recorded-not-activated"
        or receipt.get("release_ready") is not False
        or receipt.get("sequence") != approval["sequence"]
        or receipt.get("subject_sha256") != target["subject_sha256"]
        or receipt.get("proposal_reference") != proposal
        or receipt.get("environment") != prior["environment"]
        or receipt.get("request_sha256") in (target["request_sha256"], current["request_sha256"])
    ):
        raise Rejected("rollback_native_receipt")
    after = snapshot(state)
    old_tables, tables = (s["promotion"]["tables"] for s in (before, after))
    if (
        before["promotion"]["migration"] != after["promotion"]["migration"]
        or old_tables["authorities"] != tables["authorities"]
        or tables["events"]["rows"] != old_tables["events"]["rows"] + 1
        or tables["heads"]["rows"] != old_tables["heads"]["rows"]
        or set(before["objects"]) != set(after["objects"])
        or any(
            before["objects"][k] != after["objects"][k]
            for k in before["objects"]
            if k != "releases"
        )
    ):
        raise Rejected("rollback_native_history_transition")
    retry = kube_promotion.invoke(root, state, config, selected_request, image)
    if (
        retry.get("status") != "recorded-not-activated"
        or retry.get("release_ready") is not False
        or identity(retry.get("receipt") or {}) != identity(receipt)
        or snapshot(state) != after
    ):
        raise Rejected("rollback_native_retry")
    refused(
        "conflicting_same_sequence",
        {**approval, "expires_at": approval["expires_at"] - 1},
        "rollback_head_changed",
    )
    return {
        "scope": "controlled-ordinary-promoter-rollback-not-M16-acceptance",
        "status": "pass",
        "release_ready": False,
        "from_receipt": current,
        "target_receipt": target,
        "admitted": accepted,
        "retry": retry,
        "request": selected_request,
        "negative": negatives,
        "before": before,
        "after": after,
        "sequence_path": [target["sequence"], current["sequence"], receipt["sequence"]],
    }
