"""Explicit rollback intent; an unchanged bundle gets a new selection sequence."""

import psycopg

from mlsecops import promotion_state, release_policy, storage
from mlsecops.contracts import Rejected, digest, require_fields

PUBLIC_REJECTIONS = ("rollback_from_history", "rollback_target_history", "rollback_head_changed")


def intent(approval, bundle_sequence):
    rollback = approval["rollback"]
    require_fields(rollback, ("from_sequence", "from_request_sha256", "target_request_sha256"))
    previous = release_policy.integer(rollback["from_sequence"])
    following = release_policy.integer(approval["sequence"])
    for field in ("from_request_sha256", "target_request_sha256"):
        storage.object_id(rollback[field])
    if (
        approval["action"] != "rollback"
        or following != previous + 1
        or previous <= bundle_sequence
        or rollback["from_request_sha256"] == rollback["target_request_sha256"]
    ):
        raise Rejected("release_rollback_binding")
    return dict(rollback)


def history(client, rollback, selection, reference, *, selected=False):
    """Bind signed intent to immutable events; SQL CAS still serializes selection.

    A retry is allowed only while this exact request remains the current head.
    Serving additionally requires its event's previous link to match the intent.
    """
    environment = selection["environment"]
    try:
        with storage.connect(client) as connection:
            previous = connection.execute(
                "SELECT sequence, request_sha256, previous_sha256 FROM ml_promotion.events "
                "WHERE environment = %s AND sequence = %s",
                (environment, rollback["from_sequence"]),
            ).fetchone()
            target = connection.execute(
                "SELECT sequence, request_sha256, previous_sha256 FROM ml_promotion.events "
                "WHERE environment = %s AND request_sha256 = %s",
                (environment, rollback["target_request_sha256"]),
            ).fetchone()
            head = connection.execute(
                "SELECT head.sequence, head.request_sha256, event.previous_sha256 "
                "FROM ml_promotion.heads head LEFT JOIN ml_promotion.events event "
                "ON event.environment = head.environment AND event.sequence = head.sequence "
                "AND event.request_sha256 = head.request_sha256 WHERE head.environment = %s",
                (environment,),
            ).fetchone()
    except psycopg.Error:
        raise Rejected("rollback_history_unavailable") from None
    if previous is None or previous[:2] != (
        rollback["from_sequence"],
        rollback["from_request_sha256"],
    ):
        raise Rejected("rollback_from_history")
    if (
        target is None
        or type(target[0]) is not int
        or not 1 <= target[0] < rollback["from_sequence"]
        or target[1] != rollback["target_request_sha256"]
    ):
        raise Rejected("rollback_target_history")
    content = storage.get(client, "releases", rollback["target_request_sha256"])
    if not isinstance(content, bytes) or digest(content) != rollback["target_request_sha256"]:
        raise Rejected("rollback_target_integrity")
    prior = promotion_state.request(content)
    if prior["sequence"] != target[0] or any(
        prior[field] != selection[field]
        for field in ("environment", "policy_sha256", "subject_sha256", "proposal_reference")
    ):
        raise Rejected("rollback_target_binding")
    if not selected and head is not None and head[:2] == previous[:2]:
        return
    if head != (selection["sequence"], reference, rollback["from_request_sha256"]):
        raise Rejected("rollback_head_changed")
