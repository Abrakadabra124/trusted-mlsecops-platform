"""Authentic captured trust response replay after two real policy transitions."""

from mlsecops import release_policy, trust
from mlsecops.contracts import Rejected, canonical, decode, digest


def validate_read(lease, envelope, server_clock):
    wall, _ = lease.sample()
    release_policy.integer(server_clock)
    if abs(wall - server_clock) > 2:
        raise Rejected("candidate_replay_server_clock")
    payload = trust.validate(envelope, lease.root, lease.environment, int(wall))
    trust.validate(envelope, lease.root, lease.environment, server_clock)
    return payload, wall


def capture(lease):
    with lease.lock:
        envelope, server_clock = lease.reader()
        payload, _ = validate_read(lease, envelope, server_clock)
        saved = canonical(envelope)
        if (
            payload != lease.payload
            or payload["version"] != lease.floor
            or digest(saved) != lease.observed_digest
        ):
            raise Rejected("candidate_replay_capture_binding")
        return saved


def response(lease, saved, current, server_clock):
    with lease.lock:
        if type(saved) is not bytes:
            raise Rejected("candidate_replay_capture_type")
        old = decode(saved, release_policy.MAX_DOCUMENT)
        if canonical(old) != saved:
            raise Rejected("candidate_replay_capture_encoding")
        current_payload, _ = validate_read(lease, current, server_clock)
        old_payload, wall = validate_read(lease, old, server_clock)
        if (
            current_payload != lease.payload
            or current_payload["version"] != lease.floor
            or digest(canonical(current)) != lease.observed_digest
            or current_payload["version"] != old_payload["version"] + 2
            or any(
                current_payload[field] != old_payload[field]
                for field in ("promotion_policy_sha256", "revoked_artifacts", "revoked_keys")
            )
        ):
            raise Rejected("candidate_replay_binding")
        return old, {
            "prior_document_sha256": digest(saved),
            "current_document_sha256": lease.observed_digest,
            "prior_version": old_payload["version"],
            "current_version": current_payload["version"],
            "prior_expires_at_epoch": old_payload["expires_at"],
            "checked_at_epoch": wall,
            "server_epoch": server_clock,
            "prior_valid_seconds": min(
                old_payload["expires_at"] - wall, old_payload["expires_at"] - server_clock
            ),
        }
