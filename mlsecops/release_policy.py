import re

from mlsecops import signing
from mlsecops.acceptance import GATES
from mlsecops.contracts import Rejected, canonical, digest, require_fields
from mlsecops.storage import object_id

MAX_DOCUMENT = 1024 * 1024
ROLES = ("publisher", "assessor", "approver")


def name(value):
    if not isinstance(value, str) or re.fullmatch(r"[a-z][a-z0-9._-]{0,95}", value) is None:
        raise Rejected("release_invalid_identity")
    return value


def integer(value, minimum=1, maximum=2**53 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise Rejected("release_invalid_integer")
    return value


def window(document, clock, maximum=86400):
    integer(clock)
    issued, expires = (integer(document[field]) for field in ("issued_at", "expires_at"))
    if not issued <= clock < expires or not 0 < expires - issued <= maximum:
        raise Rejected("release_expired_or_future_document")
    return issued, expires


def checked(envelope, kind, public):
    try:
        if len(canonical(envelope)) > MAX_DOCUMENT:
            raise Rejected("release_document_too_large")
        payload = signing.verify(envelope, kind, public)
        if signing.decode64(envelope["payload"]) != canonical(payload):
            raise Rejected("release_noncanonical_payload")
        return payload
    except RecursionError as error:
        raise Rejected("release_document_nesting") from error


def verify_policy(envelope, *, trusted_root, expected_policy, environment, clock):
    object_id(expected_policy)
    name(environment)
    policy = checked(envelope, "promotion-policy", trusted_root)
    require_fields(
        policy,
        (
            "schema_version",
            "environment",
            "version",
            "issued_at",
            "expires_at",
            "required_gates",
            "identities",
        ),
    )
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
        raise Rejected("release_unknown_policy_schema")
    integer(policy["version"])
    window(policy, clock)
    if digest(canonical(policy)) != expected_policy or policy["environment"] != environment:
        raise Rejected("release_policy_context_mismatch")
    if policy["required_gates"] != list(GATES):
        raise Rejected("release_required_gates_changed")
    require_fields(policy["identities"], ROLES)
    keys, issuers = {signing.decode64(trusted_root)}, set()
    for identity in policy["identities"].values():
        require_fields(identity, ("issuer", "public_key"))
        issuer, key = name(identity["issuer"]), signing.decode64(identity["public_key"])
        if len(key) != 32 or key in keys or issuer in issuers:
            raise Rejected("release_authorities_not_separated")
        keys.add(key)
        issuers.add(issuer)
    return policy
