"""Planned authority-root replacement, signed by both the old and new owner."""

from mlsecops import release_policy, signing, trust
from mlsecops.contracts import Rejected, canonical, digest, require_fields
from mlsecops.storage import object_id

KIND = "trust-root-rotation"
FIELDS = (
    "schema_version",
    "environment",
    "current_root",
    "next_root",
    "previous_version",
    "previous_sha256",
    "next_version",
    "next_sha256",
    "issued_at",
    "expires_at",
)


def key_id(public):
    raw = signing.decode64(public)
    if len(raw) != 32 or signing.encode64(raw) != public:
        raise Rejected("rotation_root_invalid")
    return digest(raw)


def authorization(package, current_root):
    require_fields(package, ("schema_version", "authorization", "acceptance", "document"))
    if type(package["schema_version"]) is not int or package["schema_version"] != 1:
        raise Rejected("rotation_package_schema")
    if len(canonical(package)) > release_policy.MAX_DOCUMENT:
        raise Rejected("rotation_package_size")
    key_id(current_root)
    intent = release_policy.checked(package["authorization"], KIND, current_root)
    require_fields(intent, FIELDS)
    object_id(intent["previous_sha256"])
    return intent


def verify(package, *, previous, environment, current_root, next_root, clock):
    intent = authorization(package, current_root)
    old_id, new_id = key_id(current_root), key_id(next_root)
    before = trust.validate(previous, current_root, environment, clock)
    after = trust.validate(package["document"], next_root, environment, clock)
    accepted = release_policy.checked(package["acceptance"], KIND, next_root)
    expected = {
        "schema_version": 1,
        "environment": environment,
        "current_root": current_root,
        "next_root": next_root,
        "previous_version": before["version"],
        "previous_sha256": digest(canonical(previous)),
        "next_version": after["version"],
        "next_sha256": digest(canonical(package["document"])),
        "issued_at": after["issued_at"],
        "expires_at": intent["expires_at"],
    }
    if canonical(intent) != canonical(expected) or canonical(accepted) != canonical(expected):
        raise Rejected("rotation_signed_binding")
    issued, expires = release_policy.window(intent, clock, 600)
    trust.successor(before, after)
    if (
        old_id == new_id
        or {old_id, new_id}.intersection(before["revoked_keys"])
        or issued < before["issued_at"]
        or expires > min(before["expires_at"], after["expires_at"])
        or after["promotion_policy_sha256"] != before["promotion_policy_sha256"]
        or after["revoked_artifacts"] != before["revoked_artifacts"]
        or after["revoked_keys"] != sorted([*before["revoked_keys"], old_id])
    ):
        raise Rejected("rotation_policy_or_revocation_binding")
    return intent


def migration_sql():
    # Additive migration: never change the checksum of authority schema v1.
    return """CREATE TABLE ml_trust.root_rotations (
    version bigint PRIMARY KEY REFERENCES ml_trust.documents(version),
    sha256 text NOT NULL UNIQUE CHECK (sha256 ~ '^[a-f0-9]{64}$'),
    package bytea NOT NULL CHECK (octet_length(package) BETWEEN 1 AND 1048576),
    CHECK (encode(sha256(package), 'hex') = sha256)
);
REVOKE ALL ON ml_trust.root_rotations FROM PUBLIC, ml_serving, ml_promoter;
"""
