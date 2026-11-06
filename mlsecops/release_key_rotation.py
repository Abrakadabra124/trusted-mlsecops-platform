"""Bounded policy-owner authorization for one release signer transition."""

import copy

from mlsecops import release_policy, signing, storage
from mlsecops.contracts import Rejected, canonical, digest, require_fields

KIND = "release-key-rotation"
FIELDS = (
    "schema_version",
    "environment",
    "role",
    "previous_policy_sha256",
    "next_policy_sha256",
    "sequence",
    "request_sha256",
    "issued_at",
    "expires_at",
)


def verify(package, *, trusted_root, expected_policy, head, environment, clock):
    require_fields(package, ("schema_version", "authorization", "previous_policy", "next_policy"))
    if type(package["schema_version"]) is not int or package["schema_version"] != 1:
        raise Rejected("release_rotation_schema")
    try:
        if len(canonical(package)) > release_policy.MAX_DOCUMENT:
            raise Rejected("release_rotation_size")
    except RecursionError:
        raise Rejected("release_rotation_nesting") from None
    require_fields(head, ("sequence", "request_sha256"))
    release_policy.integer(head["sequence"])
    storage.object_id(head["request_sha256"])
    intent = release_policy.checked(package["authorization"], KIND, trusted_root)
    require_fields(intent, FIELDS)
    if intent["role"] not in release_policy.ROLES:
        raise Rejected("release_rotation_role")
    issued, expires = release_policy.window(intent, clock, 600)
    policies = [
        release_policy.verify_policy(
            package[field],
            trusted_root=trusted_root,
            expected_policy=reference,
            environment=environment,
            clock=clock,
        )
        for field, reference in (
            ("previous_policy", expected_policy),
            ("next_policy", intent["next_policy_sha256"]),
        )
    ]
    before, after = policies
    expected = {
        "schema_version": 1,
        "environment": environment,
        "role": intent["role"],
        "previous_policy_sha256": expected_policy,
        "next_policy_sha256": digest(canonical(after)),
        **head,
        "issued_at": issued,
        "expires_at": expires,
    }
    if canonical(intent) != canonical(expected):
        raise Rejected("release_rotation_binding")
    role = intent["role"]
    old_key, new_key = (
        digest(signing.decode64(policy["identities"][role]["public_key"])) for policy in policies
    )
    successor = copy.deepcopy(before)
    successor.update(
        version=before["version"] + 1,
        issued_at=after["issued_at"],
        expires_at=after["expires_at"],
    )
    successor["identities"][role]["public_key"] = after["identities"][role]["public_key"]
    if (
        old_key == new_key
        or canonical(after) != canonical(successor)
        or after["issued_at"] < before["issued_at"]
        or issued < after["issued_at"]
        or expires > min(before["expires_at"], after["expires_at"])
    ):
        raise Rejected("release_rotation_policy_change")
    return {
        "intent": intent,
        "previous_version": before["version"],
        "next_version": after["version"],
        "previous_key": old_key,
        "next_key": new_key,
        "release_ready": False,
    }


def migration_sql():
    return """CREATE TABLE ml_promotion.policy_rotations (
    environment text NOT NULL REFERENCES ml_promotion.authorities(environment),
    version bigint NOT NULL CHECK (version BETWEEN 2 AND 9007199254740991),
    previous_version bigint NOT NULL CHECK (previous_version BETWEEN 1 AND 9007199254740990),
    boundary_sequence bigint NOT NULL,
    request_sha256 text NOT NULL REFERENCES ml.releases(sha256),
    previous_policy_sha256 text NOT NULL CHECK (previous_policy_sha256 ~ '^[a-f0-9]{64}$'),
    policy_sha256 text NOT NULL CHECK (policy_sha256 ~ '^[a-f0-9]{64}$'),
    sha256 text NOT NULL UNIQUE CHECK (sha256 ~ '^[a-f0-9]{64}$'),
    package bytea NOT NULL CHECK (octet_length(package) BETWEEN 1 AND 1048576),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (environment, version),
    UNIQUE (environment, policy_sha256),
    FOREIGN KEY (environment, boundary_sequence) REFERENCES ml_promotion.events(environment, sequence),
    CHECK (version = previous_version + 1),
    CHECK (previous_policy_sha256 <> policy_sha256),
    CHECK (encode(sha256(package), 'hex') = sha256)
);
REVOKE ALL ON ml_promotion.policy_rotations FROM PUBLIC, ml_promoter, ml_serving;
"""
