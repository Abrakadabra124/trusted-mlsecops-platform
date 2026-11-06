"""Explicit, additive release-policy history migration for owned storage."""

from mlsecops import promotion_state, release_key_rotation, release_policy, signing, storage
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.storage_bootstrap import admin, validate


def migrate(state, *, backend=None):
    name, execute = (validate(state)["name"], admin) if backend is None else backend(state)
    script = release_key_rotation.migration_sql()
    checksum = digest(script.encode())
    if promotion_state.migration_version(name, execute) == 2:
        return checksum
    original = f"1:{digest(promotion_state.migration_sql().encode())}"
    execute(
        name,
        f"""BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
SELECT pg_advisory_xact_lock(hashtextextended('mlsecops-release-policy-migration',0));
SET LOCAL ROLE ml_owner;
DO $migration$
DECLARE history text;
BEGIN
    SELECT string_agg(version || ':' || sha256, E'\\n' ORDER BY version)
        INTO history FROM ml_promotion.migrations;
    IF history = '{original}' THEN
        {script}
        INSERT INTO ml_promotion.migrations VALUES (2, '{checksum}');
    ELSIF history IS DISTINCT FROM E'{original}\\n2:{checksum}' THEN
        RAISE EXCEPTION 'promotion_migration_history_mismatch';
    END IF;
END $migration$;
COMMIT;""",
    )
    if promotion_state.migration_version(name, execute) != 2:
        raise Rejected("release_rotation_migration_readback")
    return checksum


def snapshot(name, execute, environment):
    release_policy.name(environment)
    observed = decode(
        execute(
            name,
            f"""SELECT jsonb_build_object(
        'policy_sha256', authority.policy_sha256,
        'head', jsonb_build_object('sequence',head.sequence,'request_sha256',head.request_sha256),
        'clock', floor(extract(epoch FROM clock_timestamp()))::bigint,
        'rotation_sha256', (SELECT sha256 FROM ml_promotion.policy_rotations
            WHERE environment = '{environment}' ORDER BY version DESC LIMIT 1))
        FROM ml_promotion.authorities AS authority JOIN ml_promotion.heads AS head USING(environment)
        WHERE authority.environment = '{environment}';""",
        ).encode()
    )
    require_fields(observed, ("policy_sha256", "head", "clock", "rotation_sha256"))
    storage.object_id(observed["policy_sha256"])
    release_policy.integer(observed["clock"])
    require_fields(observed["head"], ("sequence", "request_sha256"))
    release_policy.integer(observed["head"]["sequence"])
    storage.object_id(observed["head"]["request_sha256"])
    if observed["rotation_sha256"] is not None:
        storage.object_id(observed["rotation_sha256"])
    return observed


def record_sql(verified, content):
    intent = verified["intent"]
    env, sequence, request = intent["environment"], intent["sequence"], intent["request_sha256"]
    old, new = intent["previous_policy_sha256"], intent["next_policy_sha256"]
    reference = digest(content)
    return f"""BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
SET LOCAL ROLE ml_owner;
DO $rotation$
DECLARE current_head ml_promotion.heads%ROWTYPE;
        previous ml_promotion.policy_rotations%ROWTYPE;
        pinned text; observed bigint;
BEGIN
    SELECT * INTO current_head FROM ml_promotion.heads WHERE environment='{env}' FOR UPDATE;
    IF NOT FOUND OR current_head.sequence IS DISTINCT FROM {sequence}
        OR current_head.request_sha256 IS DISTINCT FROM '{request}' THEN
        RAISE EXCEPTION 'release_rotation_head_changed';
    END IF;
    SELECT policy_sha256 INTO pinned FROM ml_promotion.authorities WHERE environment='{env}' FOR UPDATE;
    SELECT * INTO previous FROM ml_promotion.policy_rotations WHERE environment='{env}' ORDER BY version DESC LIMIT 1;
    observed := floor(extract(epoch FROM clock_timestamp()))::bigint;
    IF observed < {intent["issued_at"]} OR observed >= {intent["expires_at"]} THEN
        RAISE EXCEPTION 'release_rotation_expired';
    END IF;
    IF pinned = '{new}' AND previous.sha256 = '{reference}' THEN
        RETURN;
    END IF;
    IF pinned IS DISTINCT FROM '{old}' THEN
        RAISE EXCEPTION 'release_rotation_policy_conflict';
    END IF;
    IF previous.version IS NOT NULL AND (previous.version != {verified["previous_version"]}
        OR previous.policy_sha256 != '{old}' OR previous.boundary_sequence > {sequence}) THEN
        RAISE EXCEPTION 'release_rotation_history_conflict';
    END IF;
    INSERT INTO ml_promotion.policy_rotations(environment,version,previous_version,boundary_sequence,
        request_sha256,previous_policy_sha256,policy_sha256,sha256,package)
    VALUES ('{env}',{verified["next_version"]},{verified["previous_version"]},{sequence},'{request}',
        '{old}','{new}','{reference}',decode('{content.hex()}','hex'));
    UPDATE ml_promotion.authorities SET policy_sha256='{new}' WHERE environment='{env}';
END $rotation$;
COMMIT;"""


def rotate(state, package, *, trusted_root, expected_policy, environment, lease, backend=None):
    if lease.environment != environment:
        raise Rejected("release_rotation_trust_environment")
    name, execute = (validate(state)["name"], admin) if backend is None else backend(state)
    if promotion_state.migration_version(name, execute) != 2:
        raise Rejected("release_rotation_migration_required")
    observed = snapshot(name, execute, environment)
    with lease.lock:
        wall, _ = lease.sample()
        if abs(wall - observed["clock"]) > 2:
            raise Rejected("release_rotation_clock_skew")
    verified = release_key_rotation.verify(
        package,
        trusted_root=trusted_root,
        expected_policy=expected_policy,
        head=observed["head"],
        environment=environment,
        clock=observed["clock"],
    )
    content = canonical(package)
    reference = digest(content)
    following = verified["intent"]["next_policy_sha256"]
    reused = observed["policy_sha256"] == following and observed["rotation_sha256"] == reference
    if not reused and observed["policy_sha256"] != expected_policy:
        raise Rejected("release_rotation_policy_conflict")
    policy = release_policy.checked(package["next_policy"], "promotion-policy", trusted_root)
    scope = {
        "policy_sha256": following,
        "keys": [
            digest(signing.decode64(public))
            for public in (
                trusted_root,
                *(identity["public_key"] for identity in policy["identities"].values()),
            )
        ],
        "artifacts": [
            reference,
            following,
            digest(canonical(package["authorization"])),
            digest(canonical(package["next_policy"])),
        ],
    }
    lease.refresh()
    with lease.lock:
        trusted = lease.check(**scope)
        if verified["previous_key"] not in lease.payload["revoked_keys"]:
            raise Rejected("release_rotation_old_key_not_revoked")
    if not reused:
        execute(name, record_sql(verified, content))
        committed = snapshot(name, execute, environment)
        if (
            committed["policy_sha256"] != following
            or committed["rotation_sha256"] != reference
            or committed["head"] != observed["head"]
        ):
            raise Rejected("release_rotation_commit_readback")
        trusted = lease.check(**scope)
    return {
        "rotation_sha256": reference,
        "policy_sha256": following,
        "head": observed["head"],
        "trust": trusted,
        "reused": reused,
        "release_ready": False,
    }
