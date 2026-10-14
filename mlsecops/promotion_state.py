import psycopg

from mlsecops import release_policy, storage
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.storage_bootstrap import admin, validate

FIELDS = (
    "schema_version",
    "kind",
    "environment",
    "policy_sha256",
    "sequence",
    "subject_sha256",
    "proposal_reference",
    "authorization_reference",
    "issued_at",
    "expires_at",
)


def request(content):
    if not isinstance(content, bytes):
        raise Rejected("promotion_request_invalid")
    payload = decode(content, 65536)
    require_fields(payload, FIELDS)
    if (
        content != canonical(payload)
        or type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or payload["kind"] != "promotion-selection"
    ):
        raise Rejected("promotion_request_invalid")
    release_policy.name(payload["environment"])
    for field in (
        "policy_sha256",
        "subject_sha256",
        "proposal_reference",
        "authorization_reference",
    ):
        storage.object_id(payload[field])
    for field in ("sequence", "issued_at", "expires_at"):
        release_policy.integer(payload[field])
    if not 0 < payload["expires_at"] - payload["issued_at"] <= 3600:
        raise Rejected("promotion_request_window_invalid")
    return payload


def migration_sql():
    return """SET LOCAL ROLE ml_owner;
CREATE SCHEMA ml_promotion;
REVOKE ALL ON SCHEMA ml_promotion FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA ml_promotion REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA ml_promotion REVOKE ALL ON FUNCTIONS FROM PUBLIC;
CREATE TABLE ml_promotion.migrations (version integer PRIMARY KEY, sha256 text NOT NULL);
CREATE TABLE ml_promotion.authorities (
    environment text COLLATE "C" PRIMARY KEY CHECK (environment ~ '^[a-z][a-z0-9._-]{0,95}$'),
    policy_sha256 text NOT NULL CHECK (policy_sha256 ~ '^[a-f0-9]{64}$')
);
CREATE TABLE ml_promotion.events (
    environment text NOT NULL REFERENCES ml_promotion.authorities(environment),
    sequence bigint NOT NULL CHECK (sequence BETWEEN 1 AND 9007199254740991),
    request_sha256 text NOT NULL UNIQUE REFERENCES ml.releases(sha256),
    previous_sha256 text REFERENCES ml.releases(sha256),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (environment, sequence)
);
CREATE TABLE ml_promotion.heads (
    environment text PRIMARY KEY REFERENCES ml_promotion.authorities(environment),
    sequence bigint NOT NULL DEFAULT 0 CHECK (sequence BETWEEN 0 AND 9007199254740991),
    request_sha256 text REFERENCES ml.releases(sha256),
    CHECK ((sequence = 0) = (request_sha256 IS NULL))
);
CREATE FUNCTION ml_promotion.record_selection(reference text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
DECLARE
    raw bytea;
    body jsonb;
    pinned text;
    current_head ml_promotion.heads%ROWTYPE;
    next_sequence bigint;
    issued bigint;
    expires bigint;
    observed bigint;
    field text;
BEGIN
    IF reference IS NULL OR reference !~ '^[a-f0-9]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE = 'P1001', MESSAGE = 'promotion_invalid_request';
    END IF;
    SELECT payload INTO raw FROM ml.releases WHERE sha256 = reference;
    IF raw IS NULL OR octet_length(raw) > 65536 THEN
        RAISE EXCEPTION USING ERRCODE = 'P1001', MESSAGE = 'promotion_missing_or_oversized_request';
    END IF;
    body := convert_from(raw, 'UTF8')::jsonb;
    IF jsonb_typeof(body) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION USING ERRCODE = 'P1001', MESSAGE = 'promotion_invalid_request';
    END IF;
    IF ARRAY(SELECT jsonb_object_keys(body) ORDER BY 1) IS DISTINCT FROM ARRAY[
        'authorization_reference', 'environment', 'expires_at', 'issued_at', 'kind',
        'policy_sha256', 'proposal_reference', 'schema_version', 'sequence', 'subject_sha256'
    ] OR jsonb_typeof(body->'schema_version') IS DISTINCT FROM 'number'
      OR body->>'schema_version' IS DISTINCT FROM '1'
      OR body->>'kind' IS DISTINCT FROM 'promotion-selection'
      OR jsonb_typeof(body->'environment') IS DISTINCT FROM 'string'
      OR (body->>'environment') !~ '^[a-z][a-z0-9._-]{0,95}$' THEN
        RAISE EXCEPTION USING ERRCODE = 'P1001', MESSAGE = 'promotion_invalid_request';
    END IF;
    FOREACH field IN ARRAY ARRAY['policy_sha256', 'subject_sha256', 'proposal_reference', 'authorization_reference'] LOOP
        IF jsonb_typeof(body->field) IS DISTINCT FROM 'string'
          OR (body->>field) !~ '^[a-f0-9]{64}$' THEN
            RAISE EXCEPTION USING ERRCODE = 'P1001', MESSAGE = 'promotion_invalid_digest';
        END IF;
    END LOOP;
    FOREACH field IN ARRAY ARRAY['sequence', 'issued_at', 'expires_at'] LOOP
        IF jsonb_typeof(body->field) IS DISTINCT FROM 'number'
          OR (body->>field) !~ '^[1-9][0-9]{0,15}$'
          OR (body->>field)::bigint > 9007199254740991 THEN
            RAISE EXCEPTION USING ERRCODE = 'P1001', MESSAGE = 'promotion_invalid_integer';
        END IF;
    END LOOP;
    next_sequence := (body->>'sequence')::bigint;
    issued := (body->>'issued_at')::bigint;
    expires := (body->>'expires_at')::bigint;
    SELECT * INTO current_head FROM ml_promotion.heads
        WHERE environment = body->>'environment' FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P1002', MESSAGE = 'promotion_unknown_environment';
    END IF;
    SELECT policy_sha256 INTO pinned FROM ml_promotion.authorities
        WHERE environment = current_head.environment;
    IF pinned IS DISTINCT FROM body->>'policy_sha256' THEN
        RAISE EXCEPTION USING ERRCODE = 'P1002', MESSAGE = 'promotion_policy_mismatch';
    END IF;
    observed := floor(extract(epoch FROM clock_timestamp()))::bigint;
    IF issued > observed OR observed >= expires OR expires <= issued OR expires - issued > 3600 THEN
        RAISE EXCEPTION USING ERRCODE = 'P1003', MESSAGE = 'promotion_expired_or_future';
    END IF;
    IF NOT EXISTS (SELECT FROM ml.releases WHERE sha256 = body->>'proposal_reference')
      OR NOT EXISTS (SELECT FROM ml.releases WHERE sha256 = body->>'authorization_reference') THEN
        RAISE EXCEPTION USING ERRCODE = 'P1001', MESSAGE = 'promotion_material_missing';
    END IF;
    IF next_sequence = current_head.sequence AND reference = current_head.request_sha256 THEN
        IF NOT EXISTS (SELECT FROM ml_promotion.events WHERE environment = current_head.environment
            AND sequence = next_sequence AND request_sha256 = reference) THEN
            RAISE EXCEPTION USING ERRCODE = 'P1005', MESSAGE = 'promotion_head_event_mismatch';
        END IF;
        RETURN reference;
    END IF;
    IF next_sequence != current_head.sequence + 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'P1004', MESSAGE = 'promotion_sequence_conflict';
    END IF;
    INSERT INTO ml_promotion.events(environment, sequence, request_sha256, previous_sha256)
        VALUES (current_head.environment, next_sequence, reference, current_head.request_sha256);
    UPDATE ml_promotion.heads SET sequence = next_sequence, request_sha256 = reference
        WHERE environment = current_head.environment;
    RETURN reference;
END;
$body$;
REVOKE ALL ON FUNCTION ml_promotion.record_selection(text) FROM PUBLIC;
GRANT USAGE ON SCHEMA ml_promotion TO ml_promoter, ml_serving;
GRANT SELECT ON ml_promotion.authorities, ml_promotion.heads, ml_promotion.events TO ml_promoter, ml_serving;
GRANT EXECUTE ON FUNCTION ml_promotion.record_selection(text) TO ml_promoter;
"""


def install(state):
    name = validate(state)["name"]
    script = migration_sql()
    checksum = digest(script.encode())
    if not admin(name, "SELECT to_regclass('ml_promotion.migrations');"):
        admin(
            name,
            f"BEGIN;\n{script}\nINSERT INTO ml_promotion.migrations VALUES (1, '{checksum}');\nCOMMIT;",
        )
    if (
        admin(
            name, "SELECT version || ':' || sha256 FROM ml_promotion.migrations ORDER BY version;"
        )
        != f"1:{checksum}"
    ):
        raise Rejected("promotion_migration_history_mismatch")
    return checksum


def require_legacy_backup_scope(name):
    if admin(name, "SELECT to_regnamespace('ml_promotion');"):
        raise Rejected("backup_promotion_ledger_not_supported")


def configure(state, environment, policy_sha256):
    name = validate(state)["name"]
    release_policy.name(environment)
    storage.object_id(policy_sha256)
    observed = admin(
        name,
        f"SELECT policy_sha256 FROM ml_promotion.authorities WHERE environment = '{environment}';",
    )
    if observed and observed != policy_sha256:
        raise Rejected("promotion_configuration_conflict")
    admin(
        name,
        f"""BEGIN;
SET LOCAL ROLE ml_owner;
INSERT INTO ml_promotion.authorities VALUES ('{environment}', '{policy_sha256}') ON CONFLICT DO NOTHING;
INSERT INTO ml_promotion.heads (environment) VALUES ('{environment}') ON CONFLICT DO NOTHING;
COMMIT;""",
    )
    if (
        admin(
            name,
            f"SELECT policy_sha256 FROM ml_promotion.authorities WHERE environment = '{environment}';",
        )
        != policy_sha256
    ):
        raise Rejected("promotion_configuration_conflict")


def state(client, environment):
    release_policy.name(environment)
    try:
        with storage.connect(client) as connection:
            row = connection.execute(
                "SELECT sequence, request_sha256 FROM ml_promotion.heads WHERE environment = %s",
                (environment,),
            ).fetchone()
    except psycopg.Error as error:
        raise Rejected(f"promotion_state_rejected:{error.sqlstate or 'unavailable'}") from None
    if row is None:
        raise Rejected("promotion_state_missing")
    return {
        "environment": environment,
        "sequence": row[0],
        "request_sha256": row[1],
        "release_ready": False,
    }
