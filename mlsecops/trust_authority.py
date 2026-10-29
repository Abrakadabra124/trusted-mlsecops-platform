import argparse
import sys

import psycopg

from mlsecops import signing, storage, trust, trust_rotation
from mlsecops.contracts import Rejected, canonical, decode, digest, read_json
from mlsecops.release_policy import MAX_DOCUMENT, name
from mlsecops.storage_bootstrap import admin, validate
from mlsecops.storage_schema import TABLES


def read(client, environment, public, *, expected_host=None):
    name(environment)
    options = {} if expected_host is None else {"expected_host": expected_host}
    if storage.connection_parameters(client, **options)["user"] not in (
        "ml_serving",
        "ml_promoter",
    ):
        raise Rejected("trust_client_identity")
    try:
        with storage.connect(client, **options) as connection:
            row = connection.execute(
                "SELECT settings.root_public, document.version, document.sha256, document.envelope, "
                "floor(extract(epoch FROM clock_timestamp()))::bigint "
                "FROM ml_trust.settings CROSS JOIN LATERAL "
                "(SELECT * FROM ml_trust.documents ORDER BY version DESC LIMIT 1) document "
                "WHERE settings.environment = %s",
                (environment,),
            ).fetchone()
    except Rejected as error:
        if str(error) != "storage_connection_rejected":
            raise
        raise trust.Unavailable("trust_service_unavailable") from None
    except psycopg.Error:
        raise trust.Unavailable("trust_service_unavailable") from None
    if row is None or row[0] != public:
        raise Rejected("trust_authority_missing_or_foreign")
    content = bytes(row[3])
    if not 0 < len(content) <= MAX_DOCUMENT or digest(content) != row[2]:
        raise Rejected("trust_document_integrity")
    envelope = decode(content, MAX_DOCUMENT)
    payload = trust.validate(envelope, public, environment, row[4])
    if content != canonical(envelope) or type(row[1]) is not int or row[1] != payload["version"]:
        raise Rejected("trust_document_version_mismatch")
    return envelope, row[4]


def migration_sql():
    return """SET LOCAL ROLE ml_owner;
CREATE SCHEMA ml_trust;
REVOKE ALL ON SCHEMA ml_trust FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA ml_trust REVOKE ALL ON TABLES FROM PUBLIC;
CREATE TABLE ml_trust.migrations (version integer PRIMARY KEY, sha256 text NOT NULL);
CREATE TABLE ml_trust.settings (
    singleton boolean PRIMARY KEY CHECK (singleton),
    environment text NOT NULL,
    root_public text NOT NULL
);
CREATE TABLE ml_trust.documents (
    version bigint PRIMARY KEY CHECK (version BETWEEN 1 AND 9007199254740991),
    sha256 text NOT NULL UNIQUE CHECK (sha256 ~ '^[a-f0-9]{64}$'),
    envelope bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 1 AND 1048576),
    CHECK (encode(sha256(envelope), 'hex') = sha256)
);
GRANT USAGE ON SCHEMA ml_trust TO ml_serving, ml_promoter;
GRANT SELECT ON ml_trust.settings, ml_trust.documents TO ml_serving, ml_promoter;
"""


def commands(state, backend):
    # The backend is a trusted operator dependency, never a request/CLI field.
    return (validate(state)["name"], admin) if backend is None else backend(state)


def migration_version(container, execute):
    observed = execute(
        container, "SELECT version || ':' || sha256 FROM ml_trust.migrations ORDER BY version;"
    )
    first = "1:" + digest(migration_sql().encode())
    if observed == first:
        return 1
    if observed == first + "\n2:" + digest(trust_rotation.migration_sql().encode()):
        return 2
    raise Rejected("trust_migration_mismatch")


def install(state, environment, public, *, backend=None):
    name(environment)
    if len(signing.decode64(public)) != 32 or signing.encode64(signing.decode64(public)) != public:
        raise Rejected("trust_root_invalid")
    container, execute = commands(state, backend)
    script = migration_sql()
    checksum = digest(script.encode())
    if not execute(container, "SELECT to_regnamespace('ml_trust');"):
        nonempty = " OR ".join(f"EXISTS (SELECT FROM ml.{table})" for table in TABLES)
        execute(
            container,
            f"""BEGIN;
SELECT pg_advisory_xact_lock(19293822);
DO $guard$ BEGIN
    IF to_regnamespace('ml_promotion') IS NOT NULL OR {nonempty} THEN
        RAISE EXCEPTION 'trust_requires_separate_empty_storage';
    END IF;
END $guard$;
{script}
INSERT INTO ml_trust.migrations VALUES (1, '{checksum}');
INSERT INTO ml_trust.settings VALUES (true, '{environment}', '{public}');
COMMIT;""",
        )
    migration_version(container, execute)
    if (
        execute(container, "SELECT environment || ':' || root_public FROM ml_trust.settings;")
        != f"{environment}:{public}"
    ):
        raise Rejected("trust_configuration_conflict")
    return checksum


def current(state, *, backend=None):
    container, execute = commands(state, backend)
    migration_version(container, execute)
    result = decode(
        execute(
            container,
            "SELECT jsonb_build_object('environment', settings.environment, 'root_public', settings.root_public, "
            "'version', document.version, 'sha256', document.sha256, 'envelope', encode(document.envelope, 'hex'), "
            "'clock', floor(extract(epoch FROM clock_timestamp()))::bigint) "
            "FROM ml_trust.settings LEFT JOIN LATERAL "
            "(SELECT * FROM ml_trust.documents ORDER BY version DESC LIMIT 1) document ON true;",
        ).encode()
    )
    if result["envelope"] is not None:
        content = bytes.fromhex(result["envelope"])
        result["envelope"] = decode(content, MAX_DOCUMENT)
        payload = trust.validate(result["envelope"], result["root_public"], result["environment"])
        if (
            digest(content) != result["sha256"]
            or payload["version"] != result["version"]
            or content != canonical(result["envelope"])
        ):
            raise Rejected("trust_document_integrity")
    return container, result


def publish(state, envelope, *, backend=None):
    container, before = current(state, backend=backend)
    payload = trust.validate(
        envelope, before["root_public"], before["environment"], before["clock"]
    )
    content = canonical(envelope)
    reference = digest(content)
    if before["envelope"] is not None:
        if reference == before["sha256"]:
            return {"version": payload["version"], "document_sha256": reference, "reused": True}
        trust.successor(
            trust.validate(before["envelope"], before["root_public"], before["environment"]),
            payload,
        )
    elif payload["version"] != 1:
        raise Rejected("trust_initial_version")
    previous_version = before["version"] or 0
    previous_reference = before["sha256"] or ""
    execute = admin if backend is None else backend(state)[1]
    execute(
        container,
        f"""BEGIN;
SELECT pg_advisory_xact_lock(19293822);
DO $guard$ DECLARE observed_version bigint; observed_reference text; observed_clock bigint;
BEGIN
    SELECT version, sha256 INTO observed_version, observed_reference
        FROM ml_trust.documents ORDER BY version DESC LIMIT 1;
    IF coalesce(observed_version, 0) != {previous_version}
      OR coalesce(observed_reference, '') != '{previous_reference}' THEN
        RAISE EXCEPTION 'trust_concurrent_update_conflict';
    END IF;
    observed_clock := floor(extract(epoch FROM clock_timestamp()))::bigint;
    IF observed_clock < {payload["issued_at"]} OR observed_clock >= {payload["expires_at"]} THEN
        RAISE EXCEPTION 'trust_update_expired_or_future';
    END IF;
END $guard$;
SET LOCAL ROLE ml_owner;
INSERT INTO ml_trust.documents VALUES ({payload["version"]}, '{reference}', decode('{content.hex()}', 'hex'));
COMMIT;""",
    )
    if (
        execute(
            container,
            f"SELECT sha256 FROM ml_trust.documents WHERE version = {payload['version']};",
        )
        != reference
    ):
        raise Rejected("trust_update_unconfirmed")
    return {"version": payload["version"], "document_sha256": reference, "reused": False}


def update(
    state, policy_sha256, key, *, revoked_artifacts=(), revoked_keys=(), lifetime=3600, backend=None
):
    from mlsecops.release_policy import integer

    storage.object_id(policy_sha256)
    integer(lifetime, maximum=86400)
    _, previous = current(state, backend=backend)
    payload = {
        "schema_version": 1,
        "environment": previous["environment"],
        "version": (previous["version"] or 0) + 1,
        "promotion_policy_sha256": policy_sha256,
        "issued_at": previous["clock"],
        "expires_at": previous["clock"] + lifetime,
        "revoked_artifacts": [],
        "revoked_keys": [],
    }
    if previous["envelope"] is not None:
        old = trust.validate(previous["envelope"], previous["root_public"], previous["environment"])
        payload.update({field: old[field] for field in ("revoked_artifacts", "revoked_keys")})
    for field, additions in (
        ("revoked_artifacts", revoked_artifacts),
        ("revoked_keys", revoked_keys),
    ):
        payload[field] = sorted(
            set(payload[field]) | {storage.object_id(value) for value in additions}
        )
    return publish(state, signing.sign(payload, "trust-policy", key), backend=backend)


def main(arguments=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("install", "publish", "update", "show"))
    parser.add_argument("--state", required=True)
    parser.add_argument("--backend", choices=("docker", "kubernetes"), default="docker")
    parser.add_argument("--confirm-authority", action="store_true")
    parser.add_argument("--environment", default="local-cpu")
    parser.add_argument("--root-public")
    parser.add_argument("--document")
    parser.add_argument("--policy")
    parser.add_argument("--key")
    parser.add_argument("--revoke-artifact", action="append", default=[])
    parser.add_argument("--revoke-key", action="append", default=[])
    parser.add_argument("--lifetime", type=int, default=3600)
    options = parser.parse_args(arguments)
    try:
        backend = None
        if options.backend == "kubernetes":
            from mlsecops.kube_trust import binding

            backend = binding
        if options.action != "show" and not options.confirm_authority:
            raise Rejected("trust_explicit_authority_confirmation_required")
        if options.action == "install":
            result = {
                "migration_sha256": install(
                    options.state, options.environment, options.root_public, backend=backend
                )
            }
        elif options.action == "publish":
            if options.document is None:
                raise Rejected("trust_signed_document_required")
            result = publish(options.state, read_json(options.document), backend=backend)
        elif options.action == "update":
            if options.key is None:
                raise Rejected("trust_signing_key_required")
            result = update(
                options.state,
                options.policy,
                options.key,
                revoked_artifacts=options.revoke_artifact,
                revoked_keys=options.revoke_key,
                lifetime=options.lifetime,
                backend=backend,
            )
        else:
            _, value = current(options.state, backend=backend)
            result = {
                "environment": value["environment"],
                "version": value["version"],
                "document_sha256": value["sha256"],
            }
        print(canonical({**result, "release_ready": False}).decode())
        return 0
    except (Rejected, OSError, ValueError):
        print(
            canonical(
                {
                    "status": "fail",
                    "error": "trust_authority_command_rejected",
                    "release_ready": False,
                }
            ).decode(),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
