from mlsecops import promotion_state, release_key_rotation, storage_snapshot
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.storage_bootstrap import admin

TABLES = ("authorities", "events", "heads")


def migration(version=1):
    if type(version) is not int or version not in (1, 2):
        raise Rejected("promotion_backup_migration_mismatch")
    original = {"version": 1, "sha256": digest(promotion_state.migration_sql().encode())}
    if version == 1:
        return original
    return [
        original,
        {"version": 2, "sha256": digest(release_key_rotation.migration_sql().encode())},
    ]


def schema_version(history):
    for version in (1, 2):
        if canonical(history) == canonical(migration(version)):
            return version
    raise Rejected("promotion_backup_migration_mismatch")


def tables_for(history):
    return (*TABLES, "policy_rotations") if schema_version(history) == 2 else TABLES


def validate_ledger(value, *, version=None):
    require_fields(value, ("migration", "tables"))
    observed = schema_version(value["migration"])
    if version is not None and observed != version:
        raise Rejected("promotion_backup_migration_changed")
    storage_snapshot.validate_ledger(
        value["tables"], expected_tables=tables_for(value["migration"])
    )
    return value


def ledger_sql(version=1):
    if type(version) is not int or version not in (1, 2):
        raise Rejected("promotion_backup_migration_mismatch")
    selections = {
        "authorities": """SELECT authority.environment, 0 AS sequence,
            jsonb_build_array(authority.environment, authority.policy_sha256) AS row_data,
            NOT EXISTS (SELECT FROM ml_promotion.heads AS head
                WHERE head.environment = authority.environment) AS invalid
            FROM ml_promotion.authorities AS authority""",
        "events": """SELECT event.environment, event.sequence,
            jsonb_build_array(event.environment, event.sequence, event.request_sha256,
                event.previous_sha256, extract(epoch FROM event.recorded_at)::text) AS row_data,
            (event.sequence != row_number() OVER ordered
                OR event.previous_sha256 IS DISTINCT FROM lag(event.request_sha256) OVER ordered
                OR (convert_from(material.payload,'UTF8')::jsonb->>'environment') IS DISTINCT FROM event.environment
                OR (convert_from(material.payload,'UTF8')::jsonb->>'sequence') IS DISTINCT FROM event.sequence::text
                OR (convert_from(material.payload,'UTF8')::jsonb->>'policy_sha256') IS DISTINCT FROM authority.policy_sha256
            ) AS invalid
            FROM ml_promotion.events AS event
            LEFT JOIN ml.releases AS material ON material.sha256 = event.request_sha256
            LEFT JOIN ml_promotion.authorities AS authority ON authority.environment = event.environment
            WINDOW ordered AS (PARTITION BY event.environment ORDER BY event.sequence)""",
        "heads": """SELECT head.environment, head.sequence,
            jsonb_build_array(head.environment, head.sequence, head.request_sha256) AS row_data,
            (head.sequence != (SELECT count(*) FROM ml_promotion.events AS event
                WHERE event.environment = head.environment)
                OR head.request_sha256 IS DISTINCT FROM (SELECT request_sha256
                    FROM ml_promotion.events AS event WHERE event.environment = head.environment
                    ORDER BY sequence DESC LIMIT 1)) AS invalid
            FROM ml_promotion.heads AS head""",
    }
    if version == 2:
        selections["authorities"] = selections["authorities"].replace(
            ") AS invalid",
            """ ) OR authority.policy_sha256 IS DISTINCT FROM coalesce(
                (SELECT policy_sha256 FROM ml_promotion.policy_rotations AS rotation
                 WHERE rotation.environment = authority.environment ORDER BY version DESC LIMIT 1),
                authority.policy_sha256) AS invalid""",
        )
        selections["events"] = selections["events"].replace(
            "IS DISTINCT FROM authority.policy_sha256",
            """IS DISTINCT FROM coalesce(
                (SELECT policy_sha256 FROM ml_promotion.policy_rotations AS rotation
                 WHERE rotation.environment = event.environment AND rotation.boundary_sequence < event.sequence
                 ORDER BY version DESC LIMIT 1),
                (SELECT previous_policy_sha256 FROM ml_promotion.policy_rotations AS rotation
                 WHERE rotation.environment = event.environment ORDER BY version LIMIT 1),
                authority.policy_sha256)""",
        )
        selections[
            "policy_rotations"
        ] = """SELECT rotation.environment, rotation.version AS sequence,
            jsonb_build_array(rotation.environment, rotation.version, rotation.previous_version,
                rotation.boundary_sequence, rotation.request_sha256, rotation.previous_policy_sha256,
                rotation.policy_sha256, rotation.sha256, encode(rotation.package,'hex'),
                extract(epoch FROM rotation.recorded_at)::text) AS row_data,
            (rotation.version != rotation.previous_version + 1
                OR rotation.previous_version != coalesce(lag(rotation.version) OVER ordered, rotation.previous_version)
                OR rotation.previous_policy_sha256 IS DISTINCT FROM coalesce(
                    lag(rotation.policy_sha256) OVER ordered, rotation.previous_policy_sha256)
                OR rotation.boundary_sequence < coalesce(lag(rotation.boundary_sequence) OVER ordered, 1)
                OR rotation.request_sha256 IS DISTINCT FROM event.request_sha256
                OR rotation.sha256 != encode(sha256(rotation.package),'hex')) AS invalid
            FROM ml_promotion.policy_rotations AS rotation
            LEFT JOIN ml_promotion.events AS event ON event.environment = rotation.environment
                AND event.sequence = rotation.boundary_sequence
            WINDOW ordered AS (PARTITION BY rotation.environment ORDER BY rotation.version)"""
    summaries = [
        f"""SELECT '{table}' AS name, jsonb_build_object(
            'rows', count(*), 'bytes', coalesce(sum(octet_length(convert_to(row_data::text,'UTF8'))),0),
            'sha256', encode(sha256(convert_to(coalesce(string_agg(row_data::text, E'\\n'
                ORDER BY environment COLLATE "C", sequence),''),'UTF8')),'hex'),
            'invalid', count(*) FILTER (WHERE invalid)
        ) AS detail FROM ({query}) AS entries"""
        for table, query in selections.items()
    ]
    return (
        "SELECT jsonb_build_object('migration', (SELECT CASE WHEN count(*)=1 THEN "
        "jsonb_agg(jsonb_build_object('version',version,'sha256',sha256) ORDER BY version)->0 ELSE "
        "jsonb_agg(jsonb_build_object('version',version,'sha256',sha256) ORDER BY version) END "
        "FROM ml_promotion.migrations), 'tables', "
        "(SELECT jsonb_object_agg(name,detail) FROM ("
        + " UNION ALL ".join(summaries)
        + ") AS tables))"
    )


def read(name):
    version = promotion_state.migration_version(name, admin)
    return validate_ledger(
        decode(admin(name, ledger_sql(version) + ";", timeout=65).encode()), version=version
    )


def validate_combined(tables, promotion, *, version=None):
    validate_ledger(promotion, version=version)
    storage_snapshot.validate_ledger(tables)
    storage_snapshot.validate_ledger(
        {**tables, **promotion["tables"]},
        expected_tables=(*storage_snapshot.TABLES, *tables_for(promotion["migration"])),
    )


def freeze(name):
    admin(name, "ALTER DATABASE mlsecops CONNECTION LIMIT 0;")
    terminated = admin(
        name,
        "SELECT pg_terminate_backend(pid,5000) FROM pg_stat_activity "
        "WHERE datname='mlsecops' AND usename<>'postgres' AND backend_type='client backend';",
    )
    if (
        any(value != "t" for value in terminated.splitlines())
        or admin(name, "SELECT datconnlimit FROM pg_database WHERE datname='mlsecops';") != "0"
        or admin(
            name,
            "SELECT count(*) FROM pg_stat_activity WHERE datname='mlsecops' AND usename<>'postgres';",
        )
        != "0"
    ):
        raise Rejected("promotion_restore_sessions_not_fenced")


def thaw(name):
    admin(name, "ALTER DATABASE mlsecops CONNECTION LIMIT -1;")
    if admin(name, "SELECT datconnlimit FROM pg_database WHERE datname='mlsecops';") != "-1":
        raise Rejected("promotion_restore_maintenance_not_released")
