from mlsecops import promotion_state, storage_snapshot
from mlsecops.contracts import Rejected, decode, digest, require_fields
from mlsecops.storage_bootstrap import admin

TABLES = ("authorities", "events", "heads")


def migration():
    return {"version": 1, "sha256": digest(promotion_state.migration_sql().encode())}


def validate_ledger(value):
    require_fields(value, ("migration", "tables"))
    require_fields(value["migration"], ("version", "sha256"))
    if type(value["migration"]["version"]) is not int or value["migration"] != migration():
        raise Rejected("promotion_backup_migration_mismatch")
    storage_snapshot.validate_ledger(value["tables"], expected_tables=TABLES)
    return value


def ledger_sql():
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
        "SELECT jsonb_build_object('migration', (SELECT jsonb_build_object('version',version,"
        "'sha256',sha256) FROM ml_promotion.migrations), 'tables', "
        "(SELECT jsonb_object_agg(name,detail) FROM ("
        + " UNION ALL ".join(summaries)
        + ") AS tables))"
    )


def read(name):
    return validate_ledger(decode(admin(name, ledger_sql() + ";", timeout=65).encode()))


def validate_combined(tables, promotion):
    validate_ledger(promotion)
    storage_snapshot.validate_ledger(tables)
    storage_snapshot.validate_ledger(
        {**tables, **promotion["tables"]},
        expected_tables=(*storage_snapshot.TABLES, *TABLES),
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
