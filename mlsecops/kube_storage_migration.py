import argparse
import sys
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from mlsecops import kube_storage
from mlsecops.contracts import (
    Rejected,
    canonical,
    decode,
    digest,
    now,
    read_json,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.signing import sign, verify
from mlsecops.storage_backup import migration, read_backup, trusted_keys
from mlsecops.storage_pki import workspace_id
from mlsecops.storage_restore import validate_toc
from mlsecops.storage_snapshot import json_session, ledger_sql, validate_ledger


def ledger(state):
    return validate_ledger(decode(kube_storage.admin(state, ledger_sql())))


def connection_limit(state):
    value = kube_storage.admin(
        state, "SELECT datconnlimit FROM pg_database WHERE datname='mlsecops';"
    )
    if value not in {"-1", "0"}:
        raise Rejected("migration_unexpected_connection_limit")
    return int(value)


@contextmanager
def exclusive(state):
    arguments = kube_storage.command_arguments(
        state,
        [
            "psql",
            "-X",
            "-qAt",
            "-v",
            "ON_ERROR_STOP=1",
            "-h",
            "/tmp",
            "-U",
            "postgres",
            "-d",
            "mlsecops",
        ],
    )
    query = (
        "SET idle_session_timeout='300s';\n"
        "SELECT jsonb_build_object('locked',pg_try_advisory_lock(724931,1),'pid',pg_backend_pid());\n"
    )
    with json_session(arguments, query) as (result, process):
        require_fields(result, ("locked", "pid"))
        if result["locked"] is not True or type(result["pid"]) is not int or result["pid"] <= 0:
            raise Rejected("migration_busy_or_lock_invalid")

        def ensure():
            count = kube_storage.admin(
                state,
                f"SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=724931 AND objid=1 AND objsubid=2 AND pid={result['pid']} AND granted;",
            )
            if process.poll() is not None or count != "1":
                raise Rejected("migration_lock_lost")

        ensure()
        yield ensure


def verify_record(envelope, kind, expected, public):
    record = verify(envelope, kind, public["trust"])
    require_fields(record, (*expected, "recorded_at"))
    if any(canonical(record[name]) != canonical(value) for name, value in expected.items()):
        raise Rejected("migration_record_binding_mismatch")
    try:
        moment = datetime.fromisoformat(record["recorded_at"])
        if moment.tzinfo is None or moment > datetime.now(UTC):
            raise ValueError("invalid timestamp")
    except (TypeError, ValueError) as error:
        raise Rejected("migration_record_timestamp_invalid") from error
    return record


def write_record(state, path, kind, expected, public):
    envelope = sign({**expected, "recorded_at": now()}, kind, safe_child(state, "keys/trust.pem"))
    record = verify_record(envelope, kind, expected, public)
    write_json(path, envelope)
    return record


def freeze(state):
    kube_storage.admin(state, "ALTER DATABASE mlsecops CONNECTION LIMIT 0;")
    results = kube_storage.admin(
        state,
        "SELECT pg_terminate_backend(pid,5000) FROM pg_stat_activity WHERE datname='mlsecops' AND usename<>'postgres' AND backend_type='client backend';",
    )
    if any(value != "t" for value in results.splitlines()) or connection_limit(state) != 0:
        raise Rejected("migration_sessions_not_fenced")
    if (
        kube_storage.admin(
            state,
            "SELECT count(*) FROM pg_stat_activity WHERE datname='mlsecops' AND usename<>'postgres';",
        )
        != "0"
    ):
        raise Rejected("migration_sessions_remain")


def archive_command(state, arguments, content, timeout=30):
    return kube_storage.execute(
        state,
        [
            "sh",
            "-c",
            '"$@"; result=$?; cat > /dev/null; exit "$result"',
            "archive",
            "pg_restore",
            *arguments,
        ],
        content=content,
        timeout=timeout,
    )


def restore_archive(state, content):
    archive_command(
        state,
        [
            "--host=/tmp",
            "--username=postgres",
            "--dbname=mlsecops",
            "--data-only",
            "--no-owner",
            "--no-privileges",
            "--single-transaction",
            "--exit-on-error",
        ],
        content=content,
        timeout=120,
    )


def migrate(root, state, directory, public):
    started = time.monotonic()
    state = Path(state)
    public = trusted_keys(public)
    if public != trusted_keys(read_json(safe_child(state, "trusted-keys.json"))):
        raise Rejected("migration_current_trust_mismatch")
    statement, content = read_backup(
        directory, public, read_json(Path(root) / "policies/local-cpu.json")
    )
    if statement["source_workspace"] != workspace_id(state):
        raise Rejected("migration_source_workspace_mismatch")
    marker = kube_storage.validate(state)
    expected_migration = migration()
    if (
        kube_storage.admin(
            state, "SELECT version || ':' || sha256 FROM ml.schema_migrations ORDER BY version;"
        )
        != f"{expected_migration['version']}:{expected_migration['sha256']}"
    ):
        raise Rejected("migration_target_schema_mismatch")
    validate_toc(archive_command(state, ["--list"], content))
    context = {
        "schema_version": 1,
        "backup_id": digest(canonical(statement)),
        "source_workspace": statement["source_workspace"],
        "namespace_uid": marker["resources"]["Namespace/_/ml-storage"],
        "volume_uid": marker["volume_uid"],
        "storage_spec_digest": marker["spec_digest"],
        "trusted_keys_digest": digest(canonical(public)),
        "tables_digest": digest(canonical(statement["tables"])),
        "release_ready": False,
    }
    intent_path = safe_child(kube_storage.local_state(state), "migration-intent.json")
    receipt_path = safe_child(kube_storage.local_state(state), "migration-receipt.json")
    prepared_context = {**context, "status": "storage-migration-prepared"}
    with exclusive(state) as ensure:
        before = ledger(state)
        limit = connection_limit(state)
        if intent_path.exists():
            intent = verify_record(
                read_json(intent_path), "cluster-storage-migration-intent", prepared_context, public
            )
        else:
            if (
                receipt_path.exists()
                or limit != -1
                or any(entry["rows"] for entry in before.values())
            ):
                raise Rejected("migration_target_not_fresh")
            intent = write_record(
                state, intent_path, "cluster-storage-migration-intent", prepared_context, public
            )
        completed_context = {
            **context,
            "status": "storage-migrated-not-release-ready",
            "intent_digest": digest(canonical(intent)),
        }
        completed = receipt_path.exists()
        if completed:
            verify_record(
                read_json(receipt_path),
                "cluster-storage-migration-receipt",
                completed_context,
                public,
            )
            if before != statement["tables"]:
                raise Rejected("migration_existing_target_changed")
        elif before != statement["tables"] and any(entry["rows"] for entry in before.values()):
            raise Rejected("migration_partial_target_requires_review")
        if not (completed and limit == -1):
            ensure()
            freeze(state)
            observed = ledger(state)
            if completed and observed != statement["tables"]:
                raise Rejected("migration_existing_target_changed")
            if observed != statement["tables"]:
                if any(entry["rows"] for entry in observed.values()):
                    raise Rejected("migration_concurrent_target_write")
                ensure()
                restore_archive(state, content)
            if ledger(state) != statement["tables"]:
                raise Rejected("migration_restored_ledger_mismatch")
            ensure()
            if not completed:
                write_record(
                    state,
                    receipt_path,
                    "cluster-storage-migration-receipt",
                    completed_context,
                    public,
                )
            ensure()
            kube_storage.admin(state, "ALTER DATABASE mlsecops CONNECTION LIMIT -1;")
        if connection_limit(state) != -1:
            raise Rejected("migration_target_not_reopened")
    return {
        **context,
        "status": "storage-migrated-not-release-ready",
        "observed_at": now(),
        "reused": completed,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "database_rows": sum(entry["rows"] for entry in statement["tables"].values()),
        "database_bytes": sum(entry["bytes"] for entry in statement["tables"].values()),
        "receipt_digest": digest(canonical(read_json(receipt_path))),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Import a signed owned-workspace backup into private Kubernetes storage"
    )
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--trust", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = migrate(
            Path(__file__).resolve().parents[1],
            arguments.state,
            arguments.backup,
            read_json(arguments.trust),
        )
        write_json(arguments.state / "evidence/kubernetes-storage-migration.json", result)
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        print(f"Cluster storage migration rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
