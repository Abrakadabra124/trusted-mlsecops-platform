import argparse
import re
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mlsecops import promotion_recovery
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    digest,
    now,
    read_json,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.signing import ROLES, decode64, sign, verify
from mlsecops.storage_bootstrap import IMAGE, admin, validate, verify_configuration
from mlsecops.storage_schema import DATABASE, SCHEMA_VERSION, TABLES, migration_sql
from mlsecops.storage_snapshot import MAX_ARCHIVE, binary_command, snapshot, validate_ledger


def trusted_keys(value):
    require_fields(value, ROLES)
    if any(len(decode64(public)) != 32 for public in value.values()):
        raise Rejected("backup_trust_bundle_invalid")
    return value


def migration():
    return {"version": SCHEMA_VERSION, "sha256": digest(migration_sql().encode())}


def verify_manifest(envelope, public, policy, moment=None):
    trusted_keys(public)
    statement = verify(envelope, "storage-backup", public["trust"])
    extended = isinstance(statement, dict) and statement.get("schema_version") == 2
    require_fields(
        statement,
        (
            "schema_version",
            "format",
            "started_at",
            "completed_at",
            "source_workspace",
            "image",
            "migration",
            "policy_digest",
            "trusted_keys_digest",
            "archive",
            "tables",
            *(("promotion",) if extended else ()),
        ),
    )
    require_fields(statement["migration"], ("version", "sha256"))
    if (
        type(statement["schema_version"]) is not int
        or statement["schema_version"] not in (1, 2)
        or statement["format"] != "postgres-custom-data-only"
        or statement["image"] != IMAGE
        or type(statement["migration"]["version"]) is not int
        or statement["migration"] != migration()
        or statement["policy_digest"] != digest(canonical(policy))
        or statement["trusted_keys_digest"] != digest(canonical(public))
        or not isinstance(statement["source_workspace"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", statement["source_workspace"])
    ):
        raise Rejected("backup_context_mismatch")
    try:
        started, completed = (
            datetime.fromisoformat(statement[field]) for field in ("started_at", "completed_at")
        )
        current = moment if moment is not None else datetime.now(UTC)
        if (
            started.tzinfo is None
            or completed.tzinfo is None
            or not started <= completed <= current
            or current - started > timedelta(hours=24)
        ):
            raise Rejected("backup_time_window_invalid")
    except (TypeError, ValueError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("backup_timestamp_invalid") from error
    archive = statement["archive"]
    require_fields(archive, ("name", "sha256", "bytes"))
    if (
        archive["name"] != "data.dump"
        or type(archive["bytes"]) is not int
        or not 5 <= archive["bytes"] <= MAX_ARCHIVE
        or not isinstance(archive["sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", archive["sha256"])
    ):
        raise Rejected("backup_archive_metadata_invalid")
    validate_ledger(statement["tables"])
    if extended:
        promotion_recovery.validate_combined(statement["tables"], statement["promotion"])
    return statement


def read_backup(directory, public, policy):
    directory = Path(directory)
    statement = verify_manifest(read_json(safe_child(directory, "manifest.json")), public, policy)
    content = bounded_read(safe_child(directory, "data.dump"), MAX_ARCHIVE)
    if (
        len(content) != statement["archive"]["bytes"]
        or digest(content) != statement["archive"]["sha256"]
        or not content.startswith(b"PGDMP")
    ):
        raise Rejected("backup_archive_integrity_failed")
    return statement, content


def create(root, state, *, include_promotion=False):
    from mlsecops.promotion_state import require_legacy_backup_scope

    root, state = Path(root), Path(state)
    marker = validate(state)
    if not include_promotion:
        require_legacy_backup_scope(marker["name"])
    verify_configuration(state, marker["name"])
    expected = migration()
    if (
        admin(
            marker["name"],
            "SELECT version || ':' || sha256 FROM ml.schema_migrations ORDER BY version;",
        )
        != f"{expected['version']}:{expected['sha256']}"
    ):
        raise Rejected("backup_source_migration_invalid")
    public = trusted_keys(read_json(state / "trusted-keys.json"))
    policy = read_json(root / "policies/local-cpu.json")
    started = now()
    with snapshot(marker["name"], include_promotion=include_promotion) as observed:
        arguments = [
            "docker",
            "exec",
            "--user",
            "999:999",
            marker["name"],
            "pg_dump",
            "-h",
            "/tmp",
            "-U",
            "postgres",
            "-d",
            DATABASE,
            "--format=custom",
            "--compress=0",
            "--data-only",
            "--no-privileges",
            "--no-large-objects",
            "--lock-wait-timeout=5s",
            "--strict-names",
            f"--snapshot={observed['snapshot']}",
        ]
        for table in TABLES:
            arguments.extend(("--table", f"ml.{table}"))
        if include_promotion:
            for table in promotion_recovery.TABLES:
                arguments.extend(("--table", f"ml_promotion.{table}"))
        content = binary_command(arguments)
    statement = {
        "schema_version": 2 if include_promotion else 1,
        "format": "postgres-custom-data-only",
        "started_at": started,
        "completed_at": now(),
        "source_workspace": marker["workspace_id"],
        "image": IMAGE,
        "migration": expected,
        "policy_digest": digest(canonical(policy)),
        "trusted_keys_digest": digest(canonical(public)),
        "archive": {"name": "data.dump", "sha256": digest(content), "bytes": len(content)},
        "tables": observed["tables"],
        **({"promotion": observed["promotion"]} if include_promotion else {}),
    }
    envelope = sign(statement, "storage-backup", state / "keys/trust.pem")
    verify_manifest(envelope, public, policy)
    identifier = digest(canonical(statement))
    parent = safe_child(state, "backups")
    parent.mkdir(exist_ok=True)
    destination = safe_child(parent, identifier)
    if destination.exists():
        raise Rejected("backup_destination_exists")
    with tempfile.TemporaryDirectory(prefix="pending-", dir=parent) as temporary:
        temporary = Path(temporary)
        atomic_write(temporary / "data.dump", content)
        write_json(temporary / "manifest.json", envelope)
        read_backup(temporary, public, policy)
        temporary.rename(destination)
    return {
        "backup_id": identifier,
        "directory": str(destination.resolve()),
        "bytes": len(content),
        "tables": statement["tables"],
        **({"promotion": statement["promotion"]} if include_promotion else {}),
        "status": "verified-backup-not-release",
    }


def main():
    parser = argparse.ArgumentParser(description="Create a signed, consistent local SQL backup")
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--include-promotion", action="store_true")
    arguments = parser.parse_args()
    try:
        result = create(
            Path(__file__).resolve().parents[1],
            arguments.state,
            include_promotion=arguments.include_promotion,
        )
        write_json(arguments.state / "evidence/storage-backup.json", result)
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        print(f"Storage backup rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
