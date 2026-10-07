import argparse
import re
import sys
import time
from pathlib import Path

from mlsecops.bootstrap import initialize
from mlsecops.contracts import (
    Rejected,
    canonical,
    decode,
    digest,
    now,
    read_json,
    require_fields,
    write_json,
)
from mlsecops.storage_backup import read_backup, trusted_keys
from mlsecops.storage_bootstrap import admin, bootstrap, validate, verify_configuration
from mlsecops.storage_schema import DATABASE, TABLES
from mlsecops.storage_snapshot import binary_command, ledger_sql, validate_ledger


def ledger(name):
    return validate_ledger(decode(admin(name, ledger_sql() + ";", timeout=65).encode()))


def validate_toc(content):
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise Rejected("restore_archive_toc_invalid") from error
    names = []
    for line in lines:
        if not line or line.startswith(";"):
            continue
        match = re.fullmatch(r"[0-9]+; [0-9]+ [0-9]+ TABLE DATA ml ([a-z_]+) ml_owner", line)
        if match is None:
            raise Rejected("restore_archive_toc_invalid")
        names.append(match[1])
    if len(names) != len(TABLES) or set(names) != set(TABLES):
        raise Rejected("restore_archive_table_scope_invalid")


def restore(root, directory, target, public, port=15440):
    started = time.monotonic()
    root, target = Path(root), Path(target)
    if target.is_symlink() or target.parent.is_symlink():
        raise Rejected("restore_target_symlink")
    target = target.resolve()
    public = trusted_keys(public)
    policy = read_json(root / "policies/local-cpu.json")
    statement, content = read_backup(directory, public, policy)
    identifier = digest(canonical(statement))
    receipt_path = target / "recovery.json"
    if target.exists() and any(target.iterdir()):
        if not receipt_path.exists():
            raise Rejected("restore_requires_new_target")
        receipt = read_json(receipt_path)
        require_fields(
            receipt,
            (
                "schema_version",
                "backup_id",
                "source_workspace",
                "target_workspace",
                "container_id",
                "port",
                "restored_at",
                "elapsed_seconds",
                "tables",
                "status",
                "release_ready",
            ),
        )
        marker = validate(target)
        if (
            type(receipt["schema_version"]) is not int
            or receipt["schema_version"] != 1
            or receipt["backup_id"] != identifier
            or receipt["source_workspace"] != statement["source_workspace"]
            or receipt["target_workspace"] != marker["workspace_id"]
            or marker["workspace_id"] == statement["source_workspace"]
            or receipt["container_id"] != marker["container_id"]
            or receipt["port"] != port
            or marker["port"] != port
            or receipt["release_ready"] is not False
            or receipt["status"] != "storage-restored-not-release-ready"
            or receipt["tables"] != statement["tables"]
        ):
            raise Rejected("restore_receipt_identity_mismatch")
        verify_configuration(target, marker["name"])
        if (
            ledger(marker["name"]) != statement["tables"]
            or read_json(target / "recovered-public-keys.json") != public
        ):
            raise Rejected("restore_existing_target_changed")
        return {**receipt, "reused": True}
    initialize(root, target)
    bootstrap(target, port)
    marker = validate(target)
    if marker["workspace_id"] == statement["source_workspace"]:
        raise Rejected("restore_source_target_identity_collision")
    if any(entry["rows"] for entry in ledger(marker["name"]).values()):
        raise Rejected("restore_target_database_not_empty")
    prefix = ["docker", "exec", "--user", "999:999", "-i", marker["name"], "pg_restore"]
    validate_toc(binary_command([*prefix, "--list"], content, output_limit=65536))
    binary_command(
        [
            *prefix,
            "--host=/tmp",
            "--username=postgres",
            f"--dbname={DATABASE}",
            "--data-only",
            "--no-owner",
            "--no-privileges",
            "--single-transaction",
            "--exit-on-error",
        ],
        content,
        output_limit=65536,
    )
    observed = ledger(marker["name"])
    if observed != statement["tables"]:
        raise Rejected("restore_ledger_mismatch")
    verify_configuration(target, marker["name"])
    write_json(target / "recovered-public-keys.json", public)
    receipt = {
        "schema_version": 1,
        "backup_id": identifier,
        "source_workspace": statement["source_workspace"],
        "target_workspace": marker["workspace_id"],
        "container_id": marker["container_id"],
        "port": port,
        "restored_at": now(),
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "tables": observed,
        "status": "storage-restored-not-release-ready",
        "release_ready": False,
    }
    write_json(receipt_path, receipt)
    return {**receipt, "reused": False}


def main():
    parser = argparse.ArgumentParser(
        description="Restore a verified SQL backup into a new owned workspace"
    )
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--trust", type=Path, required=True)
    parser.add_argument("--port", type=int, default=15440)
    arguments = parser.parse_args()
    try:
        result = restore(
            Path(__file__).resolve().parents[1],
            arguments.backup,
            arguments.target,
            read_json(arguments.trust),
            arguments.port,
        )
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        print(f"Storage restore rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
