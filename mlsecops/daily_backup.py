"""Create an owned lab backup or recheck its independently stored pin offline."""

import argparse
import configparser
import os
import shlex
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mlsecops import storage_backup, storage_pki
from mlsecops.contracts import (
    Rejected,
    canonical,
    decode,
    digest,
    read_json,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.inventory import command
from mlsecops.recovery_lock import target_lock
from mlsecops.security_events import hexadecimal

ROOT = Path(__file__).resolve().parents[1]


def check_timer(directory):
    """Verify shipped unit wiring and two calendar firings without a systemd manager."""
    unit = "mlsecops-daily-backup"

    def config(suffix):
        value = configparser.ConfigParser(interpolation=None)
        value.optionxform = str
        with (directory / (unit + suffix)).open(encoding="utf-8") as source:
            value.read_file(source)
        return value

    calendar = "*-*-* 02:00:00 UTC"
    timer, service = config(".timer"), config(".service")["Service"]
    checkout = "/srv/trusted-mlsecops-platform"
    if (
        dict(timer["Timer"])
        != dict(OnCalendar=calendar, AccuracySec="1s", Persistent="true", Unit=unit + ".service")
        or timer["Install"]["WantedBy"] != "timers.target"
        or service["WorkingDirectory"] != checkout
        or service["Type"] != "oneshot"
        or service["User"] != "mlsecops"
        or service["StateDirectory"] != "mlsecops-backup"
        or shlex.split(service["ExecStart"])
        != [
            checkout + "/.venv/bin/python",
            "-B",
            "-m",
            "mlsecops.daily_backup",
            "run",
            "--state",
            checkout + "/.runtime",
            "--owner",
            "/etc/mlsecops/backup-owner.json",
            "--inventory",
            "/var/lib/mlsecops-backup/latest.json",
        ]
    ):
        raise Rejected("daily_backup_timer_config")
    # Fixed UTC base spanning the spring clock change in European time zones.
    observed = subprocess.run(
        [
            "systemd-analyze",
            "calendar",
            "--base-time=2026-03-28 23:00:00 UTC",
            "--iterations=2",
            calendar,
        ],
        env={**os.environ, "LC_ALL": "C", "TZ": "UTC", "SYSTEMD_COLORS": "0"},
        capture_output=True,
        check=False,
        timeout=10,
    )
    if observed.returncode or not all(
        stamp in observed.stdout
        for stamp in (b"Sun 2026-03-29 02:00:00 UTC", b"Mon 2026-03-30 02:00:00 UTC")
    ):
        raise Rejected("daily_backup_calendar_rejected")
    return dict(
        unit=unit + ".timer", calendar=calendar, persistent=True, scope="shipped-unit-config"
    )


def verified(state, owner, backup_id, *, started_after=None):
    directory = safe_child(state, "backups/" + hexadecimal(backup_id))
    policy = read_json(ROOT / "policies/local-cpu.json")
    statement, _ = storage_backup.read_backup(directory, owner["trusted_keys"], policy)
    if (
        statement["schema_version"] != 2
        or "recovery_point_at" not in statement
        or statement["source_workspace"] != owner["workspace_id"]
        or digest(canonical(statement)) != backup_id
    ):
        raise Rejected("daily_backup_snapshot_binding")
    started = datetime.fromisoformat(statement["started_at"])
    point = datetime.fromisoformat(statement["recovery_point_at"])
    # Retain the existing conservative 24 h limit at the end of archive readback.
    current = datetime.now(UTC)
    if not started <= point <= datetime.fromisoformat(statement["completed_at"]) <= current or (
        current - started > timedelta(hours=24)
        or started_after is not None
        and started < started_after
    ):
        raise Rejected("daily_backup_time_window")
    return dict(
        workspace_id=owner["workspace_id"],
        backup_id=backup_id,
        started_at=statement["started_at"],
        recovery_point_at=statement["recovery_point_at"],
        completed_at=statement["completed_at"],
    )


def execute(action, state, owner_path, inventory):
    state, owner_path, inventory = map(Path, (state, owner_path, inventory))
    if (
        owner_path.resolve() == inventory.resolve()
        or owner_path.resolve().is_relative_to(state.resolve())
        or inventory.resolve().is_relative_to(state.resolve())
    ):
        raise Rejected("daily_backup_requires_external_owner_and_pin")
    owner = read_json(owner_path)
    require_fields(owner, ("workspace_id", "trusted_keys"))
    hexadecimal(owner["workspace_id"], 32)
    storage_backup.trusted_keys(owner["trusted_keys"])
    if action == "verify":
        receipt = read_json(inventory)
        require_fields(
            receipt,
            (
                "workspace_id",
                "backup_id",
                "started_at",
                "recovery_point_at",
                "completed_at",
                "source_revision",
            ),
        )
        result = verified(state, owner, receipt["backup_id"])
        result["source_revision"] = hexadecimal(receipt["source_revision"], 40)
        if receipt != result:
            raise Rejected("daily_backup_inventory_mismatch")
        return result
    if action != "run":
        raise Rejected("daily_backup_action")
    with target_lock(inventory):
        if (
            storage_pki.workspace_id(state) != owner["workspace_id"]
            or read_json(safe_child(state, "trusted-keys.json")) != owner["trusted_keys"]
        ):
            raise Rejected("daily_backup_source_owner")
        revision = hexadecimal(command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]), 40)
        started = datetime.now(UTC)
        child = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "mlsecops.storage_backup",
                "--state",
                str(state.absolute()),
                "--include-promotion",
                "--recovery-point",
            ],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=600,
        )
        if child.returncode:
            raise Rejected("daily_backup_command_failed")
        capture = decode(child.stdout, 65536)
        if not isinstance(capture, dict) or capture.get("status") != "verified-backup-not-release":
            raise Rejected("daily_backup_command_result")
        result = verified(state, owner, capture["backup_id"], started_after=started)
        result["source_revision"] = revision
        write_json(inventory, result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("check-timer", help="validate shipped units without installation or login")
    for action in ("run", "verify"):
        command_parser = commands.add_parser(action)
        for name in ("state", "owner", "inventory"):
            command_parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        result = (
            check_timer(ROOT / "infra/systemd")
            if args.action == "check-timer"
            else execute(args.action, args.state, args.owner, args.inventory)
        )
        print(canonical(result).decode())
        return 0
    except (
        KeyError,
        TypeError,
        ValueError,
        OSError,
        configparser.Error,
        subprocess.TimeoutExpired,
    ) as error:
        print(
            str(error) if isinstance(error, Rejected) else "daily_backup_unavailable",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
