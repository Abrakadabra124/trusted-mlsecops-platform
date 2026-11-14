"""Check the shipped daily backup on an owned disposable GitHub Ubuntu system manager."""

import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mlsecops import daily_backup
from mlsecops.contracts import Rejected, bounded_read, decode, digest

UNIT = "mlsecops-daily-backup"
SYSTEM = "/run/systemd/system"
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
SECOND = 1_000_000


def require(condition):
    if not condition:
        raise Rejected("daily_backup_scheduler_evidence")


def require_host():
    require(
        sys.platform == "linux"
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.getuid() != 0
    )
    import pwd

    user = pwd.getpwuid(os.getuid()).pw_name
    require(
        re.fullmatch(r"[a-z_][a-z0-9_-]*", user)
        and "ID=ubuntu" in Path("/etc/os-release").read_text().splitlines()
    )
    return user


def privileged(*args):
    result = subprocess.run(
        ["sudo", "-n", *args],
        capture_output=True,
        text=True,
        timeout=30,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode:
        raise Rejected("daily_backup_scheduler_command_" + args[0])
    return result.stdout.strip()


def timestamp_us(name, kind, field):
    # systemctl's formatted date can lose microseconds. Read PID 1's uint64 property.
    obj = privileged(
        "busctl",
        "--system",
        "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "GetUnit",
        "s",
        name,
    )
    match = re.fullmatch(r'o "(/org/freedesktop/systemd1/unit/[a-zA-Z0-9_]+)"', obj)
    require(match is not None)
    value = privileged(
        "busctl",
        "--system",
        "get-property",
        "org.freedesktop.systemd1",
        match[1],
        "org.freedesktop.systemd1." + kind,
        field,
    )
    require(re.fullmatch(r"t [0-9]+", value))
    return int(value[2:])


def iso(micros):
    return (EPOCH + timedelta(microseconds=micros)).isoformat()


def next_daily(micros):
    instant = EPOCH + timedelta(microseconds=micros)
    following = instant.replace(hour=2, minute=0, second=0, microsecond=0)
    if following <= instant:
        following += timedelta(days=1)
    return (following - EPOCH) // timedelta(microseconds=1)


def properties(unit, fields):
    raw = privileged("systemctl", "show", "--property=" + ",".join(fields), unit)
    return dict(line.split("=", 1) for line in raw.splitlines())


def observe(timer, service):
    deadline = time.monotonic() + 650
    while time.monotonic() < deadline:
        result = properties(
            service,
            ("LoadState", "ActiveState", "SubState", "Result", "ExecMainCode", "ExecMainStatus"),
        )
        require(result["LoadState"] == "loaded" and result["Result"] == "success")
        if result["ExecMainCode"] == "1" and result["ActiveState"] == "inactive":
            require(result["SubState"] == "dead" and result["ExecMainStatus"] == "0")
            break
        time.sleep(0.5)
    else:
        raise Rejected("daily_backup_scheduler_timeout")
    timer_state = properties(timer, ("LoadState", "ActiveState", "SubState", "Result", "Unit"))
    require(
        timer_state
        == dict(
            LoadState="loaded",
            ActiveState="active",
            SubState="waiting",
            Result="success",
            Unit=service,
        )
    )


def capture(root, state, owner_path, inventory):
    """Return (independently reverified inventory, scheduler primary fields) after cleanup."""
    user = require_host()
    root, state, owner_path, inventory = (
        Path(p).absolute() for p in (root, state, owner_path, inventory)
    )
    require(
        not inventory.exists()
        and state.is_dir()
        and owner_path.is_file()
        and inventory.parent.is_dir()
    )
    templates = root / "infra/systemd"
    daily_backup.check_timer(templates)
    unique = UNIT + "-" + uuid.uuid4().hex
    timer, service = unique + ".timer", unique + ".service"
    # Reject special unit-file characters before placing any caller path in an override.
    paths = (root, state, owner_path, inventory, inventory.parent, Path(sys.executable))
    require(all(re.fullmatch(r"[\w./: ~-]+", p.as_posix()) and ".." not in p.parts for p in paths))
    command = f'"{sys.executable}" -B -m mlsecops.daily_backup run --state "{state}" --owner "{owner_path}" --inventory "{inventory}"'
    with tempfile.TemporaryDirectory() as temporary, ExitStack() as cleanup:
        folder = Path(temporary)
        cleanup.callback(privileged, "systemctl", "daemon-reload")

        def link(name, content, *, dropin=False):
            parent = f"{SYSTEM}/{name}.d" if dropin else SYSTEM
            if dropin:
                privileged("mkdir", "--", parent)
                cleanup.callback(privileged, "rmdir", "--", parent)
            target = parent + ("/qualification.conf" if dropin else "/" + name)
            source = folder / (name + (".conf" if dropin else ""))
            source.write_text(content, encoding="utf-8")
            # Without --force, ln refuses an existing entry. The runner alone owns
            # the temporary directory and it outlives the manager reload and cleanup.
            privileged("ln", "-sT", "--", str(source), target)
            cleanup.callback(privileged, "unlink", "--", target)

        link(
            timer,
            (templates / (UNIT + ".timer"))
            .read_text()
            .replace("Unit=" + UNIT + ".service", "Unit=" + service),
        )
        link(service, (templates / (UNIT + ".service")).read_text())
        link(timer, "[Timer]\nOnActiveSec=3s\n", dropin=True)
        link(
            service,
            f"[Service]\nUser={user}\nWorkingDirectory={root}\nStateDirectory=\nReadWritePaths=\n"
            f'ReadWritePaths="{state}" "{inventory.parent}"\nExecStart=\nExecStart={command}\n'
            "PrivateTmp=no\n",
            dropin=True,
        )
        privileged("systemctl", "daemon-reload")
        # Persistent timers store one stamp outside /run. Clean only this timer's stamp.
        cleanup.callback(privileged, "systemctl", "clean", "--what=state", timer)
        cleanup.callback(privileged, "systemctl", "stop", timer, service)
        start = time.time_ns() // 1000
        privileged("systemctl", "start", timer)
        observe(timer, service)
        last = timestamp_us(timer, "Timer", "LastTriggerUSec")
        following = timestamp_us(timer, "Timer", "NextElapseUSecRealtime")
        began = timestamp_us(service, "Service", "ExecMainStartTimestamp")
        ended = timestamp_us(service, "Service", "ExecMainExitTimestamp")
        require(
            start + 3 * SECOND
            <= last
            <= began
            <= ended
            <= time.time_ns() // 1000
            < following
            == next_daily(last)
        )
        # If a calendar deadline passed before the observed trigger, its cause is ambiguous.
        require(last < next_daily(start))
        receipt = daily_backup.execute("verify", state, owner_path, inventory)
        require(
            datetime.fromisoformat(iso(began))
            <= datetime.fromisoformat(receipt["started_at"])
            <= datetime.fromisoformat(receipt["recovery_point_at"])
            <= datetime.fromisoformat(receipt["completed_at"])
            <= datetime.fromisoformat(iso(ended))
        )
        retained = bounded_read(inventory, 4096)
        require(decode(retained) == receipt)
        pin = digest(retained)
    for name in (timer, service, timer + ".d", service + ".d"):
        require(not os.path.lexists(Path(SYSTEM) / name))
    return receipt, dict(
        unit=timer,
        calendar="*-*-* 02:00:00 UTC",
        trigger="controlled-on-active",
        daily_cadence_observed=False,
        runtime_units_removed=True,
        exit_status=0,
        last_trigger_utc=iso(last),
        next_elapse_utc=iso(following),
        service_started_at=iso(began),
        service_exited_at=iso(ended),
        backup_id=receipt["backup_id"],
        inventory_sha256=pin,
    )
