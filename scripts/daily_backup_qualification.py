"""Exercise the timer's command, signed SQL snapshot and offline pin readback."""

import argparse
import configparser
import io
import shlex
import subprocess
import sys
import unittest
from contextlib import nullcontext, redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mlsecops import daily_backup as daily
from mlsecops import promotion_recovery, storage_backup
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from mlsecops.signing import ROLES, create_key, sign

ROOT = Path(__file__).resolve().parents[1]
UNIT = "mlsecops-daily-backup"


class DailyBackup(unittest.TestCase):
    def setUp(self):
        folder = Path(self.enterContext(TemporaryDirectory()))
        self.state = folder / "state"
        self.owner = folder / "operator/owner.json"
        self.inventory = folder / "inventory/latest.json"
        self.workspace = "a" * 32
        self.public = {r: create_key(self.state / f"keys/{r}.pem") for r in ROLES}
        write_json(self.owner, {"workspace_id": self.workspace, "trusted_keys": self.public})
        write_json(self.state / "trusted-keys.json", self.public)
        write_json(
            self.state / "workspace.json",
            dict(
                product="trusted-mlsecops",
                schema_version=1,
                workspace_id=self.workspace,
            ),
        )

        def tables(keys):
            return {k: dict(rows=0, bytes=0, invalid=0, sha256="1" * 64) for k in keys}

        migration = storage_backup.migration()
        self.enterContext(
            patch.object(
                storage_backup,
                "validate",
                return_value=dict(name="owned", workspace_id=self.workspace),
            )
        )
        self.enterContext(
            patch.object(
                storage_backup,
                "admin",
                side_effect=lambda name, query: (
                    "f" if "ml_trust" in query else f"{migration['version']}:{migration['sha256']}"
                ),
            )
        )
        self.enterContext(patch.object(storage_backup, "verify_configuration"))
        self.enterContext(
            patch.object(
                storage_backup,
                "snapshot",
                side_effect=lambda *a, **kw: nullcontext(
                    dict(
                        snapshot="controlled",
                        recovery_point_at=datetime.now(UTC).isoformat(),
                        tables=tables(storage_backup.TABLES),
                        promotion=dict(
                            migration=promotion_recovery.migration(),
                            tables=tables(promotion_recovery.TABLES),
                        ),
                    )
                ),
            )
        )
        self.enterContext(patch.object(storage_backup, "binary_command", return_value=b"PGDMP-lab"))
        self.enterContext(patch.object(daily, "command", return_value="c" * 40))
        self.backup = self.enterContext(
            patch.object(daily.subprocess, "run", side_effect=self.child)
        )

    def child(self, argv, **kwargs):
        self.assertEqual(
            argv,
            [
                sys.executable,
                "-B",
                "-m",
                "mlsecops.storage_backup",
                "--state",
                str(self.state),
                "--include-promotion",
                "--recovery-point",
            ],
        )
        with patch.object(sys, "argv", argv[3:]), redirect_stdout(io.StringIO()) as output:
            code = storage_backup.main()
        return subprocess.CompletedProcess(argv, code, output.getvalue().encode())

    def call(self, action):
        return daily.execute(action, self.state, self.owner, self.inventory)

    def resign(self, receipt, **change):
        directory = self.state / "backups" / receipt["backup_id"]
        manifest, _ = storage_backup.read_backup(
            directory, self.public, read_json(ROOT / "policies/local-cpu.json")
        )
        if change.pop("without_point", False):
            del manifest["recovery_point_at"]
        manifest.update(change)
        if manifest["schema_version"] == 1:
            del manifest["promotion"]
        pin = digest(canonical(manifest))
        dest = directory.with_name(pin)
        dest.mkdir()
        (dest / "data.dump").write_bytes((directory / "data.dump").read_bytes())
        write_json(
            dest / "manifest.json", sign(manifest, "storage-backup", self.state / "keys/trust.pem")
        )
        write_json(self.inventory, {**read_json(self.inventory), "backup_id": pin})

    def test_foreign_source_refused_before_backup(self):
        write_json(self.owner, dict(workspace_id="b" * 32, trusted_keys=self.public))
        with self.assertRaises(Rejected):
            self.call("run")
        self.backup.assert_not_called()
        self.assertFalse(self.inventory.exists())

    def test_units_execute_normal_cli_and_verify_after_source_is_gone(self):
        def unit(ext):
            cfg = configparser.ConfigParser(interpolation=None)
            cfg.read(ROOT / "infra/systemd" / (UNIT + ext))
            return cfg

        timer, service = unit(".timer"), unit(".service")["Service"]
        self.assertEqual(timer["Timer"]["OnCalendar"], "*-*-* 02:00:00 UTC")
        self.assertTrue(timer["Timer"].getboolean("Persistent"))
        self.assertEqual(timer["Timer"]["Unit"], UNIT + ".service")
        self.assertEqual(timer["Install"]["WantedBy"], "timers.target")
        self.assertEqual(service["Type"], "oneshot")
        self.assertEqual(service["User"], "mlsecops")
        args = shlex.split(service["ExecStart"])
        self.assertEqual(
            args[:4],
            [
                service["WorkingDirectory"] + "/.venv/bin/python",
                "-B",
                "-m",
                "mlsecops.daily_backup",
            ],
        )
        parser = argparse.ArgumentParser()
        parser.add_argument("action", choices=["run"])
        for name in ("state", "owner", "inventory"):
            parser.add_argument("--" + name, required=True)
        config = parser.parse_args(args[4:])
        self.assertEqual(config.state, service["WorkingDirectory"] + "/.runtime")
        self.assertTrue(config.owner.startswith("/etc/"))
        self.assertTrue(config.inventory.startswith("/var/lib/" + service["StateDirectory"] + "/"))
        for i, target in (
            (config.state, self.state),
            (config.owner, self.owner),
            (config.inventory, self.inventory),
        ):
            args[args.index(i)] = str(target)
        with patch.object(sys, "argv", args[3:]), redirect_stdout(io.StringIO()):
            self.assertEqual(daily.main(), 0)
        (self.state / "workspace.json").unlink()
        (self.state / "trusted-keys.json").unlink()
        result = self.call("verify")
        self.assertEqual(result["workspace_id"], self.workspace)
        self.assertEqual(result["backup_id"], read_json(self.inventory)["backup_id"])
        self.backup.assert_called_once()

    def test_signed_stale_future_foreign_and_v1_snapshots_rejected(self):
        receipt = self.call("run")
        current = datetime.now(UTC)
        for change in (
            dict(started_at=(current - timedelta(hours=24, seconds=1)).isoformat()),
            dict(completed_at=(current + timedelta(hours=1)).isoformat()),
            dict(source_workspace="d" * 32),
            dict(schema_version=1),
            dict(without_point=True),
        ):
            with self.subTest(change=change):
                self.resign(receipt, **change)
                with self.assertRaises(Rejected):
                    self.call("verify")

    def test_no_replay_of_previous_success_and_no_automatic_purge(self):
        old = self.call("run")
        new = self.call("run")
        self.assertNotEqual(old["backup_id"], new["backup_id"])
        previous = self.inventory.read_bytes()
        self.backup.side_effect = None
        self.backup.return_value = subprocess.CompletedProcess(
            [],
            0,
            canonical({"status": "verified-backup-not-release", "backup_id": old["backup_id"]}),
        )
        with self.assertRaises(Rejected):
            self.call("run")
        self.assertEqual(self.inventory.read_bytes(), previous)
        self.assertTrue((self.state / "backups" / old["backup_id"] / "data.dump").is_file())
        self.assertEqual(self.call("verify")["backup_id"], new["backup_id"])

    def test_login_free_timer_check_rejects_wrong_unit_cadence_and_handler(self):
        directory = self.state / "units"
        directory.mkdir()
        for ext in (".timer", ".service"):
            (directory / (UNIT + ext)).write_bytes(
                (ROOT / "infra/systemd" / (UNIT + ext)).read_bytes()
            )
        with patch.object(sys, "platform", "linux"):
            calendar = b"Next elapse: Sun 2026-03-29 02:00:00 UTC\n Iter. #2: Mon 2026-03-30 02:00:00 UTC\n"
            self.backup.side_effect = None
            self.backup.return_value = subprocess.CompletedProcess([], 0, calendar)
            result = daily.check_timer(directory)
            self.assertEqual(result["calendar"], "*-*-* 02:00:00 UTC")
            self.assertEqual(self.backup.call_args.args[0][0:2], ["systemd-analyze", "calendar"])
            self.backup.return_value = subprocess.CompletedProcess([], 0, b"No elapse")
            with self.assertRaises(Rejected):
                daily.check_timer(directory)
            for ext, before, after in (
                (".timer", "Persistent=true", "Persistent=false"),
                (".timer", "02:00:00", "12:00:00"),
                (".service", "daily_backup run", "daily_backup verify"),
            ):
                path = directory / (UNIT + ext)
                original = path.read_text()
                path.write_text(original.replace(before, after))
                self.backup.reset_mock()
                with self.subTest(change=after), self.assertRaises(Rejected):
                    daily.check_timer(directory)
                self.backup.assert_not_called()
                path.write_text(original)

    def test_archive_tampering_or_replaced_trust_is_rejected(self):
        receipt = self.call("run")
        owner = read_json(self.owner)
        replacement = {**self.public, "trust": create_key(self.state / "foreign.pem")}
        write_json(self.owner, {**owner, "trusted_keys": replacement})
        with self.assertRaises(Rejected):
            self.call("verify")
        with self.assertRaises(Rejected):
            self.call("run")
        self.backup.assert_called_once()
        write_json(self.owner, owner)
        (self.state / "backups" / receipt["backup_id"] / "data.dump").write_bytes(b"PGDMP-bad")
        with self.assertRaisesRegex(Rejected, "backup_archive_integrity_failed"):
            self.call("verify")

    def test_exact_age_boundary_and_source_offline_cli(self):
        receipt = self.call("run")
        start = datetime.fromisoformat(receipt["started_at"])
        for delta, code in ((timedelta(hours=24), 0), (timedelta(hours=24, microseconds=1), 1)):
            clock = start + delta

            class FixedClock(datetime):
                @classmethod
                def now(cls, tz=None):
                    return clock.astimezone(tz)

            with (
                self.subTest(delta=delta),
                patch.object(daily, "datetime", FixedClock),
                patch.object(storage_backup, "datetime", FixedClock),
                patch.object(
                    sys,
                    "argv",
                    [
                        "daily_backup",
                        "verify",
                        "--state",
                        str(self.state),
                        "--owner",
                        str(self.owner),
                        "--inventory",
                        str(self.inventory),
                    ],
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(daily.main(), code)

    def test_failure_and_misconfigured_inventory_do_not_publish_a_pin(self):
        with self.assertRaises(Rejected):
            daily.execute("run", self.state, self.owner, self.state / "backups/latest.json")
        self.backup.assert_not_called()
        self.backup.side_effect = None
        for code, output in (
            (1, b""),
            (0, b"{}"),
            (0, b'{"status":"verified-backup-not-release","backup_id":"../latest"}'),
        ):
            self.backup.return_value = subprocess.CompletedProcess([], code, output)
            with self.subTest(output=output), self.assertRaises(Rejected):
                self.call("run")
            self.assertFalse(self.inventory.exists())

    def test_inventory_times_must_match_and_unknown_action_refused(self):
        receipt = self.call("run")
        write_json(self.inventory, {**receipt, "recovery_point_at": "2000-01-01T00:00:00Z"})
        with self.assertRaisesRegex(Rejected, "daily_backup_inventory_mismatch"):
            self.call("verify")
        with self.assertRaisesRegex(Rejected, "daily_backup_action"):
            self.call("unknown")

    def test_module_entrypoint_check_timer_without_login(self):
        import runpy

        with (
            patch.dict(sys.modules),
            patch.object(sys, "argv", ["daily_backup", "check-timer"]),
            redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as exited,
        ):
            sys.modules.pop("mlsecops.daily_backup")
            self.backup.side_effect = None
            self.backup.return_value = subprocess.CompletedProcess(
                [], 0, b"Sun 2026-03-29 02:00:00 UTC\nMon 2026-03-30 02:00:00 UTC\n"
            )
            runpy.run_module("mlsecops.daily_backup", run_name="__main__")
        self.assertEqual(exited.exception.code, 0)
