"""Exercise the hosted unit lifecycle at the system manager boundary."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, write_json
from scripts import daily_backup_systemd_native as hosted


class Timer(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.temp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.state = self.temp / "state"
        self.state.mkdir()
        self.owner = self.temp / "owner.json"
        self.owner.write_text("{}")
        self.inventory = self.temp / "latest.json"
        self.ops = []
        self.ticks = 1794614400 * 1_000_000
        self.micros = self.enterContext(
            patch.object(hosted, "timestamp_us", side_effect=self.timestamp)
        )
        self.enterContext(patch.object(hosted, "require_host", return_value="runner"))
        self.enterContext(patch.object(hosted, "privileged", side_effect=self.manager))
        self.receipt = dict(
            backup_id="a" * 64,
            started_at=hosted.iso(self.ticks + 3000),
            recovery_point_at=hosted.iso(self.ticks + 4000),
            completed_at=hosted.iso(self.ticks + 5000),
        )
        self.enterContext(patch.object(hosted.daily_backup, "execute", return_value=self.receipt))
        self.enterContext(patch.object(hosted.time, "sleep"))
        self.enterContext(
            patch.object(
                hosted.time,
                "time_ns",
                side_effect=lambda: (
                    (
                        self.ticks + 10000
                        if any(op[:2] == ("systemctl", "start") for op in self.ops)
                        else self.ticks - 3_500_000
                    )
                    * 1000
                ),
            )
        )
        self.units = {}
        self.enterContext(patch.object(hosted.daily_backup, "check_timer"))

    def timestamp(self, name, kind, field):
        if kind == "Timer":
            return self.ticks if field == "LastTriggerUSec" else hosted.next_daily(self.ticks)
        return self.ticks + (2000 if field == "ExecMainStartTimestamp" else 6000)

    def manager(self, *argv):
        self.ops.append(argv)
        if argv[:2] == ("systemctl", "start"):
            write_json(self.inventory, self.receipt)
        if argv[0] == "ln":
            self.units[str(argv[-1])] = Path(argv[-2]).read_text()
        if argv[0] == "systemctl" and "show" in argv:
            name = str(argv[-1])
            if name.endswith(".timer"):
                return (
                    "LoadState=loaded\nActiveState=active\nSubState=waiting\nResult=success\nUnit="
                    + name[:-6]
                    + ".service"
                )
            return "LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainCode=1\nExecMainStatus=0\n"
        return ""

    def test_real_templates_daily_schedule_and_bounded_trigger_teardown(self):
        receipt, proof = hosted.capture(self.root, self.state, self.owner, self.inventory)
        self.assertEqual(receipt, self.receipt)
        self.assertEqual(proof["trigger"], "controlled-on-active")
        self.assertFalse(proof["daily_cadence_observed"])
        self.assertTrue(proof["runtime_units_removed"])
        self.assertEqual(proof["next_elapse_utc"], hosted.iso(hosted.next_daily(self.ticks)))
        self.assertIn(
            "OnCalendar=*-*-* 02:00:00 UTC",
            next(v for k, v in self.units.items() if k.endswith(".timer")),
        )
        self.assertIn("OnActiveSec=", next(v for k, v in self.units.items() if ".timer.d/" in k))
        self.assertTrue(
            any(
                "mlsecops.daily_backup run" in v and "User=runner" in v for v in self.units.values()
            )
        )
        self.assertEqual(set(self.units), {str(op[-1]) for op in self.ops if op[0] == "unlink"})
        self.assertFalse(any("enable" in op for op in self.ops))

    def test_bad_next_elapse_and_failed_service_never_yield_even_when_cleaned(self):
        for broken in ("calendar", "service"):
            self.inventory.unlink(missing_ok=True)
            self.ops.clear()
            self.units.clear()
            self.micros.side_effect = lambda n, k, f: (
                self.ticks if f == "NextElapseUSecRealtime" else self.timestamp(n, k, f)
            )

            def manager(*args):
                out = self.manager(*args)
                return (
                    out.replace("Result=success", "Result=exit-code")
                    if broken == "service" and "show" in args
                    else out
                )

            with (
                self.subTest(broken=broken),
                patch.object(hosted, "privileged", side_effect=manager),
                self.assertRaises(Rejected),
            ):
                hosted.capture(self.root, self.state, self.owner, self.inventory)
            self.assertEqual(set(self.units), {str(op[-1]) for op in self.ops if op[0] == "unlink"})

    def test_host_guard_and_existing_inventory_precede_manager_access(self):
        self.inventory.write_text("{}")
        with self.assertRaises(Rejected):
            hosted.capture(self.root, self.state, self.owner, self.inventory)
        self.assertEqual(self.ops, [])

    def test_failure_during_publication_keeps_foreign_entry_and_releases_prior_links(self):
        def refuse(*argv):
            if argv[0] == "ln" and str(argv[-1]).endswith(".service"):
                raise Rejected("existing")
            return self.manager(*argv)

        with patch.object(hosted, "privileged", side_effect=refuse), self.assertRaises(Rejected):
            hosted.capture(self.root, self.state, self.owner, self.inventory)
        self.assertEqual(len(self.units), 1)
        self.assertEqual(set(self.units), {str(op[-1]) for op in self.ops if op[0] == "unlink"})


class ManagerBoundary(unittest.TestCase):
    def test_requires_ubuntu_nonroot_and_hosted_owner(self):
        env = dict(GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted", RUNNER_OS="Linux")
        with (
            patch.dict(hosted.os.environ, env),
            patch.object(hosted.sys, "platform", "linux"),
            patch.object(hosted.os, "getuid", create=True, return_value=1001),
            patch.dict(
                hosted.sys.modules,
                pwd=SimpleNamespace(getpwuid=lambda uid: SimpleNamespace(pw_name="runner")),
            ),
            patch.object(Path, "read_text", return_value="ID=ubuntu\n"),
        ):
            self.assertEqual(hosted.require_host(), "runner")
            with (
                patch.dict(hosted.os.environ, RUNNER_ENVIRONMENT="self-hosted"),
                self.assertRaises(Rejected),
            ):
                hosted.require_host()

    def test_dbus_uses_numeric_timestamp_from_manager(self):
        def reply(text, code=0):
            return subprocess.CompletedProcess([], code, text, "")

        for replies, valid in (
            ([reply('o "/org/freedesktop/systemd1/unit/owned_2etimer"'), reply("t 1234567")], True),
            ([reply("untrusted")], False),
            ([reply('o "/org/freedesktop/systemd1/unit/owned_2etimer"'), reply("t -1")], False),
            ([reply("", 1)], False),
        ):
            with (
                self.subTest(valid=valid),
                patch.object(hosted.subprocess, "run", side_effect=replies) as child,
            ):
                if valid:
                    self.assertEqual(
                        hosted.timestamp_us("owned.timer", "Timer", "LastTriggerUSec"), 1234567
                    )
                    self.assertEqual(
                        child.call_args.args[0][-2:],
                        ["org.freedesktop.systemd1.Timer", "LastTriggerUSec"],
                    )
                else:
                    with self.assertRaises(Rejected):
                        hosted.timestamp_us("owned.timer", "Timer", "LastTriggerUSec")
                self.assertEqual(child.call_args.args[0][:3], ["sudo", "-n", "busctl"])

    def test_wait_deadline_is_bounded_when_service_never_exits(self):
        waiting = dict(
            LoadState="loaded",
            ActiveState="activating",
            SubState="start",
            Result="success",
            ExecMainCode="0",
            ExecMainStatus="0",
        )
        with (
            patch.object(hosted, "properties", return_value=waiting),
            patch.object(hosted.time, "monotonic", side_effect=[0, 1, 651]),
            patch.object(hosted.time, "sleep", new_callable=Mock) as wait,
            self.assertRaisesRegex(Rejected, "timeout"),
        ):
            hosted.observe("owned.timer", "owned.service")
        wait.assert_called_once()
        self.assertEqual(
            hosted.next_daily(2 * 3600 * hosted.SECOND), (24 + 2) * 3600 * hosted.SECOND
        )
