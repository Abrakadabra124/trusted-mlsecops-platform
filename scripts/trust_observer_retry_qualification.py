"""Retry only a confirmed, reaped journal-contention child within its normal cycle."""

import contextlib
import io
import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import security_trust_service as service
from mlsecops.contracts import Rejected


class ContentionRecovery(unittest.TestCase):
    def setUp(self):
        with patch.object(service.source, "configuration", return_value=({}, "a" * 64)):
            self.observer = service.Observer(str(Path("private.json").resolve()))

    def test_reaped_busy_child_recovers_before_next_normal_period(self):
        self.assertTrue(hasattr(self.observer, "check"), "bounded contention recovery is missing")
        first, second = Mock(), Mock()
        first.poll.return_value, second.poll.return_value = 42, 0
        created = []

        def spawn(*args, **kwargs):
            if created:
                first.wait.assert_called_once()
                self.assertIsNone(self.observer.child)
            process = (first, second)[len(created)]
            created.append(process)
            return process

        with (
            patch.object(service.subprocess, "Popen", side_effect=spawn),
            patch.object(service.time, "monotonic", return_value=1),
            patch.object(self.observer.stopped, "wait") as wait,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertTrue(self.observer.check(0))
        wait.assert_called_once_with(1)
        second.wait.assert_called_once()
        self.assertIsNone(self.observer.child)

    def test_other_failures_are_not_retried_or_treated_as_success(self):
        for code in (None, 1, 41, 43, 44, 97):
            self.observer.last_exit_code = code
            with (
                self.subTest(code=code),
                patch.object(self.observer, "once", return_value=False) as once,
                patch.object(self.observer.stopped, "wait") as wait,
            ):
                self.assertFalse(self.observer.check(0))
            once.assert_called_once()
            wait.assert_not_called()

    def test_persistent_busy_has_at_most_two_retries(self):
        self.observer.last_exit_code = 42
        with (
            patch.object(self.observer, "once", return_value=False) as once,
            patch.object(service.time, "monotonic", return_value=1),
            patch.object(self.observer.stopped, "wait") as wait,
        ):
            self.assertFalse(self.observer.check(0))
        self.assertEqual(once.call_count, 3)
        self.assertEqual(wait.call_count, 2)

    def test_insufficient_cycle_budget_prevents_another_child(self):
        self.observer.last_exit_code = 42
        with (
            patch.object(self.observer, "once", return_value=False) as once,
            patch.object(service.time, "monotonic", return_value=21),
            patch.object(self.observer.stopped, "wait") as wait,
        ):
            self.assertFalse(self.observer.check(0))
        once.assert_called_once()
        wait.assert_not_called()

    def test_stop_during_backoff_never_starts_another_child(self):
        self.observer.last_exit_code = 42
        with (
            patch.object(self.observer, "once", return_value=False) as once,
            patch.object(service.time, "monotonic", return_value=1),
            patch.object(
                self.observer.stopped, "wait", side_effect=lambda _: self.observer.stopped.set()
            ),
        ):
            self.assertFalse(self.observer.check(0))
        once.assert_called_once()

    def test_reap_budget_reserves_terminate_then_kill_waits(self):
        self.observer.last_exit_code = 42
        with (
            patch.object(self.observer, "once", return_value=False) as once,
            patch.object(service.time, "monotonic", return_value=18),
            patch.object(self.observer.stopped, "wait") as wait,
        ):
            self.assertFalse(self.observer.check(0))
        once.assert_called_once()
        wait.assert_not_called()

    def test_delayed_backoff_cannot_launch_past_cycle_budget(self):
        self.observer.last_exit_code = 42
        with (
            patch.object(self.observer, "once", return_value=False) as once,
            patch.object(service.time, "monotonic", side_effect=[17, 19, 31]),
            patch.object(self.observer.stopped, "wait") as wait,
        ):
            self.assertFalse(self.observer.check(0))
        once.assert_called_once()
        wait.assert_called_once_with(1)

    def test_failed_reap_remains_fatal_even_for_a_busy_exit_code(self):
        process = Mock()
        process.poll.return_value = 42
        process.wait.side_effect = subprocess.TimeoutExpired("owned-child", 1)
        with (
            patch.object(service.subprocess, "Popen", return_value=process) as spawn,
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaisesRegex(Rejected, "cleanup_unconfirmed"),
        ):
            self.observer.check(0)
        spawn.assert_called_once()
        self.assertIs(self.observer.child, process)


if __name__ == "__main__":
    unittest.main()
