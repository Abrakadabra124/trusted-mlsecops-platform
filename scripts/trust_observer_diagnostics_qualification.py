"""Finite exit-code diagnostics must never reveal source data or exceptions."""

import contextlib
import errno
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import security_event_store as journal
from mlsecops import security_trust_events as source
from mlsecops import security_trust_service as service
from mlsecops.contracts import Rejected


class Diagnostics(unittest.TestCase):
    def test_only_known_failures_map_to_finite_exit_codes(self):
        self.assertTrue(hasattr(source, "diagnostic_code"), "failure classifier is missing")
        for error, code in (
            (Rejected("trust_security_source_unavailable"), 41),
            (Rejected("security_store_unavailable"), 43),
            (Rejected("trust_security_delivery_unconfirmed"), 44),
            (Rejected("private-path-and-token"), 1),
            (RuntimeError("trust_security_source_unavailable"), 1),
        ):
            self.assertEqual(source.diagnostic_code(error), code)

    def test_wrapped_contention_is_distinct_from_other_filesystem_failures(self):
        for cause, code in (
            (BlockingIOError(errno.EAGAIN, "PRIVATE"), 42),
            (PermissionError(errno.EACCES, "PRIVATE"), 43),
            (BlockingIOError(errno.EIO, "PRIVATE"), 43),
        ):
            unavailable = Rejected("security_store_unavailable")
            unavailable.__context__ = cause
            wrapped = Rejected("trust_security_delivery_unconfirmed")
            wrapped.__context__ = unavailable
            self.assertEqual(source.diagnostic_code(wrapped), code)
        cycle = Rejected("PRIVATE")
        cycle.__context__ = cycle
        self.assertEqual(source.diagnostic_code(cycle), 1)

    def test_diagnostics_require_pinned_heartbeat_and_preserve_ordinary_cli_status(self):
        for arguments, expected, called in (
            ([], 1, True),
            (["--diagnostic-exit-code"], 1, False),
            (["--heartbeat", "--diagnostic-exit-code"], 1, False),
            (["--heartbeat", "--config-sha256", "a" * 64, "--diagnostic-exit-code"], 41, True),
        ):
            with (
                self.subTest(arguments=arguments),
                patch.object(source, "enforce"),
                patch.object(
                    source, "configured", side_effect=Rejected("trust_security_source_unavailable")
                ) as configured,
                contextlib.redirect_stdout(io.StringIO()) as stdout,
                contextlib.redirect_stderr(io.StringIO()) as stderr,
            ):
                self.assertEqual(source.main(["--config", "private.json", *arguments]), expected)
                self.assertEqual(configured.called, called)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "trust_security_rejected\n")

    def test_parent_emits_only_known_category_from_numeric_child_status(self):
        for code, category in ((42, "journal_busy"), (97, "unclassified")):
            with patch.object(source, "configuration", return_value=({}, "a" * 64)):
                observer = service.Observer(str(Path("private.json").resolve()))
            process = Mock()
            process.poll.return_value = code
            with (
                patch.object(service.subprocess, "Popen", return_value=process),
                contextlib.redirect_stderr(io.StringIO()) as stderr,
            ):
                self.assertFalse(observer.once())
            self.assertIsNone(observer.child)
            self.assertEqual(
                json.loads(stderr.getvalue()),
                {
                    "state": "trust_observer_child_failure",
                    "category": category,
                    "release_ready": False,
                },
            )

    @unittest.skipUnless(os.name == "posix", "actual flock requires Linux")
    def test_actual_exclusive_journal_contention_is_classified_without_sql(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "journal"
            root.mkdir(mode=0o700)
            with journal.locked(str(root)):
                try:
                    with journal.locked(str(root)):
                        self.fail("simultaneous exclusive lock accepted")
                except Rejected as error:
                    self.assertEqual(source.diagnostic_code(error), 42)

    def test_failure_readback_ignores_unknown_categories_and_private_fields(self):
        from scripts import security_trust_service_native as native

        valid = {
            "state": "trust_observer_child_failure",
            "category": "journal_busy",
            "release_ready": False,
        }
        documents = [
            valid,
            {**valid, "category": "PRIVATE"},
            {**valid, "private": "SECRET"},
            {**valid, "category": []},
            {**valid, "release_ready": True},
            [],
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "observer.log"
            path.write_text(
                "PRIVATE\ntrust_observer_check_failed\n"
                + "\n".join(json.dumps(value) for value in documents),
                encoding="utf-8",
            )
            result = native.failure_state(path, lambda: {"records": []}, lambda: {"records": []})
        self.assertEqual(result["observer_failure_categories"]["journal_busy"], 1)
        self.assertEqual(sum(result["observer_failure_categories"].values()), 1)
        self.assertEqual(result["observer_failed_checks"], 1)
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertNotIn("SECRET", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
