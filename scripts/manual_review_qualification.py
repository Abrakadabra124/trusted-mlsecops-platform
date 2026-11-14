"""Local manual review through the prediction contract. No listeners or model workers."""

import asyncio
import contextlib
import io
import os
import runpy
import stat
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from mlsecops import manual_review as review
from mlsecops import serving, serving_http
from mlsecops.contracts import Rejected, canonical, decode
from mlsecops.datasets import FEATURES
from scripts import serving_http_qualification as http_tests

CASE = "a" * 64
TOKEN = "b" * 64
BODY = canonical({"schema_version": 1, "instances": [dict.fromkeys(FEATURES, 0.5)]})
ERROR = {"schema_version": 1, "request_id": "f" * 32, "error": {"code": "model_unavailable"}}


class ManualReview(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name) / ".runtime"
        self.exchange = self.enterContext(
            patch.object(review.load_measurement, "request", new_callable=AsyncMock)
        )
        self.exchange.return_value = (503, ERROR)

    def submit(self, case=CASE, **changes):
        return asyncio.run(
            review.submit(
                self.state,
                case_sha256=case,
                **{"port": 8137, "token": TOKEN, "body": BODY, **changes},
            )
        )

    def test_real_prediction_handler_with_unloaded_engine_creates_only_local_pending(self):
        factory = Mock(side_effect=AssertionError("unexpected model worker"))
        engine = serving.Engine(None, worker_factory=factory)
        harness = http_tests.ServingHttpContracts()
        harness.app = serving_http.create_app(engine, TOKEN)

        async def asgi(port, token, body):
            harness.token = token
            status, reply, reads = await harness.invoke(body=decode(body))
            self.assertEqual(reads, 0)
            return status, reply

        self.exchange.side_effect = asgi
        item = self.submit()
        self.assertEqual(item, {"case_sha256": CASE, "status": "pending human review"})
        self.exchange.assert_awaited_once_with(8137, TOKEN, BODY)
        factory.assert_not_called()
        self.assertEqual(review.pending(self.state), [item])
        with self.assertRaises(Rejected):
            self.submit("c" * 64, token="e" * 64)
        self.assertEqual(review.pending(self.state), [item])
        files = [p for p in self.state.rglob("*") if p.is_file()]
        self.assertEqual([(p.name, p.read_bytes()) for p in files], [(CASE, b"")])

    def test_status_body_and_transport_fail_closed(self):
        for status, reply in (
            (200, ERROR),
            (401, ERROR),
            (413, ERROR),
            (422, ERROR),
            (429, ERROR),
            (503, {**ERROR, "error": {"code": "not_ready"}}),
            (503, {**ERROR, "error": {"code": "security_audit_unavailable"}}),
            (503, {**ERROR, "schema_version": True}),
            (503, {**ERROR, "schema_version": 2}),
            (503, {**ERROR, "request_id": None}),
            (503, {**ERROR, "request_id": "bad"}),
            (503, {**ERROR, "private": "canary"}),
            (503, []),
        ):
            self.exchange.return_value = (status, reply)
            with self.subTest(status=status), self.assertRaises(Rejected):
                self.submit()
        self.exchange.side_effect = TimeoutError
        with self.assertRaises((TimeoutError, Rejected)):
            self.submit()
        self.assertEqual(review.pending(self.state), [])

    def test_invalid_caller_binding_and_invalid_payload_reject_before_exchange(self):
        for case in (None, ERROR["request_id"], TOKEN, "A" * 64, "../" + CASE):
            with self.assertRaises(Rejected):
                self.submit(case)
        for body in (
            None,
            b"",
            b"x" * 65537,
            b'{"private":"canary"}',
            b'{"schema_version":1,"instances":[{}]}',
            b'{"schema_version":true,"instances":[]}',
            b'{"schema_version":2,"instances":[]}',
            b'{"schema_version":1,"instances":{}}',
            b'{"schema_version":1,"instances":[]}',
        ):
            with self.assertRaises(Rejected):
                self.submit(body=body)
        self.exchange.assert_not_awaited()

    def test_fresh_http_ids_same_case_and_parallel_creates_are_idempotent(self):
        item = self.submit()
        path = next(p for p in self.state.rglob("*") if p.is_file())
        before = path.stat()
        self.exchange.return_value = (503, {**ERROR, "request_id": "1" * 32})
        self.assertEqual(self.submit(), item)
        after = path.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))
        with ThreadPoolExecutor(max_workers=8) as pool:
            duplicates = list(pool.map(self.submit, ["c" * 64] * 16))
        self.assertEqual(duplicates, [duplicates[0]] * 16)
        self.assertEqual(review.pending(self.state), [item, duplicates[0]])

    def test_invalid_existing_marker_fails_and_is_preserved(self):
        self.submit()
        marker = next(p for p in self.state.rglob("*") if p.is_file())
        marker.write_bytes(b"private-canary")
        for operation in (self.submit, lambda: review.pending(self.state)):
            with self.assertRaises(Rejected):
                operation()
        self.assertEqual(marker.read_bytes(), b"private-canary")

    def test_linked_marker_cannot_impersonate_pending(self):
        self.submit()
        marker = next(p for p in self.state.rglob("*") if p.is_file())
        os.link(marker, marker.with_name("e" * 64))
        with self.assertRaises(Rejected):
            review.pending(self.state)
        with self.assertRaises(Rejected):
            self.submit()

    def test_retry_after_file_sync_error_syncs_same_marker(self):
        with patch.object(os, "fsync", side_effect=OSError), self.assertRaises(Rejected):
            self.submit()
        marker = self.state / review.QUEUE / CASE
        original = marker.stat()
        real_sync = os.fsync
        synced = []

        def sync(fd):
            synced.append(os.fstat(fd))
            real_sync(fd)

        with patch.object(os, "fsync", side_effect=sync):
            self.assertEqual(self.submit()["status"], review.PENDING)
        self.assertTrue(any(os.path.samestat(entry, original) for entry in synced))
        self.assertTrue(os.path.samestat(marker.stat(), original))
        self.assertEqual(marker.read_bytes(), b"")

    @unittest.skipUnless(os.name == "posix", "requires real POSIX directory descriptors")
    def test_posix_real_marker_then_directory_fsync_and_private_modes(self):
        real_sync = os.fsync
        synced = []

        def sync(fd):
            real_sync(fd)
            synced.append(os.fstat(fd))

        with patch.object(os, "fsync", side_effect=sync):
            for _ in range(2):
                self.submit()
        directory = self.state / review.QUEUE
        marker = directory / CASE
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for entry, expected in zip(synced, [marker, directory, self.state] * 2, strict=True):
            self.assertTrue(os.path.samestat(entry, expected.stat()))
        for path, mode in ((marker, 0o644), (directory, 0o755)):
            original = stat.S_IMODE(path.stat().st_mode)
            path.chmod(mode)
            try:
                for operation in (self.submit, lambda: review.pending(self.state)):
                    with self.assertRaises(Rejected):
                        operation()
            finally:
                path.chmod(original)

    @unittest.skipUnless(os.name == "posix", "requires POSIX FIFO and symlinks")
    def test_posix_fifo_and_redirected_marker_or_queue_are_rejected(self):
        self.submit()
        directory = self.state / review.QUEUE
        marker = directory / CASE
        target = self.state / "elsewhere"
        marker.rename(target)
        for create in (lambda: os.mkfifo(marker, 0o600), lambda: marker.symlink_to(target)):
            create()
            for operation in (self.submit, lambda: review.pending(self.state)):
                with self.assertRaises(Rejected):
                    operation()
            marker.unlink()
        directory.rmdir()
        directory.symlink_to(self.state, target_is_directory=True)
        for operation in (self.submit, lambda: review.pending(self.state)):
            with self.assertRaises(Rejected):
                operation()
        self.assertEqual(target.read_bytes(), b"")

    def test_directory_sync_error_is_reported_and_complete_marker_can_be_retried(self):
        # Exercise dir_fd on Windows too. Only the directory capability is simulated.
        directory = self.state / review.QUEUE
        directory.mkdir(parents=True, mode=0o700)
        marker = directory / CASE
        directory_fd, state_fd = -326, -327
        real_open, real_sync, real_stat = os.open, os.fsync, os.fstat
        synced = []

        def open_at(name, flags, mode=0o777, *, dir_fd):
            self.assertEqual((name, dir_fd), (CASE, directory_fd))
            return real_open(marker, flags, mode)

        def parent(path, *, create=False):
            fd = directory_fd if path == marker else state_fd
            return contextlib.nullcontext((path.name, {"dir_fd": fd}))

        queue_stat = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=directory.stat().st_uid)

        def fstat(fd):
            return queue_stat if fd == directory_fd else real_stat(fd)

        for failing_fd, expected in (
            (directory_fd, ["file", "directory"]),
            (state_fd, ["file", "directory", "state"]),
        ):
            synced.clear()

            def sync(fd):
                if fd in (directory_fd, state_fd):
                    synced.append("directory" if fd == directory_fd else "state")
                else:
                    real_sync(fd)
                    synced.append("file")
                if fd == failing_fd:
                    raise OSError("directory sync refused")

            with (
                patch.object(review, "_parent", side_effect=parent),
                patch.object(os, "open", side_effect=open_at),
                patch.object(os, "fstat", side_effect=fstat),
                patch.object(os, "fsync", side_effect=sync),
                patch.object(os, "geteuid", return_value=queue_stat.st_uid, create=True),
                self.assertRaises(OSError),
            ):
                review._enqueue(self.state, CASE)
            self.assertEqual(synced, expected)
        self.assertEqual(marker.read_bytes(), b"")
        self.assertEqual(self.submit(), review.pending(self.state)[0])

    def test_controlled_queue_owner_and_mode_must_be_private_before_access(self):
        for uid, mode in ((123, 0o755), (456, 0o700)):
            with (
                patch.object(os, "geteuid", return_value=123, create=True),
                patch.object(os, "fstat", return_value=SimpleNamespace(st_mode=mode, st_uid=uid)),
                self.assertRaisesRegex(Rejected, "manual_review_queue_permissions"),
            ):
                review._private_queue({"dir_fd": -1})

    def test_path_only_capability_syncs_file_and_supports_offline_read(self):
        directory = self.state / review.QUEUE
        directory.mkdir(parents=True, mode=0o700)
        real_sync = os.fsync
        with (
            patch.object(
                review, "_parent", side_effect=lambda path, **_: contextlib.nullcontext((path, {}))
            ),
            patch.object(os, "fsync", wraps=real_sync) as sync,
        ):
            item = self.submit()
            self.assertEqual(review.pending(self.state), [item])
        sync.assert_called_once()

    def test_python_module_entry_lists_without_transport(self):
        out = io.StringIO()
        with (
            patch.object(sys, "argv", ["manual_review", "--state", str(self.state), "list"]),
            contextlib.redirect_stdout(out),
            self.assertRaises(SystemExit) as exit_status,
        ):
            runpy.run_path(review.__file__, run_name="__main__")
        self.assertEqual(exit_status.exception.code, 0)
        self.assertEqual(decode(out.getvalue()), [])
        self.exchange.assert_not_awaited()

    def test_cli_submit_and_offline_list_and_private_errors(self):
        secret = self.state.parent / "token"
        secret.write_text(TOKEN, encoding="ascii")
        secret.chmod(0o600)
        args = [
            "--state",
            str(self.state),
            "submit",
            "--port",
            "8137",
            "--token-file",
            str(secret),
            "--case-sha256",
            CASE,
        ]

        def cli(argv, body=BODY):
            out, err = io.StringIO(), io.StringIO()
            with (
                contextlib.redirect_stdout(out),
                contextlib.redirect_stderr(err),
                patch("sys.stdin", Mock(buffer=io.BytesIO(body))),
            ):
                code = review.main(argv)
            return code, out.getvalue(), err.getvalue()

        code, output, err = cli(args)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(decode(output)["status"], "pending human review")
        self.exchange.reset_mock()
        self.exchange.side_effect = OSError("PRIVATE-CANARY")
        code, listing, err = cli(["--state", str(self.state), "list"])
        self.assertEqual((code, err, decode(listing)), (0, "", [decode(output)]))
        self.exchange.assert_not_awaited()
        for argv in (args, ["--unknown-private-canary"]):
            code, output, err = cli(argv)
            self.assertEqual((code, output, err), (1, "", "manual_review_rejected\n"))
