"""Exercise actual Python subprocess pipes, substituting only the Docker boundary."""

import copy
import gc
import subprocess
import sys
import threading
import traceback
import unittest
import warnings
from unittest.mock import patch

from mlsecops import sandbox
from mlsecops.contracts import Rejected, canonical


class PipeContracts(unittest.TestCase):
    def execute(
        self,
        child,
        expected=None,
        timeout=1,
        *,
        cleanup_error=None,
        cleanup_code=0,
        cleanup_failure=None,
        blocked_input=False,
        exited_before_poll=False,
    ):
        processes, threads = [], []
        spawn = subprocess.Popen
        make_thread = threading.Thread

        def owned_thread(*args, **kwargs):
            thread = make_thread(*args, **kwargs)
            threads.append(thread)
            return thread

        def local_process(arguments, **kwargs):
            self.assertEqual(arguments[:2], ["docker", "run"])
            process = spawn([sys.executable, "-B", "-c", child], **kwargs)
            processes.append(process)
            if exited_before_poll:
                process.wait(timeout=5)
            return process

        with (
            patch.object(sandbox, "resolve_image", return_value="sha256:" + "a" * 64),
            patch.object(sandbox.subprocess, "Popen", side_effect=local_process),
            patch.object(sandbox.threading, "Thread", side_effect=owned_thread),
            patch.object(
                sandbox.subprocess,
                "run",
                side_effect=cleanup_error,
                return_value=subprocess.CompletedProcess([], cleanup_code),
            ) as remove,
            warnings.catch_warnings(record=True) as observed,
        ):
            warnings.simplefilter("always", ResourceWarning)
            try:
                request = {"fixture": "x" * 1024**2 if blocked_input else True}
                caught = None
                try:
                    result, _ = sandbox.run_worker("image", request, timeout=timeout)
                except BaseException as error:
                    caught = error
                self.assertEqual(len(processes), 1)
                process = processes[0]
                self.assertIsNotNone(process.poll(), "owned child remains alive after cleanup")
                self.assertEqual(len(threads), 2)
                self.assertFalse(any(thread.is_alive() for thread in threads))
                self.assertTrue(process.stdin.closed)
                self.assertTrue(process.stdout.closed, "worker stdout remains open after executor")
                remove.assert_called_once()
                if expected:
                    self.assertIsInstance(caught, Rejected)
                    self.assertEqual(str(caught), expected)
                    if cleanup_failure:
                        self.assertEqual(getattr(caught, "__notes__", []), [cleanup_failure])
                        self.assertNotIn("PRIVATE", str(caught.__notes__))
                        rendered = "".join(traceback.format_exception(caught))
                        self.assertIn(cleanup_failure, rendered)
                        self.assertNotIn("PRIVATE", rendered)
                elif cleanup_failure:
                    self.assertIsInstance(caught, Rejected)
                    self.assertEqual(str(caught), cleanup_failure)
                    self.assertIsNone(caught.__cause__)
                else:
                    self.assertIsNone(caught)
                    self.assertEqual(result, request)
                gc.collect()
                self.assertFalse([w for w in observed if issubclass(w.category, ResourceWarning)])
            finally:
                # Baseline failure must not leak the fixture's real OS handles.
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=10)
                for thread in threads:
                    thread.join(timeout=5)
                for process in processes:
                    process.stdin.close()
                    process.stdout.close()

    def test_success_closes_real_buffered_reader_before_return(self):
        self.execute("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())")

    def test_worker_failure_invalid_json_and_timeout_close_real_pipes(self):
        for child, expected in (
            ("import sys; sys.stdin.buffer.read(); sys.exit(1)", "worker_failed"),
            ("import sys; sys.stdin.buffer.read(); print('invalid')", "invalid_json"),
            ("import time; time.sleep(20)", "worker_deadline"),
        ):
            with self.subTest(expected=expected):
                self.execute(child, expected)

    def test_rm_failure_cannot_skip_blocked_child_cleanup_or_mask_deadline(self):
        for error, code, category in (
            (subprocess.TimeoutExpired("PRIVATE-command", 30), 0, "docker_rm_timeout"),
            (OSError("PRIVATE-path"), 0, "docker_rm_unavailable"),
        ):
            with self.subTest(category=category):
                self.execute(
                    "import time; time.sleep(20)",
                    "worker_deadline",
                    blocked_input=True,
                    cleanup_error=error,
                    cleanup_code=code,
                    cleanup_failure="worker_cleanup_failed:" + category,
                )

    def test_normal_rm_also_stops_child_with_blocked_large_input(self):
        self.execute("import time; time.sleep(20)", "worker_deadline", blocked_input=True)

    def test_cleanup_failure_after_success_is_explicit_failure(self):
        for error, code, category in (
            (subprocess.TimeoutExpired("PRIVATE-command", 30), 0, "docker_rm_timeout"),
            (OSError("PRIVATE-path"), 0, "docker_rm_unavailable"),
        ):
            with self.subTest(category=category):
                self.execute(
                    "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",
                    cleanup_error=error,
                    cleanup_code=code,
                    cleanup_failure="worker_cleanup_failed:" + category,
                )

    def test_callers_handled_exception_is_not_the_worker_primary_failure(self):
        try:
            raise Rejected("callers_original_failure")
        except Rejected as caller:
            self.execute(
                "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",
                cleanup_error=OSError("PRIVATE-path"),
                cleanup_failure="worker_cleanup_failed:docker_rm_unavailable",
            )
            self.assertEqual(getattr(caller, "__notes__", []), [])

    def test_best_effort_rm_exit_status_preserves_existing_auto_remove_contract(self):
        # docker run --rm can already have removed its container before this call.
        self.execute("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())", cleanup_code=1)

    def local_failure(self, fault, *, primary=True):
        processes, threads, joins = [], [], []
        spawn, make_thread = subprocess.Popen, threading.Thread
        blocked = fault == "kill-denied"

        def local_process(arguments, **kwargs):
            child = (
                "import time; time.sleep(60)"
                if primary
                else "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"
            )
            process = spawn([sys.executable, "-B", "-c", child], **kwargs)
            kill, wait = process.kill, process.wait
            processes.append((process, kill, wait))

            def stop():
                if blocked:
                    raise OSError("PRIVATE-kill-denied")
                kill()

            def reap(timeout):
                if blocked:
                    # Real wait timeout on the still-running owned child.
                    return wait(timeout=0.05)
                wait(timeout=timeout)
                # Simulate a failed wait API result after the OS child exits.
                if fault == "wait-timeout":
                    raise subprocess.TimeoutExpired("PRIVATE-wait", timeout)
                raise OSError("PRIVATE-wait-error")

            process.kill, process.wait = stop, reap
            return process

        def owned_thread(*args, **kwargs):
            thread = make_thread(*args, **kwargs)
            join = thread.join
            threads.append(thread)
            joins.append(join)
            if blocked:
                # Keep the failure fixture bounded; do not pretend the threads exited.
                thread.join = lambda timeout: join(timeout=min(timeout, 0.05))
            return thread

        codes = {
            "kill-denied": "process_stop_failed,process_wait_timeout,local_cleanup_incomplete",
            "wait-timeout": "process_wait_timeout",
            "wait-oserror": "process_wait_failed",
        }
        note = "worker_cleanup_failed:" + codes[fault]
        with (
            patch.object(sandbox, "resolve_image", return_value="sha256:" + "a" * 64),
            patch.object(sandbox.subprocess, "Popen", side_effect=local_process),
            patch.object(sandbox.threading, "Thread", side_effect=owned_thread),
            patch.object(
                sandbox.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)
            ),
            warnings.catch_warnings(record=True) as observed,
        ):
            warnings.simplefilter("always", ResourceWarning)
            try:
                with self.assertRaises(Rejected) as caught:
                    sandbox.run_worker("image", {"fixture": "x" * 1024**2}, timeout=1)
                self.assertEqual(str(caught.exception), "worker_deadline" if primary else note)
                if primary:
                    self.assertEqual(caught.exception.__notes__, [note])
                rendered = "".join(traceback.format_exception(caught.exception))
                self.assertIn(note, rendered)
                self.assertNotIn("PRIVATE", rendered)
                process = processes[0][0]
                self.assertEqual(len(threads), 2)
                if blocked:
                    self.assertIsNone(process.poll())
                    self.assertTrue(all(t.is_alive() for t in threads))
                    self.assertFalse(process.stdin.closed)
                    self.assertFalse(process.stdout.closed)
                else:
                    self.assertIsNotNone(process.poll())
                    self.assertFalse(any(t.is_alive() for t in threads))
                    self.assertTrue(process.stdin.closed and process.stdout.closed)
            finally:
                # Bypass injected failures to stop every fixture-owned OS process even red.
                for process, kill, wait in processes:
                    if process.poll() is None:
                        kill()
                    wait(timeout=10)
                for join in joins:
                    join(timeout=5)
                for process, _, _ in processes:
                    process.stdin.close()
                    process.stdout.close()
            self.assertFalse(any(t.is_alive() for t in threads))
            self.assertTrue(
                all(
                    p.poll() is not None and p.stdin.closed and p.stdout.closed
                    for p, _, _ in processes
                )
            )
            gc.collect()
            self.assertFalse([w for w in observed if issubclass(w.category, ResourceWarning)])

    def test_kill_denial_preserves_deadline_and_reports_actual_incomplete_cleanup(self):
        self.local_failure("kill-denied")

    def test_wait_timeout_and_oserror_preserve_primary_and_expose_secondary(self):
        for fault in ("wait-timeout", "wait-oserror"):
            with self.subTest(fault=fault):
                self.local_failure(fault)

    def test_wait_failure_after_success_never_returns_worker_success(self):
        for fault in ("wait-timeout", "wait-oserror"):
            with self.subTest(fault=fault):
                self.local_failure(fault, primary=False)

    def test_oversized_output_denies_running_worker_and_cleans_real_pipes(self):
        with patch.object(sandbox, "MAX_PROTOCOL", 1024):
            self.execute(
                "import sys,time; sys.stdin.buffer.read(); "
                "sys.stdout.buffer.write(b'x'*2048); sys.stdout.buffer.flush(); time.sleep(60)",
                "worker_output_limit",
            )

    def test_oversized_output_from_exited_worker_is_incomplete_not_success(self):
        with patch.object(sandbox, "MAX_PROTOCOL", 1024):
            self.execute(
                "import sys; sys.stdout.buffer.write(b'x'*2048)",
                "worker_protocol_incomplete",
                exited_before_poll=True,
            )


class ImageAndProtocolContracts(unittest.TestCase):
    def test_pinned_image_and_source_guards_use_only_inspect_fixture(self):
        original = dict(
            Id="sha256:" + "a" * 64,
            Os="linux",
            Architecture="amd64",
            Config={"Labels": {"org.trusted-mlsecops.source-fingerprint": "b" * 64}},
        )
        with (
            patch.object(
                sandbox, "command", return_value=canonical([original]).decode()
            ) as inspect,
            patch.object(sandbox, "source_fingerprint", return_value="b" * 64),
        ):
            self.assertEqual(sandbox.resolve_image("fixture:tag"), original["Id"])
            inspect.assert_called_once_with(["docker", "image", "inspect", "fixture:tag"])
        for field, value, reason in (
            ("Id", "other:" + "a" * 64, "invalid_image_digest"),
            ("Id", "sha256:" + "a" * 63, "invalid_image_digest"),
            ("Os", "windows", "incompatible_image_profile"),
            ("Architecture", "arm64", "incompatible_image_profile"),
            ("Config", {}, "image_source_fingerprint_mismatch_rebuild_required"),
            ("Config", {"Labels": None}, "image_source_fingerprint_mismatch_rebuild_required"),
            (
                "Config",
                {"Labels": {"org.trusted-mlsecops.source-fingerprint": "c" * 64}},
                "image_source_fingerprint_mismatch_rebuild_required",
            ),
        ):
            document = copy.deepcopy(original)
            document[field] = value
            with (
                self.subTest(field=field, value=value),
                patch.object(sandbox, "command", return_value=canonical([document]).decode()),
                patch.object(sandbox, "source_fingerprint", return_value="b" * 64),
            ):
                with self.assertRaisesRegex(Rejected, "^" + reason + "$"):
                    sandbox.resolve_image("fixture:tag")

    def test_request_limits_reject_before_image_or_process_access(self):
        with (
            patch.object(sandbox, "MAX_PROTOCOL", 32),
            patch.object(sandbox, "resolve_image") as image,
            patch.object(sandbox.subprocess, "Popen") as spawn,
        ):
            for request, timeout in (({}, 0), ({}, 601), ({"fixture": "x" * 33}, 1)):
                with (
                    self.subTest(timeout=timeout),
                    self.assertRaisesRegex(Rejected, "^worker_request_limit$"),
                ):
                    sandbox.run_worker("unused", request, timeout=timeout)
            image.assert_not_called()
            spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
