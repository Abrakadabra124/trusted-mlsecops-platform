"""Exercise actual Python subprocess pipes, substituting only the Docker boundary."""

import gc
import subprocess
import sys
import threading
import traceback
import unittest
import warnings
from unittest.mock import patch

from mlsecops import sandbox
from mlsecops.contracts import Rejected


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


if __name__ == "__main__":
    unittest.main()
