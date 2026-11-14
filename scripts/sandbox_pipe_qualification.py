"""Exercise actual Python subprocess pipes, substituting only the Docker boundary."""

import gc
import subprocess
import sys
import unittest
import warnings
from unittest.mock import patch

from mlsecops import sandbox
from mlsecops.contracts import Rejected


class PipeContracts(unittest.TestCase):
    def execute(self, child, expected=None, timeout=1):
        processes = []
        spawn = subprocess.Popen

        def local_process(arguments, **kwargs):
            self.assertEqual(arguments[:2], ["docker", "run"])
            process = spawn([sys.executable, "-B", "-c", child], **kwargs)
            processes.append(process)
            return process

        with (
            patch.object(sandbox, "resolve_image", return_value="sha256:" + "a" * 64),
            patch.object(sandbox.subprocess, "Popen", side_effect=local_process),
            patch.object(
                sandbox.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)
            ),
            warnings.catch_warnings(record=True) as observed,
        ):
            warnings.simplefilter("always", ResourceWarning)
            try:
                if expected:
                    with self.assertRaisesRegex(Rejected, expected):
                        sandbox.run_worker("image", {"fixture": True}, timeout=timeout)
                else:
                    result, _ = sandbox.run_worker("image", {"fixture": True}, timeout=timeout)
                    self.assertEqual(result, {"fixture": True})
                self.assertEqual(len(processes), 1)
                process = processes[0]
                self.assertIsNotNone(process.poll())
                self.assertTrue(process.stdin.closed)
                self.assertTrue(process.stdout.closed, "worker stdout remains open after executor")
                gc.collect()
                self.assertFalse([w for w in observed if issubclass(w.category, ResourceWarning)])
            finally:
                # Baseline failure must not leak the fixture's real OS handles.
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=10)
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


if __name__ == "__main__":
    unittest.main()
