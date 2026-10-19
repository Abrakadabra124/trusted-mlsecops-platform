import io
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from mlsecops import sandbox, serving_worker, worker
from mlsecops.contracts import Rejected


class WorkerPrivacyContracts(unittest.TestCase):
    def test_guard_import_failure_is_constant_without_mocking_guard_module(self):
        source = """
import builtins, runpy, sys
original = builtins.__import__
seen = False
def controlled(name, *args, **kwargs):
    global seen
    if name == 'ctypes':
        seen = True
        raise ImportError('synthetic-private-library-path')
    return original(name, *args, **kwargs)
builtins.__import__ = controlled
module = sys.argv[1]
sys.argv = ['worker']
sys.platform = 'linux'
try:
    runpy.run_module(module, run_name='__main__')
except SystemExit:
    assert seen, 'privacy_import_probe_not_observed'
    raise
"""
        for module, expected in (
            ("mlsecops.worker", b"worker_rejected\n"),
            ("mlsecops.serving_worker", b"serving_worker_rejected\n"),
        ):
            with self.subTest(module=module):
                result = subprocess.run(
                    [sys.executable, "-c", source, module],
                    input=b"",
                    capture_output=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr.replace(b"\r\n", b"\n"), expected)

    def test_runtime_import_failure_is_constant_in_fresh_cli_process(self):
        source = """
import builtins, runpy, sys, types
sys.modules['mlsecops.process_privacy'] = types.SimpleNamespace(enforce=lambda: None)
original = builtins.__import__
def controlled(name, *args, **kwargs):
    if name == 'mlsecops.model':
        raise ImportError('synthetic-private-runtime-path')
    return original(name, *args, **kwargs)
builtins.__import__ = controlled
module = sys.argv[1]
sys.argv = ['worker']
runpy.run_module(module, run_name='__main__')
"""
        for module, expected in (
            ("mlsecops.worker", b"worker_rejected\n"),
            ("mlsecops.serving_worker", b"serving_worker_rejected\n"),
        ):
            with self.subTest(module=module):
                result = subprocess.run(
                    [sys.executable, "-c", source, module],
                    input=b'{"action":"predict"}',
                    capture_output=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr.replace(b"\r\n", b"\n"), expected)

    def test_guard_failure_prevents_opening_request_file_and_has_no_stdout(self):
        output, diagnostic = Mock(buffer=io.BytesIO()), io.StringIO()
        with (
            patch.object(
                worker, "enforce_privacy", side_effect=Rejected("synthetic-private-policy")
            ),
            patch.object(
                worker.sys, "argv", ["worker", "--request-file", "synthetic-private-path"]
            ),
            patch.object(worker.sys, "stdout", output),
            patch.object(worker.sys, "stderr", diagnostic),
            patch.object(worker.gzip, "open") as opened,
        ):
            self.assertEqual(worker.main(), 1)
        opened.assert_not_called()
        self.assertEqual(output.buffer.getvalue(), b"")
        self.assertEqual(diagnostic.getvalue(), "worker_rejected\n")

    def test_training_docker_argv_disables_core_files_before_start(self):
        with (
            patch.object(sandbox, "resolve_image", return_value="sha256:" + "a" * 64),
            patch.object(
                sandbox.subprocess, "Popen", side_effect=Rejected("controlled-stop")
            ) as spawn,
        ):
            with self.assertRaisesRegex(Rejected, "^controlled-stop$"):
                sandbox.run_worker("sha256:" + "a" * 64, {})
        arguments = spawn.call_args.args[0]
        self.assertEqual(arguments[arguments.index("--ulimit") + 1], "core=0:0")

    def test_serving_guard_precedes_session_and_success_is_preserved(self):
        events = []
        with (
            patch.object(
                serving_worker, "enforce_privacy", side_effect=lambda: events.append("guard")
            ),
            patch.object(
                serving_worker, "serve", side_effect=lambda *args: events.append("serve") or 0
            ),
        ):
            self.assertEqual(serving_worker.main(), 0)
        self.assertEqual(events, ["guard", "serve"])

    def invoke(self, arguments, *, failure=None):
        source = Mock(buffer=Mock(read=Mock(return_value=b'{"action":"predict"}')))
        output = Mock(buffer=io.BytesIO())
        diagnostic = io.StringIO()
        with (
            patch.object(worker, "enforce_privacy", create=True) as guard,
            patch.object(worker.sys, "argv", ["worker", *arguments]),
            patch.object(worker.sys, "stdin", source),
            patch.object(worker.sys, "stdout", output),
            patch.object(worker.sys, "stderr", diagnostic),
            patch.object(
                worker, "execute", side_effect=failure, return_value={"status": "controlled"}
            ) as execute,
        ):
            status = worker.main()
        return status, output.buffer.getvalue(), diagnostic.getvalue(), source, guard, execute

    def test_unknown_and_incomplete_arguments_do_not_echo_private_values(self):
        for arguments in (["--synthetic-private-value"], ["--request-file"]):
            with self.subTest(arguments_count=len(arguments)):
                status, output, diagnostic, source, _, execute = self.invoke(arguments)
                self.assertEqual((status, output, diagnostic), (1, b"", "worker_rejected\n"))
                source.buffer.read.assert_not_called()
                execute.assert_not_called()

    def test_request_file_failure_does_not_disclose_path(self):
        with patch.object(worker.gzip, "open", side_effect=OSError("synthetic-private-path")):
            status, output, diagnostic, _, _, execute = self.invoke(
                ["--request-file", "owned-input.gz"]
            )
        self.assertEqual((status, output, diagnostic), (1, b"", "worker_rejected\n"))
        execute.assert_not_called()

    def test_worker_errors_do_not_disclose_exception_text_or_traceback(self):
        for error in (Rejected("synthetic-private-input"), RuntimeError("synthetic-private-input")):
            with self.subTest(error_type=type(error).__name__):
                status, output, diagnostic, _, _, _ = self.invoke([], failure=error)
                self.assertEqual((status, output, diagnostic), (1, b"", "worker_rejected\n"))

    def test_success_calls_guard_before_reading_input(self):
        events = []
        source = Mock(
            buffer=Mock(read=Mock(side_effect=lambda limit: events.append("read") or b"{}"))
        )
        with (
            patch.object(
                worker, "enforce_privacy", create=True, side_effect=lambda: events.append("guard")
            ),
            patch.object(worker.sys, "argv", ["worker"]),
            patch.object(worker.sys, "stdin", source),
            patch.object(worker.sys, "stdout", Mock(buffer=io.BytesIO())),
            patch.object(worker, "execute", return_value={}),
        ):
            self.assertEqual(worker.main(), 0)
        self.assertEqual(events, ["guard", "read"])

    def test_guard_failure_prevents_payload_reads_and_serving(self):
        for module, reason in (
            (worker, "worker_rejected\n"),
            (serving_worker, "serving_worker_rejected\n"),
        ):
            with self.subTest(module=module.__name__):
                source, diagnostic = Mock(), io.StringIO()
                with (
                    patch.object(
                        module,
                        "enforce_privacy",
                        create=True,
                        side_effect=Rejected("synthetic-private-policy"),
                    ),
                    patch.object(module.sys, "argv", ["worker"]),
                    patch.object(module.sys, "stdin", source),
                    patch.object(module.sys, "stderr", diagnostic),
                    patch.object(serving_worker, "serve", return_value=0) as serve,
                ):
                    self.assertEqual(module.main(), 1)
                source.buffer.read.assert_not_called()
                serve.assert_not_called()
                self.assertEqual(diagnostic.getvalue(), reason)


if __name__ == "__main__":
    unittest.main()
