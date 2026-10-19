import io
import subprocess
import sys
import threading
import unittest
from unittest.mock import Mock, patch

from mlsecops import worker_transport as transport
from mlsecops.contracts import Rejected


class TransportLifecycleContracts(unittest.TestCase):
    def test_cancellation_during_cleanup_attempts_remaining_owned_resources(self):
        for fault in ("kill", "wait", "join", "close", "repeated"):
            process = Mock()
            process.poll.return_value = None
            reader = Mock(ident=1, is_alive=Mock(return_value=False))
            completed = Mock(wait=Mock(return_value=True))
            if fault in ("wait", "repeated"):
                process.wait.side_effect = KeyboardInterrupt("private-wait")
            if fault in ("join", "repeated"):
                reader.join.side_effect = KeyboardInterrupt("private-join")
            if fault == "close":
                process.stdout.close.side_effect = KeyboardInterrupt("private-close")
            with (
                patch.object(transport.os, "name", "posix"),
                patch.object(transport.signal, "SIGKILL", 9, create=True),
                patch.object(
                    transport.os,
                    "killpg",
                    create=True,
                    side_effect=KeyboardInterrupt("private-kill") if fault == "kill" else None,
                ),
            ):
                with self.assertRaises(KeyboardInterrupt) as raised:
                    transport.cleanup(process, [(reader, process.stdout, completed)])
            self.assertEqual(str(raised.exception), "")
            process.wait.assert_called_once_with(timeout=5)
            reader.join.assert_called_once_with(timeout=2)
            process.stderr.close.assert_called_once_with()
            self.assertEqual(
                process.stdout.close.call_count, int(fault not in ("join", "repeated"))
            )

    def test_mixed_reader_completion_closes_only_independent_safe_stream(self):
        for blocked_stream in ("stdout", "stderr"):
            process = Mock()
            entries = [
                (
                    Mock(ident=1, is_alive=Mock(return_value=name == blocked_stream)),
                    getattr(process, name),
                    Mock(wait=Mock(return_value=True)),
                )
                for name in ("stdout", "stderr")
            ]
            with patch.object(transport.os, "killpg", create=True):
                with self.assertRaisesRegex(Rejected, "^worker_cleanup_incomplete$"):
                    transport.cleanup(process, entries)
            for name in ("stdout", "stderr"):
                self.assertEqual(
                    getattr(process, name).close.call_count, int(name != blocked_stream)
                )

    def test_private_failure_then_cleanup_cancellation_has_constant_cli_exit(self):
        process = Mock(stdout=io.BytesIO(b"{}"), stderr=io.BytesIO(b""))
        process.wait.side_effect = KeyboardInterrupt("private-wait")
        with (
            patch("sys.argv", ["transport", "--request-file", "private-file"]),
            patch.object(transport, "enforce_privacy"),
            patch.object(transport.subprocess, "Popen", return_value=process),
            patch.object(transport.os, "killpg", create=True),
            patch.object(transport.time, "monotonic", side_effect=RuntimeError("private-clock")),
            patch("sys.stderr", new_callable=io.StringIO) as diagnostic,
        ):
            self.assertEqual(transport.main(), 130)
        self.assertEqual(diagnostic.getvalue(), "worker_transport_cancelled\n")
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_delayed_bootstrap_cannot_masquerade_as_unstarted_reader(self):
        release = threading.Event()
        bootstrapping = threading.Event()
        original_bootstrap = threading.Thread._bootstrap_inner
        readers = []
        process = Mock(stdout=io.BytesIO(b"{}"), stderr=io.BytesIO(b""))

        def delayed(reader):
            bootstrapping.set()
            release.wait(timeout=10)
            original_bootstrap(reader)

        def uncertain_start(reader):
            readers.append(reader)
            with threading._active_limbo_lock:
                threading._limbo[reader] = reader
            threading._start_new_thread(reader._bootstrap, ())
            if not bootstrapping.wait(timeout=2):
                raise RuntimeError("controlled-bootstrap-not-observed")
            raise KeyboardInterrupt()

        try:
            with (
                patch.object(threading.Thread, "_bootstrap_inner", delayed),
                patch.object(threading.Thread, "start", uncertain_start),
                patch.object(transport.subprocess, "Popen", return_value=process),
                patch.object(transport.os, "killpg", create=True),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    transport.capture(["owned-child"])
                self.assertIsNone(readers[0].ident)
                self.assertFalse(readers[0].is_alive())
                self.assertFalse(process.stdout.closed)
                self.assertTrue(process.stderr.closed)
        finally:
            release.set()
            for reader in readers:
                self.assertTrue(reader._started.wait(timeout=5))
                reader.join(timeout=5)
                self.assertFalse(reader.is_alive())
            process.stdout.close()
            process.stderr.close()

    def test_live_child_reader_fault_and_overflow_are_observed(self):
        for fault in ("read", "overflow"):
            process = Mock(stdout=io.BytesIO(b"x" * 100), stderr=io.BytesIO(b""))
            process.poll.return_value = None
            if fault == "read":
                process.stdout = Mock(read=Mock(side_effect=OSError("private-read")))

            def construct(*, target, args, daemon):
                return Mock(
                    ident=1,
                    is_alive=Mock(return_value=False),
                    start=Mock(side_effect=lambda: target(*args)),
                )

            with (
                patch.object(transport.subprocess, "Popen", return_value=process),
                patch.object(transport.os, "killpg", create=True),
                patch.object(transport.threading, "Thread", side_effect=construct),
                patch.object(transport, "MAX_OUTPUT", 8),
            ):
                with self.assertRaisesRegex(
                    Rejected,
                    "^worker_stream_" + ("incomplete" if fault == "read" else "limit") + "$",
                ):
                    transport.capture(["owned-child"])
            process.wait.assert_called_once_with(timeout=5)

    def test_unwrap_rejects_invalid_typed_envelope(self):
        valid = {
            "schema_version": 1,
            "output": {},
            "diagnostics": {
                "bytes": 0,
                "gpu_discovery_warning": False,
                "raw_output_retained": False,
            },
        }
        for field, value in (("schema_version", True), ("schema_version", 2), ("output", [])):
            with self.assertRaisesRegex(Rejected, "^invalid_worker_transport$"):
                transport.unwrap({**valid, field: value})
        for field, value in (
            ("bytes", -1),
            ("bytes", True),
            ("bytes", transport.MAX_DIAGNOSTIC + 1),
            ("gpu_discovery_warning", 1),
            ("raw_output_retained", True),
        ):
            with self.assertRaisesRegex(Rejected, "^invalid_worker_transport$"):
                transport.unwrap({**valid, "diagnostics": {**valid["diagnostics"], field: value}})

    def test_real_owned_success_and_error_paths(self):
        cases = (
            (
                "import sys; print('{}'); sys.stderr.write('GPU device discovery failed private-canary')",
                None,
                3,
            ),
            ("import sys; sys.exit(7)", "worker_process_failed", 3),
            ("import time; time.sleep(30)", "worker_transport_deadline", 0),
            ("print('x' * 100)", "worker_stream", 3),
            ("import sys; sys.stderr.write('x' * 100)", "worker_stream", 3),
        )
        original = subprocess.Popen
        for script, error, timeout in cases:
            with self.subTest(error=error):
                children = []

                def spawn(*args, **kwargs):
                    process = original(*args, **kwargs)
                    children.append(process)
                    return process

                with (
                    patch.object(transport.subprocess, "Popen", side_effect=spawn),
                    patch.object(transport, "MAX_OUTPUT", 64),
                    patch.object(transport, "MAX_DIAGNOSTIC", 64),
                ):
                    if error is None:
                        result = transport.capture([sys.executable, "-c", script], timeout=timeout)
                        self.assertEqual(
                            transport.unwrap(result),
                            (
                                {},
                                {
                                    "bytes": len(b"GPU device discovery failed private-canary"),
                                    "gpu_discovery_warning": True,
                                    "raw_output_retained": False,
                                },
                            ),
                        )
                        self.assertNotIn("private-canary", str(result))
                    else:
                        with self.assertRaisesRegex(Rejected, error):
                            transport.capture([sys.executable, "-c", script], timeout=timeout)
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll())
                self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)

    def test_cleanup_joins_are_bounded_and_live_reader_prevents_unsafe_pipe_close(self):
        for fault in ("join", "alive", "none"):
            for platform in ("posix", "nt"):
                with self.subTest(fault=fault, platform=platform):
                    process = Mock()
                    process.poll.return_value = 0
                    reader = Mock(ident=1, is_alive=Mock(return_value=fault == "alive"))
                    if fault == "join":
                        reader.join.side_effect = RuntimeError("private-join")
                    with (
                        patch.object(transport.os, "name", platform),
                        patch.object(transport.signal, "SIGKILL", 9, create=True),
                        patch.object(
                            transport.os, "killpg", create=True, side_effect=ProcessLookupError
                        ),
                    ):
                        if fault == "none":
                            transport.cleanup(
                                process,
                                [(reader, process.stdout, Mock(wait=Mock(return_value=True)))],
                            )
                        else:
                            with self.assertRaisesRegex(Rejected, "^worker_cleanup_incomplete$"):
                                transport.cleanup(
                                    process,
                                    [(reader, process.stdout, Mock(wait=Mock(return_value=True)))],
                                )
                    reader.join.assert_called_once_with(timeout=2)
                    self.assertEqual(process.stdout.close.call_count, int(fault == "none"))
                    process.stderr.close.assert_called_once_with()

    def test_cleanup_group_denial_attempts_direct_kill_and_remaining_resources(self):
        process = Mock()
        with (
            patch.object(transport.os, "name", "posix"),
            patch.object(transport.signal, "SIGKILL", 9, create=True),
            patch.object(
                transport.os, "killpg", create=True, side_effect=PermissionError("private-group")
            ),
        ):
            with self.assertRaisesRegex(Rejected, "^worker_cleanup_incomplete$"):
                transport.cleanup(process, [])
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=5)
        process.stdout.close.assert_called_once_with()
        process.stderr.close.assert_called_once_with()

    def test_state_initialization_failure_never_spawns_child(self):
        with (
            patch.object(transport.threading, "Event", side_effect=RuntimeError("private-event")),
            patch.object(transport.subprocess, "Popen") as spawn,
        ):
            with self.assertRaises(RuntimeError):
                transport.capture(["owned-child"])
            spawn.assert_not_called()

    def test_clock_failure_and_cancellation_still_reap_child(self):
        for failure in (RuntimeError("private-clock"), KeyboardInterrupt()):
            process = Mock(stdout=io.BytesIO(b"{}"), stderr=io.BytesIO(b""), returncode=0)
            process.poll.return_value = None
            with (
                patch.object(transport.subprocess, "Popen", return_value=process),
                patch.object(transport.os, "killpg", create=True),
                patch.object(transport.time, "monotonic", side_effect=failure),
            ):
                with self.assertRaises(type(failure)):
                    transport.capture(["owned-child"])
            process.wait.assert_called_once_with(timeout=5)
            self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_cleanup_faults_attempt_remaining_resources_and_never_report_success(self):
        for fault in ("kill", "wait", "close", "all"):
            with self.subTest(fault=fault):
                output = Mock(wraps=io.BytesIO(b"{}"))
                diagnostic = Mock(wraps=io.BytesIO(b""))
                process = Mock(stdout=output, stderr=diagnostic, returncode=0)
                process.poll.return_value = None
                if fault in ("wait", "all"):
                    process.wait.side_effect = subprocess.TimeoutExpired("private", 5)
                if fault in ("close", "all"):
                    output.close.side_effect = OSError("private-close")
                failure = PermissionError("private-kill") if fault in ("kill", "all") else None
                with (
                    patch.object(transport.subprocess, "Popen", return_value=process),
                    patch.object(transport.os, "killpg", create=True, side_effect=failure),
                    patch.object(process, "kill", side_effect=failure),
                    patch.object(
                        transport.time, "monotonic", side_effect=RuntimeError("private-clock")
                    ),
                ):
                    with self.assertRaisesRegex(Rejected, "^worker_cleanup_incomplete$"):
                        transport.capture(["owned-child"])
                process.wait.assert_called_once_with(timeout=5)
                output.close.assert_called_once_with()
                diagnostic.close.assert_called_once_with()

    def test_partial_reader_startup_reaps_child_and_closes_owned_streams(self):
        original_thread, original_start = threading.Thread, threading.Thread.start
        for stage, failed_index in (
            ("construct", 0),
            ("construct", 1),
            ("start", 0),
            ("start", 1),
            ("started", 1),
        ):
            with self.subTest(stage=stage, failed_index=failed_index):
                process = Mock(
                    stdout=io.BytesIO(b'{"ok":true}'), stderr=io.BytesIO(b"private-diagnostic")
                )
                process.poll.return_value = None
                readers = []

                def construct(*args, **kwargs):
                    if stage == "construct" and len(readers) == failed_index:
                        raise RuntimeError("private-thread-start")
                    reader = original_thread(*args, **kwargs)
                    readers.append(reader)
                    return reader

                def start(reader):
                    index = readers.index(reader)
                    if stage == "start" and index == failed_index:
                        raise RuntimeError("private-thread-start")
                    original_start(reader)
                    if stage == "started" and index == failed_index:
                        raise RuntimeError("private-thread-start")

                with (
                    patch.object(transport.subprocess, "Popen", return_value=process),
                    patch.object(transport.threading, "Thread", side_effect=construct),
                    patch.object(original_thread, "start", start),
                    patch.object(transport.os, "killpg", create=True),
                ):
                    with self.assertRaisesRegex(
                        Rejected if stage == "start" else RuntimeError,
                        "worker_cleanup_incomplete" if stage == "start" else "private-thread-start",
                    ):
                        transport.capture(["owned-child"])
                self.assertTrue(process.wait.called)
                self.assertEqual(
                    process.stdout.closed, not (stage == "start" and failed_index == 0)
                )
                self.assertEqual(
                    process.stderr.closed, not (stage == "start" and failed_index == 1)
                )
                self.assertFalse(any(reader.is_alive() for reader in readers))
                process.stdout.close()
                process.stderr.close()

    def test_background_read_failure_does_not_print_private_traceback(self):
        class BrokenStream(io.BytesIO):
            def read(self, size):
                raise OSError("private-reader-canary")

        for broken in ("stdout", "stderr"):
            process = Mock(stdout=io.BytesIO(b'{"ok":true}'), stderr=io.BytesIO(b""), returncode=0)
            setattr(process, broken, BrokenStream())
            process.poll.return_value = 0
            with (
                patch.object(transport.subprocess, "Popen", return_value=process),
                patch.object(transport.os, "killpg", create=True),
                patch.object(threading, "excepthook") as hook,
            ):
                with self.assertRaisesRegex(Rejected, "worker_stream_incomplete"):
                    transport.capture(["owned-child"])
                hook.assert_not_called()
            self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_real_owned_child_does_not_survive_failed_reader_start(self):
        original = subprocess.Popen
        children = []

        def spawn(*args, **kwargs):
            process = original(*args, **kwargs)
            children.append(process)
            return process

        try:
            with (
                patch.object(transport.subprocess, "Popen", side_effect=spawn),
                patch.object(
                    threading.Thread, "start", side_effect=RuntimeError("controlled-start-failure")
                ),
            ):
                with self.assertRaisesRegex(Rejected, "^worker_cleanup_incomplete$"):
                    transport.capture([sys.executable, "-c", "import time; time.sleep(30)"])
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll(), "owned child survived failed startup")
            self.assertFalse(children[0].stdout.closed)
            self.assertTrue(children[0].stderr.closed)
        finally:
            for process in children:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                process.stdout.close()
                process.stderr.close()


if __name__ == "__main__":
    unittest.main()
