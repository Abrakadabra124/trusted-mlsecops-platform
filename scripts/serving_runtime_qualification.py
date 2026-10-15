import copy
import importlib.metadata
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch

from mlsecops import serving, serving_runtime
from mlsecops import serving_protocol as protocol
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.serving_runtime import Channel


class BoundedPipeContracts(unittest.TestCase):
    def test_failed_transport_is_disabled_before_process_wait(self):
        process = Mock()
        process.poll.return_value = 0
        channel = Channel(process)
        with self.assertRaisesRegex(Rejected, "serving_transport_failed"):
            channel.exchange({}, timeout=1)
        self.assertTrue(channel.closed)
        process.wait.assert_not_called()
        channel.close()
        process.wait.assert_called_once_with(timeout=3)

    def test_closed_channel_does_not_consume_pending_requests(self):
        channel = serving_runtime.Channel(Mock())
        channel.closed = True
        channel.requests.get = Mock(side_effect=AssertionError("read-after-close"))
        channel.exchange_loop()
        channel.requests.get.assert_not_called()

    def test_alive_io_thread_keeps_cleanup_unconfirmed(self):
        channel = serving_runtime.Channel(Mock())
        channel.reader = Mock(ident=1)
        channel.reader.is_alive.return_value = True
        with self.assertRaisesRegex(Rejected, "^serving_cleanup_unconfirmed$"):
            channel.close()
        channel.reader.is_alive.return_value = False
        channel.close()
        channel.process.stdin.close.assert_called_once()
        channel.process.stdout.close.assert_called_once()

    def test_thread_start_failure_reaps_child_and_closes_pipes(self):
        process = subprocess.Popen(
            [sys.executable, "-c", "import time;time.sleep(30)"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        channel = serving_runtime.Channel(process)
        try:
            with patch.object(
                serving_runtime.threading.Thread,
                "start",
                side_effect=RuntimeError("PRIVATE-CANARY"),
            ):
                with self.assertRaisesRegex(Rejected, "^serving_transport_failed$"):
                    channel.start()
            self.assertIsNotNone(process.poll())
            self.assertTrue(process.stdin.closed)
            self.assertTrue(process.stdout.closed)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
            process.stdin.close()
            process.stdout.close()

    def test_failed_thread_and_failed_kill_retain_channel_for_cleanup_retry(self):
        process = subprocess.Popen(
            [sys.executable, "-c", "import time;time.sleep(30)"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        channel = serving_runtime.Channel(process)
        try:
            with (
                patch.object(
                    serving_runtime.threading.Thread,
                    "start",
                    side_effect=RuntimeError("PRIVATE-START"),
                ),
                patch.object(process, "kill", side_effect=OSError("PRIVATE-CLEANUP")),
            ):
                with self.assertRaisesRegex(Rejected, "^serving_cleanup_unconfirmed$"):
                    channel.start()
            self.assertIsNone(process.poll())
            self.assertTrue(channel.closed)
            channel.close()
            self.assertIsNotNone(process.poll())
            self.assertTrue(process.stdin.closed)
            self.assertTrue(process.stdout.closed)
            with self.assertRaisesRegex(Rejected, "^serving_transport_closed$"):
                channel.start()
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
            process.stdin.close()
            process.stdout.close()

    def process(self, source):
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", source],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        channel = serving_runtime.Channel(process)
        self.addCleanup(channel.close)
        channel.start()
        return process, channel

    def test_real_pipe_echo_is_bounded_and_can_exchange_twice(self):
        process, channel = self.process(
            "import sys\nfor line in sys.stdin.buffer:\n sys.stdout.buffer.write(line);sys.stdout.buffer.flush()"
        )
        for value in ({"n": 1}, {"n": 2}):
            self.assertEqual(channel.exchange(value, timeout=2), value)
        channel.close()
        channel.close()
        self.assertIsNotNone(process.poll())
        with self.assertRaises(Rejected):
            channel.exchange({}, timeout=1)

    def test_hang_partial_and_excessive_output_disable_then_explicitly_reap_process(self):
        sources = (
            "import time;time.sleep(30)",
            "import sys,time;sys.stdout.write('{');sys.stdout.flush();time.sleep(30)",
            f"import sys,time;sys.stdout.write('x'*{protocol.MAX_FRAME + 2});sys.stdout.flush();time.sleep(30)",
            "import sys;sys.stdout.write('PRIVATE-CANARY\\n');sys.stdout.flush()",
            "pass",
        )
        for source in sources:
            with self.subTest(source=source[:30]):
                process, channel = self.process(source)
                started = time.monotonic()
                with self.assertRaisesRegex(Rejected, "^serving_transport_failed$"):
                    channel.exchange({}, timeout=0.3)
                self.assertLess(time.monotonic() - started, 4)
                self.assertTrue(channel.closed)
                channel.close()
                self.assertIsNotNone(process.poll())

    def test_timeout_validation_precedes_pipe_write(self):
        _, channel = self.process("import time;time.sleep(30)")
        for timeout in (0, -1, True, float("nan"), 61):
            with self.subTest(timeout=timeout), self.assertRaises(Rejected):
                channel.exchange({}, timeout=timeout)

    def test_docker_command_has_no_mounts_network_or_credentials(self):
        arguments = serving_runtime.create_arguments("sha256:" + "a" * 64, "b" * 32)
        for flag, value in (
            ("--network", "none"),
            ("--user", "65532:65532"),
            ("--cap-drop", "ALL"),
            ("--memory", "1g"),
            ("--memory-swap", "1g"),
            ("--cpus", "1"),
            ("--pids-limit", "64"),
            ("--security-opt", "no-new-privileges"),
            ("--log-driver", "none"),
        ):
            self.assertEqual(arguments[arguments.index(flag) + 1], value)
        self.assertIn("--read-only", arguments)
        self.assertIn("--rm", arguments)
        self.assertFalse(
            {"--mount", "-v", "--volume", "--env", "-e", "--privileged", "-p"} & set(arguments)
        )

    def test_wrong_resolved_image_is_rejected_before_docker_create(self):
        with (
            patch.object(serving_runtime, "resolve_image", return_value="sha256:" + "b" * 64),
            patch.object(serving_runtime, "command") as command,
        ):
            with self.assertRaisesRegex(Rejected, "serving_image_pin"):
                serving_runtime.Worker(b"model", "sha256:" + "a" * 64)
            command.assert_not_called()


class DockerLifecycleContracts(unittest.TestCase):
    def setUp(self):
        self.image = "sha256:" + "a" * 64
        self.identifier = "b" * 64
        self.exists = True
        self.remove_failure = False
        self.corrupt = False
        self.observed = {
            "Image": self.image,
            "Config": {
                "User": "65532:65532",
                "Labels": {},
                "Cmd": ["python", "-m", "mlsecops.serving_worker"],
                "Entrypoint": None,
            },
            "Mounts": [],
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "Privileged": False,
                "AutoRemove": True,
                "Memory": 1024**3,
                "MemorySwap": 1024**3,
                "NanoCpus": 10**9,
                "PidsLimit": 64,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "LogConfig": {"Type": "none"},
                "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=32m"},
            },
        }
        self.channel = Mock()
        self.channel.exchange.side_effect = self.reply
        for target, values in (
            ("resolve_image", {"return_value": self.image}),
            ("command", {"side_effect": self.command}),
            ("Channel", {"return_value": self.channel}),
        ):
            patcher = patch.object(serving_runtime, target, **values)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(serving_runtime.subprocess, "Popen", return_value=Mock())
        self.process = patcher.start()
        self.addCleanup(patcher.stop)

    def command(self, arguments, timeout):
        if arguments[1] == "create":
            session = arguments[arguments.index("--label") + 1].split("=", 1)[1]
            self.observed["Config"]["Labels"]["org.trusted-mlsecops.session"] = session
            return self.identifier
        if arguments[1] == "inspect":
            return canonical([self.observed]).decode()
        if arguments[1] == "rm":
            self.assertEqual(arguments[-1], self.identifier)
            if self.remove_failure:
                raise Rejected("controlled-remove-failure")
            self.exists = False
            return self.identifier
        self.assertIn(f"id={self.identifier}", arguments)
        return self.identifier if self.exists else ""

    def reply(self, request, timeout):
        extra = {"ready": True}
        if request["action"] == "load":
            extra.update(
                runtime_version=importlib.metadata.version("onnxruntime"),
                scan={
                    "format": "onnx",
                    "policy_version": "linear-onnx-v2",
                    "onnx_version": importlib.metadata.version("onnx"),
                    "inspected_nodes": 2,
                    "unsupported": 0,
                    "skipped": 0,
                    "errors": 0,
                },
            )
        elif request["action"] == "predict":
            extra = {
                "predictions": [
                    {"row_id": f"{request['request_id']}:{index}", "score": 0.5}
                    for index in range(len(request["features"]))
                ]
            }
        result = protocol.response(request, **extra)
        if self.corrupt:
            result["model_sha256"] = "f" * 64
        return result

    def test_constructor_readback_predict_ping_and_idempotent_cleanup(self):
        worker = serving_runtime.Worker(b"controlled", self.image).start()
        self.addCleanup(worker.close)
        self.assertEqual(worker.predict([[0.5] * 6]), [0.5])
        worker.ping()
        worker.close()
        worker.close()
        self.assertFalse(self.exists)
        self.assertEqual(self.process.call_count, 1)
        with self.assertRaises(Rejected):
            worker.ping()

    def test_every_resource_violation_is_rejected_before_process_start(self):
        changes = (
            ("Privileged", True),
            ("ReadonlyRootfs", False),
            ("NetworkMode", "host"),
            ("Memory", 0),
            ("MemorySwap", -1),
            ("NanoCpus", 0),
            ("NanoCpus", 2 * 10**9),
            ("PidsLimit", 0),
            ("AutoRemove", False),
            ("Binds", ["/host:/app"]),
            ("Devices", [{}]),
            ("PortBindings", {"80/tcp": [{}]}),
            ("CapDrop", []),
            ("SecurityOpt", []),
            ("LogConfig", {"Type": "json-file"}),
            ("Tmpfs", {}),
        )
        original = copy.deepcopy(self.observed["HostConfig"])
        for key, value in changes:
            with self.subTest(field=key):
                self.observed["HostConfig"] = {**original, key: value}
                self.exists = True
                with self.assertRaisesRegex(Rejected, "serving_load_failed"):
                    serving_runtime.Worker(b"controlled", self.image).start()
                self.assertFalse(self.exists)
        self.process.assert_not_called()

    def test_worker_ownership_precedes_create_and_start_is_one_shot(self):
        with patch.object(serving_runtime, "command", side_effect=self.command) as command:
            worker = serving_runtime.Worker(b"controlled", self.image)
            command.assert_not_called()
            self.process.assert_not_called()
            self.assertIsNone(worker.channel)
            self.assertIsNone(worker.container)
            self.assertIs(worker.start(), worker)
            with self.assertRaisesRegex(Rejected, "^serving_worker_start_state$"):
                worker.start()
            worker.close()

    def test_invalid_reply_disables_exchange_before_explicit_cleanup_retry(self):
        worker = serving_runtime.Worker(b"controlled", self.image).start()
        self.corrupt = True
        self.remove_failure = True
        with self.assertRaisesRegex(Rejected, "serving_exchange_rejected"):
            worker.ping()
        self.channel.close.assert_not_called()
        self.assertTrue(worker.closed)
        self.assertEqual(worker.container, self.identifier)
        with self.assertRaisesRegex(Rejected, "serving_worker_closed"):
            worker.ping()
        with self.assertRaisesRegex(Rejected, "serving_cleanup_unconfirmed"):
            worker.close()
        self.remove_failure = False
        worker.close()
        self.assertIsNone(worker.container)

    def test_real_channel_failure_reaches_worker_before_process_cleanup(self):
        worker = serving_runtime.Worker(b"controlled", self.image).start()
        process = Mock()
        process.poll.return_value = 0
        worker.channel = Channel(process)
        with self.assertRaisesRegex(Rejected, "serving_exchange_rejected"):
            worker.ping()
        self.assertTrue(worker.closed)
        self.assertTrue(worker.channel.closed)
        process.wait.assert_not_called()
        worker.close()
        process.wait.assert_called_once_with(timeout=3)
        self.assertFalse(self.exists)

    def test_real_worker_exchange_failure_reaches_engine_before_cleanup_finishes(self):
        reader = Mock(image=self.image)
        reader.load.return_value = Mock(
            model=b"controlled", model_sha256=digest(b"controlled"), subject_sha256="a" * 64
        )
        engine = serving.Engine(reader)
        self.addCleanup(engine.close)
        engine.activate()
        self.corrupt = True
        entered, release, returned = (threading.Event() for _ in range(3))
        errors = []

        def cleanup():
            entered.set()
            release.wait(5)

        def predict():
            try:
                engine.predict([[0.5] * 6])
            except Rejected as error:
                errors.append(str(error))
            finally:
                returned.set()

        self.channel.close.side_effect = cleanup
        caller = threading.Thread(target=predict)
        caller.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertTrue(returned.wait(1), "Worker.send still waits for cleanup")
            self.assertEqual(errors, ["serving_prediction_rejected"])
            self.assertIsNone(engine.loaded)
            self.assertIsNone(engine.worker)
        finally:
            release.set()
            caller.join(2)
        engine.drain()
        self.assertFalse(self.exists)

    def test_initial_load_failure_keeps_owned_container_for_cleanup_retry(self):
        worker = serving_runtime.Worker(b"controlled", self.image)
        self.observed["HostConfig"]["Memory"] = 0
        self.remove_failure = True
        with self.assertRaisesRegex(Rejected, "^serving_cleanup_unconfirmed$"):
            worker.start()
        self.assertTrue(worker.closed)
        self.assertEqual(worker.container, self.identifier)
        self.process.assert_not_called()
        self.remove_failure = False
        worker.close()
        self.assertIsNone(worker.container)

    def test_disappearing_container_during_remove_is_confirmed_absent(self):
        worker = serving_runtime.Worker(b"controlled", self.image).start()
        original = self.command

        def raced(arguments, timeout):
            if arguments[1] == "rm":
                self.exists = False
                raise Rejected("already-auto-removed")
            return original(arguments, timeout)

        with patch.object(serving_runtime, "command", side_effect=raced):
            worker.close()
        self.assertIsNone(worker.container)


if __name__ == "__main__":
    unittest.main()
