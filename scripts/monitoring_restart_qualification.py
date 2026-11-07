"""Cold recovery discloses lost history; old epochs and receipts cannot be replayed."""

import asyncio
import io
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from mlsecops import (
    monitoring_alerts,
    monitoring_cli,
    monitoring_delivery,
    monitoring_runtime,
    monitoring_state,
    signing,
)
from mlsecops.contracts import Rejected, canonical
from scripts import monitoring_runtime_qualification as runtime_fixtures


class RestartContracts(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = runtime_fixtures.RuntimeContracts.asyncSetUp
    cleanup = runtime_fixtures.RuntimeContracts.cleanup

    def guard(self, role="producer", epoch="b" * 32):
        return monitoring_state.Guard(
            str(self.producer.parent / "epochs"), "a" * 64, role, epoch, self.reference_sha256
        )

    def make_runtime(self, guard):
        return monitoring_runtime.Runtime(
            self.reference,
            self.reference_sha256,
            self.label_public,
            self.client,
            interval=0.02,
            epoch_guard=guard,
        )

    async def test_claim_failure_precedes_scheduler_and_valid_start_claims_only_once(self):
        guard = self.guard()
        receipt = {"history_unavailable": False}
        for failure in (Rejected("PRIVATE"), None):
            runtime = self.make_runtime(guard)
            with patch.object(guard, "claim", side_effect=failure, return_value=receipt) as claim:
                if failure:
                    with self.assertRaises(Rejected):
                        runtime.start()
                    self.assertIsNone(runtime.task)
                else:
                    runtime.start()
                    runtime.start()
                    self.assertEqual(runtime.snapshot()["epoch_admission"], receipt)
                claim.assert_called_once()
                await runtime.close()
        for guard in (object(), self.guard("sink"), self.guard(epoch="c" * 32)):
            with self.assertRaises(Rejected):
                self.make_runtime(guard)

    async def test_new_epoch_reports_history_loss_and_delivers_authentic_gap_receipt(self):
        guard = self.guard()
        receipt = {"history_unavailable": True, "previous_epochs": 1, "epoch": "b" * 32}
        runtime = self.make_runtime(guard)
        try:
            with patch.object(guard, "claim", return_value=receipt):
                runtime.start()
            async with asyncio.timeout(5):
                while runtime.snapshot()["alerts_delivered"] < 1:
                    await asyncio.sleep(0.01)
            snapshot = runtime.snapshot()
            self.assertEqual(snapshot["receipts"][0]["kind"], "telemetry_gap")
            self.assertTrue(snapshot["epoch_admission"]["history_unavailable"])
            self.assertFalse(snapshot["history_restored"])
            self.assertEqual(snapshot["data_status"], "insufficient")
            self.assertEqual(snapshot["observations"], 0)
            self.assertLess(snapshot["receipts"][0]["delivery_seconds"], 120)
            self.assertFalse(snapshot["release_ready"])
        finally:
            await runtime.close()

    async def test_sink_requires_admission_and_exposes_only_constant_startup_failure(self):
        guard = self.guard("sink")
        for failure in (Rejected("PRIVATE"), None):
            app = monitoring_delivery.App(self.sink, epoch_guard=guard)
            send, receive = AsyncMock(), AsyncMock()
            await app({"type": "http"}, receive, send)
            receive.assert_not_called()
            self.assertEqual(send.call_args_list[0].args[0]["status"], 400)
            send.reset_mock()
            receive.side_effect = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
            with patch.object(guard, "claim", side_effect=failure, return_value={}):
                await app({"type": "lifespan"}, receive, send)
            self.assertEqual(app.startup_failed, failure is not None)
            self.assertEqual(
                send.call_args_list[0].args[0]["type"],
                "lifespan.startup.failed" if failure else "lifespan.startup.complete",
            )
            self.assertNotIn("PRIVATE", str(send.call_args_list))
        for guard in (object(), self.guard(), self.guard("sink", "c" * 32)):
            with self.assertRaises(Rejected):
                monitoring_delivery.App(self.sink, epoch_guard=guard)

    async def test_cli_startup_rejection_cannot_return_success(self):
        with (
            patch.object(monitoring_cli, "enforce_privacy"),
            patch.object(sys, "argv", ["sink", "--config", "PRIVATE"]),
            patch.object(
                monitoring_cli.monitoring_config,
                "sink",
                return_value=(SimpleNamespace(startup_failed=True), 8910),
            ),
            patch.object(monitoring_cli, "run_server"),
            patch.object(sys, "stderr", io.StringIO()) as error,
        ):
            self.assertEqual(monitoring_cli.main(), 1)
            self.assertEqual(error.getvalue(), "monitoring_sink_rejected\n")
        for code in (0, 3):
            with (
                patch.object(monitoring_cli, "enforce_privacy"),
                patch.object(sys, "argv", ["sink", "--config", "PRIVATE"]),
                patch.object(
                    monitoring_cli.monitoring_config, "sink", return_value=(object(), 8910)
                ),
                patch.object(monitoring_cli, "run_server", side_effect=SystemExit(code)),
                patch.object(sys, "stderr", io.StringIO()) as error,
            ):
                self.assertEqual(monitoring_cli.main(), 1)
                self.assertEqual(error.getvalue(), "monitoring_sink_rejected\n")


@unittest.skipUnless(sys.platform == "linux", "native crash/restart uses private Linux CLI")
class NativeRestartContracts(unittest.TestCase):
    def test_sink_process_crash_consumes_epoch_and_new_epoch_rejects_old_event(self):
        with tempfile.TemporaryDirectory(prefix="PRIVATE-restart-") as temporary:
            root = Path(temporary)
            producer, sink_key = root / "producer.pem", root / "sink.pem"
            producer_public, sink_public = (
                signing.create_key(producer),
                signing.create_key(sink_key),
            )
            state_directory = str(root / "epochs")
            pin = monitoring_state.initialize(state_directory)
            with socket.socket() as allocation:
                allocation.bind(("127.0.0.1", 0))
                port = allocation.getsockname()[1]
            config = {
                "schema_version": 1,
                "reference_sha256": "a" * 64,
                "producer_public": producer_public,
                "receipt_key_file": str(sink_key),
                "port": port,
                "epoch": "b" * 32,
                "state_directory": state_directory,
                "state_sha256": pin,
            }
            path = root / "sink.json"
            command = [sys.executable, "-m", "mlsecops.monitoring_cli", "--config", str(path)]

            def start():
                path.write_bytes(canonical(config))
                child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        self.assertIsNone(child.poll(), "owned sink stopped before readiness")
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                                return child
                        except OSError:
                            if time.monotonic() >= deadline:
                                self.fail("owned sink readiness timeout")
                            time.sleep(0.02)
                except BaseException:
                    child.kill()
                    child.communicate(timeout=3)
                    raise

            def deliver(epoch):
                client = monitoring_delivery.Client(
                    producer, sink_public, port=port, reference_sha256="a" * 64, epoch=epoch
                )
                event = monitoring_alerts.event(
                    reference_sha256="a" * 64,
                    window_sha256="c" * 64,
                    evidence_sha256="d" * 64,
                    epoch=epoch,
                    sequence=1,
                    kind="telemetry_gap",
                    admitted_at_ms=time.time_ns() // 1000000,
                )
                return client, event, asyncio.run(client.send(event))

            child = start()
            try:
                old_client, old_event, _ = deliver("b" * 32)
            finally:
                child.kill()
                child.communicate(timeout=3)
            self.assertEqual(child.returncode, -signal.SIGKILL)
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", port), timeout=0.1)
            denied = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(denied.returncode, 1)
            self.assertEqual(denied.stdout, b"")
            self.assertNotIn(b"PRIVATE", denied.stderr)
            self.assertIn(b"monitoring_sink_rejected", denied.stderr)
            config["epoch"] = "e" * 32
            child = start()
            try:
                with self.assertRaises(Rejected):
                    asyncio.run(old_client.send(old_event))
                client, event, acknowledgement = deliver("e" * 32)
                self.assertEqual(asyncio.run(client.send(event)), acknowledgement)
                self.assertEqual(
                    monitoring_alerts.receipt(acknowledgement, event, sink_public)["sequence"], 1
                )
            finally:
                if child.poll() is None:
                    child.send_signal(signal.SIGINT)
                try:
                    child.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.communicate(timeout=3)
                    self.fail("owned replacement required forced termination")
            self.assertEqual(child.returncode, 130)
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", port), timeout=0.1)


if __name__ == "__main__":
    unittest.main()
