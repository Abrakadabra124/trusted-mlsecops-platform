"""Private CLI failures, plus real disposable Linux sink process delivery."""

import asyncio
import io
import os
import runpy
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from mlsecops import monitoring_alerts, monitoring_cli, monitoring_delivery, signing
from mlsecops.contracts import canonical


class CliContracts(unittest.TestCase):
    def test_module_entrypoint_uses_same_private_main(self):
        with (
            patch.object(sys, "argv", ["sink", "--config", "/private/sink.json"]),
            patch("mlsecops.process_privacy.enforce"),
            patch("mlsecops.monitoring_config.sink", return_value=(object(), 8910)),
            patch("mlsecops.serving_http.run_server"),
            self.assertRaises(SystemExit) as stopped,
        ):
            runpy.run_path(monitoring_cli.__file__, run_name="__main__")
        self.assertEqual(stopped.exception.code, 0)

    def test_explicit_config_and_loopback_only_options(self):
        app = object()
        with (
            patch.object(sys, "argv", ["monitoring-sink", "--config", "/private/config.json"]),
            patch.object(monitoring_cli, "enforce_privacy") as privacy,
            patch.object(
                monitoring_cli.monitoring_config, "sink", return_value=(app, 8910)
            ) as configure,
            patch.object(monitoring_cli, "run_server") as run,
        ):
            self.assertEqual(monitoring_cli.main(), 0)
            privacy.assert_called_once()
            configure.assert_called_once_with("/private/config.json")
            self.assertIs(run.call_args.args[0], app)
            self.assertEqual(run.call_args.kwargs["host"], "127.0.0.1")
            self.assertFalse(run.call_args.kwargs["access_log"])
            self.assertFalse(run.call_args.kwargs["proxy_headers"])

    def test_errors_are_constant_and_privacy_failure_precedes_config_loading(self):
        for failure, expected in (
            (RuntimeError("PRIVATE-CLI-CANARY"), 1),
            (KeyboardInterrupt(), 130),
        ):
            output = io.StringIO()
            with (
                patch.object(monitoring_cli, "enforce_privacy", side_effect=failure),
                patch.object(monitoring_cli.monitoring_config, "sink") as configure,
                redirect_stderr(output),
            ):
                self.assertEqual(monitoring_cli.main(), expected)
                configure.assert_not_called()
            self.assertEqual(output.getvalue(), "monitoring_sink_rejected\n")
        with (
            patch.object(monitoring_cli, "enforce_privacy"),
            patch.object(sys, "argv", ["sink", "--unrecognized-secret"]),
            redirect_stderr(io.StringIO()) as output,
        ):
            self.assertEqual(monitoring_cli.main(), 1)
        self.assertNotIn("unrecognized-secret", output.getvalue())

    @unittest.skipUnless(sys.platform == "linux", "native private CLI requires owned Linux CI")
    def test_native_cli_signed_receipt_and_verified_shutdown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            producer, sink_key = root / "producer.pem", root / "sink.pem"
            producer_public, sink_public = (
                signing.create_key(producer),
                signing.create_key(sink_key),
            )
            with socket.socket() as allocation:
                allocation.bind(("127.0.0.1", 0))
                port = allocation.getsockname()[1]
            path = root / "sink.json"
            path.write_bytes(
                canonical(
                    {
                        "schema_version": 1,
                        "reference_sha256": "a" * 64,
                        "producer_public": producer_public,
                        "receipt_key_file": str(sink_key),
                        "port": port,
                        "epoch": "b" * 32,
                    }
                )
            )
            process = subprocess.Popen(
                [sys.executable, "-m", "mlsecops.monitoring_cli", "--config", str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "PYTHONUTF8": "1"},
            )
            try:
                deadline = time.monotonic() + 10
                while True:
                    self.assertIsNone(process.poll(), "owned sink exited before listening")
                    try:
                        connection = socket.create_connection(("127.0.0.1", port), timeout=0.1)
                        connection.close()
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            self.fail("owned sink startup timeout")
                        time.sleep(0.02)
                client = monitoring_delivery.Client(
                    producer, sink_public, port=port, reference_sha256="a" * 64, epoch="b" * 32
                )
                event = monitoring_alerts.event(
                    reference_sha256="a" * 64,
                    window_sha256="c" * 64,
                    evidence_sha256="d" * 64,
                    epoch="b" * 32,
                    sequence=1,
                    kind="data_drift",
                    admitted_at_ms=time.time_ns() // 1000000,
                )
                acknowledgement = asyncio.run(client.send(event))
                self.assertEqual(
                    monitoring_alerts.receipt(acknowledgement, event, sink_public)["sequence"], 1
                )
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
                try:
                    output, error = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=3)
                    self.fail("owned sink required forced termination")
            self.assertEqual(process.returncode, 130)
            self.assertEqual(output, b"")
            self.assertEqual(error, b"monitoring_sink_rejected\n")
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", port), timeout=0.1)


if __name__ == "__main__":
    unittest.main()
