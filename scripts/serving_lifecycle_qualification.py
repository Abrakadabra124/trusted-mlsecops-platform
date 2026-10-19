import asyncio
import io
import signal
import subprocess
import sys
import unittest
from contextlib import redirect_stderr
from unittest.mock import Mock, patch

import uvicorn
from uvicorn.lifespan.on import LifespanOn

from mlsecops import serving_http, serving_lifecycle


class ServingLifecycleContracts(unittest.TestCase):
    def test_server_started_state_is_required(self):
        for started in (False, True):
            server = Mock(started=started)
            with patch.object(uvicorn, "Server", return_value=server):
                if started:
                    serving_http.run_server(Mock(), host="127.0.0.1", port=8080)
                else:
                    with self.assertRaisesRegex(Exception, "serving_startup_incomplete"):
                        serving_http.run_server(Mock(), host="127.0.0.1", port=8080)
            server.run.assert_called_once_with()

    def test_server_cancellation_is_not_swallowed_by_convenience_wrapper(self):
        app = serving_http.create_app(Mock(), "a" * 64)

        def interrupt(server, *args, **kwargs):
            server.started = True
            raise KeyboardInterrupt("private-cancel")

        with (
            patch("sys.argv", ["serving", "--config", "private-config"]),
            patch.object(serving_http, "enforce_privacy"),
            patch.object(serving_http, "configured", return_value=app),
            patch.object(uvicorn.Server, "run", interrupt),
            redirect_stderr(io.StringIO()) as diagnostic,
        ):
            self.assertEqual(serving_http.main(), 130)
        self.assertEqual(diagnostic.getvalue(), "serving_configuration_rejected\n")

    def test_real_lifespan_positive_control_and_attribute_forwarding(self):
        engine = Mock()
        app = serving_http.create_app(engine, "a" * 64)

        async def lifecycle():
            driver = LifespanOn(uvicorn.Config(app, lifespan="on", log_config=None))
            await driver.startup()
            await driver.shutdown()
            self.assertFalse(
                driver.error_occurred or driver.startup_failed or driver.shutdown_failed
            )

        with (
            patch("sys.argv", ["serving", "--config", "private-config"]),
            patch.object(serving_http, "enforce_privacy"),
            patch.object(serving_http, "configured", return_value=app),
            patch.object(
                serving_http,
                "run_server",
                side_effect=lambda *args, **kwargs: asyncio.run(lifecycle()),
            ),
        ):
            self.assertEqual(serving_http.main(), 0)
        self.assertIsNotNone(app.state.metrics)
        engine.activate.assert_called_once_with()
        engine.close.assert_called_once_with()

    def test_direct_failure_before_or_after_startup_is_sanitized(self):
        for started in (False, True):

            async def application(scope, receive, send):
                await receive()
                if started:
                    await send({"type": "lifespan.startup.complete"})
                    await receive()
                raise RuntimeError("PRIVATE-LIFECYCLE-CANARY")

            wrapper = serving_lifecycle.Middleware(application)

            async def lifecycle():
                driver = LifespanOn(uvicorn.Config(wrapper, lifespan="on", log_config=None))
                await driver.startup()
                await driver.shutdown()
                self.assertTrue(driver.startup_failed or driver.shutdown_failed)

            with self.assertLogs("uvicorn.error", level="ERROR") as logs:
                asyncio.run(lifecycle())
            self.assertTrue(wrapper.lifecycle_failed)
            self.assertNotIn("PRIVATE-LIFECYCLE-CANARY", "\n".join(logs.output))
            self.assertNotIn("Traceback", "\n".join(logs.output))

    def test_actual_lifespan_logs_are_constant_and_cli_exit_is_nonzero(self):
        for stage in ("activate", "close"):
            with self.subTest(stage=stage):
                engine = Mock()
                getattr(engine, stage).side_effect = RuntimeError("PRIVATE-LIFECYCLE-CANARY")
                app = serving_http.create_app(engine, "a" * 64)

                async def lifecycle():
                    driver = LifespanOn(uvicorn.Config(app, lifespan="on", log_config=None))
                    await driver.startup()
                    await driver.shutdown()
                    self.assertTrue(driver.startup_failed or driver.shutdown_failed)

                with (
                    patch("sys.argv", ["serving", "--config", "private-config"]),
                    patch.object(serving_http, "enforce_privacy"),
                    patch.object(serving_http, "configured", return_value=app),
                    patch.object(
                        serving_http,
                        "run_server",
                        side_effect=lambda *args, **kwargs: asyncio.run(lifecycle()),
                    ),
                    self.assertLogs("uvicorn.error", level="ERROR") as logs,
                    redirect_stderr(io.StringIO()) as diagnostic,
                ):
                    code = serving_http.main()
                self.assertEqual(code, 1)
                self.assertEqual(diagnostic.getvalue(), "serving_configuration_rejected\n")
                self.assertNotIn("PRIVATE-LIFECYCLE-CANARY", "\n".join(logs.output))
                self.assertNotIn("Traceback", "\n".join(logs.output))
                self.assertTrue(all(record.exc_info is None for record in logs.records))
                engine.close.assert_called_once_with()


@unittest.skipUnless(sys.platform == "linux", "native serving SIGINT requires disposable Linux CI")
class NativeServingCancellationContracts(unittest.TestCase):
    def test_owned_cli_sigint_closes_engine_and_returns_nonzero_without_traceback(self):
        import select

        script = """
import socket, sys, uvicorn
from unittest.mock import Mock
from mlsecops import serving_http
with socket.socket() as reservation:
    reservation.bind(('127.0.0.1', 0))
    port = reservation.getsockname()[1]
class OwnedServer(uvicorn.Server):
    async def startup(self, sockets=None):
        await super().startup(sockets=sockets)
        if self.started:
            print('READY', flush=True)
uvicorn.Server = OwnedServer
engine = Mock(close=lambda: print('CLOSED', flush=True))
serving_http.configured = lambda path: serving_http.create_app(engine, 'a' * 64)
sys.argv = ['serving', '--config', 'controlled', '--port', str(port)]
raise SystemExit(serving_http.main())
"""
        process = subprocess.Popen(
            [sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        try:
            ready, _write, _error = select.select([process.stdout], [], [], 15)
            self.assertTrue(ready, "owned_serving_startup_timeout")
            self.assertEqual(process.stdout.readline(), b"READY\n", "owned_serving_startup_failed")
            process.send_signal(signal.SIGINT)
            output, diagnostic = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 130)
            self.assertEqual(output, b"CLOSED\n")
            self.assertEqual(diagnostic, b"serving_configuration_rejected\n")
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()


if __name__ == "__main__":
    unittest.main()
