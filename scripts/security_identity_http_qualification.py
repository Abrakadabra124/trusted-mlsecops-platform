"""Identity source admission, cancellation and owned process cleanup."""

import asyncio
import inspect
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from mlsecops import security_identity_http as source
from mlsecops import serving_http
from mlsecops.contracts import Rejected, canonical, decode


class IntegrationBoundary(unittest.TestCase):
    def test_http_app_accepts_explicit_identity_audit_source(self):
        self.assertIn("identity_audit", inspect.signature(serving_http.create_app).parameters)

    def test_native_guard_precedes_host_resources(self):
        from scripts import security_identity_events_native as native

        with (
            patch.object(native.sys, "platform", "win32"),
            patch.object(native.security_event_audit_fixture, "live") as resources,
        ):
            with self.assertRaisesRegex(Rejected, "identity_source_hosted_required"):
                native.qualify()
            resources.assert_not_called()

    def test_native_interruption_requires_lifespan_cleanup(self):
        from scripts import security_identity_events_native as native

        for closed, failed, expected in (
            (True, False, None),
            (False, False, "identity_fixture_cleanup_unconfirmed"),
            (True, True, "identity_fixture_lifecycle_failed"),
        ):
            with self.subTest(closed=closed, failed=failed):
                identity = Mock(closed=closed, child=None, pending=None, ticker=None)
                app = Mock(lifecycle_failed=failed)
                with (
                    patch.object(native, "hosted"),
                    patch.object(native, "enforce"),
                    patch.object(
                        native,
                        "bounded_read",
                        side_effect=[
                            canonical(
                                dict(
                                    identity_file="identity",
                                    token_file="token",
                                    operator_file="operator",
                                )
                            ),
                            b"a" * 64,
                            b"b" * 64,
                        ],
                    ),
                    patch.object(
                        native.security_identity_http, "configured", return_value=identity
                    ),
                    patch.object(native.serving_http, "create_app", return_value=app),
                    patch.object(native.serving_http, "run_server", side_effect=KeyboardInterrupt),
                    redirect_stdout(io.StringIO()) as output,
                ):
                    try:
                        if expected is None:
                            native.serve("private-config", 8080)
                        else:
                            with self.assertRaisesRegex(Rejected, expected):
                                native.serve("private-config", 8080)
                    except KeyboardInterrupt:
                        self.fail(
                            "fixture failed to validate cleanup after Uvicorn reraised SIGINT"
                        )
                    self.assertEqual(
                        output.getvalue(), "identity_fixture_cleanup_pass\n" if closed else ""
                    )

    def test_actual_uvicorn_startup_refusal_is_normalized_after_cleanup(self):
        from scripts import security_identity_events_native as native

        identity = source.Observer.__new__(source.Observer)
        identity.closed, identity.child, identity.pending = False, None, None
        identity.ticker = None
        identity.start = AsyncMock(side_effect=Rejected("controlled_probe_failure"))
        identity.close = AsyncMock(side_effect=lambda: setattr(identity, "closed", True))
        with (
            patch.object(native, "hosted"),
            patch.object(native, "enforce"),
            patch.object(
                native,
                "bounded_read",
                side_effect=[
                    canonical(
                        dict(identity_file="identity", token_file="token", operator_file="operator")
                    ),
                    b"a" * 64,
                    b"b" * 64,
                ],
            ),
            patch.object(native.security_identity_http, "configured", return_value=identity),
            redirect_stdout(io.StringIO()) as output,
        ):
            try:
                with self.assertRaisesRegex(Rejected, "identity_fixture_startup_failed"):
                    native.serve("private-config", 0)
            except SystemExit as failure:
                self.fail(f"unhandled pinned Uvicorn startup exit: {failure.code}")
            identity.close.assert_awaited_once()
            self.assertEqual(output.getvalue(), "identity_fixture_cleanup_pass\n")


class Process:
    def __init__(self, code=0, *, ignore_terminate=False, ignore_kill=False):
        self.returncode = code
        self.ignore_terminate, self.ignore_kill = ignore_terminate, ignore_kill
        self.terminated = self.killed = 0
        self.exit = asyncio.Event()

    async def wait(self):
        if self.returncode is None:
            await self.exit.wait()
        return self.returncode

    def terminate(self):
        self.terminated += 1
        if not self.ignore_terminate:
            self.returncode = -15
            self.exit.set()

    def kill(self):
        self.killed += 1
        if not self.ignore_kill:
            self.returncode = -9
            self.exit.set()


class OwnedChild(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        path = self.root / "identity.json"
        path.write_bytes(
            canonical(
                dict(
                    schema_version=1,
                    producer_config=str(self.root / "producer.json"),
                    service_sha256="a" * 64,
                )
            )
        )
        self.observer = source.configured(str(path))
        self.spawn = AsyncMock(return_value=Process())
        self.real_spawn = source.asyncio.create_subprocess_exec
        patcher = patch.object(source.asyncio, "create_subprocess_exec", self.spawn)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addAsyncCleanup(self.observer.close)

    async def test_start_probe_and_report_use_one_pinned_child_without_output_or_input(self):
        with self.assertRaises(Rejected):
            await self.observer.report("b" * 32, "credential")
        await self.observer.start()
        await self.observer.report("b" * 32, "credential")
        arguments, options = self.spawn.call_args
        self.assertEqual(
            options,
            dict(
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                cwd=Path(source.__file__).resolve().parents[1],
            ),
        )
        self.assertIn(self.observer.pin, arguments)
        self.assertIn("credential", arguments)
        self.assertIn("b" * 32, arguments)
        self.assertIsNone(self.observer.child)
        self.assertIsNone(self.observer.pending)
        with self.assertRaises(Rejected):
            await self.observer.start()
        for reason, correlation in (("raw", "b" * 32), ("role", "bad")):
            with self.assertRaises(Rejected):
                await self.observer.report(correlation, reason)
        await self.observer.close()
        with self.assertRaises(Rejected):
            await self.observer.report("b" * 32, "credential")

    async def test_spawn_failure_and_nonzero_exit_are_private_unavailable(self):
        for effect in (OSError("PRIVATE-CANARY"), None):
            self.spawn.side_effect = effect
            self.spawn.return_value = Process(1)
            with self.assertRaisesRegex(Rejected, "^identity_security_unavailable$"):
                await self.observer.start()
            self.assertIsNone(self.observer.child)
            self.assertIsNone(self.observer.pending)

    async def test_busy_source_does_not_spawn_or_queue_more_work(self):
        await self.observer.start()
        process = Process(None)
        self.spawn.return_value = process
        task = asyncio.create_task(self.observer.report("b" * 32, "credential"))
        while self.observer.child is None:
            await asyncio.sleep(0)
        before = self.spawn.call_count
        with self.assertRaisesRegex(Rejected, "identity_security_busy"):
            await self.observer.report("c" * 32, "role")
        self.assertEqual(self.spawn.call_count, before)
        process.returncode = 0
        process.exit.set()
        await task

    async def test_child_deadline_terminates_and_reaps_with_kill_fallback(self):
        await self.observer.start()
        process = Process(None, ignore_terminate=True)
        self.spawn.return_value = process
        with (
            patch.object(source, "CHILD_SECONDS", 0.01),
            patch.object(source, "STOP_SECONDS", 0.01),
        ):
            with self.assertRaisesRegex(Rejected, "identity_security_unavailable"):
                await self.observer.report("b" * 32, "credential")
        self.assertEqual((process.terminated, process.killed, process.returncode), (1, 1, -9))
        self.assertIsNone(self.observer.child)

    async def test_real_owned_python_process_is_reaped_on_deadline(self):
        await self.observer.start()
        children = []

        async def spawn(*arguments, **options):
            process = await self.real_spawn(
                sys.executable, "-c", "import time; time.sleep(60)", **options
            )
            children.append(process)
            return process

        self.spawn.side_effect = spawn
        with patch.object(source, "CHILD_SECONDS", 0.02):
            with self.assertRaisesRegex(Rejected, "identity_security_unavailable"):
                await self.observer.report("b" * 32, "credential")
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertIsNone(self.observer.child)

    async def test_cancelled_waiter_retains_child_until_close(self):
        await self.observer.start()
        process = Process(None)
        self.spawn.return_value = process
        waiter = asyncio.create_task(self.observer.report("b" * 32, "credential"))
        while self.observer.child is None:
            await asyncio.sleep(0)
        waiter.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await waiter
        self.assertIsNotNone(self.observer.pending)
        await self.observer.close()
        self.assertIsNone(self.observer.child)
        self.assertEqual(process.returncode, -15)

    async def test_concurrent_close_during_spawn_keeps_ownership_and_reaps(self):
        await self.observer.start()
        release, entered = asyncio.Event(), asyncio.Event()
        process = Process(None)

        async def spawn(*args, **kwargs):
            entered.set()
            await release.wait()
            return process

        self.spawn.side_effect = spawn
        waiter = asyncio.create_task(self.observer.report("b" * 32, "credential"))
        await entered.wait()
        first = asyncio.create_task(self.observer.close())
        await asyncio.sleep(0)
        second = asyncio.create_task(self.observer.close())
        release.set()
        await asyncio.gather(first, second)
        with self.assertRaises(asyncio.CancelledError):
            await waiter
        self.assertIsNone(self.observer.child)
        self.assertEqual(process.returncode, -15)

    async def test_outer_deadline_does_not_forget_pending_operation(self):
        await self.observer.start()
        process = Process(None)
        self.spawn.return_value = process
        with patch.object(source, "WAIT_SECONDS", 0.01):
            with self.assertRaisesRegex(Rejected, "identity_security_unavailable"):
                await self.observer.report("b" * 32, "credential")
        self.assertIsNotNone(self.observer.pending)
        await self.observer.close()
        self.assertIsNone(self.observer.child)

    async def test_unconfirmed_reap_and_foreign_loop_cannot_claim_cleanup(self):
        process = Process(None, ignore_terminate=True, ignore_kill=True)
        with patch.object(source, "STOP_SECONDS", 0.01):
            with self.assertRaises(TimeoutError):
                await source.stop(process)
        process.returncode = 0
        process.exit.set()
        other = object()
        self.observer.loop = other
        with self.assertRaisesRegex(Rejected, "identity_security_lifecycle"):
            await self.observer.close()
        self.observer.loop = None

    async def test_invalid_wait_result_is_not_reaped_and_retained_child_is_closed(self):
        process = Process(None, ignore_terminate=True)
        process.wait = AsyncMock(return_value=None)
        with self.assertRaisesRegex(Rejected, "cleanup_unconfirmed"):
            await source.stop(process)
        process = Process(None)
        self.observer.child = process
        await self.observer.close()
        self.assertEqual(process.returncode, -15)
        self.assertIsNone(self.observer.child)

    async def test_delayed_spawn_cleanup_timeout_remains_owned_for_later_reap(self):
        await self.observer.start()
        entered, release = asyncio.Event(), asyncio.Event()
        process = Process(None)

        async def spawn(*args, **kwargs):
            entered.set()
            await release.wait()
            return process

        self.spawn.side_effect = spawn
        waiter = asyncio.create_task(self.observer.report("b" * 32, "credential"))
        await entered.wait()
        with patch.object(source, "WAIT_SECONDS", 0.01):
            with self.assertRaisesRegex(Rejected, "cleanup_unconfirmed"):
                await self.observer.close()
        self.assertIsNotNone(self.observer.pending)
        release.set()
        await self.observer.close()
        with self.assertRaises(asyncio.CancelledError):
            await waiter
        self.assertEqual(process.returncode, -15)

    async def test_stale_completion_callback_does_not_clear_another_operation(self):
        other = object()
        self.observer.pending = other
        done = asyncio.get_running_loop().create_future()
        done.set_result(None)
        self.observer.finished(done)
        self.assertIs(self.observer.pending, other)
        self.observer.pending = None

    async def test_periodic_heartbeat_fault_recovers_and_stops_with_owner(self):
        await self.observer.start()
        self.assertIsNotNone(self.observer.ticker)
        initial = self.observer.last_success
        with (
            patch.object(source, "TICK_SECONDS", 0.001),
            patch.object(source, "HEARTBEAT_SECONDS", 0),
        ):
            self.spawn.return_value = Process(1)
            # Wake the initially sleeping scheduler without cancelling its owner.
            self.observer.ticker.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await self.observer.ticker
            self.observer.ticker = asyncio.create_task(self.observer.heartbeat_loop())
            async with asyncio.timeout(1):
                while not self.observer.tick_fault:
                    await asyncio.sleep(0.002)
            self.assertEqual(self.observer.last_success, initial)
            self.spawn.return_value = Process()
            async with asyncio.timeout(1):
                while self.observer.tick_fault:
                    await asyncio.sleep(0.002)
            self.assertGreater(self.observer.last_success, initial)
            self.assertIn("heartbeat", self.spawn.call_args.args)
        await self.observer.close()
        before = self.spawn.call_count
        await asyncio.sleep(0.01)
        self.assertIsNone(self.observer.ticker)
        self.assertEqual(self.spawn.call_count, before)

    async def test_scheduler_is_idle_before_due_and_never_queues_behind_busy_child(self):
        with patch.object(source, "TICK_SECONDS", 0.001):
            await self.observer.start()
            await asyncio.sleep(0.01)
            self.assertEqual(self.spawn.call_count, 1)
            self.spawn.return_value = Process(None)
            operation = asyncio.create_task(self.observer.report("b" * 32, "credential"))
            while self.observer.child is None:
                await asyncio.sleep(0)
            with patch.object(source, "HEARTBEAT_SECONDS", 0):
                await asyncio.sleep(0.01)
                self.assertEqual(self.spawn.call_count, 2)
            await self.observer.close()
            with self.assertRaises(asyncio.CancelledError):
                await operation

    async def test_scheduler_spawn_failure_closes_coroutine_and_keeps_cleanup_available(self):
        real = source.asyncio.create_task

        def create(coroutine, **options):
            if options.get("name") == "mlsecops-identity-heartbeat":
                raise RuntimeError("controlled_task_failure")
            return real(coroutine, **options)

        with patch.object(source.asyncio, "create_task", side_effect=create):
            with self.assertRaisesRegex(RuntimeError, "controlled_task_failure"):
                await self.observer.start()
        await self.observer.close()
        self.assertIsNone(self.observer.ticker)
        self.assertIsNone(self.observer.child)

    async def test_cancelled_close_retains_slow_scheduler_but_still_reaps_owned_child(self):
        entered, cancelled, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def slow_scheduler():
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                await release.wait()

        task = asyncio.create_task(slow_scheduler())
        self.observer.ticker = task
        child = Process(None)
        self.observer.child = child
        await entered.wait()
        closer = asyncio.create_task(self.observer.close())
        try:
            await cancelled.wait()
            closer.cancel()
            with self.assertRaisesRegex(Rejected, "scheduler_cleanup_unconfirmed"):
                await closer
            self.assertIs(self.observer.ticker, task)
            self.assertEqual(child.returncode, -15)
        finally:
            release.set()
            await task
            await self.observer.close()
        self.assertIsNone(self.observer.ticker)


class HttpIdentity(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.identity = source.Observer.__new__(source.Observer)
        self.identity.start = AsyncMock()
        self.identity.close = AsyncMock()
        self.identity.report = AsyncMock()
        self.engine = Mock()
        self.app = serving_http.create_app(
            self.engine, "a" * 64, metrics_token="b" * 64, identity_audit=self.identity
        )

    async def invoke(self, path="/v1/predict", headers=()):
        outgoing, reads = [], []

        async def receive():
            reads.append(True)
            return dict(type="http.request", body=b"PRIVATE-CANARY", more_body=False)

        async def send(message):
            outgoing.append(message)

        await self.app(
            dict(
                type="http",
                asgi={"version": "3.0"},
                http_version="1.1",
                method="POST" if path == "/v1/predict" else "GET",
                scheme="http",
                path=path,
                raw_path=path.encode(),
                query_string=b"",
                headers=list(headers),
                client=("127.0.0.1", 12345),
                server=("127.0.0.1", 8080),
            ),
            receive,
            send,
        )
        status = next(
            message["status"] for message in outgoing if message["type"] == "http.response.start"
        )
        body = b"".join(message.get("body", b"") for message in outgoing)
        return status, body, reads

    async def test_real_auth_paths_emit_only_finite_decision_without_body_or_model_access(self):
        for path in ("/readyz", "/v1/predict", "/metrics"):
            for headers in (
                [],
                [(b"authorization", b"Bearer PRIVATE-CANARY")],
                [(b"authorization", b"Bearer " + b"a" * 64)] * 2,
            ):
                self.identity.report.reset_mock()
                status, content, reads = await self.invoke(path, headers)
                value = decode(content)
                self.assertEqual((status, reads), (401, []))
                self.identity.report.assert_awaited_once_with(value["request_id"], "credential")
                self.assertNotIn(b"PRIVATE-CANARY", content)
        self.engine.response_budget.assert_not_called()
        self.engine.predict_result.assert_not_called()

    async def test_known_credential_wrong_role_is_private_and_valid_operator_needs_no_child(self):
        for path, token in (("/readyz", "b"), ("/v1/predict", "b"), ("/metrics", "a")):
            self.identity.report.reset_mock()
            status, content, reads = await self.invoke(
                path, [(b"authorization", ("Bearer " + token * 64).encode())]
            )
            self.assertEqual((status, reads), (401, []))
            self.identity.report.assert_awaited_once_with(decode(content)["request_id"], "role")
            self.assertNotIn(token.encode() * 64, content)
        self.identity.report.reset_mock()
        self.assertEqual(
            (await self.invoke("/metrics", [(b"authorization", b"Bearer " + b"b" * 64)]))[0], 200
        )
        self.identity.report.assert_not_awaited()

    async def test_unconfirmed_audit_returns_private_503_and_still_never_reads_body(self):
        self.identity.report.side_effect = Rejected("PRIVATE-CANARY")
        for path in ("/readyz", "/v1/predict", "/metrics"):
            status, content, reads = await self.invoke(path)
            self.assertEqual((status, reads), (503, []))
            self.assertNotIn(b"PRIVATE-CANARY", content)
        self.engine.response_budget.assert_not_called()

    async def test_waiting_for_audit_does_not_block_event_loop_or_liveness(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def report(*args):
            entered.set()
            await release.wait()

        self.identity.report.side_effect = report
        pending = asyncio.create_task(self.invoke())
        await entered.wait()
        self.assertEqual((await asyncio.wait_for(self.invoke("/livez"), 0.2))[0], 200)
        self.assertFalse(pending.done())
        release.set()
        self.assertEqual((await pending)[0], 401)

    async def test_lifespan_probe_precedes_engine_and_failure_cleans_all_resources(self):
        self.identity.start.side_effect = Rejected("PRIVATE-CANARY")
        with self.assertRaises(Rejected):
            async with self.app.router.lifespan_context(self.app):
                self.fail("startup should fail")
        self.engine.activate.assert_not_called()
        self.identity.close.assert_awaited_once()
        self.engine.close.assert_called_once()
        self.identity.start.side_effect = None
        self.identity.close.side_effect = Rejected("cleanup refused")
        self.engine.close.reset_mock()
        with self.assertRaises(Rejected):
            async with self.app.router.lifespan_context(self.app):
                self.engine.activate.assert_called_once()
        self.engine.close.assert_called_once()

    async def test_wrong_source_type_cannot_create_http_app(self):
        with self.assertRaisesRegex(Rejected, "http_identity_audit_configuration"):
            serving_http.create_app(self.engine, "a" * 64, identity_audit=object())

    def test_operator_config_forwards_identity_profile_and_rejects_bad_source_path(self):
        from mlsecops.signing import encode64

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            token = root / "token"
            token.write_text("a" * 64)
            token.chmod(0o600)
            config = dict(
                storage_client=str(root / "serving"),
                trust_client=str(root / "trust"),
                context={"policy": {"environment": "local-cpu"}},
                trusted_root=encode64(b"a" * 32),
                trust_root=encode64(b"b" * 32),
                expected_policy="a" * 64,
                expected_serving_image="sha256:" + "c" * 64,
                minimum_sequence=1,
                minimum_trust_version=1,
                audit_directory=str(root / "audit"),
                token_file=str(token),
                identity_audit_file=str(root / "identity.json"),
            )
            path = root / "config.json"
            path.write_bytes(canonical(config))
            with (
                patch.object(source, "configured", return_value=self.identity) as configure,
                patch.object(serving_http, "create_app") as create,
            ):
                serving_http.configured(path)
                configure.assert_called_once_with(config["identity_audit_file"])
                self.assertIs(create.call_args.kwargs["identity_audit"], self.identity)
            for bad in ("relative", None, False):
                path.write_bytes(canonical({**config, "identity_audit_file": bad}))
                with patch.object(serving_http.serving, "Engine") as engine:
                    with self.assertRaises(Rejected):
                        serving_http.configured(path)
                    engine.assert_not_called()


if __name__ == "__main__":
    unittest.main()
