import asyncio
import os
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext, suppress
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import (
    audit_retention,
    serving,
    serving_access,
    serving_audit,
    serving_http,
    serving_http_audit,
)
from mlsecops.contracts import Rejected, canonical, decode
from mlsecops.datasets import FEATURES
from scripts import serving_http_qualification as http_contracts
from scripts.audit_admission_qualification import journal_fixture
from scripts.serving_access_qualification import credentials
from scripts.serving_native import site
from scripts.serving_native_qualification import engine_fixture


class HttpAuditContracts(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = http_contracts.ServingHttpContracts.asyncSetUp

    async def test_denied_audit_keeps_admitted_resources_until_send_finishes_or_cancels(self):
        for path in ("/readyz", "/v1/predict"):
            for failure in ("missing", "reserve", "emit"):
                for cancel in (False, True):
                    with self.subTest(path=path, failure=failure, cancel=cancel):
                        clients = serving_access.Access(credentials())
                        self.token = "a" * 64
                        self.app = serving_http.create_app(
                            self.engine,
                            clients=clients,
                            audit=None if failure == "missing" else self.journal,
                        )
                        entered, resume = asyncio.Event(), asyncio.Event()

                        async def hold_start(message):
                            if message["type"] == "http.response.start":
                                self.assertEqual(message["status"], 503)
                                entered.set()
                                await resume.wait()

                        with (
                            nullcontext()
                            if failure == "missing"
                            else patch.object(
                                self.journal, failure, side_effect=Rejected("audit_unavailable")
                            )
                        ):
                            task = asyncio.create_task(
                                self.request(path=path, send_hook=hold_start)
                            )
                            try:
                                await asyncio.wait_for(entered.wait(), 1)
                                self.assertEqual(self.app.state.slots._value, 7)
                                self.assertEqual(clients.buckets["a" * 32].inflight, 1)
                                for _index in range(3):
                                    self.assertEqual((await self.request(path=path))[0], 429)
                                self.assertEqual(clients.admissions()["a" * 32], 1)
                                self.assertEqual(self.journal.status()["reservations"], 0)
                            finally:
                                if cancel:
                                    task.cancel()
                                resume.set()
                                with suppress(asyncio.CancelledError):
                                    await task
                        self.assertEqual(self.app.state.slots._value, 8)
                        self.assertEqual(clients.buckets["a" * 32].inflight, 0)
                        self.engine.check.assert_not_called()
                        self.engine.predict.assert_not_called()

    async def packets(self, messages):
        self.audited()
        self.outgoing = []
        self.released = Mock()

        async def application(scope, receive, send):
            delivery = serving_http_audit.Delivery(
                self.journal,
                "a" * 32,
                "b" * 32,
                "predict",
                lambda: 10,
                lambda: serving_http.JSONResponse({"error": "denied"}, status_code=503),
                self.released,
            )
            delivery.context = self.audit_context
            scope[serving_http_audit.SCOPE_KEY] = delivery
            delivery.start()
            for message in messages:
                await send(message)

        async def send(message):
            self.outgoing.append(message)

        await serving_http_audit.Middleware(application)({"type": "http"}, Mock(), send)

    async def test_chunked_send_records_only_final_completion_and_ignores_extra_body(self):
        await self.packets(
            [
                {"type": "http.response.start", "status": 200, "headers": []},
                {"type": "http.response.body", "body": b"first", "more_body": True},
                {"type": "http.response.body", "body": b"last", "more_body": False},
                {"type": "http.response.body", "body": b"ignored", "more_body": False},
            ]
        )
        self.assertEqual(len(self.outgoing), 3)
        self.assertEqual(
            [value["stage"] for value in await self.events()],
            ["request_started", "response_intended", "response_started", "response_completed"],
        )
        self.released.assert_called_once()

    async def test_out_of_order_duplicate_start_and_unsupported_messages_are_rejected(self):
        start = {"type": "http.response.start", "status": 200, "headers": []}
        for messages in (
            [{"type": "http.response.body", "body": b"early"}],
            [start, start],
            [{**start, "trailers": True}],
            [start, {"type": "websocket.send", "text": "invalid"}],
        ):
            with self.subTest(messages=messages):
                with self.assertRaisesRegex(Rejected, "audit_http_message_invalid"):
                    await self.packets(messages)
                events = await self.events()
                self.assertNotIn("response_completed", [value["stage"] for value in events])
                self.assertEqual(events[-1]["stage"], "aborted")
                self.released.assert_called_once()

    async def test_slot_remains_owned_until_audit_delivery_finishes(self):
        self.audited()
        entered, resume = threading.Event(), threading.Event()
        original = self.journal._write

        def pause_intent(content):
            if decode(content)["event"]["stage"] == "response_intended":
                entered.set()
                if not resume.wait(3):
                    raise OSError("test_wait_expired")
            original(content)

        with patch.object(self.journal, "_write", pause_intent):
            task = asyncio.create_task(self.request())
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 1))
                self.assertFalse(self.app.state.pending)
                self.assertEqual(self.app.state.slots._value, 7)
                self.assertFalse(task.done())
            finally:
                task.cancel()
                resume.set()
                with suppress(asyncio.CancelledError):
                    await task
            await self.events()
        self.assertEqual(self.app.state.slots._value, 8)
        self.assertEqual(self.journal.status()["reservations"], 0)

    async def test_previous_durable_request_cannot_acknowledge_next_intent(self):
        self.audited()
        self.assertEqual((await self.request())[0], 200)
        await self.events()
        entered, resume = threading.Event(), threading.Event()
        original = self.journal._write

        def pause_next_intent(content):
            value = decode(content)
            if value["sequence"] > 4 and value["event"]["stage"] == "response_intended":
                entered.set()
                if not resume.wait(3):
                    raise OSError("test_wait_expired")
            original(content)

        with patch.object(self.journal, "_write", pause_next_intent):
            task = asyncio.create_task(self.request())
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 1))
                await asyncio.sleep(0.03)
                self.assertFalse(task.done())
                self.assertEqual(self.journal.status()["durable"], 5)
            finally:
                resume.set()
            self.assertEqual((await task)[0], 200)
            events = await self.events()
        self.assertEqual(len(events), 8)
        self.assertNotEqual(events[0]["request_id"], events[4]["request_id"])

    async def test_budget_is_rechecked_after_successful_durability_confirmation(self):
        for change in ("fence", "shorten", "generation"):
            with self.subTest(change=change):
                self.audited()
                generation = threading.Event()
                self.engine.response_budget.side_effect = None
                self.engine.response_budget.return_value = serving.ResponseBudget(
                    generation, time.monotonic() + 10
                )
                original = self.journal.confirmed

                def confirm(ticket, sequence):
                    result = original(ticket, sequence)
                    if result:
                        if change == "fence":
                            generation.set()
                        else:
                            self.engine.response_budget.return_value = serving.ResponseBudget(
                                threading.Event() if change == "generation" else generation,
                                time.monotonic() + (10 if change == "generation" else -1),
                            )
                    return result

                with patch.object(self.journal, "confirmed", confirm):
                    status, content, _ = await self.request()
                self.assertEqual(status, 503)
                self.assertNotIn("predictions", content)
                events = await self.events()
                self.assertEqual([value["status"] for value in events], [None, 200, 503, 503])
                self.assertIsNone(events[-1]["context"])

    async def test_failed_first_emit_releases_reservation_before_scope_handoff(self):
        self.audited()
        with patch.object(self.journal, "emit", side_effect=Rejected("audit_unavailable")):
            status, _, received = await self.request()
        self.assertEqual((status, received), (503, 0))
        self.engine.predict.assert_not_called()
        state = self.journal.status()
        self.assertEqual(
            (state["reservations"], state["held_slots"], state["held_bytes"]), (0, 0, 0)
        )
        self.assertEqual(self.app.state.slots._value, 8)

    async def test_failed_intent_write_denies_success_and_next_admission(self):
        self.audited()
        original = self.journal._write

        def fail_intent(content):
            if decode(content)["event"]["stage"] == "response_intended":
                raise OSError("PRIVATE_SINK_CANARY")
            original(content)

        with patch.object(self.journal, "_write", fail_intent):
            status, content, _ = await self.request()
            self.assertEqual(status, 503)
            self.assertNotIn("predictions", content)
            self.assertFalse(self.journal.status()["healthy"])
            self.engine.predict.reset_mock()
            status, _, received = await self.request()
            self.assertEqual((status, received), (503, 0))
            self.engine.predict.assert_not_called()
        self.assertEqual(self.journal.status()["reservations"], 0)

    async def test_start_send_failure_records_unknown_status_not_completed(self):
        self.audited()

        async def disconnect(message):
            if message["type"] == "http.response.start":
                raise OSError("PRIVATE_TRANSPORT_CANARY")

        with self.assertRaises(OSError):
            await self.request(send_hook=disconnect)
        events = await self.events()
        self.assertEqual(
            [value["stage"] for value in events],
            ["request_started", "response_intended", "aborted"],
        )
        self.assertIsNone(events[-1]["status"])
        self.assertIsNone(events[-1]["context"])
        self.assertEqual(self.journal.status()["reservations"], 0)

    async def test_sink_failure_after_send_is_gap_not_transport_abort(self):
        for stage in ("response_started", "response_completed"):
            with self.subTest(stage=stage):
                self.audited()
                original = self.journal._write

                def fail_after_send(content):
                    if decode(content)["event"]["stage"] == stage:
                        raise OSError("PRIVATE_SINK_CANARY")
                    original(content)

                with patch.object(self.journal, "_write", fail_after_send):
                    status, _, _ = await self.request()
                    self.assertEqual(status, 200)
                    events = await self.events()
                self.assertFalse(self.journal.status()["healthy"])
                self.assertNotIn("aborted", [value["stage"] for value in events])
                self.assertNotIn("response_completed", [value["stage"] for value in events])
                self.assertEqual(self.journal.status()["reservations"], 0)
                self.assertGreater(self.journal.status()["unconfirmed"], 0)

    def audited(self, **options):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.audit_path = Path(temporary.name) / "audit.jsonl"
        self.journal = serving_audit.Journal(self.audit_path, **options)
        self.journal.start()
        journal = self.journal

        def close():
            with suppress(Rejected):
                journal.close()

        self.addCleanup(close)
        self.app = serving_http.create_app(self.engine, self.token, audit=self.journal)

    async def request(self, *, path="/v1/predict", headers=None, send_hook=None):
        outgoing = []
        received = 0
        payload = canonical({"schema_version": 1, "instances": [{key: 0.5 for key in FEATURES}]})

        async def receive():
            nonlocal received
            received += 1
            return {"type": "http.request", "body": payload, "more_body": False}

        async def send(message):
            if send_hook is not None:
                await send_hook(message)
            outgoing.append(message)

        await self.app(
            {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.5"},
                "http_version": "1.1",
                "method": "POST" if path == "/v1/predict" else "GET",
                "scheme": "http",
                "path": path,
                "raw_path": path.encode(),
                "query_string": b"",
                "headers": headers
                if headers is not None
                else [
                    (b"authorization", f"Bearer {self.token}".encode()),
                    (b"content-type", b"application/json"),
                ],
                "client": ("127.0.0.1", 12345),
                "server": ("127.0.0.1", 8080),
            },
            receive,
            send,
        )
        status = next(
            message["status"] for message in outgoing if message["type"] == "http.response.start"
        )
        return status, decode(b"".join(message.get("body", b"") for message in outgoing)), received

    async def events(self):
        deadline = time.monotonic() + 2
        while self.journal.status()["pending"]:
            if time.monotonic() >= deadline:
                self.fail("audit_test_drain_timeout")
            await asyncio.sleep(0.005)
        return [decode(line)["event"] for line in self.audit_path.read_bytes().splitlines()]

    async def test_missing_journal_denies_before_body_but_not_liveness_or_auth(self):
        self.app = serving_http.create_app(self.engine, self.token)
        status, _, received = await self.request()
        self.assertEqual((status, received), (503, 0))
        self.engine.predict.assert_not_called()
        self.assertEqual((await self.request(path="/livez", headers=[]))[0], 200)
        self.assertEqual((await self.request(headers=[]))[0], 401)

    async def test_success_requires_durable_intent_and_records_actual_send(self):
        self.audited()

        async def inspect_start(message):
            if message["type"] == "http.response.start":
                self.assertEqual(message["status"], 200)
                self.assertGreaterEqual(self.journal.status()["durable"], 2)

        status, content, _ = await self.request(send_hook=inspect_start)
        self.assertEqual(status, 200)
        events = await self.events()
        self.assertEqual(
            [value["stage"] for value in events],
            ["request_started", "response_intended", "response_started", "response_completed"],
        )
        self.assertEqual([value["status"] for value in events], [None, 200, 200, 200])
        self.assertEqual({value["request_id"] for value in events}, {content["request_id"]})
        self.assertEqual(events[-1]["context"]["kind"], "candidate-qualification")
        self.assertNotIn("context", content)
        self.assertEqual(self.journal.status()["reservations"], 0)

    async def test_cancelled_body_never_claims_completed_response(self):
        self.audited()

        async def disconnect(message):
            if message["type"] == "http.response.body":
                raise asyncio.CancelledError()

        with self.assertRaises(asyncio.CancelledError):
            await self.request(send_hook=disconnect)
        events = await self.events()
        self.assertEqual(
            [value["stage"] for value in events],
            ["request_started", "response_intended", "response_started", "aborted"],
        )
        self.assertEqual(events[-1]["status"], 200)
        self.assertEqual(self.journal.status()["reservations"], 0)

    async def test_stalled_sink_does_not_extend_deadline_or_block_liveness(self):
        self.audited()
        generation = threading.Event()
        self.engine.response_budget.side_effect = None
        self.engine.response_budget.return_value = serving.ResponseBudget(
            generation, time.monotonic() + 0.1
        )
        self.engine.expire.side_effect = lambda selected: selected.set()
        entered, resume = threading.Event(), threading.Event()
        original = self.journal._write

        def stalled(content):
            entered.set()
            if not resume.wait(3):
                raise OSError("test_wait_expired")
            original(content)

        with patch.object(self.journal, "_write", stalled):
            task = asyncio.create_task(self.request())
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 1))
                self.assertEqual((await self.request(path="/livez", headers=[]))[0], 200)
                started = time.monotonic()
                status, content, _ = await task
                self.assertEqual(status, 503)
                self.assertNotIn("predictions", content)
                self.assertLess(time.monotonic() - started, 0.5)
            finally:
                resume.set()
                await task
            events = await self.events()
        self.assertEqual([value["status"] for value in events], [None, 200, 503, 503])
        self.assertIsNone(events[-1]["context"])
        self.assertTrue(generation.is_set())

    async def test_overload_and_anonymous_requests_do_not_consume_body_or_more_audit(self):
        self.audited(capacity=4)
        ticket = self.journal.reserve()
        try:
            status, _, received = await self.request()
            self.assertEqual((status, received), (503, 0))
            for _index in range(10):
                self.assertEqual((await self.request(headers=[]))[0], 401)
            self.assertEqual((await self.request(path="/livez", headers=[]))[0], 200)
            self.assertEqual(self.journal.status()["accepted"], 0)
            self.engine.predict.assert_not_called()
        finally:
            self.journal.release(ticket)


class HttpAuditServerContracts(unittest.TestCase):
    def test_controlled_stalled_sink_leaves_real_http_health_headroom(self):
        self.check_headroom(retained=False)

    @unittest.skipUnless(os.name == "posix", "retained concurrency and real fsync require Linux CI")
    def test_native_retained_stalled_sink_leaves_real_http_health_headroom(self):
        self.check_headroom(retained=True)

    def check_headroom(self, *, retained):
        engine = engine_fixture()
        generation = threading.Event()
        engine.response_budget.side_effect = lambda: serving.ResponseBudget(
            generation, time.monotonic() + 10
        )
        engine.check.return_value = {"ready": True}
        clients = {
            "schema_version": 1,
            "clients": [
                {
                    "principal_id": marker * 32,
                    "token": marker * 64,
                    "requests_per_second": 100,
                    "burst": 100,
                    "max_in_flight": 4,
                }
                for marker in ("a", "b", "c")
            ],
        }
        with journal_fixture(retention=audit_retention.Policy() if retained else None) as (
            journal,
            _,
        ):
            entered, resume = threading.Event(), threading.Event()
            original = journal._write
            writes = []
            started = time.monotonic()
            moments = {}

            def stalled(content):
                stage = decode(content)["event"]["stage"]
                writes.append(stage)
                if stage == "response_intended":
                    entered.set()
                    if not resume.wait(15):
                        raise OSError("test_wait_expired")
                if retained:
                    original(content)

            with (
                site(engine, clients=clients, audit=journal) as request,
                patch.object(journal, "_write", stalled),
            ):
                with ThreadPoolExecutor(max_workers=8) as pool:
                    pending = [
                        pool.submit(request, "/readyz", credential=marker * 64)
                        for marker in ("a", "b")
                        for _index in range(4)
                    ]
                    try:
                        observed = entered.wait(5)
                        moments["writer_entered"] = time.monotonic() - started
                        frame = sys._current_frames().get(journal.thread.ident)
                        stack = []
                        while frame is not None:
                            stack.append((frame.f_code.co_name, frame.f_lineno))
                            frame = frame.f_back
                        self.assertTrue(
                            observed,
                            {"journal": journal.status(), "writes": writes, "writer_stack": stack},
                        )
                        deadline = time.monotonic() + 5
                        while journal.status()["accepted"] < 16 and time.monotonic() < deadline:
                            time.sleep(0.005)
                        self.assertEqual(journal.status()["reservations"], 8)
                        self.assertEqual(journal.status()["accepted"], 16)
                        moments["all_intents"] = time.monotonic() - started
                        self.assertTrue(all(not future.done() for future in pending))
                        self.assertEqual(request("/readyz", credential="c" * 64)[0], 503)
                        moments["overload"] = time.monotonic() - started
                        self.assertEqual(request("/livez", authorized=False)[0], 200)
                        moments["health"] = time.monotonic() - started
                        self.assertFalse(resume.is_set())
                        self.assertTrue(journal.status()["healthy"])
                        self.assertTrue(all(not future.done() for future in pending))
                        self.assertEqual(journal.status()["accepted"], 16)
                    finally:
                        moments["resume"] = time.monotonic() - started
                        resume.set()
                    statuses = [future.result(timeout=3)[0] for future in pending]
                    self.assertEqual(
                        statuses,
                        [200] * 8,
                        {"moments": moments, "journal": journal.status(), "writes": writes},
                    )
                deadline = time.monotonic() + 2
                while journal.status()["pending"] and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertEqual(journal.status()["durable"], 32)
                self.assertEqual(journal.status()["reservations"], 0)
            self.assertTrue(journal.status()["healthy"])


class OwnedAuditLifecycleContracts(unittest.IsolatedAsyncioTestCase):
    async def test_injected_journal_is_not_owned_by_application_lifespan(self):
        with journal_fixture() as (journal, _):
            engine = Mock()
            app = serving_http.create_app(engine, "b" * 64, audit=journal)
            async with app.router.lifespan_context(app):
                self.assertTrue(journal.status()["healthy"])
            self.assertTrue(journal.status()["healthy"])
            engine.activate.assert_called_once()
            engine.close.assert_called_once()

    async def test_owned_journal_is_deferred_and_closed_even_if_engine_cleanup_fails(self):
        for failure in (None, "activate", "close", "start"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                engine = Mock()
                if failure in {"activate", "close"}:
                    getattr(engine, failure).side_effect = RuntimeError("controlled_failure")
                with patch.object(serving_http.serving_audit, "Journal") as factory:
                    journal = factory.return_value
                    if failure == "start":
                        journal.start.side_effect = RuntimeError("controlled_failure")
                    app = serving_http.create_app(engine, "b" * 64, audit_path=Path(temporary))
                    factory.assert_not_called()
                    context = app.router.lifespan_context(app)
                    if failure is not None:
                        with self.assertRaisesRegex(RuntimeError, "controlled_failure"):
                            async with context:
                                pass
                    else:
                        async with context:
                            self.assertIs(app.state.audit, journal)
                    factory.assert_called_once()
                    journal.start.assert_called_once()
                    journal.close.assert_called_once()
                    engine.close.assert_called_once()

    @unittest.skipUnless(os.name == "posix", "owned retained lifecycle requires Linux CI")
    async def test_native_owned_retained_lifecycle_has_no_startup_side_effects_before_lifespan(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            app = serving_http.create_app(Mock(), "b" * 64, audit_path=path)
            self.assertEqual(list(path.iterdir()), [])
            self.assertIsNone(app.state.audit)
            async with app.router.lifespan_context(app):
                journal = app.state.audit
                self.assertTrue(journal.status()["healthy"])
                self.assertIsNotNone(journal._spool)
            self.assertTrue(journal.status()["closed"])
            self.assertIsNone(journal.status()["failure"])

    async def test_ambiguous_or_relative_audit_configuration_is_rejected(self):
        with journal_fixture() as (journal, _):
            for options in (
                {"audit": {}},
                {"audit_path": "relative"},
                {"audit": journal, "audit_path": Path.cwd()},
            ):
                with self.subTest(options=options), self.assertRaises(Rejected):
                    serving_http.create_app(Mock(), "b" * 64, **options)


if __name__ == "__main__":
    unittest.main()
