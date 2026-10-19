import asyncio
import io
import os
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import serving, serving_access, serving_audit, serving_context, serving_http
from mlsecops.contracts import Rejected, canonical, decode
from mlsecops.datasets import FEATURES
from mlsecops.signing import encode64
from scripts.serving_access_qualification import credentials


class ServingHttpContracts(unittest.IsolatedAsyncioTestCase):
    async def test_private_context_is_not_serialized_or_taken_from_headers(self):
        snapshots = []
        render = serving_http.JSONResponse.render

        def capture(response, content):
            if "predictions" in content or content.get("ready"):
                snapshots.append(response.audit_context)
            return render(response, content)

        for path, method in (("/readyz", "GET"), ("/v1/predict", "POST")):
            with patch.object(serving_http.JSONResponse, "render", capture):
                status, content, _ = await self.invoke(
                    path=path,
                    method=method,
                    headers=[
                        (b"authorization", ("Bearer " + self.token).encode()),
                        (b"content-type", b"application/json"),
                        (b"x-selection-sha256", b"f" * 64),
                    ],
                )
            self.assertEqual(status, 200)
            serialized = canonical(content).decode()
            for private in ("d" * 64, "e" * 64, "f" * 64, "audit_context", "permit_sha256"):
                self.assertNotIn(private, serialized)
        self.assertEqual(snapshots, [self.audit_context, self.audit_context])

    async def test_missing_context_stale_generation_or_identity_mismatch_cannot_succeed(self):
        for path, method, operation, payload in (
            ("/readyz", "GET", self.engine.check_result, self.engine.check.return_value),
            ("/v1/predict", "POST", self.engine.predict_result, self.engine.predict.return_value),
        ):
            for variant in (
                "plain-dict",
                "missing-context",
                "old-generation",
                "wrong-model",
                "wrong-bundle",
            ):

                def invalid(*args, generation, variant=variant):
                    content = dict(payload)
                    if variant == "plain-dict":
                        return content
                    context = None if variant == "missing-context" else self.audit_context
                    if variant == "wrong-model":
                        content["model_sha256"] = "f" * 64
                    if variant == "wrong-bundle":
                        content["bundle_sha256"] = "f" * 64
                    if variant == "old-generation":
                        generation = threading.Event()
                    return serving.ServingResult(content, context, generation)

                operation.side_effect = invalid
                with self.subTest(path=path, variant=variant):
                    status, content, _ = await self.invoke(path=path, method=method)
                    self.assertEqual(status, 503)
                    self.assertNotIn("predictions", content)
                    self.assertNotIn("ready", content)

    async def test_final_deadline_denial_clears_response_context(self):
        responses = []
        render = serving_http.JSONResponse.render

        def fence(response, content):
            if "predictions" in content:
                responses.append(response)
                response.budget.generation.set()
            return render(response, content)

        with patch.object(serving_http.JSONResponse, "render", fence):
            status, content, _ = await self.invoke()
        self.assertEqual(status, 503)
        self.assertNotIn("predictions", content)
        self.assertEqual(len(responses), 1)
        self.assertIsNone(responses[0].audit_context)

    async def test_global_ready_overload_releases_client_ticket_without_refund(self):
        config = credentials()
        config["clients"][0]["burst"] = 1
        access = serving_access.Access(config, clock=lambda: 1000)
        self.app = serving_http.create_app(self.engine, clients=access, audit=self.journal)
        headers = [(b"authorization", ("Bearer " + "a" * 64).encode())]
        for _ in range(8):
            await self.app.state.slots.acquire()
        try:
            self.assertEqual(
                (await self.invoke(path="/readyz", method="GET", headers=headers))[0], 503
            )
        finally:
            for _ in range(8):
                self.app.state.slots.release()
        self.assertEqual(access.buckets["a" * 32].inflight, 0)
        self.assertEqual((await self.invoke(path="/readyz", method="GET", headers=headers))[0], 429)
        self.engine.check.assert_not_called()

    async def test_clock_failure_returns_503_and_trust_fence_precedes_quota(self):
        clock = Mock(return_value=1000)
        access = serving_access.Access(credentials(), clock=clock)
        self.app = serving_http.create_app(self.engine, clients=access, audit=self.journal)
        headers = [(b"authorization", ("Bearer " + "a" * 64).encode())]
        clock.return_value = 999
        for path, method in (("/readyz", "GET"), ("/v1/predict", "POST")):
            status, result, received = await self.invoke(path=path, method=method, headers=headers)
            self.assertEqual((status, received), (503, 0))
            self.assertNotIn("quota_clock", str(result))
        self.engine.check.assert_not_called()
        self.engine.predict.assert_not_called()
        access = serving_access.Access(credentials(), clock=lambda: 1000)
        retained = access.acquire("a" * 32)
        self.app = serving_http.create_app(self.engine, clients=access, audit=self.journal)
        self.engine.response_budget.side_effect = Rejected("expired")
        self.assertEqual((await self.invoke(headers=headers))[0], 503)
        retained.release()

    async def test_deadline_retains_client_ticket_after_response_and_until_task_completion(self):
        access = serving_access.Access(credentials(), clock=lambda: 1000)
        self.app = serving_http.create_app(self.engine, clients=access, audit=self.journal)
        entered, release = threading.Event(), threading.Event()
        generation = threading.Event()
        budget = serving.ResponseBudget(generation, time.monotonic() + 0.08)
        self.engine.response_budget.side_effect = lambda: budget
        self.engine.expire.side_effect = lambda selected: selected.set()
        headers = [
            (b"authorization", ("Bearer " + "a" * 64).encode()),
            (b"content-type", b"application/json"),
        ]

        def predict(*arguments, **keywords):
            entered.set()
            release.wait(3)
            return self.engine.predict.return_value

        self.engine.predict.side_effect = predict
        try:
            self.assertEqual((await self.invoke(headers=headers))[0], 503)
            self.assertTrue(entered.is_set())
            with self.assertRaises(serving_access.Limited):
                access.acquire("a" * 32)
        finally:
            release.set()
        for _ in range(100):
            if not self.app.state.pending:
                break
            await asyncio.sleep(0.01)
        self.assertFalse(self.app.state.pending)
        access.acquire("a" * 32).release()

    async def test_client_quota_precedes_body_and_does_not_charge_other_identity(self):
        config = credentials()
        config["clients"][0]["burst"] = 1
        access = serving_access.Access(config, clock=lambda: 1000)
        self.app = serving_http.create_app(self.engine, clients=access, audit=self.journal)
        first = [
            (b"authorization", ("Bearer " + "a" * 64).encode()),
            (b"content-type", b"application/json"),
        ]
        second = [
            (b"authorization", ("Bearer " + "b" * 64).encode()),
            (b"content-type", b"application/json"),
        ]
        self.assertEqual((await self.invoke(body={}, headers=first))[0], 422)
        status, result, received = await self.invoke(headers=first + [(b"x-client-id", b"b" * 32)])
        self.assertEqual((status, received, result["error"]["code"]), (429, 0, "client_limited"))
        self.assertEqual((await self.invoke(headers=second))[0], 200)
        self.assertEqual((await self.invoke(headers=first * 2))[0], 401)
        self.assertEqual((await self.invoke(path="/readyz", method="GET", headers=first))[0], 429)
        self.assertEqual((await self.invoke(path="/livez", method="GET", headers=[]))[0], 200)

    async def test_cancelled_http_keeps_client_ticket_until_executor_completion(self):
        access = serving_access.Access(credentials(), clock=lambda: 1000)
        self.app = serving_http.create_app(self.engine, clients=access, audit=self.journal)
        entered, release = threading.Event(), threading.Event()
        headers = [
            (b"authorization", ("Bearer " + "a" * 64).encode()),
            (b"content-type", b"application/json"),
        ]

        def predict(*arguments, **keywords):
            entered.set()
            release.wait(3)
            return self.engine.predict.return_value

        self.engine.predict.side_effect = predict
        task = asyncio.create_task(self.invoke(headers=headers))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 1))
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual((await self.invoke(headers=headers))[0], 429)
            self.assertEqual(len(self.app.state.pending), 1)
        finally:
            release.set()
            if not task.done():
                await task
        for _ in range(100):
            if not self.app.state.pending:
                break
            await asyncio.sleep(0.01)
        self.assertFalse(self.app.state.pending)
        self.assertEqual((await self.invoke(headers=headers))[0], 200)

    async def test_fenced_generation_precedes_overload_and_body_consumption(self):
        generation = threading.Event()
        generation.set()
        self.engine.response_budget.side_effect = None
        self.engine.response_budget.return_value = serving.ResponseBudget(
            generation, time.monotonic() + 10
        )
        for _ in range(8):
            await self.app.state.slots.acquire()
        status, _, received = await self.invoke()
        self.assertEqual((status, received), (503, 0))
        self.engine.predict.assert_not_called()

    async def test_body_read_uses_same_response_deadline(self):
        generation = threading.Event()
        self.engine.response_budget.side_effect = None
        self.engine.response_budget.return_value = serving.ResponseBudget(
            generation, time.monotonic() + 0.05
        )
        self.engine.expire.side_effect = lambda selected: selected.set()

        async def slow_body(request):
            await asyncio.sleep(1)
            return [[0.5] * len(FEATURES)]

        started = time.monotonic()
        with patch.object(serving_http, "read_body", side_effect=slow_body):
            status, _, _ = await self.invoke()
        self.assertEqual(status, 503)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertTrue(generation.is_set())
        self.engine.predict.assert_not_called()
        self.assertEqual(self.app.state.slots._value, 8)

    async def test_generation_is_checked_after_response_serialization(self):
        generation = threading.Event()
        self.engine.response_budget.side_effect = None
        self.engine.response_budget.return_value = serving.ResponseBudget(
            generation, time.monotonic() + 10
        )
        render = serving_http.JSONResponse.render

        def fence_during_serialization(response, content):
            if "predictions" in content:
                generation.set()
            return render(response, content)

        with patch.object(serving_http.JSONResponse, "render", fence_during_serialization):
            status, content, _ = await self.invoke()
        self.assertEqual(status, 503)
        self.assertNotIn("predictions", content)

    async def test_shortened_live_lease_is_rechecked_after_serialization(self):
        generation = threading.Event()
        self.engine.response_budget.side_effect = None
        self.engine.response_budget.return_value = serving.ResponseBudget(
            generation, time.monotonic() + 10
        )
        render = serving_http.JSONResponse.render

        def shorten_during_serialization(response, content):
            if "predictions" in content:
                self.engine.response_budget.return_value = serving.ResponseBudget(
                    generation, time.monotonic() - 0.01
                )
            return render(response, content)

        with patch.object(serving_http.JSONResponse, "render", shorten_during_serialization):
            status, content, _ = await self.invoke()
        self.assertEqual(status, 503)
        self.assertNotIn("predictions", content)

    async def test_shortened_lease_interrupts_wait_without_releasing_running_work(self):
        entered, release, generation = (threading.Event() for _ in range(3))
        self.engine.response_budget.side_effect = None
        self.engine.response_budget.return_value = serving.ResponseBudget(
            generation, time.monotonic() + 10
        )
        self.engine.expire.side_effect = lambda selected: selected.set()

        def blocked(features, *, generation):
            entered.set()
            release.wait(3)
            return {"predictions": []}

        self.engine.predict.side_effect = blocked
        request = asyncio.create_task(self.invoke())
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 1))
            self.engine.response_budget.return_value = serving.ResponseBudget(
                generation, time.monotonic() + 0.05
            )
            await asyncio.sleep(0.2)
            self.assertTrue(request.done(), "shorter lease ignored during wait")
            self.assertEqual((await request)[0], 503)
            self.assertEqual(len(self.app.state.pending), 1)
            self.assertEqual(self.app.state.slots._value, 7)
        finally:
            release.set()
            await asyncio.gather(request, return_exceptions=True)

    async def test_deadline_returns_503_but_retains_pending_task_and_slot(self):
        entered, release = threading.Event(), threading.Event()
        generation = threading.Event()
        budget = serving.ResponseBudget(generation, time.monotonic() + 0.05)
        self.engine.response_budget.return_value = budget
        self.engine.response_budget.side_effect = None
        self.engine.expire.side_effect = lambda selected: selected.set()

        def blocked(features, *, generation):
            entered.set()
            release.wait(3)
            return {"schema_version": 1, "predictions": [{"score": 0.123, "raw": "PRIVATE-CANARY"}]}

        self.engine.predict.side_effect = blocked
        request = asyncio.create_task(self.invoke())
        try:
            for _ in range(100):
                if entered.is_set():
                    break
                await asyncio.sleep(0.005)
            self.assertTrue(entered.is_set())
            await asyncio.sleep(0.1)
            self.assertTrue(request.done(), "HTTP denial waits for synchronous trust read")
            status, content, _ = await request
            self.assertEqual(status, 503)
            self.assertNotIn("PRIVATE-CANARY", canonical(content).decode())
            self.assertTrue(generation.is_set())
            self.assertEqual(len(self.app.state.pending), 1)
            self.assertEqual(self.app.state.slots._value, 7)
        finally:
            release.set()
            await asyncio.gather(request, return_exceptions=True)
        for _ in range(100):
            if not self.app.state.pending:
                break
            await asyncio.sleep(0.005)
        self.assertFalse(self.app.state.pending)
        self.assertEqual(self.app.state.slots._value, 8)

    async def asyncSetUp(self):
        self.engine = Mock()
        generation = threading.Event()
        self.engine.response_budget.side_effect = lambda: serving.ResponseBudget(
            generation, time.monotonic() + 10
        )
        self.audit_context = serving_context.QualificationContext(
            "d" * 64, "e" * 64, "a" * 64, "c" * 64
        )
        self.engine.check.return_value = {
            "ready": True,
            "bundle_sha256": "a" * 64,
            "model_sha256": "c" * 64,
        }
        self.engine.predict.return_value = {
            "schema_version": 1,
            "bundle_sha256": "a" * 64,
            "model_sha256": "c" * 64,
            "predictions": [{"decision": "score", "score": 0.75, "reason": None}],
        }
        self.engine.check_result.side_effect = lambda *, generation: serving.ServingResult(
            self.engine.check(generation=generation), self.audit_context, generation
        )
        self.engine.predict_result.side_effect = lambda features, *, generation: (
            serving.ServingResult(
                self.engine.predict(features, generation=generation), self.audit_context, generation
            )
        )
        self.token = "b" * 64
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.journal = serving_audit.Journal(Path(temporary.name) / "audit.jsonl")
        self.journal.start()
        self.addCleanup(self.journal.close, timeout=5)
        self.app = serving_http.create_app(self.engine, self.token, audit=self.journal)
        self.context = self.app.router.lifespan_context(self.app)
        await self.context.__aenter__()
        self.addAsyncCleanup(self.context.__aexit__, None, None, None)

    async def invoke(self, body=None, path="/v1/predict", method="POST", headers=None, chunks=None):
        payload = canonical(
            body
            if body is not None
            else {"schema_version": 1, "instances": [{name: 0.5 for name in FEATURES}]}
        )
        packets = list(chunks or [payload])
        outgoing = []
        received = 0

        async def receive():
            nonlocal received
            received += 1
            content = packets.pop(0)
            return {"type": "http.request", "body": content, "more_body": bool(packets)}

        async def send(message):
            outgoing.append(message)

        await self.app(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": method,
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
        content = b"".join(message.get("body", b"") for message in outgoing)
        return status, decode(content), received

    async def test_named_features_and_server_request_id(self):
        status, result, _ = await self.invoke()
        self.assertEqual(status, 200)
        self.assertRegex(result["request_id"], r"^[a-f0-9]{32}$")
        self.engine.predict.assert_called_once()
        self.assertEqual(self.engine.predict.call_args.args, ([[0.5] * len(FEATURES)],))
        self.assertIsInstance(self.engine.predict.call_args.kwargs["generation"], threading.Event)

    async def test_no_auth_or_wrong_auth_does_not_consume_body(self):
        for headers in ([], [(b"authorization", b"Bearer PRIVATE-CANARY")]):
            status, result, received = await self.invoke(headers=headers)
            self.assertEqual((status, received), (401, 0))
            self.assertNotIn("PRIVATE-CANARY", str(result))
        self.engine.predict.assert_not_called()

    async def test_strict_schema_and_nonfinite_input_are_422(self):
        valid = {name: 0.5 for name in FEATURES}
        for body in (
            {},
            {"schema_version": True, "instances": [valid]},
            {"schema_version": 1, "instances": [valid], "model_url": "http://PRIVATE-CANARY"},
            {"schema_version": 1, "instances": [valid] * 101},
            {"schema_version": 1, "instances": [{**valid, "change_size": True}]},
            {"schema_version": 1, "instances": [{**valid, "extra": 0}]},
        ):
            with self.subTest(body=tuple(body)):
                status, result, _ = await self.invoke(body)
                self.assertEqual(status, 422)
                self.assertNotIn("PRIVATE-CANARY", str(result))
        for payload in (
            b'{"schema_version":1,"schema_version":1}',
            b'{"x":NaN}',
            b'{"x":Infinity}',
        ):
            self.assertEqual((await self.invoke(chunks=[payload]))[0], 422)
        self.engine.predict.assert_not_called()

    async def test_actual_chunk_limit_is_413_without_reading_rest(self):
        status, _, received = await self.invoke(chunks=[b"x" * 65536, b"x", b"never-read"])
        self.assertEqual((status, received), (413, 2))
        self.engine.predict.assert_not_called()

    async def test_length_and_encoding_headers_are_validated(self):
        common = [
            (b"authorization", f"Bearer {self.token}".encode()),
            (b"content-type", b"application/json"),
        ]
        for extra, expected in (
            ([(b"content-length", b"65537")], 413),
            ([(b"content-length", b"-1")], 422),
            ([(b"content-length", b"1"), (b"content-length", b"1")], 422),
            ([(b"content-length", b"0")], 422),
            ([(b"content-encoding", b"gzip")], 422),
        ):
            with self.subTest(headers=extra):
                self.assertEqual((await self.invoke(headers=common + extra))[0], expected)
        self.engine.predict.assert_not_called()

    async def test_untrusted_ready_and_busy_have_explicit_status(self):
        self.engine.check.side_effect = Rejected("PRIVATE-CANARY")
        status, result, _ = await self.invoke(path="/readyz", method="GET")
        self.assertEqual(status, 503)
        self.assertNotIn("PRIVATE-CANARY", str(result))
        self.engine.predict.side_effect = Rejected("serving_busy")
        self.assertEqual((await self.invoke())[0], 429)
        self.engine.predict.side_effect = RuntimeError("PRIVATE-CANARY")
        status, result, _ = await self.invoke()
        self.assertEqual(status, 503)
        self.assertNotIn("PRIVATE-CANARY", str(result))

    async def test_global_inflight_limit_rejects_before_body(self):
        for _ in range(8):
            await self.app.state.slots.acquire()
        status, _, received = await self.invoke()
        self.assertEqual((status, received), (429, 0))
        for _ in range(8):
            self.app.state.slots.release()

    async def test_liveness_is_not_readiness_and_no_documentation_routes(self):
        status, result, received = await self.invoke(path="/livez", method="GET", headers=[])
        self.assertEqual((status, result, received), (200, {"status": "alive"}, 0))
        self.assertEqual((await self.invoke(path="/docs", method="GET"))[0], 404)

    async def test_cancelled_request_keeps_slot_until_inference_thread_finishes(self):
        entered, release = threading.Event(), threading.Event()

        def blocked(features, *, generation):
            entered.set()
            release.wait(3)
            raise Rejected("PRIVATE-CANARY")

        self.engine.predict.side_effect = blocked
        task = asyncio.create_task(self.invoke())
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 2))
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(self.app.state.slots._value, 7)
        finally:
            release.set()
            await asyncio.sleep(0.05)
        self.assertEqual(self.app.state.slots._value, 8)


class ServingConfigurationContracts(unittest.TestCase):
    def test_missing_token_and_unapproved_config_never_create_unauthenticated_app(self):
        for token in (None, "", "weak", "b" * 63, "g" * 64):
            with self.subTest(token=token), self.assertRaises(Rejected):
                serving_http.create_app(Mock(), token)

    def test_private_token_file_and_explicit_external_pins(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            secret = directory / "token"
            secret.write_text("b" * 64)
            secret.chmod(0o600)
            config = {
                "storage_client": str(directory / "serving-client"),
                "trust_client": str(directory / "trust-client"),
                "context": {"policy": {"environment": "local-cpu"}},
                "trusted_root": encode64(b"a" * 32),
                "trust_root": encode64(b"b" * 32),
                "expected_policy": "a" * 64,
                "expected_serving_image": "sha256:" + "c" * 64,
                "minimum_sequence": 2,
                "minimum_trust_version": 3,
                "audit_directory": str(directory / "audit"),
                "token_file": str(secret),
            }
            path = directory / "config.json"
            without_audit = {
                key: value for key, value in config.items() if key != "audit_directory"
            }
            path.write_bytes(canonical(without_audit))
            with self.assertRaises(Rejected):
                serving_http.configured(path)
            for invalid in (None, False, 0, "", [], {}, "relative-audit"):
                with self.subTest(audit_directory=invalid):
                    path.write_bytes(canonical({**config, "audit_directory": invalid}))
                    with (
                        patch.object(serving_http.serving, "Engine") as engine,
                        patch.object(serving_http.serving_audit, "Journal") as journal,
                    ):
                        with self.assertRaises(Rejected):
                            serving_http.configured(path)
                        engine.assert_not_called()
                        journal.assert_not_called()
            path.write_bytes(canonical(config))
            with patch.object(serving_http.serving, "Engine") as engine:
                app = serving_http.configured(path)
                self.assertIsNotNone(app)
                reader = engine.call_args.args[0]
                self.assertEqual(reader.floor, 2)
                self.assertEqual(reader.trust.floor, 3)
            metrics_secret = directory / "metrics-token"
            metrics_secret.write_text("c" * 64)
            metrics_secret.chmod(0o600)
            path.write_bytes(canonical({**config, "metrics_token_file": str(metrics_secret)}))
            with patch.object(serving_http, "create_app") as create:
                serving_http.configured(path)
                self.assertEqual(create.call_args.kwargs["metrics_token"], "c" * 64)
            for invalid in (None, False, "", "relative-token", []):
                path.write_bytes(canonical({**config, "metrics_token_file": invalid}))
                with self.assertRaises(Rejected):
                    serving_http.configured(path)
            path.write_bytes(canonical({**config, "metrics_token_file": str(metrics_secret)}))
            if os.name == "posix":
                metrics_secret.chmod(0o644)
                with self.assertRaisesRegex(Rejected, "http_token_permissions"):
                    serving_http.configured(path)
                metrics_secret.chmod(0o600)
            metrics_secret.write_bytes(b"c" * 66)
            with self.assertRaises(Rejected):
                serving_http.configured(path)
            path.write_bytes(canonical({**config, "token_file": "relative-token"}))
            with self.assertRaises(Rejected):
                serving_http.configured(path)
            secret.write_bytes(canonical(credentials()))
            multi = {key: value for key, value in config.items() if key != "token_file"}
            multi["principals_file"] = str(secret)
            path.write_bytes(canonical(multi))
            with patch.object(serving_http, "create_app") as create:
                serving_http.configured(path)
                access = create.call_args.kwargs["clients"]
                self.assertEqual(access.authenticate(["Bearer " + "a" * 64]), "a" * 32)
                self.assertEqual(access.authenticate(["Bearer " + "b" * 64]), "b" * 32)
            path.write_bytes(canonical({**multi, "token_file": str(secret)}))
            with self.assertRaises(Rejected):
                serving_http.configured(path)
            path.write_bytes(canonical(multi))
            secret.write_bytes(b" " * 65537)
            with self.assertRaises(Rejected):
                serving_http.configured(path)

    def test_direct_client_configuration_rejects_conflicting_token_or_wrong_type(self):
        for token, clients in (("a" * 64, serving_access.Access(credentials())), (None, {})):
            with self.assertRaises(Rejected):
                serving_http.create_app(Mock(), token, clients=clients)

    def test_cli_binds_loopback_and_does_not_enable_access_logs_or_proxy_headers(self):
        with (
            patch("sys.argv", ["serving", "--config", "controlled.json"]),
            patch.object(serving_http, "enforce_privacy"),
            patch.object(serving_http, "configured", return_value=Mock()),
            patch.object(serving_http, "run_server") as run,
        ):
            self.assertEqual(serving_http.main(), 0)
            self.assertEqual(run.call_args.kwargs["host"], "127.0.0.1")
            self.assertIs(run.call_args.kwargs["access_log"], False)
            self.assertIs(run.call_args.kwargs["proxy_headers"], False)
        with (
            patch("sys.argv", ["serving", "--config", "PRIVATE-CANARY", "--port", "1"]),
            patch.object(serving_http, "enforce_privacy"),
            redirect_stderr(io.StringIO()) as diagnostic,
        ):
            self.assertEqual(serving_http.main(), 1)
        self.assertEqual(diagnostic.getvalue(), "serving_configuration_rejected\n")


if __name__ == "__main__":
    unittest.main()
