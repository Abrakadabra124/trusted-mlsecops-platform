import asyncio
import io
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import serving_http
from mlsecops.contracts import Rejected, canonical, decode
from mlsecops.datasets import FEATURES
from mlsecops.signing import encode64


class ServingHttpContracts(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = Mock()
        self.engine.check.return_value = {"ready": True, "bundle_sha256": "a" * 64}
        self.engine.predict.return_value = {
            "schema_version": 1,
            "bundle_sha256": "a" * 64,
            "predictions": [{"decision": "score", "score": 0.75, "reason": None}],
        }
        self.token = "b" * 64
        self.app = serving_http.create_app(self.engine, self.token)
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
        self.engine.predict.assert_called_once_with([[0.5] * len(FEATURES)])

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

        def blocked(features):
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
                "token_file": str(secret),
            }
            path = directory / "config.json"
            path.write_bytes(canonical(config))
            with patch.object(serving_http.serving, "Engine") as engine:
                app = serving_http.configured(path)
                self.assertIsNotNone(app)
                reader = engine.call_args.args[0]
                self.assertEqual(reader.floor, 2)
                self.assertEqual(reader.trust.floor, 3)
            path.write_bytes(canonical({**config, "token_file": "relative-token"}))
            with self.assertRaises(Rejected):
                serving_http.configured(path)

    def test_cli_binds_loopback_and_does_not_enable_access_logs_or_proxy_headers(self):
        with (
            patch("sys.argv", ["serving", "--config", "controlled.json"]),
            patch.object(serving_http, "configured", return_value=Mock()),
            patch.object(serving_http.uvicorn, "run") as run,
        ):
            self.assertEqual(serving_http.main(), 0)
            self.assertEqual(run.call_args.kwargs["host"], "127.0.0.1")
            self.assertIs(run.call_args.kwargs["access_log"], False)
            self.assertIs(run.call_args.kwargs["proxy_headers"], False)
        with (
            patch("sys.argv", ["serving", "--config", "PRIVATE-CANARY", "--port", "1"]),
            redirect_stderr(io.StringIO()) as diagnostic,
        ):
            self.assertEqual(serving_http.main(), 1)
        self.assertEqual(diagnostic.getvalue(), "serving_configuration_rejected\n")


if __name__ == "__main__":
    unittest.main()
