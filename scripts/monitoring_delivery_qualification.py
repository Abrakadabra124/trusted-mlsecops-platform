"""Real owned loopback HTTP, signatures, total deadlines and transport cleanup."""

import asyncio
import time
import unittest
from unittest.mock import patch

from mlsecops import monitoring_alerts, monitoring_delivery, signing
from mlsecops.contracts import Rejected, canonical
from mlsecops.load_probe import listen
from scripts import monitoring_alerts_qualification as fixtures


class DeliveryContracts(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fixture = fixtures.AlertContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def client(self, port):
        return monitoring_delivery.Client(
            self.fixture.producer,
            self.fixture.sink_public,
            port=port,
            reference_sha256="a" * 64,
            epoch="b" * 32,
        )

    async def test_actual_http_round_trip_idempotent_ack_and_sequence_rejection(self):
        app = monitoring_delivery.App(self.fixture.sink, clock=lambda: 2000)
        with listen(app) as port:
            client = self.client(port)
            event = self.fixture.event()
            first = await client.send(event)
            self.assertEqual(await client.send(event), first)
            self.assertEqual(
                monitoring_alerts.receipt(first, event, self.fixture.sink_public)["received_at_ms"],
                2000,
            )
            with self.assertRaises(Rejected):
                await client.send(self.fixture.event(3))
            with self.assertRaises(Rejected):
                await monitoring_delivery.exchange(port, {"forged": True})
        self.assertEqual(self.fixture.sink._last, 1)

    async def fake(self, payload, *, hold=False):
        tasks = set()

        async def handle(reader, writer):
            task = asyncio.current_task()
            tasks.add(task)
            try:
                await reader.readuntil(b"\r\n\r\n")
                if hold:
                    await asyncio.Event().wait()
                else:
                    writer.write(payload)
                    await writer.drain()
            finally:
                writer.close()
                tasks.discard(task)

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        async def close():
            server.close()
            pending = list(tasks)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            await asyncio.wait_for(server.wait_closed(), timeout=3)
            self.assertFalse(tasks)

        self.addAsyncCleanup(close)
        return port

    async def test_untrusted_http_framing_and_json_are_not_receipts(self):
        responses = (
            b"bad\r\n\r\n",
            b"HTTP/1.1 302 Found\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: 16385\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nxx",
            b"HTTP/1.1 200 OK\r\nMalformed\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-Pad: " + b"x" * 9000 + b"\r\n\r\n",
        )
        for response in responses:
            port = await self.fake(response)
            with self.subTest(response=response[:25]), self.assertRaises(Rejected):
                await self.client(port).send(self.fixture.event())

    async def test_timeout_bounds_full_exchange_and_closes_owned_connection(self):
        port = await self.fake(b"", hold=True)
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            await self.client(port).send(self.fixture.event())
        self.assertLess(time.monotonic() - started, 3)

    async def test_http_success_without_authentic_bound_receipt_is_rejected(self):
        for envelope in ({}, self.fixture.send(self.fixture.event(1))):
            body = canonical(envelope)
            raw = (
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
            port = await self.fake(raw)
            with self.assertRaises(Rejected):
                await self.client(port).send(self.fixture.event(2))

    async def test_client_configuration_and_event_are_pinned_before_network(self):
        for port in (True, 0, 65536, "80"):
            with self.assertRaises(Rejected):
                self.client(port)
        with self.assertRaises(Rejected):
            monitoring_delivery.Client(
                self.fixture.sink_key,
                self.fixture.sink_public,
                port=12345,
                reference_sha256="a" * 64,
                epoch="b" * 32,
            )
        for key, value in (("reference_sha256", "f" * 64), ("epoch", "f" * 32)):
            with self.assertRaises(Rejected):
                await self.client(12345).send({**self.fixture.event(), key: value})
        for payload in ({"oversized": "x" * 20000}, None):
            with self.assertRaises(Rejected):
                await monitoring_delivery.exchange(12345, payload)


class SinkHttpContracts(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fixture = fixtures.AlertContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.app = monitoring_delivery.App(self.fixture.sink, clock=lambda: 2000)

    async def invoke(
        self, *, body=None, headers=None, path="/v1/alerts", method="POST", query=b"", messages=None
    ):
        body = (
            canonical(signing.sign(self.fixture.event(), "monitor-alert", self.fixture.producer))
            if body is None
            else body
        )
        headers = (
            [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
            if headers is None
            else headers
        )
        pending = list(messages or [{"type": "http.request", "body": body, "more_body": False}])
        sent = []

        async def receive():
            return pending.pop(0)

        async def send(message):
            sent.append(message)

        await self.app(
            {
                "type": "http",
                "path": path,
                "method": method,
                "query_string": query,
                "headers": headers,
            },
            receive,
            send,
        )
        return sent

    async def test_request_boundary_rejects_invalid_frames_without_consuming_sequence(self):
        for options in (
            {"method": "GET"},
            {"path": "/other"},
            {"query": b"x=1"},
            {"body": b"bad"},
            {"headers": []},
            {"headers": [(b"content-type", b"text/plain"), (b"content-length", b"1")]},
            {"headers": [(b"content-type", b"application/json"), (b"content-length", b"20000")]},
            {
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", b"1"),
                    (b"content-length", b"1"),
                ]
            },
            {
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", b"1"),
                    (b"transfer-encoding", b"chunked"),
                ]
            },
            {"messages": [{"type": "http.disconnect"}]},
            {"messages": [{"type": "http.request", "body": b"x" * 17000, "more_body": False}]},
        ):
            with self.subTest(options=str(options)[:80]):
                result = await self.invoke(**options)
                self.assertEqual(result[0]["status"], 400)
                self.assertEqual(result[1]["body"], b'{"status":"rejected"}')
        self.assertEqual(self.fixture.sink._last, 0)
        self.assertEqual((await self.invoke())[0]["status"], 200)

    async def test_oversized_chunk_is_rejected_before_copying_into_body_buffer(self):
        class GuardedBuffer(bytearray):
            def extend(self, content):
                raise AssertionError("oversized chunk reached allocation")

        with patch.object(monitoring_delivery, "bytearray", GuardedBuffer, create=True):
            result = await self.invoke(
                messages=[{"type": "http.request", "body": b"x" * 17000, "more_body": False}]
            )
        self.assertEqual(result[0]["status"], 400)

    async def test_fragmented_valid_body_and_truncated_body(self):
        body = canonical(signing.sign(self.fixture.event(), "monitor-alert", self.fixture.producer))
        messages = [
            {"type": "http.request", "body": body[:10], "more_body": True},
            {"type": "http.request", "body": body[10:], "more_body": False},
        ]
        self.assertEqual((await self.invoke(body=body, messages=messages))[0]["status"], 200)
        self.assertEqual(
            (
                await self.invoke(
                    messages=[{"type": "http.request", "body": b"{}", "more_body": False}]
                )
            )[0]["status"],
            400,
        )

    async def test_wrong_app_configuration_and_unknown_asgi_protocol_are_rejected(self):
        for sink, clock in ((object(), lambda: 2000), (self.fixture.sink, None)):
            with self.assertRaises(Rejected):
                monitoring_delivery.App(sink, clock=clock)

        async def receive():
            return {"type": "unexpected"}

        async def send(message):
            self.fail("unknown protocol must not return success")

        for kind in ("websocket", "lifespan"):
            with self.assertRaises(Rejected):
                await self.app({"type": kind}, receive, send)


if __name__ == "__main__":
    unittest.main()
