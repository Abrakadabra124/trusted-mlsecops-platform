"""ASGI transport contracts with the real controlled collector and signatures."""

import asyncio
import unittest
from unittest.mock import patch

from mlsecops import security_event_http as http
from mlsecops import security_event_runtime as runtime
from mlsecops.contracts import canonical, decode
from scripts import security_event_health_qualification as fixtures


class HttpContracts(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fx = fixtures.HealthContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.book = self.fx.book
        self.book.snapshot = self.book.document
        keys = self.fx.fx.fixture.keys
        self.collector = runtime.Collector(
            self.book,
            keys["receipt"],
            keys["collector"],
            wall=lambda: 2100,
            monotonic=lambda: 1000,
        )
        self.addAsyncCleanup(self.collector.close)
        self.app = http.App(self.collector, "a" * 64, "b" * 64)

    async def asyncTearDown(self):
        await self.collector.close()
        directory = self.fx.fx.fixture.directory
        self.fx.doCleanups()
        self.assertFalse(directory.exists(), "owned fixture directory survived cleanup")

    async def call(self, path, *, method="POST", token="a" * 64, raw=None, headers=None, query=b""):
        raw = canonical(self.fx.fx.envelope()) if raw is None else raw
        request_headers = (
            [
                (b"authorization", ("Bearer " + token).encode("ascii")),
                (b"content-type", b"application/json"),
                (b"content-length", str(len(raw)).encode("ascii")),
            ]
            if headers is None
            else headers
        )
        received, sent = [], []

        async def receive():
            received.append(True)
            return {"type": "http.request", "body": raw}

        async def send(value):
            sent.append(value)

        await self.app(
            {
                "type": "http",
                "method": method,
                "path": path,
                "headers": request_headers,
                "query_string": query,
            },
            receive,
            send,
        )
        self.assertLessEqual(len(sent[1]["body"]), http.MAX_RESPONSE)
        self.assertIn((b"cache-control", b"no-store"), sent[0]["headers"])
        return sent[0]["status"], decode(sent[1]["body"]), received

    async def test_real_ingress_receipt_readback_and_separated_operator_access(self):
        await self.collector.start()
        status, receipt, _ = await self.call("/events")
        self.assertEqual(status, 200)
        self.assertEqual(receipt, self.book.document()["records"][0]["receipt"])
        status, result, _ = await self.call("/incidents/0", method="GET", token="b" * 64, raw=b"")
        self.assertEqual(status, 200)
        self.assertEqual(len(result["incidents"]), 1)
        status, _, received = await self.call("/incidents/0", method="GET", raw=b"")
        self.assertEqual((status, received), (401, []))
        status, _, received = await self.call("/events", token="b" * 64)
        self.assertEqual((status, received), (401, []))

    async def test_bad_framing_size_json_query_and_unknown_routes_do_not_mutate(self):
        await self.collector.start()
        before = self.book.document()
        auth = (b"authorization", b"Bearer " + b"a" * 64)
        for extra in (
            [(b"content-length", b"4097"), (b"content-type", b"application/json")],
            [(b"content-length", b"1"), (b"content-length", b"1")],
            [
                (b"content-length", b"1"),
                (b"content-type", b"application/json"),
                (b"transfer-encoding", b"chunked"),
            ],
            [
                (b"content-length", b"1"),
                (b"content-type", b"application/json"),
                (b"content-encoding", b"gzip"),
            ],
        ):
            self.assertEqual((await self.call("/events", headers=[auth, *extra]))[0], 400)
        self.assertEqual((await self.call("/events", raw=b"{"))[0], 400)
        self.assertEqual((await self.call("/events", query=b"private=canary"))[0], 400)
        self.assertEqual((await self.call("/unknown"))[0], 404)
        self.assertEqual(self.book.document(), before)

    async def test_runtime_refusal_and_outage_are_constant_without_echo(self):
        await self.collector.start()
        self.assertEqual(
            (await self.call("/events", raw=b"{}"))[:2], (503, {"status": "unavailable"})
        )
        with patch.object(self.book, "admit", side_effect=OSError("PRIVATE-CANARY")):
            self.assertEqual((await self.call("/events"))[:2], (503, {"status": "unavailable"}))
        self.assertEqual(self.app.ingress.buckets["0" * 32].inflight, 0)

    async def test_heartbeat_health_pagination_and_quota(self):
        await self.collector.start()
        self.assertEqual(
            (await self.call("/health", method="GET", token="b" * 64, raw=b""))[0], 503
        )
        heartbeat = canonical(self.fx.heartbeat())
        self.assertEqual((await self.call("/heartbeat", raw=heartbeat))[0], 200)
        self.assertEqual(
            (await self.call("/health", method="GET", token="b" * 64, raw=b""))[0], 200
        )
        self.assertEqual(
            (await self.call("/incidents/1025", method="GET", token="b" * 64, raw=b""))[0], 503
        )
        tickets = [self.app.ingress.acquire("0" * 32) for _ in range(4)]
        try:
            status, _, received = await self.call("/events")
            self.assertEqual((status, received), (429, []))
        finally:
            for ticket in tickets:
                ticket.release()

    async def test_lifespan_owns_task_and_start_failure_is_constant(self):
        queue = asyncio.Queue()
        await queue.put({"type": "lifespan.startup"})
        await queue.put({"type": "lifespan.shutdown"})
        sent = []

        async def send(value):
            sent.append(value)

        await self.app({"type": "lifespan"}, queue.get, send)
        self.assertEqual(
            [m["type"] for m in sent], ["lifespan.startup.complete", "lifespan.shutdown.complete"]
        )
        self.assertIsNone(self.collector.task)
        await queue.put({"type": "lifespan.startup"})
        with patch.object(self.book, "poll", side_effect=OSError("PRIVATE-CANARY")):
            await self.app({"type": "lifespan"}, queue.get, send)
        self.assertTrue(self.app.startup_failed)
        self.assertEqual(
            sent[-1], {"type": "lifespan.startup.failed", "message": "security_start_failed"}
        )
        self.assertIsNone(self.collector.task)


if __name__ == "__main__":
    unittest.main()
