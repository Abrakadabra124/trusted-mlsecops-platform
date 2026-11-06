"""Portable contracts for the M14 client, not native M14 acceptance."""

import asyncio
import unittest
from contextlib import suppress

from mlsecops import load_measurement as load
from mlsecops.contracts import Rejected, canonical


def summary(sample, **kwargs):
    return load.summarize(sample, elapsed_ns=132_000_000_000, **kwargs)


def rows(count=1000):
    warmup = [
        {"client": i, "start_ns": 0, "end_ns": 10_000_000, "status": 200, "outcome": "ok"}
        for i in range(10)
    ]
    interval = min(100_000_000, 100_000_000_000 // max(1, count))
    return warmup + [
        {
            "client": i % 10,
            "start_ns": 10_000_000_000 + i * interval,
            "end_ns": 10_010_000_000 + i * interval,
            "status": 200,
            "outcome": "ok",
        }
        for i in range(count)
    ]


class ReportContracts(unittest.TestCase):
    def test_clean_profile_and_exact_nearest_rank(self):
        result = summary(rows())
        self.assertTrue(result["profile_met"])
        self.assertEqual(result["measured"]["attempts"], 1000)
        self.assertEqual(result["measured"]["latency_ms"]["p99"], 10)
        self.assertEqual(result["measured"]["rps"], 1000 / 120)
        self.assertEqual(load.distribution([1, 2, 3, 100])["p95"], 100)

    def test_warmup_selected_by_start_and_tail_is_not_lost(self):
        sample = rows()
        sample += [
            dict(sample[0], client=9, start_ns=9_999_999_999, end_ns=10_500_000_000),
            dict(sample[0], start_ns=129_999_999_999, end_ns=131_000_000_000),
        ]
        sample.sort(key=lambda r: (r["start_ns"], r["client"]))
        result = summary(sample)
        self.assertEqual(result["warmup"]["attempts"], 11)
        self.assertEqual(result["measured"]["attempts"], 1001)
        self.assertEqual(result["measured"]["latency_ms"]["max"], 1000.000001)

    def test_timeouts_quotas_errors_and_mismatches_are_never_dropped(self):
        for status, outcome in [
            (0, "timeout"),
            (0, "transport"),
            (429, "limited"),
            (200, "mismatch"),
            (503, "http_error"),
        ]:
            with self.subTest(outcome=outcome):
                sample = rows()
                sample[-1].update(status=status, outcome=outcome, end_ns=112_000_000_000)
                result = summary(sample)
                self.assertFalse(result["profile_met"])
                self.assertEqual(result["measured"]["attempts"], 1000)
                self.assertEqual(result["measured"]["outcomes"][outcome], 1)
                self.assertEqual(result["measured"]["latency_ms"]["max"], 2100)

    def test_fast_denials_cannot_replace_successful_predictions(self):
        sample = rows()
        for row in sample:
            row.update(status=429, outcome="limited")
        result = summary(sample)
        self.assertFalse(result["profile_met"])
        self.assertIsNone(result["measured"]["success_latency_ms"])

    def test_warmup_wrong_digest_still_invalidates_profile(self):
        sample = rows()
        sample[0]["outcome"] = "mismatch"
        self.assertFalse(summary(sample)["profile_met"])

    def test_malformed_missing_client_and_overlapping_rows_rejected(self):
        for field, value in [
            ("client", True),
            ("client", 10),
            ("start_ns", -1),
            ("start_ns", 130_000_000_000),
            ("end_ns", -1),
            ("end_ns", float("inf")),
            ("status", True),
            ("status", 201),
            ("outcome", "secret"),
            ("status", 0),
        ]:
            sample = rows()
            sample[0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(Rejected):
                summary(sample)
        with self.assertRaises(Rejected):
            summary(rows() + [rows()[0]])
        self.assertFalse(summary([row for row in rows() if row["client"] == 0])["profile_met"])
        sample = rows()
        sample[0]["raw_body"] = "private"
        with self.assertRaises(Rejected):
            summary(sample)

    def test_empty_or_capped_run_never_passes(self):
        for sample in ([], rows(999)):
            self.assertFalse(summary(sample)["profile_met"])
        self.assertFalse(summary(rows(), exhausted=True)["profile_met"])

    def test_missing_window_invalid_envelope_and_redirect_never_pass(self):
        self.assertFalse(load.summarize(rows(), elapsed_ns=110_000_000_000)["profile_met"])
        for elapsed in (True, -1, 1.0, 2**63):
            with self.subTest(elapsed=elapsed), self.assertRaises(Rejected):
                load.summarize([], elapsed_ns=elapsed)
        for sample, exhausted in (((), False), ([], 1), ([{}] * (load.MAX_ATTEMPTS + 1), False)):
            with self.assertRaises(Rejected):
                summary(sample, exhausted=exhausted)
        sample = rows()
        sample[0].update(status=302, outcome="http_error")
        self.assertFalse(summary(sample)["profile_met"])

    def test_warmup_coverage_latency_and_error_thresholds_are_exact(self):
        self.assertFalse(summary(rows()[10:])["profile_met"])
        sample = rows(2000)
        sample[-1].update(status=503, outcome="http_error")
        self.assertTrue(summary(sample)["profile_met"])
        sample[-2].update(status=503, outcome="http_error")
        self.assertFalse(summary(sample)["profile_met"])
        for milliseconds, expected in ((200, True), (201, False)):
            sample = rows()
            for row in sample:
                row["end_ns"] = row["start_ns"] + milliseconds * 1_000_000
            self.assertEqual(summary(sample)["profile_met"], expected)
        for milliseconds, expected in ((500, True), (501, False)):
            sample = rows()
            for row in sample[-11:]:
                row["end_ns"] = row["start_ns"] + milliseconds * 1_000_000
            self.assertEqual(summary(sample)["profile_met"], expected)


class ClientContracts(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, reply, *, delay=0, timeout=0.2, prefix=b""):
        received = []
        tasks = set()

        async def handler(reader, writer):
            task = asyncio.current_task()
            tasks.add(task)
            try:
                received.append(await reader.readuntil(b"\r\n\r\n"))
                writer.write(prefix)
                await writer.drain()
                await asyncio.sleep(delay)
                writer.write(reply)
                await writer.drain()
            except (ConnectionError, asyncio.IncompleteReadError):
                # The timeout test may close before Windows delivers the connection.
                pass
            finally:
                writer.close()
                with suppress(ConnectionError):
                    await writer.wait_closed()
                tasks.remove(task)

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        try:
            result = await load.request(
                server.sockets[0].getsockname()[1], "a" * 64, b"{}", timeout=timeout
            )
            return result, received
        finally:
            server.close()
            await server.wait_closed()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def test_bounded_loopback_http(self):
        body = canonical({"hello": "world"})
        result, received = await self.exercise(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\n\r\n"
            + body
        )
        self.assertEqual(result, (200, {"hello": "world"}))
        self.assertIn(b"Connection: close\r\n", received[0])
        self.assertIn(b"POST /v1/predict HTTP/1.1\r\n", received[0])

    async def test_absolute_timeout_includes_response_body(self):
        with self.assertRaises(TimeoutError):
            await self.exercise(b"", delay=0.06, timeout=0.01)
        with self.assertRaises(TimeoutError):
            await self.exercise(
                b"}",
                prefix=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{",
                delay=0.1,
                timeout=0.05,
            )

    async def test_ambiguous_large_and_truncated_response_rejected(self):
        for reply in [
            b"bad\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\ninvalid-header\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nBad Name: x\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nX: " + b"x" * 17000 + b"\r\n\r\n",
        ]:
            with self.subTest(size=len(reply)), self.assertRaises((Rejected, ValueError, EOFError)):
                await self.exercise(reply)

    async def test_reject_configuration_before_opening_connections(self):
        for port, token, body in [
            (True, "a" * 64, b"{}"),
            (0, "a" * 64, b"{}"),
            (1, "private\r\n", b"{}"),
            (1, "a" * 64, b""),
            (1, "a" * 64, b"x" * 65537),
        ]:
            with self.assertRaisesRegex(Rejected, "load_request_contract"):
                await load.request(port, token, body)
        for options in (
            {"warmup": -1},
            {"duration": 0},
            {"duration": float("nan")},
            {"limit": True},
            {"limit": 9},
            {"warmup": float("inf")},
        ):
            with self.assertRaisesRegex(Rejected, "load_collection_profile"):
                await load.collect(None, None, **options)

    async def test_ten_clients_and_failures_accounted_once(self):
        active, peak = 0, 0
        all_started = asyncio.Event()

        async def exchange(client):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            if active == 10:
                all_started.set()
            try:
                await all_started.wait()
                await asyncio.sleep(0.01)
                if client == 0:
                    raise TimeoutError
                if client == 1:
                    raise OSError("private exception")
                return 200, {"valid": True}
            finally:
                active -= 1

        observation = await load.collect(
            exchange, lambda _: True, warmup=0.1, duration=0.4, limit=1000
        )
        sample, exhausted = observation["records"], observation["exhausted"]
        self.assertEqual(peak, 10)
        self.assertEqual(active, 0)
        self.assertFalse(exhausted)
        self.assertEqual({r["client"] for r in sample}, set(range(10)))
        self.assertEqual({r["outcome"] for r in sample}, {"ok", "timeout", "transport"})
        self.assertNotIn("private", str(sample))

    async def test_limit_bounds_completed_and_inflight_work(self):
        async def exchange(client):
            await asyncio.sleep(0)
            return 429, {}

        observation = await load.collect(exchange, lambda _: False, warmup=0, duration=1, limit=25)
        sample, exhausted = observation["records"], observation["exhausted"]
        self.assertTrue(exhausted)
        self.assertEqual(len(sample), 25)
        self.assertTrue(all(row["outcome"] == "limited" for row in sample))

    async def test_response_validation_failure_is_recorded_and_cancellation_propagates(self):
        async def exchange(client):
            return 200, {}

        observation = await load.collect(
            exchange, lambda _: "not a boolean", warmup=0, duration=1, limit=10
        )
        self.assertEqual({row["outcome"] for row in observation["records"]}, {"mismatch"})
        task = asyncio.create_task(load.collect(exchange, lambda _: True, warmup=0, duration=10))
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task


if __name__ == "__main__":
    unittest.main()
