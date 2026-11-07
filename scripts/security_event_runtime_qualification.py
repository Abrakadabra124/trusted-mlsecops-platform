"""Controlled scheduler lifecycle and ingress checks, not elapsed-time acceptance."""

import asyncio
import unittest
from unittest.mock import patch

from mlsecops import security_event_runtime as runtime
from mlsecops.contracts import Rejected
from scripts import security_event_health_qualification as fixtures


class RuntimeContracts(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fx = fixtures.HealthContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.clock = 2100
        self.mono = 1000
        self.book = self.fx.book
        self.book.snapshot = self.book.document
        keys = self.fx.fx.fixture.keys
        self.runtime = runtime.Collector(
            self.book,
            keys["receipt"],
            keys["collector"],
            wall=lambda: self.clock,
            monotonic=lambda: self.mono,
        )
        self.addAsyncCleanup(self.runtime.close)

    def advance(self, milliseconds):
        self.clock += milliseconds
        self.mono += milliseconds

    async def test_lifecycle_admission_receipt_and_operator_health(self):
        with self.assertRaises(Rejected):
            self.runtime.health()
        await self.runtime.start()
        self.runtime.heartbeat(self.fx.heartbeat())
        receipt = self.runtime.ingest(self.fx.fx.envelope())
        record = self.book.document()["records"][0]
        self.assertEqual(receipt, record["receipt"])
        self.assertTrue(self.runtime.health()["healthy"])
        self.assertEqual(len(self.runtime.incidents(0)["incidents"]), 1)
        self.assertIsNone(self.runtime.incidents(0)["next_offset"])
        self.assertEqual(self.runtime.ingest(self.fx.fx.envelope()), receipt)
        task = self.runtime.task
        await self.runtime.close()
        self.assertTrue(task.done())
        with self.assertRaises(Rejected):
            self.runtime.ingest(self.fx.fx.envelope())

    async def test_tick_generates_gap_once_routes_and_preserves_it_after_restart(self):
        await self.runtime.start()
        self.advance(90000)
        self.runtime.tick()
        self.assertFalse(self.runtime.health()["healthy"])
        self.assertEqual(len(self.runtime.incidents(0)["incidents"]), 1)
        self.runtime.tick()
        self.assertEqual(len(self.book.document()["records"]), 1)
        await self.runtime.close()
        await self.runtime.start()
        self.assertEqual(len(self.runtime.incidents(0)["incidents"]), 1)

    async def test_storage_error_never_returns_healthy_and_next_tick_can_recover(self):
        await self.runtime.start()
        self.runtime.heartbeat(self.fx.heartbeat())
        with patch.object(self.book, "poll", side_effect=Rejected("simulated failure")):
            with self.assertRaises(Rejected):
                self.runtime.health()
        with patch.object(self.book, "route", side_effect=Rejected("simulated failure")):
            with self.assertRaises(Rejected):
                self.runtime.ingest(self.fx.fx.envelope())
        self.assertFalse(self.runtime.health()["healthy"])
        self.runtime.tick()
        self.assertTrue(self.runtime.health()["healthy"])

    async def test_clock_divergence_is_sticky_and_cannot_rebase_receipt_time(self):
        await self.runtime.start()
        self.clock += 6000
        with self.assertRaises(Rejected):
            self.runtime.tick()
        self.mono += 6000
        with self.assertRaises(Rejected):
            self.runtime.health()

    async def test_scheduler_task_is_owned_and_start_failure_leaves_no_task(self):
        with patch.object(asyncio, "create_task", side_effect=RuntimeError("simulated failure")):
            with self.assertRaises(RuntimeError):
                await self.runtime.start()
        self.assertIsNone(self.runtime.task)
        with self.assertRaises(Rejected):
            self.runtime.health()
        await self.runtime.start()
        with self.assertRaises(Rejected):
            await self.runtime.start()


if __name__ == "__main__":
    unittest.main()
