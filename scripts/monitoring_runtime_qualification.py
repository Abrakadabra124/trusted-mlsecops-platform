"""Owned scheduled monitoring with a real signed loopback sink."""

import asyncio
import dataclasses
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from mlsecops import monitoring_alerts, monitoring_delivery, monitoring_runtime, signing
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.load_probe import listen
from scripts.monitoring_qualification import reference
from scripts.monitoring_stream_qualification import context


class RuntimeContracts(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.producer, self.sink_key, self.label_key = (
            root / name for name in ("producer.pem", "sink.pem", "labels.pem")
        )
        producer, sink_public, self.label_public = (
            signing.create_key(path) for path in (self.producer, self.sink_key, self.label_key)
        )
        self.reference = reference()
        self.reference_sha256 = digest(canonical(self.reference))
        self.sink = monitoring_alerts.Sink(
            producer, self.sink_key, reference_sha256=self.reference_sha256, epoch="b" * 32
        )
        self.listener = listen(monitoring_delivery.App(self.sink))
        port = self.listener.__enter__()
        self.addCleanup(self.listener.__exit__, None, None, None)
        self.client = monitoring_delivery.Client(
            self.producer,
            sink_public,
            port=port,
            reference_sha256=self.reference_sha256,
            epoch="b" * 32,
        )
        self.runtime = monitoring_runtime.Runtime(
            self.reference, self.reference_sha256, self.label_public, self.client, interval=0.02
        )
        self.runtime.start()
        self.addAsyncCleanup(self.cleanup)
        self.request = 0

    async def cleanup(self):
        try:
            await self.runtime.close()
        except Rejected:
            pass
        self.assertTrue(self.runtime.task is None or self.runtime.task.done())

    async def batch(self, *, shifted=False, count=100):
        rows = [[0.05 if shifted else (index % 10 + 0.5) / 10] * 6 for index in range(count)]
        predictions = [{"decision": "score", "reason": None, "score": row[0]} for row in rows]
        self.runtime.observe(context(), rows, predictions, f"{self.request:032x}")
        self.request += 1
        await asyncio.sleep(0.002)

    async def wait(self, predicate):
        async with asyncio.timeout(5):
            while not predicate(self.runtime.snapshot()):
                await asyncio.sleep(0.01)
        return self.runtime.snapshot()

    async def test_ten_clean_scheduled_windows_and_two_shift_windows_deliver_real_receipts(self):
        for _ in range(100):
            await self.batch()
        result = await self.wait(lambda state: state["windows_evaluated"] == 10)
        self.assertEqual(result["alerts_delivered"], 0)
        self.assertTrue(result["healthy"])
        for _ in range(20):
            await self.batch(shifted=True)
        result = await self.wait(lambda state: state["alerts_delivered"] == 2)
        self.assertEqual(
            [item["kind"] for item in result["receipts"]], ["data_drift", "prediction_drift"]
        )
        self.assertTrue(all(0 <= item["delivery_seconds"] < 120 for item in result["receipts"]))
        self.assertEqual(self.sink._last, 2)
        self.assertFalse(result["release_ready"])
        self.assertNotIn("predictions", canonical(result).decode())

    async def test_signed_delayed_labels_use_retained_actual_observation_ids(self):
        for _ in range(10):
            await self.batch()
        state = await self.wait(lambda item: item["windows_evaluated"] == 1)
        window_sha = state["reports"][-1]["window_sha256"]
        # Scores0.05..0.95 repeat; mark200 observed predictions as positive labels.
        from mlsecops.monitoring_stream import observation_id

        issued = time.time_ns() // 1000000
        document = {
            "schema_version": 1,
            "reference_sha256": self.reference_sha256,
            "window_sha256": window_sha,
            "issued_at_ms": issued,
            "expires_at_ms": issued + 60000,
            "labels": [
                {"observation_id": observation_id(f"{request:032x}", row), "label": 1}
                for request in (0, 1)
                for row in range(100)
            ],
        }
        envelope = signing.sign(document, "monitor-labels", self.label_key)
        result = self.runtime.labels(envelope)
        self.assertEqual(result["alert"], "quality_degradation")
        self.assertEqual(self.runtime.labels(envelope)["accepted_labels"], 0)
        state = await self.wait(lambda item: item["alerts_delivered"] == 1)
        self.assertEqual(state["receipts"][0]["kind"], "quality_degradation")
        with self.assertRaises(Rejected):
            self.runtime.labels(
                signing.sign(
                    {**document, "window_sha256": "f" * 64}, "monitor-labels", self.label_key
                )
            )

    async def test_sink_outage_is_visible_retry_keeps_event_and_recovers(self):
        calls = []
        original = self.client.send

        async def unreliable(event):
            calls.append(dict(event))
            if len(calls) == 1:
                raise Rejected("private transport details")
            return await original(event)

        with patch.object(self.client, "send", side_effect=unreliable):
            for _ in range(20):
                await self.batch(shifted=True)
            state = await self.wait(lambda item: item["delivery_failures"] >= 1)
            self.assertFalse(state["healthy"])
            state = await self.wait(lambda item: item["alerts_delivered"] == 2)
        self.assertEqual(calls[0], calls[1])
        self.assertTrue(state["healthy"])
        self.assertNotIn("private transport", canonical(state).decode())

    async def test_wrong_model_observation_latches_failure_without_collecting(self):
        trace = dataclasses.replace(context(), model_sha256="f" * 64)
        with self.assertRaises(Rejected):
            self.runtime.observe(
                trace, [[0.5] * 6], [{"decision": "score", "reason": None, "score": 0.5}], "f" * 32
            )
        self.assertFalse(self.runtime.snapshot()["healthy"])
        self.assertIn("observation", self.runtime.snapshot()["faults"])
        self.assertEqual(self.runtime.snapshot()["observations"], 0)

    async def test_close_is_idempotent_and_prevents_reactivation_or_new_observations(self):
        await self.runtime.close()
        await self.runtime.close()
        with self.assertRaises(Rejected):
            self.runtime.start()
        with self.assertRaises(Rejected):
            await self.batch()
        self.assertEqual(self.runtime.snapshot()["state"], "stopped")

    async def test_failed_task_creation_closes_coroutine_and_never_claims_running(self):
        await self.runtime.close()
        runtime = monitoring_runtime.Runtime(
            self.reference, self.reference_sha256, self.label_public, self.client
        )
        with patch.object(asyncio, "create_task", side_effect=RuntimeError("private error")):
            with self.assertRaises(Rejected):
                runtime.start()
        self.assertIsNone(runtime.task)
        self.assertFalse(runtime.snapshot()["healthy"])
        await runtime.close()

    async def test_stuck_delivery_cancellation_finishes_owned_task(self):
        async def held(event):
            await asyncio.Event().wait()

        with patch.object(self.client, "send", side_effect=held):
            for _ in range(20):
                await self.batch(shifted=True)
            await self.wait(lambda item: item["pending_alerts"] > 0)
            with self.assertRaises(Rejected):
                await self.runtime.close()
        self.assertTrue(self.runtime.task.done())
        self.assertIn("shutdown", self.runtime.snapshot()["faults"])

    async def test_wall_timestamp_is_not_rounded_behind_legitimate_label_time(self):
        mono, wall = [0], [1000]
        runtime = monitoring_runtime.Runtime(
            self.reference,
            self.reference_sha256,
            self.label_public,
            self.client,
            clock=lambda: mono[0],
            wall_clock=lambda: wall[0],
        )
        mono[0], wall[0] = 950000, 1001
        self.assertEqual(runtime.sample(), (1001, 950000))
        await runtime.close()

    async def test_shutdown_retains_partial_window_as_insufficient_without_inventing_samples(self):
        await self.batch(count=1)
        await self.runtime.close()
        state = self.runtime.snapshot()
        self.assertEqual(state["windows_evaluated"], 1)
        self.assertEqual(state["reports"][0]["status"], "insufficient")
        self.assertEqual(state["reports"][0]["observations"], 1)
        self.assertEqual(state["unclosed_observations"], 0)
        self.assertEqual(state["alerts_delivered"], 0)

    async def test_signed_non_object_labels_fail_with_contract_error(self):
        for document in ([], 1, "private input"):
            with self.subTest(document=type(document).__name__):
                with self.assertRaises(Rejected):
                    self.runtime.labels(signing.sign(document, "monitor-labels", self.label_key))

    async def test_invalid_delivery_identity_roles_and_schedule_are_rejected(self):
        for client, public, options in (
            (object(), self.label_public, {}),
            (self.client, self.client.producer_public, {}),
            (self.client, self.client.sink_public, {}),
            *(
                (self.client, self.label_public, {"interval": value})
                for value in (True, 0, 2, float("nan"))
            ),
        ):
            with self.subTest(options=options, same_role=public != self.label_public):
                with self.assertRaises(Rejected):
                    monitoring_runtime.Runtime(
                        self.reference, self.reference_sha256, public, client, **options
                    )
        with patch.object(self.client, "reference_sha256", "f" * 64):
            with self.assertRaises(Rejected):
                monitoring_runtime.Runtime(
                    self.reference, self.reference_sha256, self.label_public, self.client
                )
        with self.assertRaises(Rejected):
            self.runtime.failed("private arbitrary string")

    async def test_backward_or_discontinuous_clocks_latch_failure_and_disable_health(self):
        for mono, wall in ((-1, 1000), (1, 999), (1, 7000), (False, 1000)):
            runtime = monitoring_runtime.Runtime(
                self.reference,
                self.reference_sha256,
                self.label_public,
                self.client,
                clock=lambda: 0,
                wall_clock=lambda: 1000,
            )
            with (
                patch.object(runtime, "_clock", return_value=mono),
                patch.object(runtime, "_wall_clock", return_value=wall),
            ):
                with self.assertRaisesRegex(Rejected, "monitor_clock_unavailable"):
                    runtime.sample()
                self.assertFalse(runtime.snapshot()["healthy"])
            self.assertEqual(runtime.snapshot()["faults"], ["clock"])
            await runtime.close()

    async def test_repeat_start_owns_one_task_and_scheduler_failure_never_restarts_silently(self):
        original = self.runtime.task
        self.runtime.start()
        self.assertIs(self.runtime.task, original)
        with patch.object(
            self.runtime, "cycle", side_effect=RuntimeError("PRIVATE-SCHEDULER-CANARY")
        ):
            await self.wait(lambda state: "scheduler" in state["faults"])
        self.assertTrue(original.done())
        with self.assertRaisesRegex(Rejected, "monitor_runtime_stopped"):
            self.runtime.start()
        self.assertNotIn("PRIVATE-SCHEDULER-CANARY", canonical(self.runtime.snapshot()).decode())
        await self.runtime.close()
        with self.assertRaisesRegex(Rejected, "monitor_runtime_inactive"):
            self.runtime.labels({})

    async def test_empty_windows_are_insufficient_and_window_queue_overflow_is_visible(self):
        await self.runtime.close()
        mono, wall = [0], [1000]
        runtime = monitoring_runtime.Runtime(
            self.reference,
            self.reference_sha256,
            self.label_public,
            self.client,
            clock=lambda: mono[0],
            wall_clock=lambda: wall[0],
        )
        mono[0], wall[0] = 60000000000, 61000
        await runtime.cycle()
        report = runtime.snapshot()["reports"][-1]
        self.assertEqual(
            (report["status"], report["observations"], report["alerts"]), ("insufficient", 0, [])
        )
        with patch.object(monitoring_runtime, "MAX_READY", 1):
            runtime.finish_window(61001, 61001, 60001000000)
            with self.assertRaisesRegex(Rejected, "monitor_window_queue_full"):
                runtime.finish_window(61002, 61002, 60002000000)
        self.assertEqual(len(runtime._ready), 1)
        mono[0], wall[0] = 60002000000, 61002
        await runtime.close()
        self.assertEqual(runtime.snapshot()["windows_evaluated"], 2)

    async def test_retention_is_bounded_and_pending_receipt_prevents_silent_eviction(self):
        from mlsecops.monitoring_stream import Accumulator

        def closed(sequence):
            return Accumulator(
                self.reference, self.reference_sha256, started_at_ms=1000 + sequence
            ).close(sequence=sequence, ended_at_ms=1001 + sequence)

        with patch.object(monitoring_runtime, "MAX_WINDOWS", 1):
            first, second = closed(1), closed(2)
            self.runtime.retain(first)
            self.runtime._label_reports[first.sha256] = {"status": "insufficient"}
            self.runtime.retain(second)
            self.assertNotIn(first.sha256, self.runtime._windows)
            self.assertNotIn(first.sha256, self.runtime._label_reports)
            self.assertEqual(self.runtime.snapshot()["evicted_windows"], 1)
            now, mono = self.runtime.sample()
            self.runtime.enqueue({"window_sha256": second.sha256}, "telemetry_gap", now, mono)
            with self.assertRaisesRegex(Rejected, "monitor_unacknowledged_window_retention"):
                self.runtime.retain(closed(3))
            self.assertIn(second.sha256, self.runtime._windows)
        await self.wait(lambda state: state["alerts_delivered"] == 1)

    async def test_full_alert_queue_keeps_ready_window_while_pending_delivery_drains(self):
        from mlsecops.monitoring_stream import Accumulator

        await self.runtime.close()
        runtime = monitoring_runtime.Runtime(
            self.reference, self.reference_sha256, self.label_public, self.client
        )
        closed = Accumulator(self.reference, self.reference_sha256, started_at_ms=1000).close(
            sequence=1, ended_at_ms=1001
        )
        runtime.retain(closed)
        now, mono = runtime.sample()
        runtime._ready.append((closed, now, mono))
        runtime.enqueue({"window_sha256": closed.sha256}, "telemetry_gap", now, mono)
        with patch.object(monitoring_runtime, "MAX_ALERTS", 1):
            with self.assertRaisesRegex(Rejected, "monitor_alert_queue_full"):
                runtime.enqueue({"window_sha256": closed.sha256}, "telemetry_gap", now, mono)
            await runtime.cycle()
            self.assertEqual(len(runtime._ready), 1)
            self.assertEqual(runtime.snapshot()["windows_evaluated"], 0)
            self.assertEqual(runtime.snapshot()["alerts_delivered"], 1)
        # Recovery consumes the same preserved window, without a fabricated replacement.
        await runtime.close()
        self.assertEqual(runtime.snapshot()["windows_evaluated"], 1)

    async def test_delivery_deadline_cannot_be_extended_by_late_ack_or_retry(self):
        await self.runtime.close()
        for late_ack in (False, True):
            mono, wall = [0], [1000]
            runtime = monitoring_runtime.Runtime(
                self.reference,
                self.reference_sha256,
                self.label_public,
                self.client,
                clock=lambda: mono[0],
                wall_clock=lambda: wall[0],
            )
            runtime.enqueue({"window_sha256": "f" * 64}, "telemetry_gap", 1000, 0)

            async def delayed(event):
                mono[0], wall[0] = 120000000000, 121000
                return {}

            sender = AsyncMock(side_effect=delayed)
            if not late_ack:
                mono[0], wall[0] = 120000000000, 121000
            with patch.object(self.client, "send", sender):
                await runtime.cycle()
                self.assertEqual(sender.await_count, int(late_ack))
                state = runtime.snapshot()
                self.assertEqual(state["alerts_delivered"], 0)
                self.assertEqual(state["pending_alerts"], 1)
                self.assertIn("delivery", state["faults"])
                with self.assertRaisesRegex(Rejected, "monitor_shutdown_unconfirmed"):
                    await runtime.close()
            self.assertTrue(runtime._closed)

    async def test_cancelled_shutdown_is_propagated_and_partial_state_is_unconfirmed(self):
        await self.batch(count=1)
        with patch.object(self.runtime, "cycle", side_effect=asyncio.CancelledError):
            with self.assertRaises(asyncio.CancelledError):
                await self.runtime.close()
        self.assertTrue(self.runtime.task.done())
        self.assertIn("shutdown", self.runtime.snapshot()["faults"])

    async def test_full_alert_queue_rejects_labels_before_consuming_them(self):
        from mlsecops.monitoring_stream import observation_id

        for _ in range(10):
            await self.batch()
        state = await self.wait(lambda item: item["windows_evaluated"] == 1)
        issued = time.time_ns() // 1000000
        envelope = signing.sign(
            {
                "schema_version": 1,
                "reference_sha256": self.reference_sha256,
                "window_sha256": state["reports"][0]["window_sha256"],
                "issued_at_ms": issued,
                "expires_at_ms": issued + 60000,
                "labels": [{"observation_id": observation_id("0" * 32, 0), "label": 1}],
            },
            "monitor-labels",
            self.label_key,
        )
        with patch.object(monitoring_runtime, "MAX_ALERTS", 0):
            with self.assertRaisesRegex(Rejected, "monitor_alert_queue_full"):
                self.runtime.labels(envelope)
        result = self.runtime.labels(envelope)
        self.assertEqual(result["accepted_labels"], 1)
        self.assertIsNone(result["alert"])
        state = self.runtime.snapshot()
        state["reports"][0]["observations"] = -1
        self.assertEqual(self.runtime.snapshot()["reports"][0]["observations"], 1000)

    async def test_cancellation_resistant_owned_task_is_not_reported_as_stopped(self):
        await self.runtime.close()
        runtime = monitoring_runtime.Runtime(
            self.reference, self.reference_sha256, self.label_public, self.client
        )
        entered, release = asyncio.Event(), asyncio.Event()

        async def resistant():
            entered.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                await release.wait()

        with patch.object(runtime, "run", resistant):
            runtime.start()
            await entered.wait()
            try:
                with self.assertRaisesRegex(Rejected, "monitor_shutdown_pending"):
                    await runtime.close()
                self.assertFalse(runtime._closed)
                self.assertFalse(runtime.task.done())
                self.assertIn("shutdown", runtime.snapshot()["faults"])
            finally:
                release.set()
                await asyncio.wait_for(runtime.task, 1)
                await runtime.close()
        await runtime.run()  # A stopped owner must not enter another cycle.

    async def test_same_millisecond_shutdown_waits_then_seals_complete_window_once(self):
        await self.runtime.close()
        mono, wall = [0], [1000]
        runtime = monitoring_runtime.Runtime(
            self.reference,
            self.reference_sha256,
            self.label_public,
            self.client,
            clock=lambda: mono[0],
            wall_clock=lambda: wall[0],
        )
        runtime.start()
        rows = [[0.05 + 0.1 * (index % 10)] * 6 for index in range(100)]
        predictions = [{"decision": "score", "reason": None, "score": row[0]} for row in rows]
        for index in range(10):
            runtime.observe(context(), rows, predictions, f"{index:032x}")

        samples = [0]

        def tick():
            samples[0] += 1
            return 0 if samples[0] == 1 else 2000000

        # Patch only this owner's clocks, never asyncio.sleep shared by the sink server.
        with (
            patch.object(runtime, "_clock", tick),
            patch.object(
                runtime, "_wall_clock", side_effect=lambda: 1000 if samples[0] == 1 else 1002
            ),
        ):
            await runtime.close()
        self.assertEqual(runtime.snapshot()["windows_evaluated"], 1)
        self.assertEqual(runtime.snapshot()["reports"][0]["observations"], 1000)
        self.assertTrue(runtime.task.done())


if __name__ == "__main__":
    unittest.main()
