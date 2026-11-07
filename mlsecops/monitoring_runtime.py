"""Single-event-loop owner for bounded monitoring windows and alert delivery.

Only the HTTP owner may submit completed predictions. No release transition or
training path exists here. Restart requires a new explicit producer epoch.
"""

import asyncio
import math
import time
from collections import OrderedDict, deque

from mlsecops import (
    monitoring,
    monitoring_alerts,
    monitoring_delivery,
    monitoring_labels,
    monitoring_state,
    monitoring_stream,
)
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.release_policy import checked

MAX_WINDOWS = 20
MAX_READY = 32
MAX_ALERTS = 64
FAULTS = ("clock", "observation", "queue", "delivery", "scheduler", "shutdown")


class Runtime:
    def __init__(
        self,
        reference,
        reference_sha256,
        label_public,
        client,
        *,
        interval=0.25,
        clock=time.monotonic_ns,
        wall_clock=lambda: time.time_ns() // 1000000,
        epoch_guard=None,
    ):
        self._evaluator = monitoring.Evaluator(reference, reference_sha256)
        if (
            type(client) is not monitoring_delivery.Client
            or client.reference_sha256 != reference_sha256
        ):
            raise Rejected("monitor_delivery_configuration")
        self._label_public = monitoring_alerts.public_key(label_public)
        if self._label_public in (client.producer_public, client.sink_public):
            raise Rejected("monitor_roles_not_separated")
        if (
            type(interval) not in (int, float)
            or not math.isfinite(interval)
            or not 0 < interval <= 1
        ):
            raise Rejected("monitor_schedule_interval")
        self._reference, self._reference_sha256 = decode(canonical(reference)), reference_sha256
        self._client, self._interval, self._clock, self._wall_clock = (
            client,
            interval,
            clock,
            wall_clock,
        )
        self._origin_ns = monitoring.integer(clock(), 0, 2**63 - 1)
        self._origin_ms = monitoring.integer(wall_clock(), reference["frozen_at_ms"], 2**53 - 1)
        self._last_ns = self._origin_ns
        self._last_wall_ms = self._origin_ms
        self._current = monitoring_stream.Accumulator(
            reference, reference_sha256, started_at_ms=self._origin_ms
        )
        self._started, self._count, self._sequence, self._alert_sequence = self._origin_ms, 0, 1, 1
        self._ready, self._pending = deque(), deque()
        self._windows, self._label_reports = OrderedDict(), {}
        self._reports, self._receipts = deque(maxlen=MAX_WINDOWS), deque(maxlen=128)
        self._faults = set()
        self._observations = self._evaluated = self._delivered = self._delivery_failures = (
            self._evicted
        ) = 0
        self._last_cycle = None
        self._closed = self._stopping = False
        self.task = None
        if epoch_guard is not None and (
            type(epoch_guard) is not monitoring_state.Guard
            or (epoch_guard.role, epoch_guard.epoch, epoch_guard.reference)
            != ("producer", client.epoch, reference_sha256)
        ):
            raise Rejected("monitor_epoch_guard")
        self._epoch_guard, self._epoch_receipt = epoch_guard, None

    def failed(self, kind):
        if kind not in FAULTS:
            raise Rejected("monitor_failure_kind")
        self._faults.add(kind)

    def sample(self):
        try:
            current = monitoring.integer(self._clock(), self._last_ns, 2**63 - 1)
            wall = monitoring.integer(self._wall_clock(), self._last_wall_ms, 2**53 - 1)
            expected = self._origin_ms + (current - self._origin_ns) // 1000000
            if abs(wall - expected) > 5000:
                raise Rejected("monitor_clock_discontinuity")
            self._last_ns = current
            self._last_wall_ms = wall
            return wall, current
        except Exception:
            self.failed("clock")
            raise Rejected("monitor_clock_unavailable") from None

    def start(self):
        if self._closed:
            raise Rejected("monitor_runtime_closed")
        if self.task is not None:
            if self.task.done():
                raise Rejected("monitor_runtime_stopped")
            return
        if self._epoch_guard is not None:
            self._epoch_receipt = self._epoch_guard.claim()
            if self._epoch_receipt["history_unavailable"]:
                wall, mono = self.sample()
                report = {
                    "schema_version": 1,
                    "reason": "new_epoch_history_unavailable",
                    "window_sha256": digest(canonical(self._epoch_receipt)),
                    "admission": self._epoch_receipt,
                }
                self.enqueue(report, "telemetry_gap", wall, mono)
        operation = self.run()
        try:
            self.task = asyncio.create_task(operation, name="mlsecops-monitor")
        except Exception:
            operation.close()
            self.failed("scheduler")
            raise Rejected("monitor_scheduler_start") from None

    def finish_window(self, ended, admitted_ms, admitted_ns):
        if len(self._ready) >= MAX_READY:
            self.failed("queue")
            raise Rejected("monitor_window_queue_full")
        closed = self._current.close(sequence=self._sequence, ended_at_ms=ended)
        self._ready.append((closed, admitted_ms, admitted_ns))
        self._current = monitoring_stream.Accumulator(
            self._reference, self._reference_sha256, started_at_ms=ended
        )
        self._started, self._count, self._sequence = ended, 0, self._sequence + 1

    def rotate(self, now_ms, now_ns):
        while now_ms - self._started >= 60000:
            self.finish_window(self._started + 60000, now_ms, now_ns)
        if self._count >= monitoring.MIN_OBSERVATIONS and now_ms > self._started:
            self.finish_window(now_ms, now_ms, now_ns)

    def observe(self, context, features, predictions, request_id):
        try:
            if self._stopping or self._closed or self.task is None or self.task.done():
                raise Rejected("monitor_runtime_inactive")
            now_ms, now_ns = self.sample()
            self.rotate(now_ms, now_ns)
            self._current.add(context, features, predictions, request_id)
            self._count += len(features)
            self._observations += len(features)
            self.rotate(now_ms, now_ns)
        except Exception:
            self.failed("observation")
            raise Rejected("monitor_observation_rejected") from None

    def enqueue(self, report, kind, admitted_ms, admitted_ns):
        if len(self._pending) >= MAX_ALERTS:
            self.failed("queue")
            raise Rejected("monitor_alert_queue_full")
        event = monitoring_alerts.event(
            reference_sha256=self._reference_sha256,
            window_sha256=report["window_sha256"],
            evidence_sha256=digest(canonical(report)),
            epoch=self._client.epoch,
            sequence=self._alert_sequence,
            kind=kind,
            admitted_at_ms=admitted_ms,
        )
        self._pending.append((event, admitted_ns))
        self._alert_sequence += 1

    def retain(self, closed):
        incoming = closed.document()["observations"]
        retained = sum(item[0].document()["observations"] for item in self._windows.values())
        while self._windows and (
            len(self._windows) >= MAX_WINDOWS or retained + incoming > monitoring.MAX_OBSERVATIONS
        ):
            key = next(iter(self._windows))
            if any(event["window_sha256"] == key for event, _ in self._pending):
                self.failed("queue")
                raise Rejected("monitor_unacknowledged_window_retention")
            previous, _ = self._windows.pop(key)
            retained -= previous.document()["observations"]
            self._label_reports.pop(key, None)
            self._evicted += 1
        self._windows[closed.sha256] = (
            closed,
            monitoring_labels.Labels(
                self._reference, self._reference_sha256, closed, closed.sha256, self._label_public
            ),
        )

    def labels(self, envelope):
        if self._closed or self._stopping or self.task is None or self.task.done():
            raise Rejected("monitor_runtime_inactive")
        document = checked(envelope, "monitor-labels", self._label_public)
        monitoring.schema(
            document,
            ("reference_sha256", "window_sha256", "issued_at_ms", "expires_at_ms", "labels"),
        )
        window = monitoring.sha256(document["window_sha256"])
        if window not in self._windows:
            raise Rejected("monitor_labels_unknown_window")
        if len(self._pending) >= MAX_ALERTS:
            self.failed("queue")
            raise Rejected("monitor_alert_queue_full")
        now_ms, now_ns = self.sample()
        result = self._windows[window][1].accept(envelope, clock_ms=now_ms)
        previous = self._label_reports.get(window)
        self._label_reports[window] = decode(canonical(result))
        if result["alert"] is not None and (
            previous is None or previous["alert"] != result["alert"]
        ):
            self.enqueue(result, result["alert"], now_ms, now_ns)
        return result

    async def cycle(self):
        now_ms, now_ns = self.sample()
        self.rotate(now_ms, now_ns)
        # Each window can generate at most two drift alerts, or one gap alert.
        # Keep the window intact under backpressure and deliver pending events first.
        while self._ready and len(self._pending) <= MAX_ALERTS - 2:
            closed, admitted_ms, admitted_ns = self._ready[0]
            self.retain(closed)
            report = self._evaluator.evaluate(closed.document())
            self._reports.append(report)
            self._evaluated += 1
            for kind in report["alerts"]:
                self.enqueue(report, kind, admitted_ms, admitted_ns)
            self._ready.popleft()
        self._last_cycle = now_ns
        if self._pending:
            event, admitted_ns = self._pending[0]
            try:
                if now_ns - admitted_ns >= 120000000000:
                    raise Rejected("monitor_delivery_deadline")
                acknowledgement = await self._client.send(event)
                _, finished = self.sample()
                if not 0 <= finished - admitted_ns < 120000000000:
                    raise Rejected("monitor_delivery_deadline")
                receipt = monitoring_alerts.receipt(
                    acknowledgement, event, self._client.sink_public
                )
            except Exception:
                self.failed("delivery")
                self._delivery_failures += 1
            else:
                self._pending.popleft()
                self._delivered += 1
                self._receipts.append(
                    {
                        "kind": event["kind"],
                        "window_sha256": event["window_sha256"],
                        "event_sha256": receipt["event_sha256"],
                        "received_at_ms": receipt["received_at_ms"],
                        "delivery_seconds": (finished - admitted_ns) / 1000000000,
                        "envelope": acknowledgement,
                        "event": event,
                        "admitted_ns": admitted_ns,
                        "finished_ns": finished,
                    }
                )
                self._faults.discard("delivery")
                self._last_cycle = finished

    async def run(self):
        try:
            while not self._stopping:
                await self.cycle()
                # A failed send cannot spin without the scheduled interval.
                await asyncio.sleep(self._interval)
        except Exception:
            self.failed("scheduler")

    def snapshot(self):
        running = not self._closed and self.task is not None and not self.task.done()
        try:
            _, now = self.sample()
            fresh = self._last_cycle is not None and 0 <= now - self._last_cycle <= 3000000000
        except Rejected:
            fresh = False
        document = {
            "schema_version": 1,
            "reference_sha256": self._reference_sha256,
            "epoch": self._client.epoch,
            "epoch_admission": self._epoch_receipt,
            "history_restored": False,
            "state": "stopped" if self._closed else "observing" if running else "inactive",
            "healthy": running and fresh and not self._faults,
            "faults": sorted(self._faults),
            "observations": self._observations,
            "unclosed_observations": self._count,
            "data_status": self._reports[-1]["status"] if self._reports else "insufficient",
            "windows_evaluated": self._evaluated,
            "pending_windows": len(self._ready),
            "pending_alerts": len(self._pending),
            "alerts_delivered": self._delivered,
            "delivery_failures": self._delivery_failures,
            "evicted_windows": self._evicted,
            "reports": list(self._reports),
            "label_reports": list(self._label_reports.values()),
            "receipts": [
                {
                    key: value
                    for key, value in receipt.items()
                    if key not in ("envelope", "event", "admitted_ns", "finished_ns")
                }
                for receipt in self._receipts
            ],
            "release_ready": False,
        }
        return decode(canonical(document))

    async def close(self):
        if self._closed:
            return
        self._stopping = True
        if self.task is not None:
            self.task.cancel()
            done, _ = await asyncio.wait((self.task,), timeout=3)
            if self.task not in done:
                self.failed("shutdown")
                raise Rejected("monitor_shutdown_pending")
            if not self.task.cancelled():
                self.task.result()
        try:
            if self._count:
                now_ms, now_ns = self.sample()
                if now_ms <= self._started:
                    await asyncio.sleep(0.002)
                    now_ms, now_ns = self.sample()
                self.rotate(now_ms, now_ns)
                if self._count:
                    self.finish_window(now_ms, now_ms, now_ns)
            async with asyncio.timeout(3):
                while self._ready or self._pending:
                    await self.cycle()
                    if "delivery" in self._faults:
                        break
        except asyncio.CancelledError:
            self.failed("shutdown")
            raise
        except Exception:
            self.failed("shutdown")
            raise Rejected("monitor_shutdown_unconfirmed") from None
        finally:
            self._closed = True
        if self._ready or self._pending:
            self.failed("shutdown")
            raise Rejected("monitor_shutdown_unconfirmed")
