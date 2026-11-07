"""One process-owned scheduler and durable local incident inbox.

All Store calls run serially on the ASGI event loop. No detached worker can
commit after cancellation. Filesystem stalls are not a bounded-I/O guarantee.
"""

import asyncio
import time

from mlsecops import security_event_ledger as ledger
from mlsecops import security_events as events
from mlsecops import signing
from mlsecops.contracts import Rejected, digest

INTERVAL_SECONDS = 1
PAGE_SIZE = 4


class Collector:
    def __init__(self, store, receipt_key, collector_key, *, wall=None, monotonic=None):
        self.store = store
        self.receipt_key, self.collector_key = receipt_key, collector_key
        self.wall = wall or (lambda: time.time_ns() // 1_000_000)
        self.monotonic = monotonic or (lambda: time.monotonic_ns() // 1_000_000)
        self.anchor = None
        self.previous = None
        self.clock_failed = False
        self.fault = False
        self.task = None
        self.last_tick = None
        public = signing.load_key(collector_key).public_key().public_bytes_raw()
        self.identity = digest(public)
        producer = store.registry.producer(self.identity)
        receipt = signing.encode64(signing.load_key(receipt_key).public_key().public_bytes_raw())
        if (
            producer.role != "collector"
            or producer.heartbeat_required
            or receipt != store.registry.receipt_public
        ):
            raise Rejected("security_collector_authority")

    def now(self):
        if self.clock_failed:
            raise Rejected("security_collector_clock")
        try:
            wall, mono = events.integer(self.wall()), events.integer(self.monotonic(), 0)
            if self.anchor is None:
                self.anchor = wall, mono
            first_wall, first_mono = self.anchor
            if (
                self.previous is not None
                and (wall < self.previous[0] or mono < self.previous[1])
                or abs((wall - first_wall) - (mono - first_mono)) > events.CLOCK_SKEW_MS
            ):
                raise Rejected("security_collector_clock")
            self.previous = wall, mono
            return wall
        except Exception:
            self.clock_failed = True
            raise Rejected("security_collector_clock") from None

    def available(self):
        if self.task is None or self.task.done():
            raise Rejected("security_collector_stopped")

    def external(self, envelope):
        self.available()
        # Reserve this collector's stream for transactional notice generation.
        if events.signer(envelope) == self.identity:
            raise Rejected("security_collector_reserved_identity")

    def _route(self, record):
        event_id = ledger.candidate(record["envelope"]).document()["event_id"]
        return self.store.route((event_id, self.receipt_key), clock_ms=self.now())["receipt"]

    def ingest(self, envelope):
        self.external(envelope)
        record = self.store.admit(envelope, clock_ms=self.now())
        return self._route(record)

    def heartbeat(self, envelope):
        self.external(envelope)
        return self.store.heartbeat(envelope, clock_ms=self.now())

    def tick(self):
        try:
            report = self.store.poll(clock_ms=self.now())
            for problem in report["problems"]:
                self.store.notice((problem["notice_id"], self.collector_key), clock_ms=self.now())
            failed = False
            # A late, unrouteable event must not starve unrelated pending events.
            for record in self.store.snapshot()["records"]:
                if record["receipt"] is None:
                    try:
                        self._route(record)
                    except Exception:
                        failed = True
            self.fault = failed
            self.last_tick = self.now()
        except Exception:
            self.fault = True
            raise

    def health(self):
        self.available()
        clock = self.now()
        report = self.store.poll(clock_ms=clock)
        delayed = self.last_tick is None or clock - self.last_tick > 5000
        report["collector_available"] = not (self.fault or delayed)
        report["healthy"] = report["healthy"] and report["collector_available"]
        return report

    def incidents(self, offset):
        self.available()
        self.store.registry.valid(self.now())
        if type(offset) is not int or not 0 <= offset <= ledger.MAX_RECORDS:
            raise Rejected("security_incident_page")
        records = [r for r in self.store.snapshot()["records"] if r["receipt"] is not None]
        page = records[offset : offset + PAGE_SIZE]
        next_offset = offset + PAGE_SIZE if offset + PAGE_SIZE < len(records) else None
        return {"incidents": page, "next_offset": next_offset, "release_ready": False}

    async def _loop(self):
        while True:
            await asyncio.sleep(INTERVAL_SECONDS)
            try:
                self.tick()
            except Exception:
                self.fault = True

    async def start(self):
        if self.task is not None:
            raise Rejected("security_collector_already_started")
        self.tick()
        coroutine = self._loop()
        try:
            self.task = asyncio.create_task(coroutine, name="mlsecops-security-events")
        except BaseException:
            coroutine.close()
            raise

    async def close(self):
        task, self.task = self.task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
