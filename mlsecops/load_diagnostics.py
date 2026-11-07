"""Probe-only aggregate timings. Never capture arguments, values or exception text."""

import re
import threading
import time
from contextlib import contextmanager

from mlsecops import storage, trust_session
from mlsecops.contracts import Rejected, require_fields

NAMES = (
    "reader_check",
    "trust_read",
    "worker_ping",
    "worker_predict",
    "predict_total",
    "engine_wait",
    "engine_hold",
    "client_parameters",
    "session_credentials",
)
CODES = ("overloaded", "client_limited", "unrecognized")
SCOPE = "probe-internal-diagnostics-not-independent"
WINDOW = "warmup-measurement-overload-recovery"
AUDIT_COUNTS = (
    "accepted",
    "durable",
    "pending",
    "unconfirmed",
    "durable_bytes",
    "reserved_bytes",
    "held_bytes",
    "held_slots",
    "reservations",
    "budget_bytes",
    "capacity",
)
AUDIT_FLAGS = ("healthy", "closed", "failed")
FAILURES = frozenset(
    {
        "unknown",
        "load_server_startup",
        "load_server_shutdown",
        "load_server_lifespan",
        "audit_shutdown_pending",
        "audit_failed",
        "serving_cleanup_pending",
        "serving_cleanup_unconfirmed",
        "trust_session_cleanup_unconfirmed",
        "load_monitor_inactive_or_lost",
        "load_monitor_pending",
        "load_monitor_shutdown",
    }
)


def failure_code(error):
    if (
        type(error) is Rejected
        and len(error.args) == 1
        and type(error.args[0]) is str
        and error.args[0] in FAILURES
    ):
        return error.args[0]
    return "unknown"


class Lifespan:
    """Probe-only ASGI observer; retain one finite code, never exception text."""

    def __init__(self, app):
        self.app = app
        self.cause = "unknown"

    async def __call__(self, scope, receive, send):
        try:
            await self.app(scope, receive, send)
        except Exception as error:
            if scope["type"] == "lifespan":
                self.cause = failure_code(error)
            raise


def audit_status(journal):
    status = journal.status()
    value = {name: status[name] for name in AUDIT_COUNTS[:-2] + AUDIT_FLAGS[:2]}
    value.update(
        failed=status["failure"] is not None,
        budget_bytes=journal._max_bytes,
        capacity=journal._capacity,
    )
    return checked_audit(value)


def checked_audit(value):
    require_fields(value, (*AUDIT_COUNTS, *AUDIT_FLAGS))
    if any(type(value[name]) is not bool for name in AUDIT_FLAGS) or any(
        type(value[name]) is not int or not 0 <= value[name] < 2**63 for name in AUDIT_COUNTS
    ):
        raise Rejected("load_diagnostic_audit")
    return value


def targets(engine):
    return (
        (storage, "connection_materials", "client_parameters"),
        (trust_session, "credentials", "session_credentials"),
        (engine.reader, "check", "reader_check"),
        (engine.reader.trust, "reader", "trust_read"),
        (engine.worker, "ping", "worker_ping"),
        (engine.worker, "predict", "worker_predict"),
        (engine, "predict_result", "predict_total"),
    )


class Timings:
    def __init__(self):
        self.lock = threading.Lock()
        self.rows = {name: dict(count=0, failed=0, total_ns=0, max_ns=0) for name in NAMES}

    def add(self, name, elapsed, failed):
        with self.lock:
            row = self.rows[name]
            row["count"] += 1
            row["failed"] += int(failed)
            row["total_ns"] += elapsed
            row["max_ns"] = max(row["max_ns"], elapsed)

    @contextmanager
    def measure(self, name):
        started, failed = time.monotonic_ns(), True
        try:
            yield
            failed = False
        finally:
            self.add(name, time.monotonic_ns() - started, failed)

    def wrapped(self, name, operation):
        def run(*args, **kwargs):
            with self.measure(name):
                return operation(*args, **kwargs)

        return run

    @contextmanager
    def instrument(self, engine):
        originals = [
            (obj, method, getattr(obj, method), name) for obj, method, name in targets(engine)
        ]
        original_lock = engine.exclusive

        @contextmanager
        def exclusive():
            started, entered = time.monotonic_ns(), False
            try:
                with original_lock():
                    entered = True
                    self.add("engine_wait", time.monotonic_ns() - started, False)
                    with self.measure("engine_hold"):
                        yield
            finally:
                if not entered:
                    self.add("engine_wait", time.monotonic_ns() - started, True)

        try:
            for obj, method, operation, name in originals:
                setattr(obj, method, self.wrapped(name, operation))
            engine.exclusive = exclusive
            yield
        finally:
            engine.exclusive = original_lock
            for obj, method, operation, _ in originals:
                setattr(obj, method, operation)

    def snapshot(self):
        with self.lock:
            return {name: row.copy() for name, row in self.rows.items()}


def reasons():
    return {phase: dict.fromkeys(CODES, 0) for phase in ("normal", "overload", "recovery")}


def reason(body):
    if (
        type(body) is dict
        and set(body) == {"schema_version", "request_id", "error"}
        and type(body["schema_version"]) is int
        and body["schema_version"] == 1
        and type(body["request_id"]) is str
        and re.fullmatch("[a-f0-9]{32}", body["request_id"])
        and type(body["error"]) is dict
        and set(body["error"]) == {"code"}
        and body["error"]["code"] in CODES[:2]
    ):
        return body["error"]["code"]
    return "unrecognized"


def result(timings, limited, audit):
    return {
        "scope": SCOPE,
        "window": WINDOW,
        "timings": timings.snapshot(),
        "limited": limited,
        "audit": checked_audit(audit),
    }


def checked(value, summary, overload):
    require_fields(value, ("scope", "window", "timings", "limited", "audit"))
    checked_audit(value["audit"])
    require_fields(value["timings"], NAMES)
    require_fields(value["limited"], ("normal", "overload", "recovery"))
    if value["scope"] != SCOPE or value["window"] != WINDOW:
        raise Rejected("load_diagnostic_scope")
    for row in value["timings"].values():
        require_fields(row, ("count", "failed", "total_ns", "max_ns"))
        if (
            any(type(v) is not int or not 0 <= v < 2**63 for v in row.values())
            or row["failed"] > row["count"]
            or row["max_ns"] > row["total_ns"]
            or row["count"] == 0
            and row["total_ns"] != 0
        ):
            raise Rejected("load_diagnostic_timing")
    for row in value["limited"].values():
        require_fields(row, CODES)
        if any(type(v) is not int or not 0 <= v <= 200000 for v in row.values()):
            raise Rejected("load_diagnostic_reason")
    if (
        sum(value["limited"]["normal"].values())
        != sum(summary[p]["outcomes"]["limited"] for p in ("warmup", "measured"))
        or sum(value["limited"]["overload"].values()) != overload["limited"]
        or sum(value["limited"]["recovery"].values()) > 1
    ):
        raise Rejected("load_diagnostic_count")
    return value
