"""Fixed M14 measurement primitives. No model, credentials or response bodies in rows."""

import asyncio
import math
import re
import time
from collections import Counter

from mlsecops.contracts import Rejected, decode, require_fields

CLIENTS = 10
WARMUP = 10
DURATION = 120
TIMEOUT = 2
MAX_ATTEMPTS = 200_000
OUTCOMES = ("ok", "mismatch", "limited", "http_error", "timeout", "transport")
NS = 1_000_000_000


async def request(port, token, body, *, timeout=TIMEOUT):
    """One fixed loopback HTTP/1.1 request, with an absolute wall-time budget.

    Deliberately accepts only bounded Content-Length responses from our uvicorn
    endpoint. No redirects, proxy environment, compression or remote URL input.
    Connection establishment and full body reception belong to measured latency.
    """
    if (
        type(port) is not int
        or not 1 <= port <= 65535
        or type(token) is not str
        or re.fullmatch("[a-f0-9]{64}", token) is None
        or type(body) is not bytes
        or not 0 < len(body) <= 65536
    ):
        raise Rejected("load_request_contract")
    writer = None
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection("127.0.0.1", port, limit=16384)
            writer.write(
                b"POST /v1/predict HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\nConnection: close\r\nAuthorization: Bearer "
                + token.encode("ascii")
                + b"\r\nContent-Length: "
                + str(len(body)).encode("ascii")
                + b"\r\n\r\n"
                + body
            )
            await writer.drain()
            try:
                head = await reader.readuntil(b"\r\n\r\n")
            except (asyncio.LimitOverrunError, asyncio.IncompleteReadError):
                raise Rejected("load_http_header") from None
            lines = head[:-4].split(b"\r\n")
            if (
                len(head) > 16384
                or re.fullmatch(rb"HTTP/1\.[01] [2-5][0-9]{2} [^\r\n]*", lines[0]) is None
            ):
                raise Rejected("load_http_status")
            lengths = []
            for line in lines[1:]:
                name, separator, value = line.partition(b":")
                if not separator or re.fullmatch(rb"[A-Za-z0-9-]+", name) is None:
                    raise Rejected("load_http_header")
                if name.lower() in (b"transfer-encoding", b"content-encoding"):
                    raise Rejected("load_http_encoding")
                if name.lower() == b"content-length":
                    lengths.append(value.strip())
            if len(lengths) != 1 or re.fullmatch(rb"[0-9]{1,5}", lengths[0]) is None:
                raise Rejected("load_http_length")
            length = int(lengths[0])
            if not 0 < length <= 65536:
                raise Rejected("load_http_length")
            return int(lines[0][9:12]), decode(await reader.readexactly(length), 65536)
    finally:
        if writer is not None:
            # close() immediately closes this client's transport; do not extend
            # the absolute request budget waiting for the peer to acknowledge.
            writer.close()


async def collect(exchange, valid, *, warmup=WARMUP, duration=DURATION, limit=MAX_ATTEMPTS):
    """Ten closed-loop clients. Overrides are for controlled tests, not acceptance."""
    if (
        type(warmup) not in (int, float)
        or not math.isfinite(warmup)
        or warmup < 0
        or type(duration) not in (int, float)
        or not math.isfinite(duration)
        or duration <= 0
        or type(limit) is not int
        or not CLIENTS <= limit <= MAX_ATTEMPTS
    ):
        raise Rejected("load_collection_profile")
    origin = time.monotonic_ns()
    deadline = int((warmup + duration) * NS)
    records, started = [], 0
    exhausted = False

    async def client(index):
        nonlocal started, exhausted
        while True:
            # Yield even when a controlled exchange completes synchronously.
            await asyncio.sleep(0)
            begin = time.monotonic_ns() - origin
            if begin >= deadline:
                return
            if started >= limit:
                exhausted = True
                return
            started += 1
            status, outcome = 0, "transport"
            try:
                async with asyncio.timeout(TIMEOUT):
                    status, response = await exchange(index)
                    if status == 200:
                        outcome = "ok" if valid(response) is True else "mismatch"
                    else:
                        outcome = "limited" if status == 429 else "http_error"
            except TimeoutError:
                status, outcome = 0, "timeout"
            except Exception:
                status, outcome = 0, "transport"
            records.append(
                {
                    "client": index,
                    "start_ns": begin,
                    "end_ns": time.monotonic_ns() - origin,
                    "status": status,
                    "outcome": outcome,
                }
            )

    async with asyncio.TaskGroup() as group:
        for index in range(CLIENTS):
            group.create_task(client(index))
    if len(records) != started:
        raise Rejected("load_attempts_lost")
    return {
        "records": sorted(records, key=lambda row: (row["start_ns"], row["client"])),
        "exhausted": exhausted,
        "elapsed_ns": time.monotonic_ns() - origin,
    }


def distribution(values):
    if not values:
        return None
    ordered = sorted(values)
    return {
        "min": ordered[0],
        "p50": ordered[math.ceil(len(ordered) * 0.50) - 1],
        "p95": ordered[math.ceil(len(ordered) * 0.95) - 1],
        "p99": ordered[math.ceil(len(ordered) * 0.99) - 1],
        "max": ordered[-1],
    }


def summarize(records, *, elapsed_ns, exhausted=False):
    if (
        type(records) is not list
        or len(records) > MAX_ATTEMPTS
        or type(exhausted) is not bool
        or type(elapsed_ns) is not int
        or not 0 <= elapsed_ns < 2**63
    ):
        raise Rejected("load_records_contract")
    previous = {}
    for row in records:
        require_fields(row, ("client", "start_ns", "end_ns", "status", "outcome"))
        if (
            any(type(row[field]) is not int for field in ("client", "start_ns", "end_ns", "status"))
            or not 0 <= row["client"] < CLIENTS
            or not 0 <= row["start_ns"] < (WARMUP + DURATION) * NS
            or not row["start_ns"] <= row["end_ns"] <= elapsed_ns
            or row["outcome"] not in OUTCOMES
            or row["start_ns"] < previous.get(row["client"], 0)
        ):
            raise Rejected("load_record_invalid")
        status, outcome = row["status"], row["outcome"]
        if not (
            (outcome in ("ok", "mismatch") and status == 200)
            or (outcome == "limited" and status == 429)
            or (outcome == "http_error" and 201 <= status <= 599 and status != 429)
            or (outcome in ("timeout", "transport") and status == 0)
        ):
            raise Rejected("load_outcome_invalid")
        previous[row["client"]] = row["end_ns"]

    def summary(sample, seconds):
        outcomes = Counter(row["outcome"] for row in sample)
        statuses = Counter(str(row["status"]) for row in sample)
        latency = [(row["end_ns"] - row["start_ns"]) / 1_000_000 for row in sample]
        successful = [
            value for value, row in zip(latency, sample, strict=True) if row["outcome"] == "ok"
        ]
        return {
            "attempts": len(sample),
            "successes": outcomes["ok"],
            "outcomes": {name: outcomes[name] for name in OUTCOMES},
            "statuses": dict(sorted(statuses.items())),
            "clients": {str(i): sum(row["client"] == i for row in sample) for i in range(CLIENTS)},
            "rps": len(sample) / seconds,
            "successful_rps": outcomes["ok"] / seconds,
            "unexpected_5xx": sum(500 <= row["status"] <= 599 for row in sample),
            "latency_ms": distribution(latency),
            "success_latency_ms": distribution(successful),
            "latency_histogram_le_ms": {
                str(bound): sum(value <= bound for value in latency)
                for bound in (1, 5, 10, 20, 50, 100, 200, 500, 1000, 2000)
            },
        }

    warmup = summary([row for row in records if row["start_ns"] < WARMUP * NS], WARMUP)
    measured = summary([row for row in records if row["start_ns"] >= WARMUP * NS], DURATION)
    checks = {
        "full_observation_window": elapsed_ns >= (WARMUP + DURATION) * NS,
        "not_capped": not exhausted,
        "all_clients_warmed_up": all(warmup["clients"].values()),
        "all_clients_measured": all(measured["clients"].values()),
        "at_least_1000_requests": measured["attempts"] >= 1000,
        "at_least_1000_correct_predictions": measured["successes"] >= 1000,
        "no_wrong_predictions": all(row["outcome"] != "mismatch" for row in records),
        "no_timeouts_transport_or_quota_denials": not any(
            measured["outcomes"][key] for key in ("timeout", "transport", "limited")
        ),
        "no_unexpected_non5xx_http_errors": not any(
            row["outcome"] == "http_error" and row["status"] < 500 for row in records
        ),
        "5xx_below_0_1_percent": measured["attempts"] > 0
        and measured["unexpected_5xx"] * 1000 < measured["attempts"],
        "latency_targets": all(
            value is not None and value["p95"] <= 200 and value["p99"] <= 500
            for value in (measured["latency_ms"], measured["success_latency_ms"])
        ),
    }
    return {
        "schema_version": 1,
        "scope": "client-measurement-only",
        "release_ready": False,
        "profile_met": all(checks.values()),
        "elapsed_ns": elapsed_ns,
        "checks": checks,
        "profile": {
            "clients": CLIENTS,
            "warmup_seconds": WARMUP,
            "measurement_seconds": DURATION,
            "request_timeout_seconds": TIMEOUT,
            "max_attempts": MAX_ATTEMPTS,
            "percentiles": "nearest-rank",
            "model": "closed-loop",
            "connections": "one-per-request",
        },
        "warmup": warmup,
        "measured": measured,
    }
