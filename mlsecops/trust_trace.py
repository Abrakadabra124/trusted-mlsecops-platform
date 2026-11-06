"""Validate primary HTTP traces for M11, without trusting their success summaries."""

import math

from mlsecops.contracts import Rejected, require_fields
from mlsecops.release_policy import integer
from mlsecops.storage import object_id

ANCHOR = "successful-request-start-lower-bound-on-last-trust-read"
CAUSES = {
    "wall-backward": "trust_clock_invalid",
    "monotonic-backward": "trust_clock_invalid",
    "wall-jump": "trust_clock_invalid",
    "server-skew": "trust_server_clock_skew",
    "invalid-signature": "invalid_signature",
}
PHASES = (
    "injected-predict",
    "injected-ready",
    "restored-predict-1",
    "restored-predict-2",
    "restored-ready",
)


def require(condition):
    if condition is not True:
        raise Rejected("M11_trace_invalid")


def number(value):
    require(type(value) in (int, float) and -(2**53) < value < 2**53 and math.isfinite(value))
    return value


def records(value):
    require(isinstance(value, list) and 1 <= len(value) <= 4096)
    return value


def refusal(value, fault):
    require_fields(value, ("anchor", "fault", "first_503_seconds", "observations", "trace"))
    require(
        fault
        in ("outage", "blackhole", "policy-change", "revocation", "key-revocation", "root-rotation")
    )
    require(value["anchor"] == ANCHOR and value["fault"] == fault)
    rows = records(value["trace"])
    require(integer(value["observations"]) == len(rows))
    first, previous, denials = None, 0, 0
    for row in rows:
        require_fields(row, ("start_seconds", "end_seconds", "http_status"))
        start, end = number(row["start_seconds"]), number(row["end_seconds"])
        status = row["http_status"]
        require(type(status) is int and status in (200, 503) and previous <= start <= end <= 65)
        if status == 200:
            require(first is None and end < 60)
        else:
            first = end if first is None else first
            denials += 1
        previous = end
    require(denials >= 2 and first <= 60 and number(value["first_503_seconds"]) == first)
    require(fault not in ("outage", "blackhole") or rows[-1]["start_seconds"] >= 60)
    return first


def approval_expiry(value):
    require_fields(value, ("expires_at", "started_epoch", "first_503_seconds_from_expiry", "trace"))
    expires, started = integer(value["expires_at"]), number(value["started_epoch"])
    require(0 < expires - started <= 120)
    rows = records(value["trace"])
    previous, elapsed, first, successes, denials = started, 0, None, 0, 0
    for row in rows:
        require_fields(row, ("start_epoch", "end_epoch", "end_seconds", "http_status"))
        start, end, seconds = (number(row[k]) for k in ("start_epoch", "end_epoch", "end_seconds"))
        status = row["http_status"]
        require(type(status) is int and status in (200, 503))
        require(previous <= start <= end and elapsed <= seconds <= 127)
        require(abs(end - started - seconds) <= 2)
        if status == 200:
            require(first is None and end < expires and seconds < expires - started)
            successes += 1
        else:
            if first is None:
                first = end - expires
                require(-2 <= first <= 0 and seconds <= expires - started)
            denials += 1
        previous, elapsed = end, seconds
    require(successes > 0 and denials >= 2 and rows[-1]["start_epoch"] >= expires + 1)
    require(
        math.isclose(number(value["first_503_seconds_from_expiry"]), first, rel_tol=0, abs_tol=1e-6)
    )
    return first


def dependency(value, fault, cause, *, replay=False):
    fields = ("fault", "cause", "scope", "max_golden_error", "trace")
    require_fields(value, (*fields, "replay", "recovery_max_golden_error") if replay else fields)
    require(value["fault"] == fault and value["cause"] == cause)
    require(
        value["scope"] == "injected-reader-dependencies"
        and 0 <= number(value["max_golden_error"]) <= 1e-6
    )
    rows = records(value["trace"])
    require(len(rows) == len(PHASES))
    previous, wall = 0, 0
    for phase, row in zip(PHASES, rows, strict=True):
        require_fields(
            row,
            (
                "phase",
                "started_seconds",
                "finished_seconds",
                "wall_started",
                "wall_finished",
                "status",
            ),
        )
        start, end, start_wall, end_wall = (
            number(row[k])
            for k in ("started_seconds", "finished_seconds", "wall_started", "wall_finished")
        )
        require(row["phase"] == phase and type(row["status"]) is int and row["status"] == 503)
        require(previous <= start <= end <= 60 and wall <= start_wall <= end_wall)
        previous, wall = end, end_wall


def dependency_faults(values):
    records(values)
    require(len(values) == len(CAUSES))
    observed = []
    for value in values:
        require(isinstance(value, dict) and isinstance(value.get("fault"), str))
        fault = value["fault"]
        require(fault in CAUSES and fault not in observed)
        dependency(value, fault, CAUSES[fault])
        observed.append(fault)
    return sorted(observed)


def version_replay(value):
    dependency(value, "version-replay", "trust_version_replay", replay=True)
    require(0 <= number(value["recovery_max_golden_error"]) <= 1e-6)
    replay = value["replay"]
    require_fields(
        replay,
        (
            "checked_at_epoch",
            "server_epoch",
            "prior_expires_at_epoch",
            "prior_valid_seconds",
            "prior_version",
            "current_version",
            "prior_document_sha256",
            "current_document_sha256",
        ),
    )
    old, current = integer(replay["prior_version"]), integer(replay["current_version"])
    require(old < current)
    checked, server = number(replay["checked_at_epoch"]), integer(replay["server_epoch"])
    expires = integer(replay["prior_expires_at_epoch"])
    require(0 < checked < expires and abs(server - checked) <= 2)
    require(
        math.isclose(
            number(replay["prior_valid_seconds"]), expires - checked, rel_tol=0, abs_tol=1e-6
        )
    )
    require(
        object_id(replay["prior_document_sha256"]) != object_id(replay["current_document_sha256"])
    )
    return {"prior_version": old, "current_version": current}
