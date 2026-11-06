"""Bound the wall-clock mapping of the monotonic client measurement window."""

import time

from mlsecops.contracts import Rejected, require_fields

NS = 1_000_000_000


def sample():
    before = time.time_ns()
    monotonic = time.monotonic_ns()
    after = time.time_ns()
    return {"before_ns": before, "monotonic_ns": monotonic, "after_ns": after}


def window(clock, elapsed_ns):
    require_fields(clock, ("start", "end"))
    start, end = clock["start"], clock["end"]
    for value in (start, end):
        require_fields(value, ("before_ns", "monotonic_ns", "after_ns"))
        if (
            any(type(v) is not int or not 0 <= v < 2**63 for v in value.values())
            or not 0 <= value["after_ns"] - value["before_ns"] <= 10_000_000
        ):
            raise Rejected("load_clock_anchor")
    if (
        type(elapsed_ns) is not int
        or elapsed_ns < 0
        or end["monotonic_ns"] - start["monotonic_ns"] != elapsed_ns
    ):
        raise Rejected("load_clock_elapsed")
    start_mid = (start["before_ns"] + start["after_ns"]) // 2
    end_mid = (end["before_ns"] + end["after_ns"]) // 2
    uncertainty = abs(end_mid - start_mid - elapsed_ns) + max(
        value["after_ns"] - value["before_ns"] for value in (start, end)
    )
    if uncertainty > 100_000_000:
        raise Rejected("load_clock_drift")
    return {
        "start_ns": start_mid + 10 * NS,
        "end_ns": start_mid + 130 * NS,
        "uncertainty_ns": uncertainty,
    }
