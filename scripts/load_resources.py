"""Pure projection of operator-observed Kubelet Summary data for one pinned container."""

import calendar
import re
from datetime import datetime

from mlsecops.contracts import Rejected, canonical, digest, require_fields

NS = 1_000_000_000
FIELDS = (
    "identity_sha256",
    "started_ns",
    "observed_ns",
    "cpu_at_ns",
    "cpu_core_ns",
    "memory_at_ns",
    "usage_bytes",
    "working_set_bytes",
    "rss_bytes",
)


def timestamp(value):
    match = (
        re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z", value)
        if type(value) is str
        else None
    )
    if match is None:
        raise Rejected("load_resource_timestamp")
    try:
        seconds = calendar.timegm(datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S").timetuple())
    except ValueError:
        raise Rejected("load_resource_timestamp") from None
    result = seconds * NS + int((match[2] or "").ljust(9, "0"))
    if not 0 <= result < 2**63:
        raise Rejected("load_resource_timestamp")
    return result


def checked(value):
    require_fields(value, FIELDS)
    if (
        type(value["identity_sha256"]) is not str
        or re.fullmatch("[a-f0-9]{64}", value["identity_sha256"]) is None
        or any(
            type(value[key]) is not int or not 0 <= value[key] < 2**64
            for key in FIELDS
            if key != "identity_sha256"
        )
        or value["working_set_bytes"] > value["usage_bytes"]
        or any(
            not value["started_ns"] <= value[key] <= value["observed_ns"]
            or value["observed_ns"] - value[key] > 30 * NS
            for key in ("cpu_at_ns", "memory_at_ns")
        )
    ):
        raise Rejected("load_resource_sample")
    return value


def extract(document, reference, *, observed_ns):
    require_fields(reference, ("node", "name", "namespace", "uid", "container"))
    if any(type(value) is not str or not value for value in reference.values()):
        raise Rejected("load_resource_identity")
    try:
        if document["node"]["nodeName"] != reference["node"]:
            raise Rejected("load_resource_node")
        pods = [
            pod
            for pod in document["pods"]
            if pod["podRef"] == {key: reference[key] for key in ("name", "namespace", "uid")}
        ]
        if len(pods) != 1 or len(pods[0]["containers"]) != 1:
            raise Rejected("load_resource_pod")
        container = pods[0]["containers"][0]
        if container["name"] != reference["container"]:
            raise Rejected("load_resource_container")
        cpu, memory = container["cpu"], container["memory"]
        return checked(
            {
                "identity_sha256": digest(canonical(reference)),
                "started_ns": timestamp(container["startTime"]),
                "observed_ns": observed_ns,
                "cpu_at_ns": timestamp(cpu["time"]),
                "cpu_core_ns": cpu["usageCoreNanoSeconds"],
                "memory_at_ns": timestamp(memory["time"]),
                "usage_bytes": memory["usageBytes"],
                "working_set_bytes": memory["workingSetBytes"],
                "rss_bytes": memory["rssBytes"],
            }
        )
    except (KeyError, TypeError, IndexError):
        raise Rejected("load_resource_missing") from None


def summarize(samples, *, start_ns, end_ns):
    if (
        type(samples) is not list
        or not 2 <= len(samples) <= 256
        or type(start_ns) is not int
        or type(end_ns) is not int
        or not 0 <= start_ns < end_ns < 2**63
        or end_ns - start_ns != 120 * NS
    ):
        raise Rejected("load_resource_window")
    previous = None
    for row in samples:
        checked(row)
        if previous is not None:
            if (
                any(row[key] != previous[key] for key in ("identity_sha256", "started_ns"))
                or any(
                    row[key] < previous[key]
                    for key in ("observed_ns", "cpu_at_ns", "cpu_core_ns", "memory_at_ns")
                )
                or row["cpu_at_ns"] == previous["cpu_at_ns"]
                and row["cpu_core_ns"] != previous["cpu_core_ns"]
                or row["memory_at_ns"] == previous["memory_at_ns"]
                and any(
                    row[key] != previous[key]
                    for key in ("usage_bytes", "working_set_bytes", "rss_bytes")
                )
            ):
                raise Rejected("load_resource_reset_or_change")
        previous = row

    def window(field):
        before = [i for i, row in enumerate(samples) if row[field] <= start_ns]
        after = [i for i, row in enumerate(samples) if row[field] >= end_ns]
        if not before or not after:
            raise Rejected("load_resource_window_uncovered")
        selected = samples[before[-1] : after[0] + 1]
        times = sorted({row[field] for row in selected})
        gap = max(b - a for a, b in zip(times, times[1:]))
        if gap > 20 * NS:
            raise Rejected("load_resource_sampling_gap")
        return selected, gap

    cpu, cpu_gap = window("cpu_at_ns")
    memory, memory_gap = window("memory_at_ns")
    cpu_ns = cpu[-1]["cpu_core_ns"] - cpu[0]["cpu_core_ns"]
    cpu_window = cpu[-1]["cpu_at_ns"] - cpu[0]["cpu_at_ns"]
    return {
        "source": "kubelet-summary-container",
        "samples": len(samples),
        "requested_window_seconds": (end_ns - start_ns) / NS,
        "cpu_observed_seconds": cpu_window / NS,
        "cpu_core_seconds": cpu_ns / NS,
        "average_cpu_cores": cpu_ns / cpu_window,
        "max_sample_gap_seconds": max(cpu_gap, memory_gap) / NS,
        "max_sampled_usage_bytes": max(row["usage_bytes"] for row in memory),
        "max_sampled_working_set_bytes": max(row["working_set_bytes"] for row in memory),
        "max_sampled_rss_bytes": max(row["rss_bytes"] for row in memory),
        "true_peak_memory_measured": False,
    }
