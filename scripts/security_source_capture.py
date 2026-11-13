"""Private primary-record capture from an already owned fixture and emitters.

No provisioning, processes, key/token copying, persistence or generic verifier
dependency. Call read_incidents while the collector is available, then stop its
writer before capture_delivery. The caller owns cleanup and private retention.
"""

from pathlib import Path

from mlsecops import security_event_store as storage
from mlsecops.contracts import Rejected, bounded_read, canonical, decode
from mlsecops.security_event_ledger import MAX_RECORDS


def read_incidents(fixture):
    """Read every full signed incident page; reject stalled/truncated pagination."""
    records, offset = [], 0
    while True:
        status, page = fixture.exchange("GET", f"/incidents/{offset}")
        if (
            status != 200
            or type(page) is not dict
            or set(page) != {"incidents", "next_offset", "release_ready"}
            or page["release_ready"] is not False
            or type(page["incidents"]) is not list
        ):
            raise Rejected("source_capture_incidents")
        records.extend(page["incidents"])
        if len(records) > MAX_RECORDS:
            raise Rejected("source_capture_incidents")
        following = page["next_offset"]
        if following is None:
            return decode(canonical(records))
        if type(following) is not int or not offset < following == len(records) <= MAX_RECORDS:
            raise Rejected("source_capture_incidents")
        offset = following


def capture_delivery(fixture, emitters, *, incidents, collector_snapshot=None):
    """Copy the exact generic wireformat, never a projection of signed records.

    collector_snapshot is a controlled-test seam (for example Ledger.document).
    The default reads the existing private Linux Store after the caller stops the
    collector. This does not assert source provenance or successful cleanup.
    """
    config = decode(bounded_read(fixture.directory / "collector.json", 16384), 16384)
    if collector_snapshot is None:
        collector_snapshot = storage.Store(
            config["state_directory"], config["state_sha256"], fixture.registry
        ).snapshot
    queues = [emitter.store.snapshot() for emitter in emitters]
    collector = collector_snapshot()
    clock = fixture.now()
    if (
        clock < max([collector["updated_at_ms"], *(q["updated_at_ms"] for q in queues)])
        or canonical(incidents) != canonical(collector["records"])
        or any(record["receipt"] is None for q in [collector, *queues] for record in q["records"])
    ):
        raise Rejected("source_capture_incomplete")
    bundle = {
        "registry": {
            "envelope": decode(bounded_read(Path(config["registry_file"]), 32768), 32768),
            "root": config["registry_root"],
            "pin": config["registry_sha256"],
            "clock_ms": clock,
        },
        "outboxes": queues,
        "collector": collector,
        "incidents": incidents,
    }
    return decode(canonical(bundle))
