"""Time a restoration through its first verified serving response and bind the source proposal."""

from datetime import UTC, datetime, timedelta

from mlsecops import load_clock
from mlsecops.contracts import Rejected


def measure(clock, *, primary, sql, statement, proposal, report, serving_verified_ns):
    """All monotonic readings must come from the same hosted process/boot.

    The caller takes the start anchor before handing recovery to the storage
    adapter and the end anchor immediately after validating a healthy reply.
    Negative drills and cleanup are outside the availability measurement.
    """
    start, end = clock["start"]["monotonic_ns"], clock["end"]["monotonic_ns"]
    elapsed = end - start
    load_clock.window(clock, elapsed)
    if (
        type(serving_verified_ns) is not int
        or not start <= primary["start_ns"] < primary["finish_ns"] <= serving_verified_ns <= end
        or not 0 < elapsed <= 900 * load_clock.NS
    ):
        raise Rejected("recovery_serving_timeline")
    point = datetime.fromisoformat(statement["recovery_point_at"])
    if point.utcoffset() is None:
        raise Rejected("recovery_snapshot_clock")
    utc_epoch = datetime(1970, 1, 1, tzinfo=UTC)
    point_ns = ((point - utc_epoch) // timedelta(microseconds=1)) * 1000
    # The initial anchor includes healthy baseline probes. RPO must extend
    # through the actual loss of the source. A timestamp immediately after
    # its confirmed stop bounds that loss conservatively.
    outage = datetime.fromisoformat(primary["source_stopped_at"])
    if outage.utcoffset() is None:
        raise Rejected("recovery_snapshot_clock")
    outage_ns = ((outage - utc_epoch) // timedelta(microseconds=1)) * 1000
    if not clock["start"]["before_ns"] <= outage_ns <= clock["end"]["after_ns"]:
        raise Rejected("recovery_outage_clock")
    age = outage_ns - point_ns
    if point_ns > clock["start"]["before_ns"] or age > 86400 * load_clock.NS:
        raise Rejected("recovery_snapshot_age")
    if (
        proposal["target_workspace"] != primary["target"]["workspace_id"]
        or proposal["release_ready"] is not False
        or proposal["status"] != "verified-proposal-requires-assurance"
        or proposal["subject_sha256"] != report["subject_sha256"]
        or proposal["proposal_reference"] != report["proposal_reference"]
        or proposal["model_sha256"] != report["model_sha256"]
        or any(
            proposal[key] != sql[key]
            for key in ("model_sha256", "candidate_reference", "evaluation_reference")
        )
    ):
        raise Rejected("recovery_candidate_binding")
    return dict(rto_seconds=elapsed / load_clock.NS, rpo_seconds=age / load_clock.NS)
