"""Recompute M23 green-window evidence; this packet is not promotion permission."""

import dataclasses

from mlsecops import monitoring, monitoring_stream
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.datasets import FEATURES
from mlsecops.load_golden import Golden

PHASES = ("ready", "outage", "attempt", "recover")
MAX_PACKET = 32 * 1024 * 1024
GREEN_FIELDS = (
    "healthy",
    "state",
    "faults",
    "epoch",
    "reference_sha256",
    "data_status",
    "observations",
    "windows_evaluated",
    "pending_windows",
    "pending_alerts",
    "alerts_delivered",
    "unclosed_observations",
    "release_ready",
    "reports",
)


def verify(packet, *, reference, context, golden, campaign):
    monitoring.schema(packet, ("campaign", "context", "windows"))
    if (
        type(campaign) is not str
        or len(campaign) != 32
        or any(c not in "0123456789abcdef" for c in campaign)
        or packet["campaign"] != campaign
        or packet["context"] != dataclasses.asdict(context)
        or type(golden) is not Golden
        or (golden.model, golden.bundle) != (context.model_sha256, context.bundle_sha256)
        or type(packet["windows"]) is not list
        or not 4 <= len(packet["windows"]) <= 128
        or len(canonical(packet)) > MAX_PACKET
    ):
        raise Rejected("security_green_packet_binding")
    reference_hash = digest(canonical(reference))
    evaluator = monitoring.Evaluator(reference, reference_hash)
    golden_row = decode(golden.body)["instances"][0]
    golden_features = [golden_row[name] for name in FEATURES]
    requests, reports, phases = set(), {}, []
    counts = dict.fromkeys(PHASES, 0)
    observations = 0
    for sequence, item in enumerate(packet["windows"], 1):
        require_fields(
            item,
            (
                "phase",
                "document",
                "predictions",
                "http",
                "monitor",
                "observed_at_ms",
                "observation_started_at_ms",
            ),
        )
        phase = item["phase"]
        if phase not in PHASES:
            raise Rejected("security_green_phase")
        if not phases or phase != phases[-1]:
            phases.append(phase)
        if phases != list(PHASES[: len(phases)]):
            raise Rejected("security_green_order")
        document = item["document"]
        if (
            document["sequence"] != sequence
            or type(item["http"]) is not list
            or not 1 <= len(item["http"]) <= 64
        ):
            raise Rejected("security_green_window_inventory")
        stream = monitoring_stream.Accumulator(
            reference, reference_hash, started_at_ms=document["started_at_ms"]
        )
        golden_seen = 0
        for record in item["http"]:
            require_fields(record, ("features", "response"))
            response = record["response"]
            monitoring.schema(
                response, ("request_id", "bundle_sha256", "model_sha256", "predictions")
            )
            if (
                response["request_id"] in requests
                or response["bundle_sha256"] != context.bundle_sha256
                or response["model_sha256"] != context.model_sha256
            ):
                raise Rejected("security_green_http_binding")
            stream.add(context, record["features"], response["predictions"], response["request_id"])
            requests.add(response["request_id"])
            for features, prediction in zip(
                record["features"], response["predictions"], strict=True
            ):
                if features == golden_features:
                    if not golden.valid({**response, "predictions": [prediction]}):
                        raise Rejected("security_green_golden_mismatch")
                    golden_seen += 1
        closed = stream.close(sequence=sequence, ended_at_ms=document["ended_at_ms"])
        if (
            closed.content != canonical(document)
            or canonical(closed.predictions) != canonical(item["predictions"])
            or document["observations"] != 1000
            or not golden_seen
        ):
            raise Rejected("security_green_primary_changed")
        report = evaluator.evaluate(document)
        if (
            report["status"] != "observed"
            or report["prediction_status"] != "observed"
            or report["abstentions"]
            or report["alerts"]
            or any(
                value is None or value >= monitoring.PSI_THRESHOLD
                for value in report["psi"].values()
            )
        ):
            raise Rejected("security_green_drift")
        reports[closed.sha256] = report
        observations += 1000
        observed = monitoring.integer(item["observed_at_ms"], document["ended_at_ms"], 2**53 - 1)
        monitoring.integer(
            item["observation_started_at_ms"], document["started_at_ms"], document["ended_at_ms"]
        )
        if observed - document["ended_at_ms"] > 10000:
            raise Rejected("security_green_stale_window")
        state = item["monitor"]
        require_fields(state, GREEN_FIELDS)
        for key, expected in (
            ("observations", observations),
            ("windows_evaluated", sequence),
            ("pending_windows", 0),
            ("pending_alerts", 0),
            ("alerts_delivered", 0),
            ("unclosed_observations", 0),
        ):
            if type(state[key]) is not int or state[key] != expected:
                raise Rejected("security_green_accounting")
        if (
            state["healthy"] is not True
            or state["state"] != "observing"
            or state["faults"] != []
            or state["epoch"] != campaign
            or state["reference_sha256"] != reference_hash
            or state["data_status"] != "observed"
            or state["release_ready"] is not False
            or type(state["reports"]) is not list
            or not 1 <= len(state["reports"]) <= 128
            or state["reports"][-1] != report
            or any(row != reports.get(row.get("window_sha256")) for row in state["reports"])
        ):
            raise Rejected("security_green_monitor")
        counts[phase] += 1
    if phases != list(PHASES):
        raise Rejected("security_green_incomplete")
    return {
        "status": "pass",
        "scope": "actual-candidate-green-window-packet-not-full-M23",
        "model_sha256": context.model_sha256,
        "subject_sha256": context.bundle_sha256,
        "reference_sha256": reference_hash,
        "observations": observations,
        "phase_windows": counts,
        "packet_sha256": digest(canonical(packet)),
        "release_ready": False,
    }


def verify_timeline(packet, timeline):
    """Bind real HTTP intervals to independent operator actions on the same host.

    Hosted kind nodes and the runner share the kernel wall clock. Compare the
    operator's wall/monotonic deltas and fail on a clock jump; do not grant a
    tolerance that admits observations outside the confirmed fault interval.
    """
    require_fields(timeline, (*PHASES, "finish"))
    anchor = timeline["ready"]
    previous_ms = previous_ns = 0
    for phase in (*PHASES, "finish"):
        action = timeline[phase]
        fields = (
            ("started_at_ms", "started_ns")
            if phase == "finish"
            else ("started_at_ms", "started_ns", "finished_at_ms", "finished_ns")
        )
        require_fields(action, fields)
        for side in ("started",) if phase == "finish" else ("started", "finished"):
            wall = monitoring.integer(action[side + "_at_ms"], 1, 2**53 - 1)
            steady = monitoring.integer(action[side + "_ns"], 1, 2**63 - 1)
            drift = (wall - anchor["started_at_ms"]) - (steady - anchor["started_ns"]) / 1000000
            if wall < previous_ms or steady < previous_ns or abs(drift) > 1000:
                raise Rejected("security_outage_operator_clock")
            previous_ms, previous_ns = wall, steady
    intervals = {
        "ready": (timeline["ready"]["finished_at_ms"], timeline["outage"]["started_at_ms"]),
        "outage": (timeline["outage"]["finished_at_ms"], timeline["attempt"]["started_at_ms"]),
        "attempt": (timeline["attempt"]["finished_at_ms"], timeline["recover"]["started_at_ms"]),
        "recover": (timeline["recover"]["finished_at_ms"], timeline["finish"]["started_at_ms"]),
    }
    previous = 0
    covered = set()
    for item in packet["windows"]:
        start = item["observation_started_at_ms"]
        finish = item["observed_at_ms"]
        if start < previous or finish < start or finish > timeline["finish"]["started_at_ms"]:
            raise Rejected("security_outage_observation_order")
        previous = finish
        lower, upper = intervals[item["phase"]]
        if lower <= start <= finish <= upper:
            covered.add(item["phase"])
    if covered != set(PHASES):
        raise Rejected("security_outage_window_not_during_action")
