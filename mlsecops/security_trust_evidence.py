"""Bounded periodic trust evidence replay, with caller-owned authority/source pins.

Signed documents and events prove their contents. SQL commit readbacks, process
lifecycle, cleanup and monotonic observations remain assertions of the pinned
hosted harness, not independently signed clocks or a full M23/R1 acceptance.
"""

import math

from mlsecops import security_event_config as config
from mlsecops import security_event_ledger as ledger
from mlsecops import security_event_outbox as outbox
from mlsecops import security_events as events
from mlsecops import security_source_evidence, security_trust_events, trust
from mlsecops.contracts import Rejected, canonical, digest

MAX_BYTES = 4 * 1024 * 1024
METHOD_FILES = (
    "scripts/security_trust_service_native.py",
    "scripts/security_trust_evidence_qualification.py",
    "scripts/security_event_audit_fixture.py",
    "scripts/security_event_live_qualification.py",
    "scripts/security_events_qualification.py",
    "scripts/security_identity_events_native.py",
    "scripts/release_reader_native.py",
    "mlsecops/security_trust_evidence.py",
    "mlsecops/security_source_evidence.py",
    "mlsecops/security_trust_events.py",
    "mlsecops/security_trust_service.py",
    "mlsecops/trust_authority.py",
)
CASES = (
    "source-heartbeat-reaches-independent-collector",
    "second-supervisor-refused-before-child",
    "confirmed-lock-contention-cannot-publish-heartbeat",
    "confirmed-lock-contention-recovers-within-original-wait",
    "committed-revocation-delivered-by-actual-periodic-source",
    "unavailable-source-cannot-mask-failure-with-heartbeat",
    "collector-outage-keeps-owned-supervisor-and-pending-event",
    "recovery-preserves-original-event-and-no-duplicates",
    "supervisor-stopped-with-confirmed-child-cleanup",
    "supervisor-restart-preserves-history-and-increases-counter",
    "supervisor-stopped-with-confirmed-child-cleanup",
    "stopped-observer-detected-by-signed-gap-within-120s",
    "absent-source-denies-fresh-promotion-audit",
    "private-output-has-no-credentials-or-source-payload",
    "collector-private-state-cleaned",
    "owned-sql-volume-cleaned",
    "source-unchanged",
)
STAGES = (
    "initial",
    "revoked_b",
    "unavailable_before",
    "unavailable_after",
    "restored",
    "pending_c",
    "recovered",
    "restarted",
    "stopped",
    "gap",
)
OBSERVATIONS = (
    "commit_started_seconds",
    "contention_released_seconds",
    "first_delivery_seconds",
    "busy_failures",
    "contention_heartbeat",
    "source_failed_checks",
    "duplicate_exit_code",
    "duplicate_stdout_empty",
    "duplicate_rejection",
    "unavailable_observer_alive",
    "outage_observer_alive",
    "initial_health",
    "final_health",
    "promotion_denied",
    "private_output_clean",
    "stops",
)


def _require(condition):
    if not condition:
        raise Rejected("security_trust_evidence_invalid")


def _seconds(value):
    _require(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 600)
    return value


def _history(packet, root):
    events.shape(packet, ("environment", "initial_root", "commits"))
    _require(packet["environment"] == "local-cpu" and packet["initial_root"] == root)
    commits = packet["commits"]
    _require(type(commits) is list and len(commits) == 2)
    previous, projected = [], []
    for version, commit in enumerate(commits, 2):
        events.shape(commit, ("at_seconds", "result", "history"))
        _seconds(commit["at_seconds"])
        result, history = commit["result"], commit["history"]
        events.shape(result, ("version", "document_sha256", "reused"))
        projected = security_trust_events.project(
            history, environment="local-cpu", initial_root=root
        )
        _require(
            type(result["version"]) is int
            and result["version"] == version
            and result["reused"] is False
            and history["head_version"] == version
            and result["document_sha256"] == history["head_sha256"]
            and history["documents"][: len(previous)] == previous
        )
        for index, document in enumerate(history["documents"]):
            payload = trust.validate(document["envelope"], root, "local-cpu")
            _require(
                payload["revoked_artifacts"] == ["b" * 64, "c" * 64][:index]
                and payload["revoked_keys"] == []
                and payload["promotion_policy_sha256"] == "a" * 64
            )
        _require(len(projected) == version - 1)
        previous = history["documents"]
    return projected


def _snapshot(state, root, pin):
    events.shape(state, ("registry", "outboxes", "collector", "incidents"))
    authority = state["registry"]
    events.shape(authority, ("envelope", "root", "pin", "clock_ms"))
    _require(authority["root"] == root and authority["pin"] == pin)
    registry = config.Registry(
        authority["envelope"],
        trusted_root=root,
        expected_sha256=pin,
        clock_ms=authority["clock_ms"],
    )
    _require(type(state["outboxes"]) is list and len(state["outboxes"]) == 1)
    document = state["outboxes"][0]
    producers = [p for p in registry.producers if p.role == "trust"]
    _require(len(producers) == 1 and producers[0].heartbeat_required)
    queue = outbox.Outbox(registry, producers[0].identity, document)
    book = ledger.Ledger(registry, state["collector"])
    _require(
        authority["clock_ms"] >= max(document["updated_at_ms"], state["collector"]["updated_at_ms"])
        and canonical(state["incidents"]) == canonical(state["collector"]["records"])
        and not book.pending()
    )
    heartbeat = registry.heartbeat(document["heartbeat"], clock_ms=document["updated_at_ms"])
    return registry, queue.document(), book, heartbeat


def _lifecycle(packet, states, beats):
    obs = packet["observations"]
    events.shape(obs, OBSERVATIONS)
    for key in (
        "duplicate_stdout_empty",
        "duplicate_rejection",
        "unavailable_observer_alive",
        "outage_observer_alive",
        "promotion_denied",
        "private_output_clean",
    ):
        _require(obs[key] is True)
    for key, value in (("duplicate_exit_code", 1), ("initial_health", 200), ("final_health", 503)):
        _require(type(obs[key]) is int and obs[key] == value)
    for key in ("busy_failures", "source_failed_checks"):
        _require(1 <= events.integer(obs[key]) <= 100)
    _require(obs["contention_heartbeat"] == states["initial"]["outboxes"][0]["heartbeat"])
    began, released, delivered = [
        _seconds(obs[k])
        for k in ("commit_started_seconds", "contention_released_seconds", "first_delivery_seconds")
    ]
    times = {s["name"]: s["at_seconds"] for s in packet["stages"]}
    first, second = packet["trust"]["commits"]
    _require(
        times["initial"]
        <= began
        <= first["at_seconds"]
        <= released
        <= delivered
        <= times["revoked_b"]
        and delivered - began <= 45
        and times["revoked_b"] - delivered <= 5
        and times["restored"] <= second["at_seconds"] <= times["pending_c"]
        and times["unavailable_before"] + 35
        <= times["unavailable_after"]
        <= times["unavailable_before"] + 45
    )
    for commit, next_stage in ((first, "revoked_b"), (second, "pending_c")):
        # SQL statement clock and local observations are retained, not signed time attestations.
        sql_ms = commit["history"]["clock"] * 1000
        next_clock = states[next_stage]["registry"]["clock_ms"]
        _require(sql_ms <= next_clock and next_clock - sql_ms <= 47000)
    stops = obs["stops"]
    _require(type(stops) is list and len(stops) == 2)
    for stop, lower, upper in zip(
        stops, ("recovered", "restarted"), ("restarted", "stopped"), strict=True
    ):
        events.shape(stop, ("at_seconds", "exit_code", "graceful", "group_absent"))
        _require(
            times[lower] <= _seconds(stop["at_seconds"]) <= times[upper]
            and type(stop["exit_code"]) is int
            and stop["exit_code"] == 0
            and stop["graceful"] is True
            and stop["group_absent"] is True
        )
    cleanup = packet["cleanup"]
    events.shape(
        cleanup,
        (
            "at_seconds",
            "collector_stopped",
            "collector_directory_absent",
            "sql_directory_absent",
            "source_unchanged",
        ),
    )
    _require(_seconds(cleanup["at_seconds"]) >= times["gap"])
    for key in (
        "collector_stopped",
        "collector_directory_absent",
        "sql_directory_absent",
        "source_unchanged",
    ):
        _require(cleanup[key] is True)
    periodic = (beats["revoked_b"]["observed_at_ms"] - beats["initial"]["observed_at_ms"]) / 1000
    notice = (
        times["gap"]
        - times["stopped"]
        + (states["stopped"]["registry"]["clock_ms"] - beats["stopped"]["observed_at_ms"]) / 1000
    )
    _require(25 <= periodic <= 40 and 90 <= notice <= 120)
    return dict(
        max_commit_delivery_seconds=delivered - began,
        periodic_seconds=periodic,
        forced_contention_recovery_seconds=delivered - released,
        stopped_source_notice_seconds=notice,
    )


def verify(
    packet,
    *,
    expected_source,
    expected_fingerprint,
    expected_materials,
    expected_registry_root,
    expected_registry_pin,
    expected_trust_root,
):
    """Replay primary records without services, filesystem reads or clock rebasing."""
    try:
        _require(len(canonical(packet)) <= MAX_BYTES)
        events.shape(
            packet,
            (
                "schema_version",
                "source",
                "fingerprint",
                "materials",
                "cases",
                "trust",
                "stages",
                "observations",
                "cleanup",
            ),
        )
        events.version(packet["schema_version"])
        _require(
            events.hexadecimal(packet["source"], 40) == expected_source
            and events.hexadecimal(packet["fingerprint"]) == expected_fingerprint
            and packet["cases"] == list(CASES)
        )
        events.shape(expected_materials, METHOD_FILES)
        events.shape(packet["materials"], METHOD_FILES)
        for name in METHOD_FILES:
            _require(events.hexadecimal(packet["materials"][name]) == expected_materials[name])
        projected = _history(packet["trust"], expected_trust_root)
        stages = packet["stages"]
        _require(type(stages) is list and len(stages) == len(STAGES))
        states, queues, beats = {}, {}, {}
        previous_time, previous_clock, previous_queue, previous_collector = 0, 0, None, []
        for index, (stage, name) in enumerate(zip(stages, STAGES, strict=True)):
            events.shape(stage, ("name", "at_seconds", "state"))
            _require(stage["name"] == name and _seconds(stage["at_seconds"]) >= previous_time)
            state = stage["state"]
            registry, queue, book, beat = _snapshot(
                state, expected_registry_root, expected_registry_pin
            )
            clock = state["registry"]["clock_ms"]
            _require(clock >= previous_clock)
            if index:
                _require(
                    abs((clock - previous_clock) / 1000 - (stage["at_seconds"] - previous_time))
                    <= 2
                )
                for old, new in zip(previous_queue["records"], queue["records"]):
                    _require(
                        old["envelope"] == new["envelope"]
                        and old["queued_at_ms"] == new["queued_at_ms"]
                        and (old["receipt"] is None or old["receipt"] == new["receipt"])
                    )
                prior = beats[STAGES[index - 1]]
                _require(
                    beat["sequence"] >= prior["sequence"]
                    and beat["observed_at_ms"] >= prior["observed_at_ms"]
                    and beat["last_event_sequence"] >= prior["last_event_sequence"]
                    and (beat["sequence"] != prior["sequence"] or beat == prior)
                )
            _require(len(queue["records"]) == (0 if index == 0 else 1 if index < 5 else 2))
            if name in ("initial", "revoked_b", "restored", "restarted"):
                _require(beat["last_event_sequence"] == len(queue["records"]))
            _require(state["collector"]["records"][: len(previous_collector)] == previous_collector)
            pending = [r for r in queue["records"] if r["receipt"] is None]
            _require(len(pending) == (1 if name == "pending_c" else 0))
            accepted = [r["envelope"] for r in queue["records"] if r["receipt"] is not None]
            actual = []
            for record in state["collector"]["records"]:
                value = registry.verify(
                    record["envelope"], clock_ms=record["ingested_at_ms"]
                ).document()
                if value["kind"] != "telemetry.gap":
                    actual.append(record["envelope"])
            _require(actual == accepted)
            for record in queue["records"]:
                if record["receipt"] is not None:
                    _require(
                        any(
                            r["envelope"] == record["envelope"]
                            and r["receipt"] == record["receipt"]
                            for r in state["collector"]["records"]
                        )
                    )
            if name in ("initial", "restored", "restarted", "unavailable_after"):
                stream = next(
                    s
                    for s in state["collector"]["telemetry"]["streams"]
                    if s["producer_id"] == queue["producer_id"]
                )
                _require(
                    stream["heartbeat"] is not None
                    and stream["heartbeat"]["envelope"] == queue["heartbeat"]
                )
                if name != "unavailable_after":
                    _require(book.poll(clock_ms=clock)["healthy"] is True)
            states[name], queues[name], beats[name] = state, queue, beat
            previous_time, previous_clock = stage["at_seconds"], clock
            previous_queue, previous_collector = queue, state["collector"]["records"]
        _require(
            queues["unavailable_before"] == queues["unavailable_after"]
            and beats["restored"]["sequence"] > beats["unavailable_after"]["sequence"]
            and beats["restarted"]["sequence"] > beats["recovered"]["sequence"]
            and queues["restarted"] == queues["stopped"] == queues["gap"]
        )
        _require(
            queues["pending_c"]["records"][-1]["envelope"]
            == queues["recovered"]["records"][-1]["envelope"]
            and queues["revoked_b"]["records"][0] == queues["gap"]["records"][0]
        )
        subjects = {}
        for index, (record, fields, commit) in enumerate(
            zip(queues["gap"]["records"], projected, packet["trust"]["commits"], strict=True)
        ):
            verified = registry.verify(record["envelope"], clock_ms=record["queued_at_ms"])
            value = verified.document()
            _require({k: value[k] for k in fields} == fields)
            document = trust.validate(
                commit["history"]["documents"][-1]["envelope"], expected_trust_root, "local-cpu"
            )
            before = states[("initial", "restored")[index]]["registry"]["clock_ms"]
            created = states[("revoked_b", "pending_c")[index]]["registry"]["clock_ms"]
            delivered = states[("revoked_b", "recovered")[index]]["registry"]["clock_ms"]
            # issued_at is SQL epoch seconds rounded down before publishing.
            # A later history readback is not the commit time: the source may
            # already have observed that commit when the owner reads it back.
            _require(max(before, document["issued_at"] * 1000) <= record["queued_at_ms"] <= created)
            receipt = registry.receipt(record["receipt"], verified)
            earliest_delivery = created if index == 1 else record["queued_at_ms"]
            _require(
                earliest_delivery
                <= receipt["ingested_at_ms"]
                <= receipt["routed_at_ms"]
                <= delivered
            )
            subjects[value["event_id"]] = {
                **{k: fields[k] for k in ("kind", "reason", "asset_sha256", "bundle_sha256")},
                "producer_id": queues["gap"]["producer_id"],
            }
        primary = states["gap"]
        producer_id = queues["gap"]["producer_id"]
        stream = next(
            s
            for s in primary["collector"]["telemetry"]["streams"]
            if s["producer_id"] == producer_id
        )
        _require(
            stream["heartbeat"]["envelope"] == queues["gap"]["heartbeat"]
            and beats["gap"]["last_event_sequence"] == 2
        )
        problems = book.poll(clock_ms=primary["registry"]["clock_ms"])["problems"]
        problems = [
            p for p in problems if p["producer_id"] == producer_id and p["reason"] == "heartbeat"
        ]
        _require(len(problems) == 1)
        gaps = []
        for record in primary["collector"]["records"]:
            verified = registry.verify(record["envelope"], clock_ms=record["ingested_at_ms"])
            event = verified.document()
            if (
                event["kind"] == "telemetry.gap"
                and event["asset_sha256"] == problems[0]["notice_id"]
            ):
                _require(
                    event["reason"] == "heartbeat"
                    and event["correlation_id"] == event["asset_sha256"][:32]
                    and event["bundle_sha256"] is None
                    and 90000 <= event["observed_at_ms"] - beats["gap"]["observed_at_ms"] <= 120000
                )
                receipt = registry.receipt(record["receipt"], verified)
                _require(
                    event["observed_at_ms"]
                    <= receipt["ingested_at_ms"]
                    <= receipt["routed_at_ms"]
                    <= beats["gap"]["observed_at_ms"] + 120000
                )
                gaps.append(event)
        _require(len(gaps) == 1)
        subjects[gaps[0]["event_id"]] = {
            k: gaps[0][k] for k in security_source_evidence.SUBJECT_FIELDS
        }
        security_source_evidence.verify_delivery(
            primary,
            expected_root=expected_registry_root,
            expected_pin=expected_registry_pin,
            expected_events=subjects,
        )
        timings = _lifecycle(packet, states, beats)
        return dict(
            status="pass",
            source=expected_source,
            fingerprint=expected_fingerprint,
            cases=list(CASES),
            **timings,
            release_ready=False,
            scope="continuous-trust-source-not-full-M23-or-R1",
            packet_sha256=digest(canonical(packet)),
        )
    except (Rejected, KeyError, TypeError, ValueError, IndexError, OverflowError, RecursionError):
        raise Rejected("security_trust_evidence_invalid") from None
