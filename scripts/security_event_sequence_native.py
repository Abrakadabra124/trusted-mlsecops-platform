"""Hosted real-time sequence loss, with pure replay of retained private evidence.

Two sequential isolated collectors; no SQL, Kubernetes or model workload. A replay
validates signed contents and recorded observations, not independent clock attestation.
The public component result never grants M23/R1 acceptance or release authority.
"""

import os
import socket
import sys
import time
from pathlib import Path

from mlsecops import security_event_config as config
from mlsecops import security_event_ledger as ledger
from mlsecops import security_event_store as storage
from mlsecops import security_events as events
from mlsecops import signing
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    require_fields,
)
from mlsecops.inventory import command, source_fingerprint

MODES = ("ingest-hole", "heartbeat-head-only")
PHASES = ("opened", "restarted", "noticed", "healed", "final")
WINDOW = ("started_ns", "finished_ns", "started_ms", "finished_ms")
PACKET_PATH = ".runtime/evidence/security-sequence-private.json"
SCOPE = "hosted-sequence-component-not-full-M23-R1"
CASE_NAMES = (
    "origin",
    "live-heartbeats",
    "restart-anchor",
    "sequence-notice-identity",
    "signed-route-delivery",
    "notice-within-120s",
    "gap-healed",
    "late-semantics",
    "duplicate-no-incident",
    "forged-producer-rejected",
    "history-retained",
    "owned-cleanup",
)


def _require(condition):
    if not condition:
        raise Rejected("sequence_packet_invalid")


def _window(value, anchor):
    for field in WINDOW:
        _require(type(value[field]) is int and value[field] > 0)
    _require(value["started_ns"] <= value["finished_ns"])
    _require(value["started_ms"] <= value["finished_ms"])
    for side in ("started", "finished"):
        drift = (value[side + "_ns"] - anchor["started_ns"]) / 1000000 - (
            value[side + "_ms"] - anchor["started_ms"]
        )
        _require(abs(drift) <= 5000)


def _stream(state, producer):
    return next(s for s in state["telemetry"]["streams"] if s["producer_id"] == producer)


def _verify_mode(value, expected_mode):
    require_fields(
        value,
        (
            "mode",
            "registry",
            "registry_root",
            "registry_sha256",
            "producer",
            "held_envelope",
            "heartbeats",
            "requests",
            "captures",
            "restarts",
            "cleanup",
        ),
    )
    _require(value["mode"] == expected_mode)
    captures = value["captures"]
    require_fields(captures, PHASES)
    requests, heartbeats = value["requests"], value["heartbeats"]
    _require(type(requests) is list and type(heartbeats) is list and 4 <= len(heartbeats) <= 8)
    expected_requests = [
        "first",
        *(["opening"] if expected_mode == "ingest-hole" else []),
        "healing",
        "duplicate",
        "forged",
    ]
    _require([r["name"] for r in requests] == expected_requests)
    by_name = {r["name"]: r for r in requests}
    anchor = by_name["opening"] if expected_mode == "ingest-hole" else heartbeats[1]
    _window(anchor, anchor)
    registry = config.Registry(
        value["registry"],
        trusted_root=value["registry_root"],
        expected_sha256=value["registry_sha256"],
        clock_ms=anchor["started_ms"],
    )
    producer = registry.producer(value["producer"])
    _require(producer.role == "intake" and producer.heartbeat_required)
    _require(
        [p.identity for p in registry.producers if p.heartbeat_required] == [producer.identity]
    )
    head = 3 if expected_mode == "ingest-hole" else 2
    previous = None
    previous_finished = 0
    for item in heartbeats:
        require_fields(item, (*WINDOW, "envelope", "record"))
        _window(item, anchor)
        _require(item["started_ns"] >= previous_finished)
        previous_finished = item["finished_ns"]
        require_fields(item["record"], ("envelope", "ingested_at_ms"))
        _require(item["record"]["envelope"] == item["envelope"])
        ingested = item["record"]["ingested_at_ms"]
        _require(item["started_ms"] <= ingested <= item["finished_ms"])
        hb = registry.heartbeat(item["envelope"], clock_ms=ingested)
        _require(hb["producer_id"] == producer.identity)
        _require(hb["last_event_sequence"] == (0 if previous is None else head))
        if previous is not None:
            _require(hb["sequence"] == previous["sequence"] + 1)
            _require(0 <= hb["observed_at_ms"] - previous["observed_at_ms"] <= 40000)
        else:
            _require(hb["sequence"] == 1)
        previous = hb
    states, reports = {}, {}
    previous_finished = 0
    for phase in PHASES:
        sample = captures[phase]
        require_fields(sample, (*WINDOW, "state", "health", "health_status", "incidents"))
        _window(sample, anchor)
        _require(sample["started_ns"] >= previous_finished)
        previous_finished = sample["finished_ns"]
        state = sample["state"]
        book = ledger.Ledger(registry, state)
        _require(sample["started_ms"] <= state["updated_at_ms"] <= sample["finished_ms"])
        report = book.poll(clock_ms=state["updated_at_ms"])
        observed = sample["health"]
        require_fields(observed, (*report, "collector_available"))
        _require(sample["started_ms"] <= observed["observed_at_ms"] <= sample["finished_ms"])
        _require(observed["collector_available"] is True)
        for key in report:
            if key != "observed_at_ms":
                _require(canonical(observed[key]) == canonical(report[key]))
        _require(sample["health_status"] == (200 if report["healthy"] else 503))
        _require(report["awaiting_heartbeat"] == [] and report["expired_heartbeats"] == 0)
        _require(report["pending_deliveries"] == 0 and report["storage_full"] is False)
        _require(all(r["receipt"] is not None for r in state["records"]))
        _require(sample["incidents"] == state["records"])
        stream = _stream(state, producer.identity)
        _require(stream["heartbeat"] in [h["record"] for h in heartbeats])
        states[phase], reports[phase] = state, report
    opened = states["opened"]
    opening = _stream(opened, producer.identity)
    since = opening["sequence_gap_since_ms"]
    _require(type(since) is int and opening["sequence_generation"] == 1)
    _require(anchor["started_ms"] <= since <= anchor["finished_ms"])
    for phase in ("opened", "restarted", "noticed"):
        stream = _stream(states[phase], producer.identity)
        _require(stream["sequence_gap_since_ms"] == since and stream["sequence_generation"] == 1)
        _require(reports[phase]["open_sequence_gaps"] == 1 and reports[phase]["healthy"] is False)
    _require(reports["opened"]["problems"] == reports["restarted"]["problems"] == [])
    _require(states["restarted"]["records"] == opened["records"])
    initial = [
        registry.verify(r["envelope"], clock_ms=r["ingested_at_ms"]).document()
        for r in opened["records"]
    ]
    _require([e["sequence"] for e in initial] == ([1, 3] if head == 3 else [1]))
    _require(all(e["producer_id"] == producer.identity for e in initial))
    _require(previous["observed_at_ms"] >= since + 60000)
    _require(heartbeats[-1]["finished_ns"] <= captures["noticed"]["finished_ns"])
    noticed = states["noticed"]
    _require(len(noticed["records"]) == len(initial) + 1)
    _require(noticed["records"][:-1] == opened["records"])
    problems = reports["noticed"]["problems"]
    _require(len(problems) == 1)
    problem = problems[0]
    notice_id = digest(
        canonical(
            dict(
                config=registry.sha256,
                producer=producer.identity,
                epoch=producer.epoch,
                reason="sequence",
                generation=1,
            )
        )
    )
    _require(
        problem
        == dict(
            notice_id=notice_id,
            producer_id=producer.identity,
            epoch=producer.epoch,
            reason="sequence",
            since_ms=since,
            deadline_at_ms=since + 120000,
        )
    )
    notice = noticed["records"][-1]
    event = registry.verify(notice["envelope"], clock_ms=notice["ingested_at_ms"])
    body = event.document()
    _require(body["kind"] == "telemetry.gap" and body["reason"] == "sequence")
    _require(registry.producer(body["producer_id"]).role == "collector")
    _require(body["asset_sha256"] == notice_id and body["correlation_id"] == notice_id[:32])
    _require(since + 90000 <= body["observed_at_ms"] <= since + 120000)
    registry.receipt(notice["receipt"], event)
    elapsed = (captures["noticed"]["finished_ns"] - anchor["started_ns"]) / 1000000000
    _require(90 <= elapsed <= 120)
    healed = states["healed"]
    _require(healed["records"][:-1] == noticed["records"])
    last = healed["records"][-1]
    _require(last["envelope"] == value["held_envelope"])
    held = registry.verify(value["held_envelope"], clock_ms=last["ingested_at_ms"]).document()
    _require(held["sequence"] == 2 and held["producer_id"] == producer.identity)
    _require(last["late"] is (expected_mode == "ingest-hole"))
    for phase in ("healed", "final"):
        _require(reports[phase]["healthy"] is True and reports[phase]["open_sequence_gaps"] == 0)
        _require(reports[phase]["problems"] == [])
        _require(_stream(states[phase], producer.identity)["sequence_generation"] == 1)
    _require(states["final"]["records"] == healed["records"])
    deliveries = []
    for request in requests:
        require_fields(request, (*WINDOW, "name", "envelope", "status", "response"))
        _window(request, anchor)
        duration = (request["finished_ns"] - request["started_ns"]) / 1000000000
        _require(0 <= duration <= 60)
        if request["name"] == "forged":
            _require(request["status"] == 503 and request["response"] == {"status": "unavailable"})
            # A genuinely registered signer with a valid signature cannot impersonate intake.
            signer = registry.producer(events.signer(request["envelope"]))
            raw = events.signed(request["envelope"], "security-event", signer.public_key)
            _require(
                signer.identity != producer.identity and raw["producer_id"] == producer.identity
            )
            try:
                registry.verify(request["envelope"], clock_ms=request["started_ms"])
            except Rejected as failure:
                _require(str(failure) == "security_producer_binding")
            else:
                raise Rejected("sequence_packet_invalid")
            continue
        _require(request["status"] == 200)
        matching = [r for r in healed["records"] if r["envelope"] == request["envelope"]]
        _require(len(matching) == 1)
        record = matching[0]
        _require(request["response"] == record["receipt"])
        if request["name"] != "duplicate":
            receipt = registry.receipt(
                record["receipt"],
                registry.verify(record["envelope"], clock_ms=record["ingested_at_ms"]),
            )
            _require(
                request["started_ms"]
                <= receipt["ingested_at_ms"]
                <= receipt["routed_at_ms"]
                <= request["finished_ms"]
            )
        deliveries.append(duration)
    _require(
        by_name["healing"]["envelope"] == by_name["duplicate"]["envelope"] == value["held_envelope"]
    )
    _require(by_name["healing"]["response"] == by_name["duplicate"]["response"])
    _require(
        captures["healed"]["finished_ns"]
        <= by_name["duplicate"]["started_ns"]
        <= by_name["duplicate"]["finished_ns"]
        <= by_name["forged"]["started_ns"]
        <= by_name["forged"]["finished_ns"]
        <= captures["final"]["started_ns"]
    )
    _require(by_name["first"]["envelope"] == opened["records"][0]["envelope"])
    if head == 3:
        _require(by_name["opening"]["envelope"] == opened["records"][1]["envelope"])
    _require(type(value["restarts"]) is list and len(value["restarts"]) == 2)
    for restart in value["restarts"]:
        require_fields(restart, ("before_pid", "after_pid", "exit_code"))
        _require(
            all(type(restart[k]) is int and restart[k] > 0 for k in ("before_pid", "after_pid"))
        )
        _require(restart["before_pid"] != restart["after_pid"])
        _require(type(restart["exit_code"]) is int and restart["exit_code"] in (0, -15))
    _require(value["restarts"][0]["after_pid"] == value["restarts"][1]["before_pid"])
    require_fields(value["cleanup"], ("process_reaped", "port_closed", "directory_removed"))
    _require(all(v is True for v in value["cleanup"].values()))
    return dict(notice_seconds=elapsed, max_http_delivery_seconds=max(deliveries))


def verify(packet, *, expected_source, expected_fingerprint):
    """Pure strict replay; callers must independently pin source and packet hash.

    The packet is private synthetic evidence, not an independent signature over
    the observer's clocks. No filesystem, subprocess, network or source mutation.
    """
    try:
        require_fields(
            packet,
            (
                "schema_version",
                "source",
                "fingerprint",
                "source_after",
                "fingerprint_after",
                "source_clean",
                "modes",
            ),
        )
        _require(type(packet["schema_version"]) is int and packet["schema_version"] == 1)
        events.hexadecimal(expected_source, 40)
        events.hexadecimal(expected_fingerprint)
        _require(packet["source"] == packet["source_after"] == expected_source)
        _require(packet["fingerprint"] == packet["fingerprint_after"] == expected_fingerprint)
        _require(packet["source_clean"] is True)
        _require(type(packet["modes"]) is list and len(packet["modes"]) == 2)
        _require(len(canonical(packet)) <= 4 * 1024 * 1024)
        timings = {
            name: _verify_mode(value, name)
            for name, value in zip(MODES, packet["modes"], strict=True)
        }
        return dict(
            schema_version=1,
            status="pass",
            source=expected_source,
            fingerprint=expected_fingerprint,
            scope=SCOPE,
            cases=[f"{mode}:{name}" for mode in MODES for name in CASE_NAMES]
            + ["source-unchanged"],
            timings=timings,
            primary_sha256=digest(canonical(packet)),
            cleanup_verified=True,
            release_ready=False,
        )
    except (
        Rejected,
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        StopIteration,
        OverflowError,
        RecursionError,
    ):
        raise Rejected("sequence_packet_invalid") from None


def _begin():
    return dict(started_ns=time.monotonic_ns(), started_ms=time.time_ns() // 1000000)


def _end(value):
    value.update(finished_ms=time.time_ns() // 1000000, finished_ns=time.monotonic_ns())
    return value


def _snapshot(store):
    deadline = time.monotonic() + 2
    while True:
        try:
            return store.snapshot()
        except Rejected as failure:
            if (
                str(failure) not in ("security_store_busy", "security_store_unavailable")
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(0.02)


def _capture(fx, store):
    sample = _begin()
    status, health = fx.exchange("GET", "/health")
    incidents, offset, seen = [], 0, set()
    while offset is not None:
        _require(type(offset) is int and offset not in seen and len(seen) < 256)
        seen.add(offset)
        code, page = fx.exchange("GET", "/incidents/" + str(offset))
        _require(code == 200 and page["release_ready"] is False)
        incidents.extend(page["incidents"])
        offset = page["next_offset"]
    sample.update(state=_snapshot(store), health=health, health_status=status, incidents=incidents)
    return _end(sample)


def _campaign(mode):
    from scripts import security_event_audit_fixture as fixture

    with fixture.live(initial_heartbeat=False, heartbeat_roles=("intake",)) as fx:
        setup = decode(bounded_read(fx.directory / "collector.json", 16384))
        store = storage.Store(setup["state_directory"], setup["state_sha256"], fx.registry)
        producer = digest(signing.decode64(fx.fx.publics["intake"]))
        result = dict(
            mode=mode,
            registry=decode(bounded_read(fx.directory / "registry.json")),
            registry_root=fx.fx.publics["root"],
            registry_sha256=fx.registry.sha256,
            producer=producer,
            heartbeats=[],
            requests=[],
            captures={},
            restarts=[],
        )
        head = 3 if mode == "ingest-hole" else 2

        def heartbeat(last):
            message = fx.fx.heartbeat(
                sequence=len(result["heartbeats"]) + 1,
                producer_id=producer,
                observed_at_ms=fx.now(),
                last_event_sequence=last,
            )
            envelope = signing.sign(message, "security-heartbeat", fx.fx.keys["intake"])
            observation = _begin()
            status, response = fx.exchange("POST", "/heartbeat", envelope, token=fx.ingress)
            _require(status == 200 and response["release_ready"] is False)
            observation.update(envelope=envelope, record=response["heartbeat"])
            result["heartbeats"].append(_end(observation))

        def submit(name, envelope, expected=200):
            request = _begin()
            status, response = fx.exchange("POST", "/events", envelope, token=fx.ingress)
            request.update(name=name, envelope=envelope, status=status, response=response)
            result["requests"].append(_end(request))
            _require(status == expected)

        def restart():
            old = fx.process
            fx.stop()  # Fixture verifies wait, exit and closed owned port.
            fx.start()
            result["restarts"].append(
                dict(before_pid=old.pid, after_pid=fx.process.pid, exit_code=old.returncode)
            )

        heartbeat(0)
        submit("first", fx.event(1))
        held = fx.event(2)
        result["held_envelope"] = held
        if mode == "ingest-hole":
            submit("opening", fx.event(3))
            anchor = result["requests"][-1]["started_ns"]
            heartbeat(head)
        else:
            heartbeat(head)
            anchor = result["heartbeats"][-1]["started_ns"]
        result["captures"]["opened"] = _capture(fx, store)
        restart()
        result["captures"]["restarted"] = _capture(fx, store)
        next_heartbeat = result["heartbeats"][-1]["started_ns"] + 30000000000
        deadline = anchor + 120000000000
        while time.monotonic_ns() <= deadline:
            if time.monotonic_ns() >= next_heartbeat:
                heartbeat(head)
                next_heartbeat = result["heartbeats"][-1]["started_ns"] + 30000000000
            sample = _capture(fx, store)
            # Waiting for a committed, routed notice, not merely unhealthy status.
            if len(sample["incidents"]) > len(result["captures"]["opened"]["incidents"]):
                result["captures"]["noticed"] = sample
                break
            time.sleep(0.5)
        if "noticed" not in result["captures"]:
            raise Rejected("sequence_deadline_failed")
        submit("healing", held)
        result["captures"]["healed"] = _capture(fx, store)
        submit("duplicate", held)
        raw = fx.registry.verify(held, clock_ms=fx.now()).document()
        forged = signing.sign(raw, "security-event", fx.fx.keys["serving"])
        submit("forged", forged, 503)
        restart()
        result["captures"]["final"] = _capture(fx, store)
        process, port, directory = fx.process, fx.port, fx.directory
    # Context-manager cleanup exceptions propagate before any success projection.
    with socket.socket() as sock:
        sock.settimeout(1)
        closed = sock.connect_ex(("127.0.0.1", port)) != 0
    result["cleanup"] = dict(
        process_reaped=process.poll() in (0, -15),
        port_closed=closed,
        directory_removed=not directory.exists(),
    )
    return result


def retain_packet(packet, path, *, expected_source, expected_fingerprint):
    """Verify before private atomic write, then verify the exact retained bytes."""
    public = verify(
        packet, expected_source=expected_source, expected_fingerprint=expected_fingerprint
    )
    content = canonical(packet)
    atomic_write(path, content, mode=0o600)
    retained = bounded_read(path, 4 * 1024 * 1024)
    _require(retained == content and digest(retained) == public["primary_sha256"])
    _require(
        verify(
            decode(retained),
            expected_source=expected_source,
            expected_fingerprint=expected_fingerprint,
        )
        == public
    )
    return public


def qualify():
    """Run only on disposable hosted Linux; this function is never a local test."""
    if (
        sys.platform != "linux"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise Rejected("sequence_hosted_required")
    root = Path(__file__).resolve().parents[1]
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("sequence_source_dirty")
    source = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint = source_fingerprint(root)
    packet = dict(
        schema_version=1,
        source=source,
        fingerprint=fingerprint,
        modes=[_campaign(mode) for mode in MODES],
        source_after=command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        fingerprint_after=source_fingerprint(root),
        source_clean=not command(["git", "-C", str(root), "status", "--porcelain"]),
    )
    return retain_packet(
        packet, root / PACKET_PATH, expected_source=source, expected_fingerprint=fingerprint
    )


def failure_report(failure):
    allowed = {
        "sequence_hosted_required",
        "sequence_source_dirty",
        "sequence_deadline_failed",
        "sequence_packet_invalid",
    }
    reason = (
        str(failure)
        if isinstance(failure, Rejected) and str(failure) in allowed
        else "sequence_campaign_failed"
    )
    return dict(
        schema_version=1,
        status="fail",
        scope=SCOPE,
        reason=reason,
        cases=[],
        timings={},
        primary_sha256=None,
        cleanup_verified=False,
        release_ready=False,
    )


if __name__ == "__main__":
    try:
        result = qualify()
    except Exception as failure:
        print(canonical(failure_report(failure)).decode("ascii"))
        raise SystemExit(1) from None
    print(canonical(result).decode("ascii"))
