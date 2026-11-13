"""Private identity primary retention and pure replay; never model acceptance."""

import math
from collections import Counter
from pathlib import Path

from mlsecops import security_event_config as config
from mlsecops import security_event_ledger as ledger
from mlsecops import security_event_outbox as outbox
from mlsecops import security_events as events
from mlsecops import security_source_evidence
from mlsecops.contracts import Rejected, atomic_write, bounded_read, canonical, decode, digest

METHOD_FILES = (
    "scripts/security_identity_events_native.py",
    "scripts/security_identity_evidence_qualification.py",
    "scripts/security_event_audit_fixture.py",
    "scripts/security_event_live_qualification.py",
    "scripts/security_events_qualification.py",
    "mlsecops/security_identity_evidence.py",
    "mlsecops/security_source_evidence.py",
)
MAX_BYTES = 4 * 1024 * 1024
SCOPE = "actual-http-and-identity-child-with-controlled-unready-engine-not-M13-M14-M23"
SERVICE = digest(b"controlled-unready-http-service-for-identity-audit")
PHASES = ("startup", "outage", "failed-startup", "recovered", "periodic", "stopped")
# Ordered, finite observations. Credential values and response bodies never enter evidence.
HTTP_CASES = (
    ("startup", "/livez", 200, None),
    ("predict-missing", "/v1/predict", 401, "credential"),
    ("ready-invalid", "/readyz", 401, "credential"),
    ("predict-role", "/v1/predict", 401, "role"),
    ("metrics-role", "/metrics", 401, "role"),
    ("metrics-missing", "/metrics", 401, "credential"),
    ("metrics-authorized", "/metrics", 200, None),
    ("outage-denial", "/v1/predict", 503, "credential"),
    ("outage-live", "/livez", 200, None),
    ("outage-metrics", "/metrics", 200, None),
    ("recovered", "/livez", 200, None),
)
SINGLE_CASES = (
    "startup-probe-creates-no-denial",
    "startup-actual-producer-heartbeat",
    "live-producer-allows-fresh-audit-challenge",
    "valid-metrics-does-not-emit-identity-denial",
    "audit-outage-denies-with-503",
    "offline-event-retained-before-child-exit",
    "liveness-and-operator-remain-available",
    "pending-outage-denies-server-startup",
    "failed-startup-keeps-original-pending",
    "startup-probe-delivers-original-event",
    "restart-retains-heartbeat-counter-and-complete-head",
    "operator-retry-is-idempotent",
    "credentials-and-input-absent-from-outbox",
    "actual-thirty-second-owned-scheduler",
    "periodic-heartbeat-reached-collector",
    "actual-stopped-producer-gap-within-120s",
    "stopped-owner-cannot-keep-sending-heartbeats",
    "missing-producer-denies-fresh-promotion-audit",
    "all-three-server-lifecycles-reaped-their-children",
    "no-credentials-in-private-server-log",
    "collector-and-private-files-cleaned",
    "source-unchanged",
)
SUMMARY_FIELDS = (
    "status",
    "source",
    "fingerprint",
    "cases",
    "max_http_seconds",
    "heartbeat_interval_seconds",
    "stopped_producer_notice_seconds",
    "release_ready",
    "scope",
)
HTTP_FIELDS = (
    "case",
    "method",
    "path",
    "status",
    "request_id",
    "reason",
    "service_sha256",
    "error_code",
    "started_at_ms",
    "completed_at_ms",
    "elapsed_seconds",
)


def _require(condition):
    if not condition:
        raise Rejected("identity_evidence_invalid")


def method_materials(root):
    return {name: digest(bounded_read(Path(root) / name)) for name in METHOD_FILES}


def observation(case, path, status, content, *, started_at_ms, completed_at_ms, elapsed_seconds):
    """Project actual HTTP output onto finite fields; never retain body or headers."""
    specification = next((row for row in HTTP_CASES if row[0] == case), None)
    _require(specification is not None and (path, status) == specification[1:3])
    reason = specification[3]
    value = decode(content) if reason is not None else None
    if value is not None:
        events.shape(value, ("schema_version", "request_id", "error"))
        events.version(value["schema_version"])
        events.hexadecimal(value["request_id"], 32)
        events.shape(value["error"], ("code",))
        _require(
            value["error"]["code"]
            == ("unauthorized" if status == 401 else "security_audit_unavailable")
        )
    return dict(
        case=case,
        method="POST" if path == "/v1/predict" else "GET",
        path=path,
        status=status,
        request_id=value["request_id"] if value is not None else None,
        reason=reason,
        service_sha256=SERVICE,
        error_code=value["error"]["code"] if value is not None else None,
        started_at_ms=started_at_ms,
        completed_at_ms=completed_at_ms,
        elapsed_seconds=elapsed_seconds,
    )


def capture(outbox_reader, collector_reader, clock):
    """Copy primary journals while the owning fixture still owns its files."""
    queue, book = outbox_reader(), collector_reader()
    return decode(canonical(dict(outbox=queue, collector=book, captured_at_ms=clock())))


def _number(value, minimum, maximum):
    _require(type(value) in (int, float) and math.isfinite(value) and minimum <= value <= maximum)
    return value


def _cleanup(packet):
    value = packet["cleanup"]
    events.shape(
        value,
        (
            "http_exits",
            "child_cleanup_markers",
            "collector_exit_code",
            "collector_port_closed",
            "fixture_removed",
            "http_owner_reaped",
            "collector_owner_reaped",
            "captured_at_ms",
            "confirmed_at_ms",
            "outage_exit_code",
            "outage_port_closed",
        ),
    )
    for field in (
        "collector_port_closed",
        "fixture_removed",
        "http_owner_reaped",
        "collector_owner_reaped",
        "outage_port_closed",
    ):
        _require(value[field] is True)
    _require(type(value["child_cleanup_markers"]) is int and value["child_cleanup_markers"] == 3)
    _require(type(value["collector_exit_code"]) is int and value["collector_exit_code"] in (0, -15))
    _require(type(value["outage_exit_code"]) is int and value["outage_exit_code"] in (0, -15))
    _require(type(value["http_exits"]) is list and len(value["http_exits"]) == 3)
    for item, phase, code in zip(
        value["http_exits"], ("outage", "failed-startup", "stopped"), (0, 1, 0), strict=True
    ):
        events.shape(item, ("phase", "exit_code", "port_closed"))
        _require(
            item["phase"] == phase
            and type(item["exit_code"]) is int
            and item["exit_code"] == code
            and item["port_closed"] is True
        )
    _require(
        events.integer(value["confirmed_at_ms"])
        >= events.integer(value["captured_at_ms"])
        == packet["snapshots"]["stopped"]["captured_at_ms"]
    )


def _snapshots(packet, registry):
    snapshots = packet["snapshots"]
    events.shape(snapshots, PHASES)
    queues, books, heartbeats = {}, {}, {}
    previous = 0
    producer = packet["delivery"]["outboxes"][0]["producer_id"]
    _require(registry.producer(producer).role == "serving")
    for phase, count, collected in zip(PHASES, (0, 6, 6, 6, 6, 6), (0, 5, 5, 6, 6, 7), strict=True):
        snap = snapshots[phase]
        events.shape(snap, ("outbox", "collector", "captured_at_ms"))
        clock = events.integer(snap["captured_at_ms"])
        registry.valid(clock)
        _require(clock >= previous)
        previous = clock
        queue = outbox.Outbox(registry, producer, snap["outbox"])
        book = ledger.Ledger(registry, snap["collector"])
        queues[phase], books[phase] = queue.document(), book.document()
        _require(
            len(queues[phase]["records"]) == count
            and len(books[phase]["records"]) == collected
            and not book.pending()
            and max(queues[phase]["updated_at_ms"], books[phase]["updated_at_ms"]) <= clock
        )
        heartbeats[phase] = registry.heartbeat(queues[phase]["heartbeat"], clock_ms=clock)
    final = queues["stopped"]["records"]
    for phase in PHASES[1:]:
        records = queues[phase]["records"]
        _require(records[:5] == final[:5])
        if phase in ("outage", "failed-startup"):
            _require(
                records[-1]["receipt"] is None
                and records[-1]["envelope"] == final[-1]["envelope"]
                and records[-1]["queued_at_ms"] == final[-1]["queued_at_ms"]
            )
        else:
            _require(records == final and all(record["receipt"] is not None for record in records))
        # Check each earlier collector against the terminal immutable event/receipt history.
        _require(
            books[phase]["records"] == books["stopped"]["records"][: len(books[phase]["records"])]
        )
    _require(queues["outage"] == queues["failed-startup"])
    _require(
        heartbeats["startup"]["sequence"] == 1
        and heartbeats["startup"]["last_event_sequence"] == 0
        and heartbeats["recovered"]["sequence"] > heartbeats["outage"]["sequence"]
        and heartbeats["recovered"]["last_event_sequence"] == 6
        and heartbeats["periodic"]["sequence"] == heartbeats["recovered"]["sequence"] + 1
        and heartbeats["periodic"] == heartbeats["stopped"]
    )
    for phase in ("startup", "recovered", "periodic", "stopped"):
        stream = next(
            s for s in books[phase]["telemetry"]["streams"] if s["producer_id"] == producer
        )
        _require(stream["heartbeat"]["envelope"] == queues[phase]["heartbeat"])
    _require(
        packet["delivery"]["outboxes"] == [queues["stopped"]]
        and packet["delivery"]["collector"] == books["stopped"]
    )
    return queues, books, heartbeats


def _http(packet, registry, queues):
    observations = packet["http"]
    _require(type(observations) is list and len(observations) == len(HTTP_CASES))
    original = queues["stopped"]["records"]
    expected_events, correlations, index, previous = {}, set(), 0, 0
    for row, specification in zip(observations, HTTP_CASES, strict=True):
        events.shape(row, HTTP_FIELDS)
        case, path, status, reason = specification
        _require(
            (row["case"], row["path"], row["status"], row["reason"]) == specification
            and type(row["status"]) is int
            and row["service_sha256"] == SERVICE
            and row["method"] == ("POST" if path == "/v1/predict" else "GET")
        )
        began, ended = events.integer(row["started_at_ms"]), events.integer(row["completed_at_ms"])
        _require(previous <= began <= ended)
        previous = ended
        elapsed = _number(row["elapsed_seconds"], 0, 8)
        _require(abs((ended - began) / 1000 - elapsed) <= 0.1)
        if reason is None:
            _require(row["request_id"] is None and row["error_code"] is None)
            continue
        correlation = events.hexadecimal(row["request_id"], 32)
        _require(correlation not in correlations)
        correlations.add(correlation)
        record = original[index]
        index += 1
        event = registry.verify(record["envelope"], clock_ms=record["queued_at_ms"])
        value, receipt = event.document(), registry.receipt(record["receipt"], event)
        _require(
            value["kind"] == "identity.denied"
            and value["reason"] == reason
            and value["correlation_id"] == correlation
            and value["asset_sha256"] == SERVICE
            and value["bundle_sha256"] is None
            and event.route == "security.identity"
            and began <= record["queued_at_ms"] <= ended
        )
        if status == 401:
            # Observer, producer and collector share the native campaign host.
            # Transport clock skew cannot excuse a receipt before its HTTP cause.
            _require(
                row["error_code"] == "unauthorized"
                and began
                <= value["occurred_at_ms"]
                <= record["queued_at_ms"]
                <= receipt["ingested_at_ms"]
                <= receipt["routed_at_ms"]
                <= ended
            )
        else:
            _require(
                row["error_code"] == "security_audit_unavailable"
                and receipt["ingested_at_ms"] > ended
                and receipt["ingested_at_ms"]
                >= packet["snapshots"]["failed-startup"]["captured_at_ms"]
            )
        expected_events[value["event_id"]] = {
            key: value[key] for key in security_source_evidence.SUBJECT_FIELDS
        }
    _require(len(expected_events) == 6)
    by_case = {row["case"]: row for row in observations}
    for case, phase in (
        ("startup", "startup"),
        ("outage-denial", "outage"),
        ("recovered", "recovered"),
    ):
        _require(by_case[case]["completed_at_ms"] <= packet["snapshots"][phase]["captured_at_ms"])
    _require(
        packet["snapshots"]["startup"]["captured_at_ms"]
        <= by_case["predict-missing"]["started_at_ms"]
        and packet["snapshots"]["failed-startup"]["captured_at_ms"]
        <= by_case["recovered"]["started_at_ms"]
    )
    return expected_events


def _timing(packet, registry, books, heartbeats):
    summary = packet["summary"]
    interval = (
        heartbeats["periodic"]["observed_at_ms"] - heartbeats["recovered"]["observed_at_ms"]
    ) / 1000
    _require(_number(summary["heartbeat_interval_seconds"], 30, 40) == interval)
    last = heartbeats["stopped"]["observed_at_ms"]
    book = ledger.Ledger(registry, books["stopped"])
    report = book.poll(clock_ms=books["stopped"]["updated_at_ms"])
    _require(len(report["problems"]) == 1 and report["healthy"] is False)
    problem = report["problems"][0]
    _require(
        problem["reason"] == "heartbeat"
        and problem["producer_id"] == heartbeats["stopped"]["producer_id"]
    )
    notice = books["stopped"]["records"][-1]
    event = registry.verify(notice["envelope"], clock_ms=notice["ingested_at_ms"])
    value = event.document()
    receipt = registry.receipt(notice["receipt"], event)
    _require(
        value["kind"] == "telemetry.gap"
        and value["reason"] == "heartbeat"
        and value["asset_sha256"] == problem["notice_id"]
        and value["bundle_sha256"] is None
        and value["correlation_id"] == problem["notice_id"][:32]
        and registry.producer(value["producer_id"]).role == "collector"
        and 90000 <= value["observed_at_ms"] - last <= 120000
    )
    elapsed = _number(summary["stopped_producer_notice_seconds"], 90, 120)
    gap = packet["gap"]
    events.shape(gap, ("observed_at_ms", "elapsed_seconds", "health_status"))
    observed = events.integer(gap["observed_at_ms"])
    _require(
        type(gap["health_status"]) is int
        and gap["health_status"] == 503
        and _number(gap["elapsed_seconds"], 90, 120) == elapsed
        and abs((observed - last) / 1000 - elapsed) <= 0.1
    )
    # The snapshot is taken just after notice/health/admission readback and stopping the collector.
    # Bound this wall-clock reconciliation independently of the claimed summary duration.
    captured = packet["snapshots"]["stopped"]["captured_at_ms"]
    _require(
        value["occurred_at_ms"]
        <= value["observed_at_ms"]
        <= receipt["ingested_at_ms"]
        <= receipt["routed_at_ms"]
        <= observed
        <= captured
        and captured - observed <= 8000
    )


def verify(packet, *, expected):
    """Reconcile immutable records with owner-pinned method, finite HTTP and cleanup observations.

    This is a consistency replay, not remote attestation of the host or a rerun of HTTP.
    The external packet hash and expected owner bindings must come from the retained run.
    """
    try:
        events.shape(
            packet,
            (
                "schema_version",
                "source",
                "fingerprint",
                "method",
                "method_materials",
                "service_sha256",
                "delivery",
                "snapshots",
                "http",
                "cleanup",
                "summary",
                "gap",
            ),
        )
        events.version(packet["schema_version"])
        _require(len(canonical(packet)) <= MAX_BYTES)
        events.shape(
            expected,
            ("source", "fingerprint", "method_materials", "registry_root", "registry_sha256"),
        )
        events.hexadecimal(expected["source"], 40)
        events.hexadecimal(expected["fingerprint"])
        events.shape(expected["method_materials"], METHOD_FILES)
        for value in expected["method_materials"].values():
            events.hexadecimal(value)
        _require(
            all(
                packet[field] == expected[field]
                for field in ("source", "fingerprint", "method_materials")
            )
            and packet["method"] == SCOPE
            and packet["service_sha256"] == SERVICE
        )
        authority = packet["delivery"]["registry"]
        _require(
            authority["root"] == expected["registry_root"]
            and authority["pin"] == expected["registry_sha256"]
        )
        registry = config.Registry(
            authority["envelope"],
            trusted_root=expected["registry_root"],
            expected_sha256=expected["registry_sha256"],
            clock_ms=authority["clock_ms"],
        )
        summary = packet["summary"]
        events.shape(summary, SUMMARY_FIELDS)
        _require(
            summary["status"] == "pass"
            and summary["scope"] == SCOPE
            and summary["release_ready"] is False
            and summary["source"] == expected["source"]
            and summary["fingerprint"] == expected["fingerprint"]
        )
        counts = Counter(SINGLE_CASES)
        counts.update({"signed-identity-subject-and-route-" + str(i): 1 for i in range(1, 7)})
        counts.update(
            {
                "bounded-private-http-output": 11,
                "actual-http-identity-denied-after-delivery": 5,
                "owned-http-exit-and-port-closed": 2,
            }
        )
        _require(type(summary["cases"]) is list and Counter(summary["cases"]) == counts)
        _cleanup(packet)
        queues, books, heartbeats = _snapshots(packet, registry)
        expected_events = _http(packet, registry, queues)
        security_source_evidence.verify_delivery(
            packet["delivery"],
            expected_root=expected["registry_root"],
            expected_pin=expected["registry_sha256"],
            expected_events=expected_events,
        )
        _timing(packet, registry, books, heartbeats)
        _require(
            _number(summary["max_http_seconds"], 0, 8)
            == max(row["elapsed_seconds"] for row in packet["http"])
        )
        return decode(canonical(summary))
    except (
        OSError,
        Rejected,
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        StopIteration,
        OverflowError,
        RecursionError,
    ):
        raise Rejected("identity_evidence_invalid") from None


def replay(path, *, expected_sha256, expected):
    try:
        content = bounded_read(path, MAX_BYTES)
        _require(digest(content) == expected_sha256)
        packet = decode(content, MAX_BYTES)
        _require(content == canonical(packet))
        return {**verify(packet, expected=expected), "primary_sha256": expected_sha256}
    except (OSError, Rejected, KeyError, TypeError, ValueError, IndexError):
        raise Rejected("identity_evidence_invalid") from None


def retain(root, packet, *, expected):
    verify(packet, expected=expected)
    content = canonical(packet)
    pin = digest(content)
    path = Path(root) / ".runtime/security-identity-primary" / (pin + ".json")
    atomic_write(path, content)
    result = replay(path, expected_sha256=pin, expected=expected)
    # Preserve owner pins separately so a future composition does not derive its
    # authority from the primary packet it is supposed to verify.
    binding = canonical({"expected": expected, "primary_sha256": pin})
    binding_path = path.with_suffix(".bindings.json")
    atomic_write(binding_path, binding)
    _require(bounded_read(binding_path, MAX_BYTES) == binding)
    return {**result, "binding_sha256": digest(binding)}
