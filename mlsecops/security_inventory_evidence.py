"""Pure replay of private inventory campaign evidence using owner-supplied pins.

Replays signatures and controlled graph predicates. Candidate SQL reads, CLI
timings and cleanup are observations of the pinned native recorder, not proof
of current SQL state. Candidate requests retain finite projections and opaque
request hashes, never client paths, credentials, model bytes or raw CLI output.
This component cannot grant M19/M23 acceptance or release authority.
"""

import re

from mlsecops import asset_graph, security_event_config, security_events
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.security_source_evidence import verify_delivery

SCOPE = "actual-candidate-sql-and-controlled-graph-not-full-M19-M23"
MAX_BYTES = 4 * 1024 * 1024
METHODS = (
    "scripts/security_inventory_events_native.py",
    "scripts/asset_graph_fixture.py",
    "scripts/security_source_capture.py",
    "mlsecops/security_inventory_evidence.py",
    "mlsecops/security_inventory_events.py",
    "mlsecops/security_source_evidence.py",
    "mlsecops/candidate_lineage.py",
    "mlsecops/asset_graph.py",
)
BINDINGS = (
    "candidate_reference",
    "evaluation_reference",
    "model_sha256",
    "image_id",
    "source_revision",
    "source_fingerprint",
)
STEPS = (
    ("candidate-valid", None, 0),
    ("candidate-source-mismatch", "digest", 1),
    ("candidate-image-mismatch-offline", "digest", 2),
    ("candidate-blocked-pending", None, 2),
    ("candidate-valid-after-retry", None, 2),
    ("candidate-missing", None, 2),
    ("graph-valid", None, 2),
    ("graph-digest", "digest", 3),
    ("graph-owner", "owner", 4),
    ("graph-dangling", "dangling", 5),
    ("graph-cycle", "cycle", 6),
    ("candidate-request-pin", None, 6),
)


def _require(condition):
    if not condition:
        raise Rejected("inventory_evidence_invalid")


def _interval(value):
    start = security_events.integer(value["started_at_ms"])
    end = security_events.integer(value["finished_at_ms"])
    elapsed = security_events.integer(value["elapsed_ns"], 0)
    _require(start <= end and end - start <= 30_000 and elapsed <= 30_000_000_000)
    return start, end


def _graph_reason(request):
    # Validate every retained field even when assess exits on an early owner error.
    security_events.shape(
        request, ("document", "snapshot", "revoked", "trusted_owners", "environment")
    )
    graph, snapshot = request["document"], request["snapshot"]
    security_events.shape(graph, ("schema_version", "assets"))
    security_events.shape(
        snapshot, ("schema_version", "environment", "graph_sha256", "deployments")
    )
    security_events.version(graph["schema_version"])
    security_events.version(snapshot["schema_version"])
    _require(request["environment"] == snapshot["environment"])
    for name in (request["environment"], snapshot["environment"], *request["trusted_owners"]):
        _require(type(name) is str and re.fullmatch(r"[a-z][a-z0-9._-]{0,95}", name) is not None)
    security_events.hexadecimal(snapshot["graph_sha256"])
    for asset in graph["assets"]:
        security_events.shape(
            asset, ("asset_id", "kind", "sha256", "owner", "environment", "dependencies")
        )
        for key in ("asset_id", "kind", "owner", "environment"):
            _require(
                type(asset[key]) is str
                and re.fullmatch(r"[a-z][a-z0-9._-]{0,95}", asset[key]) is not None
            )
        security_events.hexadecimal(asset["sha256"])
        _require(asset["environment"] == request["environment"])
        for reference in asset["dependencies"]:
            security_events.shape(reference, ("asset_id", "sha256"))
            _require(
                type(reference["asset_id"]) is str
                and re.fullmatch(r"[a-z][a-z0-9._-]{0,95}", reference["asset_id"]) is not None
            )
            security_events.hexadecimal(reference["sha256"])
    for record in snapshot["deployments"]:
        security_events.shape(
            record,
            (
                "asset_id",
                "sha256",
                "release_sha256",
                "model_sha256",
                "runtime_sha256",
                "policy_sha256",
            ),
        )
        _require(
            type(record["asset_id"]) is str
            and re.fullmatch(r"[a-z][a-z0-9._-]{0,95}", record["asset_id"]) is not None
        )
        for key in ("sha256", "release_sha256", "model_sha256", "runtime_sha256", "policy_sha256"):
            security_events.hexadecimal(record[key])
    for reference in request["revoked"]:
        security_events.shape(reference, ("asset_id", "sha256"))
        _require(
            type(reference["asset_id"]) is str
            and re.fullmatch(r"[a-z][a-z0-9._-]{0,95}", reference["asset_id"]) is not None
        )
        security_events.hexadecimal(reference["sha256"])
    try:
        asset_graph.assess(**request)
    except asset_graph.InventoryMismatch as error:
        return error.reason
    return None


def _candidate_request(item, bindings):
    request = item["candidate_request"]
    security_events.shape(request, ("candidate_reference", "evaluation_reference", "expected"))
    security_events.shape(
        request["expected"], ("source_revision", "source_fingerprint", "image_id")
    )
    expected = {key: bindings[key] for key in ("source_revision", "source_fingerprint", "image_id")}
    case = item["case_id"]
    if case == "candidate-source-mismatch":
        _require(expected["source_revision"] != "0" * 40)
        expected["source_revision"] = "0" * 40
    elif case in ("candidate-image-mismatch-offline", "candidate-blocked-pending"):
        _require(expected["image_id"] != "sha256:" + "f" * 64)
        expected["image_id"] = "sha256:" + "f" * 64
    candidate = "0" * 64 if case == "candidate-missing" else bindings["candidate_reference"]
    _require(
        request
        == dict(
            candidate_reference=candidate,
            evaluation_reference=bindings["evaluation_reference"],
            expected=expected,
        )
    )
    _require(item["graph_request"] is None and item["subject_sha256"] == candidate)


def verify(
    packet,
    *,
    expected_source,
    expected_fingerprint,
    expected_methods,
    expected_candidate,
    expected_root,
    expected_pin,
):
    """Verify a packet; expected_candidate is the owner's six-field binding map.

    The owner must obtain all expectations independently, not copy them from an
    untrusted packet. primary_sha256 pins the whole canonical private packet.
    """
    try:
        security_events.shape(
            packet,
            (
                "schema_version",
                "scope",
                "source",
                "fingerprint",
                "methods",
                "bindings",
                "observations",
                "bundle",
                "retry",
                "cleanup",
                "sql",
            ),
        )
        security_events.version(packet["schema_version"])
        _require(len(canonical(packet)) <= MAX_BYTES and packet["scope"] == SCOPE)
        security_events.hexadecimal(expected_source, 40)
        security_events.hexadecimal(expected_fingerprint)
        _require(
            packet["source"] == expected_source and packet["fingerprint"] == expected_fingerprint
        )
        security_events.shape(expected_methods, METHODS)
        for value in expected_methods.values():
            security_events.hexadecimal(value)
        _require(packet["methods"] == expected_methods)
        security_events.shape(expected_candidate, BINDINGS)
        for key in (
            "candidate_reference",
            "evaluation_reference",
            "model_sha256",
            "source_fingerprint",
        ):
            security_events.hexadecimal(expected_candidate[key])
        _require(
            expected_candidate["source_revision"] == expected_source
            and expected_candidate["source_fingerprint"] == expected_fingerprint
        )
        image = expected_candidate["image_id"]
        _require(type(image) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", image) is not None)
        _require(packet["bindings"] == expected_candidate)
        sql = packet["sql"]
        security_events.shape(
            sql,
            (
                "before",
                "after",
                "owned_container_before",
                "owned_container_after",
                "source_sql_cleanup",
            ),
        )
        _require(sql["source_sql_cleanup"] == "caller-owned-not-performed")
        security_events.hexadecimal(sql["owned_container_before"])
        _require(sql["owned_container_before"] == sql["owned_container_after"])
        security_events.shape(sql["before"], ("manifests", "lineage", "candidates", "evaluations"))
        for table in sql["before"].values():
            security_events.shape(table, ("objects", "digest"))
            _require(security_events.integer(table["objects"], 0) <= 2000)
            security_events.hexadecimal(table["digest"])
        _require(sql["before"] == sql["after"])
        cleanup = packet["cleanup"]
        security_events.shape(
            cleanup,
            (
                "collector_process_stopped",
                "collector_port_closed",
                "fixture_removed",
                "confirmed_at_ms",
            ),
        )
        _require(
            all(
                cleanup[key] is True
                for key in ("collector_process_stopped", "collector_port_closed", "fixture_removed")
            )
        )
        closed = security_events.integer(cleanup["confirmed_at_ms"])
        bundle = packet["bundle"]
        authority = bundle["registry"]
        registry = security_event_config.Registry(
            authority["envelope"],
            trusted_root=expected_root,
            expected_sha256=expected_pin,
            clock_ms=authority["clock_ms"],
        )
        _require(authority["clock_ms"] <= closed)
        _require(type(bundle["outboxes"]) is list and len(bundle["outboxes"]) == 1)
        queue = bundle["outboxes"][0]
        _require(len(queue["records"]) == 6)
        observations = packet["observations"]
        _require(type(observations) is list and len(observations) == len(STEPS))
        _require(len({observations[index]["request_sha256"] for index in (0, 1, 2, 5)}) == 4)
        for repeated, original in ((3, 2), (4, 0), (11, 0)):
            _require(
                observations[repeated]["request_sha256"] == observations[original]["request_sha256"]
            )
        expected_events, previous_end, count = {}, 0, 0
        for item, (case, reason, total) in zip(observations, STEPS):
            security_events.shape(
                item,
                (
                    "case_id",
                    "subject_kind",
                    "subject_sha256",
                    "request_sha256",
                    "configured_request_sha256",
                    "candidate_request",
                    "graph_request",
                    "decision",
                    "returncode",
                    "started_at_ms",
                    "finished_at_ms",
                    "elapsed_ns",
                    "before_count",
                    "after_count",
                    "event_id",
                ),
            )
            _require(item["case_id"] == case)
            start, end = _interval(item)
            _require(previous_end <= start <= end <= authority["clock_ms"])
            previous_end = end
            _require(
                security_events.integer(item["before_count"], 0) == count
                and security_events.integer(item["after_count"], 0) == total
            )
            accepted = case in ("candidate-valid", "candidate-valid-after-retry", "graph-valid")
            _require(
                type(item["returncode"]) is int and item["returncode"] == (0 if accepted else 1)
            )
            _require(
                item["decision"] == ("verified" if accepted else "inventory_security_rejected")
            )
            security_events.hexadecimal(item["request_sha256"])
            pin = item["configured_request_sha256"]
            _require(
                pin == ("0" * 64 if case == "candidate-request-pin" else item["request_sha256"])
            )
            _require(case != "candidate-request-pin" or pin != item["request_sha256"])
            if case.startswith("graph-"):
                _require(
                    item["subject_kind"] == "controlled-graph" and item["candidate_request"] is None
                )
                _require(
                    digest(canonical(item["graph_request"]))
                    == item["request_sha256"]
                    == item["subject_sha256"]
                )
                _require(_graph_reason(item["graph_request"]) == reason)
            else:
                _require(item["subject_kind"] == "actual-sql-candidate")
                _candidate_request(item, expected_candidate)
            if reason is not None:
                record = queue["records"][count]
                verified = registry.verify(record["envelope"], clock_ms=record["queued_at_ms"])
                event = verified.document()
                _require(
                    start
                    <= event["occurred_at_ms"]
                    <= event["observed_at_ms"]
                    <= record["queued_at_ms"]
                    <= end
                )
                receipt = registry.receipt(record["receipt"], verified)
                # The recorder and collector share a host clock. Online CLI
                # return follows delivery; only the offline case uses retry time.
                _require(
                    record["queued_at_ms"] <= receipt["ingested_at_ms"] <= receipt["routed_at_ms"]
                )
                if case != "candidate-image-mismatch-offline":
                    _require(receipt["routed_at_ms"] <= end)
                _require(
                    item["event_id"] == event["event_id"]
                    and item["event_id"] not in expected_events
                )
                expected_events[item["event_id"]] = dict(
                    kind="inventory.mismatch",
                    reason=reason,
                    asset_sha256=item["subject_sha256"],
                    bundle_sha256=None,
                    producer_id=queue["producer_id"],
                )
            else:
                _require(item["event_id"] is None)
            count = total
        retry = packet["retry"]
        security_events.shape(
            retry, ("pending_record", "started_at_ms", "finished_at_ms", "elapsed_ns", "delivered")
        )
        start, end = _interval(retry)
        _require(
            observations[3]["finished_at_ms"] <= start <= end <= observations[4]["started_at_ms"]
        )
        _require(type(retry["delivered"]) is int and retry["delivered"] == 1)
        pending = dict(queue["records"][1], receipt=None)
        _require(retry["pending_record"] == pending)
        event = registry.verify(pending["envelope"], clock_ms=pending["queued_at_ms"])
        receipt = registry.receipt(queue["records"][1]["receipt"], event)
        _require(start <= receipt["ingested_at_ms"] <= receipt["routed_at_ms"] <= end)
        delivered = verify_delivery(
            bundle,
            expected_root=expected_root,
            expected_pin=expected_pin,
            expected_events=expected_events,
        )
        inventory_ids = set()
        for record in bundle["collector"]["records"]:
            value = registry.verify(
                record["envelope"], clock_ms=record["ingested_at_ms"]
            ).document()
            if value["kind"] == "inventory.mismatch":
                inventory_ids.add(value["event_id"])
            else:
                _require(value["kind"] == "telemetry.gap")
        _require(inventory_ids == set(expected_events))
        return dict(
            status="pass",
            scope=SCOPE,
            event_count=len(delivered["events"]),
            primary_sha256=digest(canonical(packet)),
            release_ready=False,
        )
    except (Rejected, KeyError, TypeError, ValueError, IndexError, OverflowError, RecursionError):
        raise Rejected("inventory_evidence_invalid") from None
