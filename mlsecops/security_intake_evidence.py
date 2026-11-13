"""Pure replay of actual intake/controller decisions and private signed records."""

from mlsecops import security_event_ledger as ledger
from mlsecops import security_events as events
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.security_source_evidence import verify_delivery

CASES = (
    (
        "artifact-unsupported-format",
        "artifact.rejected",
        "unsupported_format",
        "model",
        "model_intake_fail",
    ),
    (
        "worker-output-schema",
        "worker.policy_violation",
        "output_schema",
        "worker_output",
        "model_intake_fail",
    ),
    (
        "offline-integrity",
        "artifact.rejected",
        "integrity",
        "model",
        "intake_security_audit_unavailable",
    ),
)
SCOPE = "intake-controller-source-primary-not-full-M23"
MAX_BYTES = 4 * 1024 * 1024


def _require(condition):
    if not condition:
        raise Rejected("source_campaign_invalid")


def _triggers(policy):
    # The trusted method binds these synthetic fixture bytes, never model inputs
    # copied from an untrusted packet. Only digests enter the primary observation.
    asset = digest(b"not-an-onnx PRIVATE-CANARY")
    base = dict(asset_sha256=asset, expected_sha256=asset, image_id="sha256:" + "1" * 64)
    return asset, (
        dict(
            base,
            entrypoint="pipeline.evaluate_verified_candidate",
            executor="synthetic-worker",
            policy_sha256=policy,
        ),
        dict(
            base,
            entrypoint="artifact_intake.inspect_candidate",
            worker_output_sha256=digest(canonical({"raw": "PRIVATE-CANARY"})),
        ),
        dict(
            base,
            expected_sha256="0" * 64,
            entrypoint="artifact_intake.inspect_candidate",
            executor="synthetic-worker",
        ),
    )


def _timings(values, observations, records, delivery):
    _require(type(values) is list and len(values) == 5)
    maximum = 0
    for item, (phase, index) in zip(
        values,
        (("online", 0), ("online", 1), ("offline-decision", 2), ("offline-wait", 2), ("retry", 2)),
        strict=True,
    ):
        events.shape(
            item,
            (
                "phase",
                "event_id",
                "start_monotonic_ns",
                "end_monotonic_ns",
                "start_utc_ns",
                "end_utc_ns",
            ),
        )
        _require(item["phase"] == phase and item["event_id"] == observations[index]["event_id"])
        for name in ("start_monotonic_ns", "end_monotonic_ns", "start_utc_ns", "end_utc_ns"):
            _require(type(item[name]) is int and item[name] > 0)
        elapsed = item["end_monotonic_ns"] - item["start_monotonic_ns"]
        wall = item["end_utc_ns"] - item["start_utc_ns"]
        _require(elapsed >= 0 and wall >= 0 and abs(elapsed - wall) <= 100_000_000)
        if phase in ("online", "retry"):
            _require(elapsed <= 60_000_000_000)
            maximum = max(maximum, elapsed)
            stamp = records[index]["ingested_at_ms"]
            routed = stamp + next(
                event["delivery_ms"]
                for event in delivery["events"]
                if event["event_id"] == item["event_id"]
            )
            occurred = ledger.candidate(records[index]["envelope"]).document()["occurred_at_ms"]
            _require(occurred <= stamp <= routed <= item["end_utc_ns"] // 1_000_000)
            if phase == "online":
                _require(item["start_utc_ns"] // 1_000_000 <= occurred)
        elif phase == "offline-decision":
            stamp = ledger.candidate(records[index]["envelope"]).document()["occurred_at_ms"]
        else:
            continue
        _require(item["start_utc_ns"] // 1_000_000 <= stamp <= item["end_utc_ns"] // 1_000_000)
    for left, right in ((2, 3), (3, 4)):
        for clock in ("monotonic_ns", "utc_ns"):
            _require(values[left]["end_" + clock] == values[right]["start_" + clock])
    return maximum / 1_000_000_000


def verify(packet, *, expected):
    """Replay source observations; authority and method pins are caller-owned.

    Controlled tests exercise the same verifier with an explicitly controlled
    transport. Only qualify's hosted real-process execution can supply native
    observations. The verifier does not independently attest observer clocks.
    """
    try:
        events.shape(
            expected,
            ("source", "fingerprint", "materials", "root", "pin", "policy_sha256", "transport"),
        )
        events.hexadecimal(expected["source"], 40)
        events.hexadecimal(expected["fingerprint"])
        events.hexadecimal(expected["policy_sha256"])
        _require(type(expected["materials"]) is dict and bool(expected["materials"]))
        _require(expected["transport"] in ("owned-linux-http", "controlled-in-memory"))
        events.shape(
            packet,
            (
                "schema_version",
                "source",
                "fingerprint",
                "method_materials",
                "source_after",
                "fingerprint_after",
                "materials_after",
                "source_clean",
                "campaign",
            ),
        )
        events.version(packet["schema_version"])
        _require(len(canonical(packet)) <= MAX_BYTES and packet["source_clean"] is True)
        _require(packet["source"] == packet["source_after"] == expected["source"])
        _require(packet["fingerprint"] == packet["fingerprint_after"] == expected["fingerprint"])
        _require(packet["method_materials"] == packet["materials_after"] == expected["materials"])
        primary = packet["campaign"]
        events.shape(
            primary,
            (
                "bundle",
                "source_observations",
                "source_timings",
                "transport_controls",
                "delivery_verification",
                "release_ready",
                "executor_scope",
                "transport_scope",
                "cleanup",
            ),
        )
        _require(primary["release_ready"] is False)
        _require(primary["executor_scope"] == "synthetic-in-process-no-worker-isolation-claim")
        _require(primary["transport_scope"] == expected["transport"])
        events.shape(primary["cleanup"], ("fixture_cleanups_confirmed",))
        _require(primary["cleanup"]["fixture_cleanups_confirmed"] is True)
        observations = primary["source_observations"]
        _require(type(observations) is list and len(observations) == 3)
        bundle = primary["bundle"]
        _require(len(bundle["outboxes"]) == 1)
        producer = bundle["outboxes"][0]["producer_id"]
        asset, triggers = _triggers(expected["policy_sha256"])
        bindings, ids = {}, []
        for observation, case, trigger in zip(observations, CASES, triggers, strict=True):
            events.shape(
                observation,
                (
                    "case_id",
                    "event_id",
                    "kind",
                    "reason",
                    "asset_sha256",
                    "bundle_sha256",
                    "subject_kind",
                    "decision",
                    "trigger_sha256",
                ),
            )
            _require(
                tuple(
                    observation[k]
                    for k in ("case_id", "kind", "reason", "subject_kind", "decision")
                )
                == case
            )
            _require(observation["asset_sha256"] == asset and observation["bundle_sha256"] is None)
            _require(observation["trigger_sha256"] == digest(canonical(trigger)))
            identity = events.hexadecimal(observation["event_id"])
            _require(identity not in ids)
            ids.append(identity)
            bindings[identity] = dict(
                kind=case[1],
                reason=case[2],
                asset_sha256=asset,
                bundle_sha256=None,
                producer_id=producer,
            )
        delivery = verify_delivery(
            bundle,
            expected_root=expected["root"],
            expected_pin=expected["pin"],
            expected_events=bindings,
        )
        _require(canonical(delivery) == canonical(primary["delivery_verification"]))
        records = bundle["collector"]["records"]
        _require(len(records) == 4)
        actual = [ledger.candidate(record["envelope"]).document() for record in records]
        _require([item["event_id"] for item in actual[:3]] == ids)
        control = primary["transport_controls"]
        _require(type(control) is list and len(control) == 1)
        events.shape(control[0], ("case_id", "event_id", "source_decision", "retry_same_envelope"))
        _require(
            control[0]["case_id"] == "lost-response"
            and control[0]["event_id"] == actual[3]["event_id"]
        )
        _require(
            control[0]["source_decision"] is False and control[0]["retry_same_envelope"] is True
        )
        _require(
            (
                actual[3]["kind"],
                actual[3]["reason"],
                actual[3]["asset_sha256"],
                actual[3]["bundle_sha256"],
                actual[3]["correlation_id"],
            )
            == ("artifact.rejected", "integrity", asset, None, "e" * 32)
        )
        # A manual transport control is not a fourth source decision. It still
        # must belong to this exact producer and its acknowledged durable queue.
        control_binding = {
            actual[3]["event_id"]: dict(
                kind="artifact.rejected",
                reason="integrity",
                asset_sha256=asset,
                bundle_sha256=None,
                producer_id=producer,
            )
        }
        verify_delivery(
            bundle,
            expected_root=expected["root"],
            expected_pin=expected["pin"],
            expected_events=control_binding,
        )
        maximum = _timings(primary["source_timings"], observations, records, delivery)
        return dict(
            status="pass",
            source=expected["source"],
            fingerprint=expected["fingerprint"],
            scope=SCOPE,
            transport=expected["transport"],
            cases=[case[0] for case in CASES],
            events=delivery["events"],
            max_online_attempt_seconds=maximum,
            primary_sha256=digest(canonical(packet)),
            cleanup_verified=True,
            release_ready=False,
        )
    except (Rejected, KeyError, TypeError, ValueError, IndexError, OverflowError, RecursionError):
        raise Rejected("source_campaign_invalid") from None
