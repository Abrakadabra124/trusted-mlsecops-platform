"""Real source decision -> durable producer -> HTTP collector -> signed receipt.

Scanner calls here use a synthetic executor in the harness, not a Kubernetes
isolation claim. Collector is a separate real Linux process with private state.
"""

import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import (
    artifact_intake,
    pipeline,
    security_event_delivery,
    security_event_outbox,
    worker,
)
from mlsecops import security_event_store as storage
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, read_json
from scripts import security_event_live_qualification as fixtures
from scripts.security_source_capture import capture_delivery, read_incidents

IMAGE = "sha256:" + "1" * 64
CONTENT = b"not-an-onnx PRIVATE-CANARY"


def _require(value, reason="source_capture_decision"):
    if not value:
        raise Rejected(reason)


def _stamp():
    return {"monotonic_ns": time.monotonic_ns(), "utc_ns": time.time_ns()}


def _interval(phase, event_id, start, end):
    _require(end["monotonic_ns"] >= start["monotonic_ns"] and end["utc_ns"] >= start["utc_ns"])
    return dict(
        phase=phase,
        event_id=event_id,
        **{"start_" + key: value for key, value in start.items()},
        **{"end_" + key: value for key, value in end.items()},
    )


def _source_decision(call, emitter, *, case_id, kind, reason, subject_kind, trigger, offline=False):
    before = emitter.store.snapshot()["records"]
    start = _stamp()
    try:
        call()
    except Rejected as error:
        end = _stamp()
        decision = str(error)
        correlation = None
        if offline:
            _require(decision == "intake_security_audit_unavailable")
        else:
            _require(isinstance(error, artifact_intake.IntakeFailure))
            report = artifact_intake.validate_failure(error.report, CONTENT, IMAGE)
            _require(report["status"] == "fail")
            _require(
                report["origin"] == "worker"
                if reason == "unsupported_format"
                else report["origin"] == "controller"
                and report["reason"] == "scanner_protocol_rejected"
            )
            correlation = report["inspection_id"]
    else:
        raise Rejected("source_capture_decision")
    records = emitter.store.snapshot()["records"]
    _require(len(records) == len(before) + 1 and records[:-1] == before)
    record = records[-1]
    event = emitter.store.registry.verify(record["envelope"], clock_ms=record["queued_at_ms"])
    value = event.document()
    _require(
        value["kind"] == kind
        and value["reason"] == reason
        and value["asset_sha256"] == digest(CONTENT)
        and value["bundle_sha256"] is None
        and (correlation is None or value["correlation_id"] == correlation)
        and (record["receipt"] is None) == offline
    )
    observation = dict(
        case_id=case_id,
        event_id=value["event_id"],
        kind=kind,
        reason=reason,
        asset_sha256=value["asset_sha256"],
        bundle_sha256=value["bundle_sha256"],
        subject_kind=subject_kind,
        decision=decision,
        trigger_sha256=digest(canonical(trigger)),
    )
    return (
        observation,
        _interval("offline-decision" if offline else "online", value["event_id"], start, end),
        record,
        end,
    )


def run_source_campaign(fixture, emitter_factory, *, collector_snapshot=None):
    """Run actual intake/controller decisions using a caller-provisioned fixture.

    The executor remains synthetic/in-process. A native caller must provision an
    owned hosted Linux LiveCollector and producer config before this call. A
    controlled caller supplies Ledger.document and an in-memory transport.
    Return private primary records only after stop AND fixture cleanups succeed;
    persist outside the deleted fixture directory, never print this packet.
    trigger_sha256 hashes bounded invocation metadata (input/output digests only).
    """
    packet = None
    try:
        # Authority comes from the owned fixture, independently of the export.
        expected_root, expected_pin = fixture.fx.publics["root"], fixture.registry.sha256
        fixture.start()
        emitter = emitter_factory()
        initial = emitter.store.snapshot()
        producer = initial["producer_id"]
        _require(
            not initial["records"]
            and emitter.store.registry.producer(producer).role == "controller"
        )
        policy = read_json(Path(__file__).resolve().parents[1] / "policies/local-cpu.json")
        observations, timings = [], []
        trigger = dict(
            asset_sha256=digest(CONTENT), expected_sha256=digest(CONTENT), image_id=IMAGE
        )

        def execute(image, request):
            return worker.execute(request), {"image_id": IMAGE}

        first, interval, _, _ = _source_decision(
            lambda: pipeline.evaluate_verified_candidate(
                {"model_digest": digest(CONTENT), "image_id": IMAGE},
                CONTENT,
                [],
                {},
                policy,
                IMAGE,
                execute,
                audit=emitter,
            ),
            emitter,
            case_id="artifact-unsupported-format",
            kind="artifact.rejected",
            reason="unsupported_format",
            subject_kind="model",
            trigger=dict(
                trigger,
                entrypoint="pipeline.evaluate_verified_candidate",
                executor="synthetic-worker",
                policy_sha256=digest(canonical(policy)),
            ),
        )
        observations.append(first)
        timings.append(interval)
        malformed = {"raw": "PRIVATE-CANARY"}
        second, interval, _, _ = _source_decision(
            lambda: artifact_intake.inspect_candidate(
                CONTENT,
                digest(CONTENT),
                IMAGE,
                IMAGE,
                lambda *_: (malformed, {"image_id": IMAGE}),
                audit=emitter,
            ),
            emitter,
            case_id="worker-output-schema",
            kind="worker.policy_violation",
            reason="output_schema",
            subject_kind="worker_output",
            trigger=dict(
                trigger,
                entrypoint="artifact_intake.inspect_candidate",
                worker_output_sha256=digest(canonical(malformed)),
            ),
        )
        observations.append(second)
        timings.append(interval)
        fixture.stop()
        third, interval, pending, offline_end = _source_decision(
            lambda: artifact_intake.inspect_candidate(
                CONTENT,
                "0" * 64,
                IMAGE,
                IMAGE,
                execute,
                audit=emitter,
            ),
            emitter,
            case_id="offline-integrity",
            kind="artifact.rejected",
            reason="integrity",
            subject_kind="model",
            offline=True,
            trigger=dict(
                trigger,
                expected_sha256="0" * 64,
                entrypoint="artifact_intake.inspect_candidate",
                executor="synthetic-worker",
            ),
        )
        observations.append(third)
        timings.append(interval)
        fixture.start()
        emitter = emitter_factory()
        retry_start = _stamp()
        timings.append(_interval("offline-wait", third["event_id"], offline_end, retry_start))
        count = emitter.retry()
        retry_end = _stamp()
        _require(count == 1)
        retried = emitter.store.snapshot()["records"][-1]
        _require(retried["envelope"] == pending["envelope"] and retried["receipt"] is not None)
        timings.append(_interval("retry", third["event_id"], retry_start, retry_end))

        # This fourth event is deliberately MANUAL: transport evidence only.
        fields = dict(
            kind="artifact.rejected",
            reason="integrity",
            correlation_id="e" * 32,
            asset_sha256=digest(CONTENT),
            bundle_sha256=None,
        )
        send = emitter.client.send

        def lost(envelope):
            send(envelope)
            raise OSError("simulated lost response")

        with patch.object(emitter.client, "send", side_effect=lost):
            try:
                emitter.emit(fields)
            except Rejected as error:
                _require(str(error) == "security_delivery_unconfirmed")
            else:
                raise Rejected("source_capture_transport")
        stored = emitter.store.snapshot()["records"][-1]
        _require(stored["receipt"] is None)
        receipt = emitter_factory().emit(fields)
        _require(
            emitter_factory().store.snapshot()["records"][-1]["envelope"] == stored["envelope"]
        )
        control = emitter.store.registry.verify(
            stored["envelope"], clock_ms=stored["queued_at_ms"]
        ).document()
        incidents = read_incidents(fixture)
        fixture.stop()
        _require(emitter_factory().emit(fields) == receipt)
        bundle = capture_delivery(
            fixture, [emitter_factory()], incidents=incidents, collector_snapshot=collector_snapshot
        )
        expected = {
            item["event_id"]: dict(
                **{key: item[key] for key in ("kind", "reason", "asset_sha256", "bundle_sha256")},
                producer_id=producer,
            )
            for item in observations
        }
        from mlsecops.security_source_evidence import verify_delivery

        verified = verify_delivery(
            bundle, expected_root=expected_root, expected_pin=expected_pin, expected_events=expected
        )
        packet = dict(
            bundle=bundle,
            source_observations=observations,
            source_timings=timings,
            transport_controls=[
                dict(
                    case_id="lost-response",
                    event_id=control["event_id"],
                    source_decision=False,
                    retry_same_envelope=True,
                )
            ],
            delivery_verification=verified,
            release_ready=False,
            executor_scope="synthetic-in-process-no-worker-isolation-claim",
            transport_scope="controlled-in-memory"
            if collector_snapshot is not None
            else "owned-linux-http",
        )
        _require(b"PRIVATE-CANARY" not in canonical(packet), "source_capture_redaction")
    finally:
        try:
            fixture.stop()  # Unlike TestCase.doCleanups, this propagates stop failures.
        finally:
            if fixture.doCleanups() is not True or fixture.directory.exists():
                raise Rejected("source_capture_cleanup_failed")
    packet["cleanup"] = {"fixture_cleanups_confirmed": True}
    return packet


@unittest.skipUnless(sys.platform == "linux", "private Linux journal/process required")
class SourceLive(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.LiveCollector("runTest")
        self.addCleanup(self.fx.doCleanups)
        self.fx.setUp()
        self.key = self.fx.fx.keys["controller"]
        self.identity = security_event_outbox.key_identity(self.key)
        self.root = str(self.fx.directory / "producer-outbox")
        self.pin = security_event_outbox.initialize(
            self.root, self.fx.registry, self.identity, clock_ms=self.fx.now()
        )
        config = decode(bounded_read(self.fx.directory / "collector.json", 16384), 16384)
        config = {
            k: config[k]
            for k in (
                "schema_version",
                "registry_file",
                "registry_root",
                "registry_sha256",
                "ingress_token_file",
                "port",
            )
        }
        config.update(
            state_directory=self.root, state_sha256=self.pin, producer_key_file=str(self.key)
        )
        self.fx.write("producer.json", canonical(config))

    def emitter(self):
        return security_event_delivery.configured(str(self.fx.directory / "producer.json"))

    def capture_campaign(self):
        """Caller may retain the returned private packet after confirmed cleanup."""
        return run_source_campaign(self.fx, self.emitter)

    def test_real_source_routes_and_retry_after_outage_and_unknown_result(self):
        packet = self.capture_campaign()
        self.assertEqual(len(packet["source_observations"]), 3)
        self.assertEqual(len(packet["bundle"]["incidents"]), 4)
        self.assertTrue(packet["cleanup"]["fixture_cleanups_confirmed"])
        print(
            "source_adapter_routes=security.artifacts,security.workers;outage_retry=pass;release_ready=false"
        )

    def test_outbox_crash_boundaries_reopen_and_role_pin(self):
        emitter = self.emitter()
        fields = dict(
            kind="artifact.rejected",
            reason="integrity",
            correlation_id="c" * 32,
            asset_sha256="d" * 64,
            bundle_sha256=None,
        )
        with patch.object(storage.os, "replace", side_effect=OSError("precommit")):
            with self.assertRaises(Rejected):
                emitter.store.enqueue((fields, self.key), clock_ms=self.fx.now())
        self.assertEqual(self.emitter().store.snapshot()["records"], [])
        rename = storage.os.replace

        def renamed(*args, **kwargs):
            rename(*args, **kwargs)
            raise OSError("postcommit")

        with patch.object(storage.os, "replace", side_effect=renamed):
            with self.assertRaises(Rejected):
                emitter.store.enqueue((fields, self.key), clock_ms=self.fx.now())
        saved = self.emitter().store.snapshot()["records"][0]
        self.assertEqual(
            self.emitter().store.enqueue((fields, self.key), clock_ms=self.fx.now()), saved
        )
        with self.assertRaises(Rejected):
            security_event_outbox.Store(
                self.root,
                self.pin,
                self.fx.registry,
                security_event_outbox.key_identity(self.fx.fx.keys["intake"]),
            ).snapshot()
        with self.assertRaises(Rejected):
            security_event_outbox.initialize(
                self.root, self.fx.registry, self.identity, clock_ms=self.fx.now()
            )
        self.assertEqual(self.emitter().store.snapshot()["records"], [saved])


if __name__ == "__main__":
    unittest.main()
