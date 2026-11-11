"""Real source decision -> durable producer -> HTTP collector -> signed receipt.

Scanner calls here use a synthetic executor in the harness, not a Kubernetes
isolation claim. Collector is a separate real Linux process with private state.
"""

import sys
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
from mlsecops.contracts import Rejected, canonical, decode, digest, read_json
from scripts import security_event_live_qualification as fixtures

IMAGE = "sha256:" + "1" * 64
CONTENT = b"not-an-onnx PRIVATE-CANARY"


@unittest.skipUnless(sys.platform == "linux", "private Linux journal/process required")
class SourceLive(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.LiveCollector("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.key = self.fx.fx.keys["controller"]
        self.identity = security_event_outbox.key_identity(self.key)
        self.root = str(self.fx.directory / "producer-outbox")
        self.pin = security_event_outbox.initialize(
            self.root, self.fx.registry, self.identity, clock_ms=self.fx.now()
        )
        config = decode((self.fx.directory / "collector.json").read_bytes())
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

    @staticmethod
    def execute(image, request):
        return worker.execute(request), {"image_id": IMAGE}

    def test_real_source_routes_and_retry_after_outage_and_unknown_result(self):
        self.fx.start()
        emitter = self.emitter()
        policy = read_json(Path(__file__).resolve().parents[1] / "policies/local-cpu.json")
        with self.assertRaises(artifact_intake.IntakeFailure):
            pipeline.evaluate_verified_candidate(
                {"model_digest": digest(CONTENT), "image_id": IMAGE},
                CONTENT,
                [],
                {},
                policy,
                IMAGE,
                self.execute,
                audit=emitter,
            )
        self.assertEqual(len(emitter.store.snapshot()["records"]), 1)
        first = emitter.store.snapshot()["records"][0]
        value = emitter.store.registry.verify(
            first["envelope"], clock_ms=first["queued_at_ms"]
        ).document()
        self.assertEqual(
            (value["kind"], value["reason"]), ("artifact.rejected", "unsupported_format")
        )
        self.assertIsNotNone(first["receipt"])
        with self.assertRaises(artifact_intake.IntakeFailure):
            artifact_intake.inspect_candidate(
                CONTENT,
                digest(CONTENT),
                IMAGE,
                IMAGE,
                lambda *_: ({"raw": "PRIVATE-CANARY"}, {"image_id": IMAGE}),
                audit=emitter,
            )
        records = emitter.store.snapshot()["records"]
        second = emitter.store.registry.verify(
            records[1]["envelope"], clock_ms=records[1]["queued_at_ms"]
        )
        self.assertEqual(second.route, "security.workers")
        # A real disconnected sink leaves a durable event and a denied source result.
        self.fx.stop()
        with self.assertRaisesRegex(Rejected, "^intake_security_audit_unavailable$"):
            artifact_intake.inspect_candidate(
                CONTENT, "0" * 64, IMAGE, IMAGE, self.execute, audit=emitter
            )
        pending = emitter.store.snapshot()["records"][-1]
        self.assertIsNone(pending["receipt"])
        self.fx.start()
        emitter = self.emitter()
        self.assertEqual(emitter.retry(), 1)
        self.assertEqual(emitter.store.snapshot()["records"][-1]["envelope"], pending["envelope"])
        # Collector commit succeeds; producer loses the network outcome.
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
            with self.assertRaises(Rejected):
                emitter.emit(fields)
        stored = emitter.store.snapshot()["records"][-1]
        receipt = self.emitter().emit(fields)
        self.assertEqual(
            self.emitter().store.snapshot()["records"][-1]["envelope"], stored["envelope"]
        )
        status, page = self.fx.exchange("GET", "/incidents/0")
        self.assertEqual(status, 200)
        self.assertEqual(len(page["incidents"]), 4)
        self.assertEqual(page["incidents"][-1]["receipt"], receipt)
        self.assertNotIn(b"PRIVATE-CANARY", canonical(page))
        self.fx.stop()
        self.assertEqual(self.emitter().emit(fields), receipt)
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
