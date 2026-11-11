"""Fresh signed audit observation, independent of ML authorization and drift."""

import copy
import unittest
from unittest.mock import patch

from mlsecops import security_event_runtime as runtime
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, digest
from scripts import security_event_health_qualification as fixtures


class AdmissionContracts(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fx = fixtures.HealthContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.keys = self.fx.fx.fixture.keys
        self.registry = self.fx.registry
        self.book = self.fx.book
        self.book.snapshot = self.book.document
        self.clock = 2100
        self.collector = runtime.Collector(
            self.book,
            self.keys["receipt"],
            self.keys["collector"],
            wall=lambda: self.clock,
            monotonic=lambda: self.clock,
        )
        self.addAsyncCleanup(self.collector.close)

    def request(self, **changes):
        producer = self.registry.producer(
            digest(signing.load_key(self.keys["promoter"]).public_key().public_bytes_raw())
        )
        value = dict(
            schema_version=1,
            producer_id=producer.identity,
            epoch=producer.epoch,
            config_sha256=self.registry.sha256,
            selection_sha256="d" * 64,
            nonce="e" * 32,
            requested_at_ms=self.clock,
        )
        value.update(changes)
        return signing.sign(value, "security-audit-request", self.keys["promoter"])

    async def healthy(self):
        self.book.heartbeat(self.fx.heartbeat(), clock_ms=self.clock)
        await self.collector.start()

    async def test_http_admission_requires_ingress_auth_and_signed_request(self):
        from mlsecops import security_event_http as http

        await self.healthy()
        app = http.App(self.collector, "a" * 64, "b" * 64)
        for token, envelope, expected in (
            ("a" * 64, self.request(), 200),
            ("b" * 64, self.request(), 401),
            ("a" * 64, {}, 503),
        ):
            raw, sent, reads = canonical(envelope), [], []

            async def receive():
                reads.append(True)
                return dict(type="http.request", body=raw)

            async def send(value):
                sent.append(value)

            await app(
                dict(
                    type="http",
                    method="POST",
                    path="/admission",
                    headers=[
                        (b"authorization", ("Bearer " + token).encode()),
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(raw)).encode()),
                    ],
                ),
                receive,
                send,
            )
            self.assertEqual(sent[0]["status"], expected)
            if expected == 401:
                self.assertEqual(reads, [])

    async def test_reply_is_bound_to_nonce_and_selection_without_granting_release(self):
        from mlsecops import security_event_admission as admission

        await self.healthy()
        request = self.request()
        receipt = self.collector.admission(request)
        result = admission.verify(self.registry, request, receipt, clock_ms=self.clock)
        self.assertIs(result["healthy"], True)
        self.assertIs(result["release_ready"], False)
        for changed in (self.request(nonce="f" * 32), self.request(selection_sha256="f" * 64)):
            with self.assertRaises(Rejected):
                admission.verify(self.registry, changed, receipt, clock_ms=self.clock)

    async def test_forgery_role_config_epoch_schema_and_stale_request_deny(self):
        await self.healthy()
        valid = self.request()
        forged = copy.deepcopy(valid)
        forged["signatures"][0]["sig"] = signing.encode64(b"x" * 64)
        for envelope in (
            forged,
            self.request(config_sha256="f" * 64),
            self.request(epoch="f" * 32),
            self.request(extra="PRIVATE-CANARY"),
            self.request(requested_at_ms=100000),
            self.request(schema_version=True),
        ):
            with self.subTest(envelope_type=type(envelope).__name__), self.assertRaises(Rejected):
                self.collector.admission(envelope)
        from mlsecops import security_events as events

        value = events.signed(
            valid, "security-audit-request", self.registry.producer(events.signer(valid)).public_key
        )
        value["producer_id"] = digest(
            signing.load_key(self.keys["serving"]).public_key().public_bytes_raw()
        )
        with self.assertRaises(Rejected):
            self.collector.admission(
                signing.sign(value, "security-audit-request", self.keys["serving"])
            )
        self.clock += 6000
        with self.assertRaises(Rejected):
            self.collector.admission(valid)

    async def test_missing_heartbeat_pending_events_fault_lag_and_stopped_deny(self):
        await self.collector.start()
        with self.assertRaises(Rejected):
            self.collector.admission(self.request())
        self.book.heartbeat(self.fx.heartbeat(), clock_ms=self.clock)
        self.collector.fault = True
        with self.assertRaises(Rejected):
            self.collector.admission(self.request())
        self.collector.fault = False
        self.clock += 5001
        with self.assertRaises(Rejected):
            self.collector.admission(self.request())
        self.collector.tick()
        self.book.admit(self.fx.fx.envelope(), clock_ms=self.clock)
        with self.assertRaises(Rejected):
            self.collector.admission(self.request())
        await self.collector.close()
        with self.assertRaises(Rejected):
            self.collector.admission(self.request())

    async def test_storage_failure_does_not_sign_healthy_response(self):
        await self.healthy()
        with patch.object(self.book, "poll", side_effect=OSError("PRIVATE-CANARY")):
            with self.assertRaises(OSError):
                self.collector.admission(self.request())

    async def test_client_requires_new_challenge_and_rejects_cached_response(self):
        from mlsecops import security_event_admission as admission

        await self.healthy()
        responses = []

        def exchange(envelope):
            response = self.collector.admission(envelope)
            responses.append(response)
            return response

        client = admission.Client(
            self.registry, self.keys["promoter"], exchange, clock=lambda: self.clock
        )
        client.check("d" * 64)
        client.check("d" * 64)
        self.assertNotEqual(responses[0], responses[1])
        client.exchange = lambda _: responses[-1]
        with self.assertRaisesRegex(Rejected, "promotion_audit_unavailable"):
            client.check("d" * 64)

    async def test_client_rejects_wrong_key_unhealthy_future_and_delayed_reply(self):
        from mlsecops import security_event_admission as admission
        from mlsecops import security_events as events

        await self.healthy()
        mode = ["forged"]

        def exchange(envelope):
            result = self.collector.admission(envelope)
            value = events.signed(
                result, "security-audit-observation", self.registry.receipt_public
            )
            if mode[0] == "forged":
                return signing.sign(value, "security-audit-observation", self.keys["promoter"])
            if mode[0] == "unhealthy":
                value["healthy"] = False
            if mode[0] == "future":
                value["observed_at_ms"] += 10000
            if mode[0] == "authority":
                value["release_ready"] = True
            if mode[0] == "delay":
                self.clock += 6000
            return signing.sign(value, "security-audit-observation", self.keys["receipt"])

        client = admission.Client(
            self.registry, self.keys["promoter"], exchange, clock=lambda: self.clock
        )
        for item in ("forged", "unhealthy", "future", "authority", "delay"):
            mode[0] = item
            with self.subTest(mode=item), self.assertRaises(Rejected):
                client.check("d" * 64)
        self.assertNotIn(b"PRIVATE-CANARY", canonical(self.book.document()))

    async def test_client_role_and_total_monotonic_deadline_are_enforced(self):
        from mlsecops import security_event_admission as admission

        await self.healthy()
        with self.assertRaisesRegex(Rejected, "security_audit_role"):
            admission.Client(self.registry, self.keys["serving"], self.collector.admission)
        ticks = iter((0.0, 2.001))
        client = admission.Client(
            self.registry,
            self.keys["promoter"],
            self.collector.admission,
            clock=lambda: self.clock,
            monotonic=lambda: next(ticks),
        )
        with self.assertRaisesRegex(Rejected, "promotion_audit_unavailable"):
            client.check("d" * 64)

    async def test_operator_configuration_pins_role_and_reload_without_cached_health(self):
        from mlsecops import security_event_admission as admission

        await self.healthy()
        fx = self.fx.fx.fixture
        registry_path = fx.directory / "registry.json"
        registry_path.write_bytes(
            canonical(signing.sign(fx.document, "security-event-config", self.keys["root"]))
        )
        token_path = fx.directory / "ingress.token"
        token_path.write_bytes(b"a" * 64)
        token_path.chmod(0o600)
        value = dict(
            schema_version=1,
            registry_file=str(registry_path),
            registry_root=fx.publics["root"],
            registry_sha256=self.registry.sha256,
            producer_key_file=str(self.keys["promoter"]),
            ingress_token_file=str(token_path),
            port=15499,
        )
        path = fx.directory / "audit.json"
        path.write_bytes(canonical(value))

        def exchange(port, token, envelope, *, path):
            self.assertEqual((port, token, path), (15499, "a" * 64, "/admission"))
            return self.collector.admission(envelope)

        with (
            patch.object(admission.time, "time_ns", return_value=self.clock * 1_000_000),
            patch.object(admission.security_event_delivery, "exchange", side_effect=exchange),
        ):
            client = admission.Configured(str(path))
            self.assertTrue(client.check("d" * 64)["healthy"])
            value["registry_sha256"] = "f" * 64
            path.write_bytes(canonical(value))
            with self.assertRaisesRegex(Rejected, "promotion_audit_unavailable"):
                client.check("d" * 64)
        with self.assertRaises(Rejected):
            admission.Configured("relative.json")


if __name__ == "__main__":
    unittest.main()
