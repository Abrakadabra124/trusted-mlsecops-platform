"""Actual Linux collector process, durable receipts and fresh admission over mTLS."""

import http.client
import socket
import sys
import time
import unittest

from mlsecops import security_event_admission as admission
from mlsecops import security_event_delivery as delivery
from mlsecops import security_event_outbox as outbox
from mlsecops import security_event_tls as tls
from mlsecops.contracts import Rejected, canonical, decode
from scripts import security_event_live_qualification as live_fixture
from scripts import security_event_tls_qualification as tls_fixture


@unittest.skipUnless(sys.platform == "linux", "durable collector requires Linux")
class TLSCollector(unittest.TestCase):
    def setUp(self):
        self.materials = tls_fixture.TLSContracts("runTest")
        self.materials.setUp()
        self.addCleanup(lambda: self.assertTrue(self.materials.doCleanups()))
        self.fx = live_fixture.LiveCollector("runTest")
        self.fx.setUp()
        self.addCleanup(lambda: self.assertTrue(self.fx.doCleanups()))
        self.config = decode((self.fx.directory / "collector.json").read_bytes())
        self.config.update(schema_version=2, tls=self.materials.server)
        self.fx.write("collector.json", canonical(self.config))
        self.client = tls.Client(self.materials.client)
        self.fx.exchange = self.exchange

    def exchange(self, method, path, value=None, *, token=None):
        deadline = time.monotonic() + 3

        def remaining():
            result = deadline - time.monotonic()
            if result <= 0:
                raise Rejected("tls_fixture_deadline")
            return result

        with self.client.open(self.fx.port, remaining) as channel:
            connection = http.client.HTTPConnection("127.0.0.1", self.fx.port, timeout=3)
            connection.sock = channel
            body = b"" if value is None else canonical(value)
            headers = {
                "Host": tls.SERVICE_NAME,
                "Authorization": "Bearer " + (token or self.fx.operator),
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            }
            try:
                channel.settimeout(remaining())
                connection.request(method, path, body=body, headers=headers)
                channel.settimeout(remaining())
                response = connection.getresponse()
                content = response.read(65537)
                self.assertLessEqual(len(content), 65536)
                self.assertEqual(response.getheader("Cache-Control"), "no-store")
                remaining()
                return response.status, decode(content)
            finally:
                connection.close()

    def producer(self, role):
        value = {name: self.config[name] for name in delivery.CONFIG_FIELDS if name in self.config}
        value.update(
            schema_version=2,
            tls=self.materials.client,
            state_directory=str(self.fx.directory / (role + "-outbox")),
            producer_key_file=str(self.fx.fx.keys[role]),
        )
        value["state_sha256"] = outbox.initialize(
            value["state_directory"],
            self.fx.registry,
            outbox.key_identity(self.fx.fx.keys[role]),
            clock_ms=self.fx.now(),
        )
        path = self.fx.directory / (role + "-producer.json")
        self.fx.write(path.name, canonical(value))
        return value, str(path)

    def test_real_collector_receipts_admission_outage_restart_and_plain_refusal(self):
        _, source_path = self.producer("serving")
        promoter, _ = self.producer("promoter")
        audit_path = self.fx.directory / "audit.json"
        self.fx.write(audit_path.name, canonical({**promoter, "schema_version": 3}))
        source = delivery.configured(source_path)
        audit = admission.Configured(str(audit_path))
        self.fx.start()
        self.assertEqual(self.exchange("GET", "/health")[0], 503)
        source.heartbeat()
        self.assertEqual(self.exchange("GET", "/health")[0], 200)
        first = dict(
            kind="identity.denied",
            reason="credential",
            correlation_id="b" * 32,
            asset_sha256="c" * 64,
            bundle_sha256=None,
        )
        receipt = source.emit(first)
        self.assertEqual(source.emit(first), receipt)
        audit.check("d" * 64)
        status, page = self.exchange("GET", "/incidents/0")
        self.assertEqual(status, 200)
        self.assertEqual(len(page["incidents"]), 1)
        event = self.fx.registry.verify(page["incidents"][0]["envelope"], clock_ms=self.fx.now())
        self.fx.registry.receipt(receipt, event)
        self.assertEqual(event.route, "security.identity")
        self.assertEqual(self.exchange("GET", "/incidents/0", token=self.fx.ingress)[0], 401)

        # TLS-only listener never serves HTTP or returns operator data in clear.
        with socket.create_connection(("127.0.0.1", self.fx.port), timeout=2) as plain:
            plain.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            try:
                content = plain.recv(1024)
            except (ConnectionResetError, ConnectionAbortedError):
                content = b""
            self.assertEqual(content, b"")
        self.fx.stop()
        with self.assertRaisesRegex(Rejected, "promotion_audit_unavailable"):
            audit.check("d" * 64)
        with self.assertRaises(Rejected):
            source.emit({**first, "correlation_id": "e" * 32})
        pending = source.store.snapshot()["records"][-1]
        self.assertIsNone(pending["receipt"])
        self.fx.start()
        source = delivery.configured(source_path)
        self.assertEqual(source.retry(), 1)
        recovered = source.store.snapshot()["records"][-1]
        self.assertEqual(recovered["envelope"], pending["envelope"])
        self.assertIsNotNone(recovered["receipt"])
        self.assertEqual(source.retry(), 0)
        source.heartbeat()
        self.assertEqual(
            self.fx.registry.heartbeat(
                source.store.snapshot()["heartbeat"], clock_ms=self.fx.now()
            )["sequence"],
            2,
        )
        audit.check("d" * 64)
        self.assertEqual(len(self.exchange("GET", "/incidents/0")[1]["incidents"]), 2)
        self.fx.stop()


if __name__ == "__main__":
    unittest.main()
