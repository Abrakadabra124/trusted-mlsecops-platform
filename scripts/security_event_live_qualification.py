"""Owned Linux subprocess + real HTTP, elapsed heartbeat deadline and restart.

Synthetic fixture provisioning is not a release candidate or full M23 gate.
"""

import http.client
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
import unittest

from mlsecops import security_event_store as storage
from mlsecops import signing
from mlsecops.contracts import canonical, decode, digest
from scripts import security_events_qualification as fixtures


@unittest.skipUnless(sys.platform == "linux", "Linux collector process required")
class LiveCollector(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.EventContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.directory = self.fx.directory
        now = self.now()
        self.fx.document.update(issued_at_ms=now - 1000, expires_at_ms=now + 600000)
        for producer in self.fx.document["producers"]:
            producer["heartbeat_required"] = producer["role"] in getattr(
                self, "heartbeat_roles", ("serving",)
            )
        self.registry = self.fx.registry_for(clock=now)
        envelope = signing.sign(self.fx.document, "security-event-config", self.fx.keys["root"])
        self.write("registry.json", canonical(envelope))
        root = str(self.directory / "state")
        pin = storage.initialize(root, self.registry, clock_ms=now)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.ingress, self.operator = secrets.token_hex(32), secrets.token_hex(32)
        self.write("ingress.token", self.ingress.encode("ascii"))
        self.write("operator.token", self.operator.encode("ascii"))
        config = {
            "schema_version": 1,
            "registry_file": str(self.directory / "registry.json"),
            "registry_root": self.fx.publics["root"],
            "registry_sha256": self.registry.sha256,
            "state_directory": root,
            "state_sha256": pin,
            "receipt_key_file": str(self.fx.keys["receipt"]),
            "collector_key_file": str(self.fx.keys["collector"]),
            "ingress_token_file": str(self.directory / "ingress.token"),
            "operator_token_file": str(self.directory / "operator.token"),
            "port": self.port,
        }
        self.write("collector.json", canonical(config))
        self.process = None
        self.output = (self.directory / "process-private.log").open("wb")
        self.addCleanup(self.output.close)
        self.addCleanup(self.stop)

    @staticmethod
    def now():
        return time.time_ns() // 1_000_000

    def write(self, name, content):
        path = self.directory / name
        path.write_bytes(content)
        path.chmod(0o600)

    def exchange(self, method, path, value=None, *, token=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        body = b"" if value is None else canonical(value)
        headers = {
            "Authorization": "Bearer " + (token or self.operator),
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(65537)
            self.assertLessEqual(len(raw), 65536)
            self.assertEqual(response.getheader("Cache-Control"), "no-store")
            return response.status, decode(raw)
        finally:
            connection.close()

    def start(self):
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "mlsecops.security_event_server",
                "--config",
                str(self.directory / "collector.json"),
            ],
            stdout=self.output,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            self.assertIsNone(self.process.poll(), "collector exited during startup")
            try:
                status, _ = self.exchange("GET", "/incidents/0")
                if status == 200:
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        self.fail("collector startup deadline")

    def stop(self):
        process, self.process = self.process, None
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
        try:
            code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            self.fail("collector graceful shutdown exceeded five seconds")
        self.assertIn(code, (0, -signal.SIGTERM))
        with socket.socket() as sock:
            sock.settimeout(1)
            self.assertNotEqual(sock.connect_ex(("127.0.0.1", self.port)), 0)

    def event(self, sequence):
        now = self.now()
        value = self.fx.event(sequence=sequence, occurred_at_ms=now, observed_at_ms=now)
        return signing.sign(value, "security-event", self.fx.keys["intake"])

    def test_http_routes_real_deadline_and_restart_recovery(self):
        self.start()
        self.assertEqual(self.exchange("GET", "/health")[0], 503)
        heartbeat = self.fx.heartbeat(
            observed_at_ms=self.now(),
            last_event_sequence=0,
            producer_id=digest(signing.decode64(self.fx.publics["serving"])),
        )
        message = signing.sign(heartbeat, "security-heartbeat", self.fx.keys["serving"])
        began = time.monotonic()
        self.assertEqual(self.exchange("POST", "/heartbeat", message, token=self.ingress)[0], 200)
        deliveries = []
        first = self.event(1)
        for envelope in (first, self.event(3), self.event(2)):
            start = time.monotonic()
            status, receipt = self.exchange("POST", "/events", envelope, token=self.ingress)
            self.assertEqual(status, 200)
            elapsed = time.monotonic() - start
            self.assertLessEqual(elapsed, 60)
            event = self.registry.verify(envelope, clock_ms=self.now())
            checked = self.registry.receipt(receipt, event)
            self.assertEqual(checked["late"], event.document()["sequence"] == 2)
            deliveries.append(elapsed)
        self.assertEqual(self.exchange("GET", "/health")[0], 200)
        original = self.exchange("POST", "/events", first, token=self.ingress)[1]
        self.assertEqual(self.exchange("GET", "/incidents/0", token=self.ingress)[0], 401)
        forged = dict(first, signatures=[{"keyid": "0" * 64, "sig": "PRIVATE-CANARY"}])
        self.assertEqual(self.exchange("POST", "/events", forged, token=self.ingress)[0], 503)
        notice = None
        while time.monotonic() - began <= 120:
            status, page = self.exchange("GET", "/incidents/0")
            self.assertEqual(status, 200)
            for record in page["incidents"]:
                event = self.registry.verify(record["envelope"], clock_ms=record["ingested_at_ms"])
                if event.document()["kind"] == "telemetry.gap":
                    notice = record
            if notice is not None:
                break
            time.sleep(0.5)
        gap_seconds = time.monotonic() - began
        self.assertIsNotNone(notice, "signed gap notice missing within actual 120 seconds")
        self.assertLessEqual(gap_seconds, 120)
        self.assertEqual(self.exchange("GET", "/health")[0], 503)
        self.stop()
        self.start()
        self.assertEqual(self.exchange("POST", "/events", first, token=self.ingress)[1], original)
        status, page = self.exchange("GET", "/incidents/0")
        self.assertEqual(status, 200)
        self.assertEqual(len(page["incidents"]), 4)
        self.assertEqual(page["incidents"][-1], notice)
        self.stop()
        self.output.flush()
        raw = (self.directory / "process-private.log").read_bytes()
        for canary in ("PRIVATE-CANARY", self.ingress, self.operator):
            self.assertNotIn(canary.encode("ascii"), raw)
        print(
            canonical(
                {
                    "max_http_delivery_seconds": max(deliveries),
                    "heartbeat_notice_seconds": gap_seconds,
                    "owned_process_stopped": True,
                    "release_ready": False,
                }
            ).decode("ascii")
        )


if __name__ == "__main__":
    unittest.main()
