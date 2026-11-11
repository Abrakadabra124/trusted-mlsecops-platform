"""Real owned TLS sockets, authentication before bearer, no infrastructure service."""

import contextlib
import importlib.util
import io
import runpy
import socket
import ssl
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from mlsecops import process_privacy, signing, storage_pki
from mlsecops import security_event_admission as admission
from mlsecops import security_event_delivery as delivery
from mlsecops import security_event_outbox as outbox
from mlsecops import security_event_server as server
from mlsecops.contracts import Rejected, canonical
from scripts import security_events_qualification as events_fixture

SERVICE = "collector.ml-audit.svc.cluster.local"


@contextmanager
def listener(context, *, stalled=False, aborted=False):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    sock.settimeout(3)
    received, failures = [], []
    stop = threading.Event()

    def serve():
        try:
            with sock.accept()[0] as raw:
                raw.settimeout(2)
                if stalled:
                    stop.wait(3)
                    return
                if context is None:
                    received.append(raw.recv(4096))
                    raw.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    return
                with context.wrap_socket(raw, server_side=True) as connection:
                    data = bytearray()
                    while b"\r\n\r\n" not in data:
                        part = connection.recv(4096)
                        if not part:
                            return
                        received.append(part)  # Retain partial HTTP too, even before EOF.
                        data.extend(part)
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
                    )
        except ssl.SSLError:
            pass  # Expected certificate refusal before any HTTP bytes.
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError) as error:
            # Closing after handshake without HTTP may abort TLS 1.3 ticket writes.
            # Accept only the explicitly expected refusal/deadline cases below.
            if not aborted:
                failures.append(type(error).__name__)
        except OSError as error:
            failures.append(type(error).__name__)

    thread = threading.Thread(target=serve, name="mlsecops-owned-tls-test", daemon=False)
    thread.start()
    try:
        yield sock.getsockname()[1], received
    finally:
        stop.set()
        sock.close()
        thread.join(4)
        if thread.is_alive() or failures:
            raise AssertionError(
                f"owned TLS listener cleanup failed:{failures}:{thread.is_alive()}"
            )


class TLSContracts(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("mlsecops.security_event_tls"),
            "authenticated audit transport not implemented",
        )
        from mlsecops import security_event_tls as tls

        self.tls = tls
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.ca_key, self.ca = storage_pki.issue("ca")
        self.write("ca.crt", self.ca.public_bytes(serialization.Encoding.PEM))
        self.issue("client", "ml_promoter")
        self.issue("server", "server")
        self.server = {
            "ca_file": str(self.root / "ca.crt"),
            "certificate_file": str(self.root / "server.crt"),
            "key_file": str(self.root / "server.key"),
        }
        self.client = {
            **self.server,
            "certificate_file": str(self.root / "client.crt"),
            "key_file": str(self.root / "client.key"),
            "address": "127.0.0.1",
            "server_name": SERVICE,
        }
        self.fx = events_fixture.EventContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.envelope = signing.sign(self.fx.event(), "security-event", self.fx.keys["intake"])

    def write(self, name, content):
        path = self.root / name
        path.write_bytes(content)
        path.chmod(0o600)

    def issue(self, name, identity, *, hostname=SERVICE, expired=False):
        moment = datetime.now(UTC) - timedelta(days=180 if expired else 0)
        with (
            patch.object(storage_pki, "server_names", return_value=[x509.DNSName(hostname)]),
            patch.object(storage_pki, "datetime", SimpleNamespace(now=lambda _: moment)),
        ):
            key, certificate = storage_pki.issue(identity, self.ca_key, self.ca)
        self.write(name + ".crt", certificate.public_bytes(serialization.Encoding.PEM))
        self.write(
            name + ".key",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )

    def send(self, port, client=None):
        return delivery.exchange(
            port, "a" * 64, self.envelope, tls=self.tls.Client(client or self.client)
        )

    def test_real_mutual_tls13_accepts_fixed_route_and_bearer_after_authentication(self):
        context = self.tls.server_context(self.server)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)
        with listener(context) as (port, received):
            self.assertEqual(self.send(port), {})
        self.assertIn(b"Authorization: Bearer " + b"a" * 64, received[0])
        self.assertIn(b"Host: " + SERVICE.encode(), received[0])

    def test_wrong_server_name_or_expired_certificate_leaks_no_http_bytes(self):
        for name, expired in (("wrong.invalid", False), (SERVICE, True)):
            self.issue("server", "server", hostname=name, expired=expired)
            with listener(self.tls.server_context(self.server), aborted=True) as (port, received):
                with self.assertRaises(Rejected):
                    self.send(port)
            self.assertEqual(received, [])

    def test_wrong_ca_or_server_certificate_as_client_cannot_authenticate(self):
        _, foreign = storage_pki.issue("ca")
        self.write("foreign.crt", foreign.public_bytes(serialization.Encoding.PEM))
        for changed in (
            {**self.client, "ca_file": str(self.root / "foreign.crt")},
            {
                **self.client,
                "certificate_file": self.server["certificate_file"],
                "key_file": self.server["key_file"],
            },
        ):
            with listener(self.tls.server_context(self.server), aborted=True) as (port, received):
                with self.assertRaises(Rejected):
                    self.send(port, changed)
            self.assertEqual(received, [])

    def test_stalled_handshake_obeys_total_wire_deadline_and_closes_owned_socket(self):
        began = time.monotonic()
        with listener(None, stalled=True) as (port, received):
            with patch.object(delivery, "TIMEOUT", 0.15), self.assertRaises(Rejected):
                self.send(port)
        self.assertLess(time.monotonic() - began, 2)
        self.assertEqual(received, [])

    def test_plain_listener_never_receives_http_bearer_or_plaintext_fallback(self):
        with listener(None, aborted=True) as (port, received):
            with self.assertRaises(Rejected):
                self.send(port)
        self.assertTrue(received)
        self.assertNotIn(b"Authorization", received[0])
        self.assertNotIn(b"a" * 64, received[0])

    def test_missing_or_expired_client_certificate_is_refused(self):
        for mode in ("missing", "expired"):
            client = self.tls.Client(self.client)
            if mode == "missing":
                client.context = ssl.create_default_context(cafile=self.client["ca_file"])
                client.context.minimum_version = ssl.TLSVersion.TLSv1_3
            else:
                self.issue("client", "ml_promoter", expired=True)
                client = self.tls.Client(self.client)
            with listener(self.tls.server_context(self.server), aborted=True) as (port, received):
                with self.assertRaises(Rejected):
                    delivery.exchange(port, "a" * 64, self.envelope, tls=client)
            self.assertEqual(received, [])

    def test_foreign_client_ca_and_tls12_are_refused(self):
        original_key, original_ca = self.ca_key, self.ca
        self.ca_key, self.ca = storage_pki.issue("ca")
        self.issue("foreign-client", "ml_promoter")
        self.ca_key, self.ca = original_key, original_ca
        foreign = {
            **self.client,
            "certificate_file": str(self.root / "foreign-client.crt"),
            "key_file": str(self.root / "foreign-client.key"),
        }
        for mode in ("foreign", "tls12"):
            client = self.tls.Client(foreign if mode == "foreign" else self.client)
            if mode == "tls12":
                client.context.minimum_version = ssl.TLSVersion.TLSv1_2
                client.context.maximum_version = ssl.TLSVersion.TLSv1_2
            with listener(self.tls.server_context(self.server), aborted=True) as (port, received):
                with self.assertRaises(Rejected):
                    delivery.exchange(port, "a" * 64, self.envelope, tls=client)
            self.assertEqual(received, [])

    def test_deadline_expiring_after_handshake_sends_no_http_bearer(self):
        client = self.tls.Client(self.client)
        with listener(self.tls.server_context(self.server), aborted=True) as (port, received):
            with (
                patch.object(delivery.time, "monotonic", side_effect=[0, 0, 0, 0, 3]),
                self.assertRaises(Rejected),
            ):
                delivery.exchange(port, "a" * 64, self.envelope, tls=client)
        self.assertEqual(received, [])

    def test_delivery_client_uses_tls_endpoint_without_plain_fallback(self):
        self.write("ingress.token", b"a" * 64)
        with listener(self.tls.server_context(self.server)) as (port, received):
            client = delivery.Client(
                self.fx.registry,
                port,
                str(self.root / "ingress.token"),
                tls=self.tls.Client(self.client),
            )
            self.assertEqual(client.send(self.envelope), {})
        self.assertIn(b"Host: " + SERVICE.encode(), received[0])

    def test_endpoint_cannot_select_url_dns_public_linklocal_or_extra_controls(self):
        for address in (
            None,
            True,
            123,
            "localhost",
            "https://host",
            "::1",
            "169.254.169.254",
            "8.8.8.8",
            "0.0.0.0",
            "239.0.0.1",
        ):
            with self.subTest(address=address), self.assertRaises(Rejected):
                self.tls.Client({**self.client, "address": address})
        for changed in (
            {**self.client, "server_name": "wrong"},
            {**self.client, "verify": False},
            {**self.client, "key_file": "relative.key"},
        ):
            with self.assertRaises(Rejected):
                self.tls.Client(changed)

    def test_invalid_mismatched_or_oversized_tls_materials_fail_before_network(self):
        self.write("invalid.crt", b"PRIVATE-CANARY")
        self.write("oversize.key", b"x" * 4097)
        for field, path in (
            ("ca_file", "invalid.crt"),
            ("certificate_file", "invalid.crt"),
            ("key_file", "server.key"),
            ("key_file", "oversize.key"),
        ):
            with patch.object(self.tls.socket, "socket") as connect, self.assertRaises(Rejected):
                self.tls.Client({**self.client, field: str(self.root / path)})
            connect.assert_not_called()

    def test_tls_client_never_invokes_dns_and_cleans_failed_connect(self):
        client = self.tls.Client(self.client)
        with listener(self.tls.server_context(self.server)) as (port, received):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")):
                self.assertEqual(delivery.exchange(port, "a" * 64, self.envelope, tls=client), {})
        self.assertTrue(received)
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
            with self.assertRaises(Rejected):
                delivery.exchange(port, "a" * 64, self.envelope, tls=client)

    def profile(self):
        now = time.time_ns() // 1_000_000
        self.fx.document.update(issued_at_ms=now - 1000, expires_at_ms=now + 600000)
        registry = self.fx.registry_for(clock=now)
        self.write(
            "registry.json",
            canonical(
                signing.sign(self.fx.document, "security-event-config", self.fx.keys["root"])
            ),
        )
        self.write("ingress.token", b"a" * 64)
        config = dict(
            schema_version=2,
            registry_file=str(self.root / "registry.json"),
            registry_root=self.fx.publics["root"],
            registry_sha256=registry.sha256,
            state_directory=str(self.root / "state"),
            state_sha256="c" * 64,
            producer_key_file=str(self.fx.keys["promoter"]),
            ingress_token_file=str(self.root / "ingress.token"),
            port=8080,
            tls=self.client,
        )
        box = outbox.Outbox.empty(
            registry, outbox.key_identity(self.fx.keys["promoter"]), clock_ms=now
        )
        box.snapshot = box.document
        return config, box

    def test_explicit_tls_producer_and_admission_schemas_do_not_downgrade(self):
        config, box = self.profile()
        with patch.object(delivery.security_event_outbox, "Store", return_value=box):
            self.write("producer.json", canonical(config))
            emitter = delivery.configured(str(self.root / "producer.json"))
            self.assertIsInstance(emitter.client.tls, self.tls.Client)
            plain = {k: v for k, v in config.items() if k != "tls"}
            self.assertIsNone(delivery.configuration({**plain, "schema_version": 1}).client.tls)
            for invalid in (
                plain,
                {**config, "schema_version": 1},
                {**config, "schema_version": True},
                {**config, "tls": None},
                {**plain, "schema_version": 3},
                {**plain, "schema_version": True},
                None,
            ):
                with self.assertRaises(Rejected):
                    delivery.configuration(invalid)
            path = self.root / "audit.json"
            self.write("audit.json", canonical({**config, "schema_version": 3}))
            self.assertIsInstance(admission.emitter(str(path)).client.tls, self.tls.Client)
            self.write("audit.json", canonical({**config, "schema_version": 2}))
            with self.assertRaises(Rejected):
                admission.emitter(str(path))

    def test_collector_invalid_schema_port_path_and_entrypoint_reject_before_listener(self):
        with self.assertRaises(Rejected):
            server.absolute("relative.json")
        fields = {name: "unused" for name in server.FIELDS}
        for version, port in ((True, 8080), (3, 8080), (1, 65536)):
            self.write(
                "invalid.json", canonical({**fields, "schema_version": version, "port": port})
            )
            with self.assertRaises(Rejected):
                server.configured(str(self.root / "invalid.json"))
        with (
            patch.object(process_privacy, "enforce"),
            patch.object(server.sys, "argv", ["collector", "--config", "relative.json"]),
            contextlib.redirect_stderr(io.StringIO()) as err,
            self.assertRaises(SystemExit) as exit,
        ):
            runpy.run_path(server.__file__, run_name="__main__")
        self.assertEqual(exit.exception.code, 1)
        self.assertEqual(err.getvalue(), "security_collector_rejected\n")

    def test_tls_collector_binds_nonloopback_only_with_mandatory_client_auth(self):
        config, box = self.profile()
        config.pop("producer_key_file")
        config.update(
            tls=self.server,
            receipt_key_file=str(self.fx.keys["receipt"]),
            collector_key_file=str(self.fx.keys["collector"]),
            operator_token_file=str(self.root / "operator.token"),
        )
        self.write("operator.token", b"b" * 64)
        self.write("collector.json", canonical(config))
        path = str(self.root / "collector.json")
        with (
            patch.object(
                server.security_event_store, "Store", return_value=Mock(registry=box.registry)
            ),
            patch.object(server, "enforce_privacy"),
            patch.object(server.sys, "argv", ["collector", "--config", path]),
            patch.object(server, "run_server") as run,
        ):
            self.assertEqual(server.main(), 0)
            self.assertEqual(run.call_args.kwargs["host"], "0.0.0.0")
            context = run.call_args.kwargs["ssl_context_factory"](None, None)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)
            self.write("collector.json", canonical({**config, "tls": {}}))
            run.reset_mock()
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(server.main(), 1)
            self.assertEqual(err.getvalue(), "security_collector_rejected\n")
            run.assert_not_called()
            plain = {k: v for k, v in config.items() if k != "tls"}
            self.write("collector.json", canonical({**plain, "schema_version": 1}))
            self.assertEqual(server.main(), 0)
            self.assertEqual(run.call_args.kwargs["host"], "127.0.0.1")
            self.assertNotIn("ssl_context_factory", run.call_args.kwargs)

            def fail_start(app, **kwargs):
                app.startup_failed = True

            run.side_effect = fail_start
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(server.main(), 1)
            self.assertEqual(err.getvalue(), "security_collector_rejected\n")


if __name__ == "__main__":
    unittest.main()
