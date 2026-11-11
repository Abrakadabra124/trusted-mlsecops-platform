"""Actual bounded loopback sockets; owned listener/thread cleanup is asserted."""

import socket
import threading
import time
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from mlsecops import security_event_delivery as delivery
from mlsecops import signing
from mlsecops.contracts import Rejected
from scripts import security_events_qualification as fixtures


@contextmanager
def reply(content, *, slowly=False):
    stop = threading.Event()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    port = listener.getsockname()[1]
    failures = []

    def serve():
        try:
            with listener.accept()[0] as connection:
                connection.settimeout(2)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    chunk = connection.recv(4096)
                    if not chunk:
                        return
                    request.extend(chunk)
                if slowly:
                    for value in content:
                        if stop.wait(0.02):
                            break
                        connection.sendall(bytes([value]))
                else:
                    connection.sendall(content)
        except OSError as error:
            if not slowly:
                failures.append(type(error).__name__)

    thread = threading.Thread(target=serve, name="mlsecops-owned-wire-test", daemon=False)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=4)
        if thread.is_alive() or failures:
            raise AssertionError("owned test listener cleanup failed")


class WireContracts(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.EventContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.envelope = signing.sign(self.fx.event(), "security-event", self.fx.keys["intake"])

    def test_real_socket_accepts_only_bounded_json_200(self):
        with reply(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
        ) as port:
            self.assertEqual(delivery.exchange(port, "a" * 64, self.envelope), {})

    def test_redirect_encoding_duplicate_lengths_and_oversized_or_partial_responses_fail(self):
        responses = [
            b"",
            b"HTTP/1.1 200 OK\r\ninvalid-header\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4097\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Encoding: gzip\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}extra",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\n\r\n{",
            b"HTTP/1.1 200 OK\r\nX:" + b"x" * 8300,
            b"HTTP/1.1 200 OK\r\nX:" + b"x" * 8200 + b"\r\nContent-Length: 2\r\n\r\n{}",
        ]
        for index, content in enumerate(responses):
            with self.subTest(case=index), reply(content) as port, self.assertRaises(Rejected):
                delivery.exchange(port, "a" * 64, self.envelope)

    def test_total_deadline_stops_slow_headers_and_releases_owned_thread(self):
        began = time.monotonic()
        with reply(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", slowly=True) as port:
            with patch.object(delivery, "TIMEOUT", 0.15), self.assertRaises(Rejected):
                delivery.exchange(port, "a" * 64, self.envelope)
        self.assertLess(time.monotonic() - began, 2)

    def test_large_valid_body_crosses_socket_read_boundary(self):
        body = b'"' + b"x" * 1500 + b'"'
        with reply(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1502\r\n\r\n"
            + body
        ) as port:
            self.assertEqual(delivery.exchange(port, "a" * 64, self.envelope), "x" * 1500)

    def test_only_fixed_routes_and_port_are_allowed_and_expired_deadline_never_connects(self):
        with patch.object(delivery.socket, "create_connection") as connect:
            with self.assertRaises(Rejected):
                delivery.exchange(8080, "a" * 64, self.envelope, path="/private")
            with self.assertRaises(Rejected):
                delivery.Client(self.fx.registry, 65536, str(self.fx.directory / "token"))
            with (
                patch.object(delivery.time, "monotonic", side_effect=[0, 3]),
                self.assertRaisesRegex(Rejected, "security_delivery_timeout"),
            ):
                delivery.exchange(8080, "a" * 64, self.envelope)
            connect.assert_not_called()

    def test_invalid_endpoint_token_and_envelope_fail_before_network(self):
        with patch.object(delivery.socket, "create_connection") as connect:
            for port, token, envelope in (
                (65536, "a" * 64, self.envelope),
                (80, "a" * 64, self.envelope),
                (8000, "PRIVATE\r\nCANARY", self.envelope),
                (8000, "a" * 64, {}),
            ):
                with self.assertRaises(Rejected):
                    delivery.exchange(port, token, envelope)
            connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
