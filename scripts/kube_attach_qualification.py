import io
import ssl
import sys
import unittest
from unittest.mock import Mock, patch

from mlsecops import kube_attach as attach
from mlsecops import serving_protocol as protocol
from mlsecops.contracts import Rejected, canonical


class AttachContracts(unittest.TestCase):
    def test_fragmented_stderr_is_classified_without_changing_refusal(self):
        connection = Mock()
        connection.recv.side_effect = [
            b"\x02\x1b[0;93m",
            b"\x02[W:onnxruntime:Default, device_discovery.cc:1] ",
            b"\x02GPU device discovery failed: PRIVATE\n",
        ]
        with self.assertRaisesRegex(Rejected, "^serving_attach_ort_device_warning$"):
            attach.exchange(connection, self.request)

    def test_device_discovery_variants_and_interleaved_stdout_preserve_diagnostic_only(self):
        for warning in (
            b"NPU device discovery failed",
            b"Failed to detect devices under",
            b"Skipping pci_bus_id for PCI path at",
        ):
            connection = Mock()
            connection.recv.side_effect = [
                b"\x02\x1b[0;93m",
                b"\x01",
                b"\x02[W:onnxruntime:Default, device_discovery.cc:1] ",
                b"\x02" + warning + b": PRIVATE\n",
            ]
            with self.assertRaisesRegex(Rejected, "^serving_attach_ort_device_warning$"):
                attach.exchange(connection, self.request)

    def test_unknown_ort_warning_is_classified_without_disclosing_or_accepting_it(self):
        connection = Mock()
        connection.recv.return_value = b"\x02[W:onnxruntime:Default, PRIVATE] unrelated warning\n"
        with self.assertRaisesRegex(Rejected, "^serving_attach_ort_other_warning$"):
            attach.exchange(connection, self.request)

    def test_stderr_diagnostics_are_byte_frame_and_time_bounded(self):
        for following in (TimeoutError("PRIVATE"), b"", "text", b"\x01PRIVATE"):
            connection = Mock()
            if isinstance(following, Exception):
                connection.recv.side_effect = following
            else:
                connection.recv.return_value = following
            self.assertEqual(
                attach.stderr_code(connection, b"\x02PRIVATE", float("inf")),
                "serving_attach_stderr",
            )
            self.assertEqual(connection.recv.call_count, 1)
        connection = Mock()
        self.assertEqual(
            attach.stderr_code(connection, b"\x02" + b"x" * 10000, float("inf")),
            "serving_attach_stderr",
        )
        connection.recv.assert_not_called()
        connection.recv.return_value = b"\x02"
        with patch.object(attach.time, "monotonic", return_value=10):
            self.assertEqual(
                attach.stderr_code(connection, b"\x02PRIVATE", 20), "serving_attach_stderr"
            )
        self.assertEqual(connection.recv.call_count, 8)
        connection.reset_mock()
        with patch.object(attach.time, "monotonic", side_effect=[10, 10.6]):
            self.assertEqual(
                attach.stderr_code(connection, b"\x02PRIVATE", 20), "serving_attach_stderr"
            )
        connection.recv.assert_not_called()

    def test_stderr_diagnostics_classify_only_finite_codes_without_accepting_payload(self):
        for payload, code in (
            (b"", "serving_attach_empty_stderr"),
            (b"serving_worker_rejected\n", "serving_attach_worker_rejected"),
            (
                b"[W:onnxruntime:Default, device_discovery.cc:1] GPU device discovery failed: PRIVATE",
                "serving_attach_ort_device_warning",
            ),
            (b"PRIVATE", "serving_attach_stderr"),
        ):
            connection = Mock()
            connection.recv.return_value = b"\x02" + payload
            with self.assertRaisesRegex(Rejected, "^" + code + "$"):
                attach.exchange(connection, self.request)

    def test_cli_distinguishes_finite_transport_codes_without_exception_text(self):
        from types import SimpleNamespace

        for phase, error, suffix in (
            ("preflight", RuntimeError("SECRET"), ""),
            ("exchange", Rejected("serving_attach_stderr"), ":serving_attach_stderr"),
            ("connect", RuntimeError("SECRET URL"), ":serving_attach_connect_failed"),
            ("http", RuntimeError("SECRET TOKEN"), ":serving_attach_http_403"),
        ):
            if phase == "http":
                error.response = SimpleNamespace(status_code=403)
            with (
                patch.object(sys, "argv", ["kube-attach", "--pod", "worker-123"]),
                patch.object(
                    attach, "enforce", side_effect=error if phase == "preflight" else None
                ),
                patch.object(attach, "open_connection") as opened,
                patch.object(attach, "serve", side_effect=error if phase == "exchange" else None),
                patch.object(sys, "stdin", Mock(buffer=io.BytesIO())),
                patch.object(sys, "stdout", Mock(buffer=io.BytesIO())),
                patch.object(sys, "stderr", io.StringIO()) as diagnostic,
            ):
                if phase in {"connect", "http"}:
                    opened.return_value.__enter__.side_effect = error
                self.assertEqual(attach.main(), 1)
                self.assertEqual(diagnostic.getvalue(), "serving_attach_rejected" + suffix + "\n")

    def setUp(self):
        self.initial = protocol.load_request(b"model")
        self.request = protocol.request(self.initial, "ping")
        self.reply = protocol.response(self.request, ready=True)
        self.content = canonical(self.reply) + b"\n"

    def test_split_stdout_reassembles_exact_bound_reply(self):
        connection = Mock()
        connection.recv.side_effect = [b"\x01" + self.content[:12], b"\x01" + self.content[12:]]
        self.assertEqual(attach.exchange(connection, self.request), self.content)
        self.assertEqual(
            connection.send.call_args.args, (b"\x00" + canonical(self.request) + b"\n",)
        )

    def test_stderr_status_text_eof_unknown_and_oversized_output_are_rejected(self):
        for value in [
            b"\x02private",
            b"\x03private",
            b"\xff\x01",
            b"\x00input",
            b"",
            "text",
            b"\x01" + b"x" * protocol.MAX_FRAME,
        ]:
            with self.subTest(value=type(value).__name__):
                connection = Mock()
                connection.recv.return_value = value
                with self.assertRaises(Rejected):
                    attach.exchange(connection, self.request)

    def test_noncanonical_extra_reply_and_wrong_binding_are_rejected(self):
        for value in [
            self.content + self.content,
            b" {}\n",
            canonical({**self.reply, "request_id": "0" * 32}) + b"\n",
        ]:
            connection = Mock()
            connection.recv.return_value = b"\x01" + value
            with self.assertRaises(Rejected):
                attach.exchange(connection, self.request)

    def test_empty_channel_frames_cannot_reset_absolute_deadline(self):
        connection = Mock()
        connection.recv.return_value = b"\x01"
        with patch.object(attach.time, "monotonic", side_effect=[0, 0, 31]):
            with self.assertRaises(Rejected):
                attach.exchange(connection, self.request)

    def test_invalid_input_is_never_sent(self):
        connection = Mock()
        with self.assertRaises(Rejected):
            attach.exchange(connection, {**self.request, "unknown": "private"})
        connection.send.assert_not_called()

    def test_model_input_is_chunked_and_reply_is_checked(self):
        request = protocol.load_request(b"x" * 50000)
        connection = Mock()
        connection.recv.return_value = b"\x01{}\n"
        with self.assertRaises(Rejected):
            attach.exchange(connection, request)
        frames = [x.args[0] for x in connection.send.call_args_list]
        self.assertGreater(len(frames), 1)
        self.assertTrue(all(x[0] == 0 and len(x) <= 16385 for x in frames))
        self.assertEqual(b"".join(x[1:] for x in frames), canonical(request) + b"\n")

    def test_connection_has_fixed_endpoint_verified_tls_no_proxy_or_redirect(self):
        connection = Mock(subprotocol=attach.SUBPROTOCOL)
        sock = Mock()
        credential = Mock()
        credential.authorization.return_value = ("a.b.c", ssl.create_default_context())
        with (
            patch.object(attach, "Client", return_value=credential),
            patch.object(attach.socket, "create_connection", return_value=sock) as dial,
            patch.object(attach, "connect", return_value=connection) as connect,
        ):
            with attach.open_connection("worker-123") as actual:
                self.assertIs(actual, connection)
        dial.assert_called_once_with(("kubernetes.default.svc", 443), timeout=10)
        args, options = connect.call_args
        self.assertTrue(
            args[0].startswith(
                "wss://kubernetes.default.svc/api/v1/namespaces/ml-serve/pods/worker-123/attach?"
            )
        )
        self.assertIn("tty=false", args[0])
        self.assertIs(options["sock"], sock)
        self.assertIsNone(options["proxy"])
        self.assertIsNone(options["compression"])
        self.assertIsNone(options["ping_interval"])
        self.assertEqual(options["subprotocols"], [attach.SUBPROTOCOL])
        self.assertEqual(options["max_queue"], 2)
        self.assertEqual(options["max_size"], protocol.MAX_FRAME + 1)
        self.assertEqual(options["additional_headers"], {"Authorization": "Bearer a.b.c"})
        self.assertFalse(options["logger"].propagate)
        connection.close.assert_called_once()
        sock.close.assert_called_once()

    def test_wrong_subprotocol_and_failed_handshake_close_socket(self):
        for fails in [False, True]:
            sock = Mock()
            connection = Mock(subprotocol="v4.channel.k8s.io")
            credential = Mock()
            credential.authorization.return_value = ("a.b.c", Mock())
            with (
                patch.object(attach, "Client", return_value=credential),
                patch.object(attach.socket, "create_connection", return_value=sock),
                patch.object(
                    attach,
                    "connect",
                    side_effect=OSError("private") if fails else None,
                    return_value=connection,
                ),
            ):
                with self.assertRaises((Rejected, OSError)):
                    with attach.open_connection("worker-123"):
                        self.fail("invalid connection admitted")
            sock.close.assert_called_once()
            if not fails:
                connection.close.assert_called_once()

    def test_invalid_pod_name_never_connects(self):
        with patch.object(attach.socket, "create_connection") as dial:
            for name in ["../secret", "pod?token=private", "", None]:
                with self.assertRaises(Rejected):
                    with attach.open_connection(name):
                        self.fail("invalid name admitted")
            dial.assert_not_called()

    def test_bridge_reuses_one_connection_then_closes_stdin(self):
        source = io.BytesIO(canonical(self.initial) + b"\n" + canonical(self.request) + b"\n")
        destination = io.BytesIO()
        connection = Mock()
        with patch.object(attach, "exchange", return_value=self.content) as exchange:
            attach.serve(connection, source, destination)
        self.assertEqual(exchange.call_count, 2)
        self.assertEqual(destination.getvalue(), self.content * 2)
        connection.send.assert_called_once_with(b"\xff\x00")

    def test_bridge_requires_one_initial_load_and_same_model_session(self):
        for requests in [
            [self.request],
            [self.initial, self.initial],
            [self.initial, {**self.request, "session_id": "0" * 32}],
            [self.initial, {**self.request, "model_sha256": "0" * 64}],
        ]:
            source = io.BytesIO(b"".join(canonical(x) + b"\n" for x in requests))
            with (
                patch.object(attach, "exchange", return_value=self.content),
                self.assertRaises(Rejected),
            ):
                attach.serve(Mock(), source, io.BytesIO())

    def test_cli_enforces_privacy_and_redacts_failures(self):
        for failure in [False, True]:
            connection = Mock()
            source = Mock(buffer=io.BytesIO())
            destination = Mock(buffer=io.BytesIO())
            diagnostic = io.StringIO()
            with (
                patch.object(sys, "argv", ["kube-attach", "--pod", "worker-123"]),
                patch.object(attach, "enforce") as enforce,
                patch.object(attach, "open_connection") as opened,
                patch.object(
                    attach, "serve", side_effect=RuntimeError("SECRET") if failure else None
                ),
                patch.object(sys, "stdin", source),
                patch.object(sys, "stdout", destination),
                patch.object(sys, "stderr", diagnostic),
            ):
                opened.return_value.__enter__.return_value = connection
                self.assertEqual(attach.main(), 1 if failure else 0)
                enforce.assert_called_once()
            self.assertEqual(
                diagnostic.getvalue(),
                "serving_attach_rejected:serving_attach_exchange_failed\n" if failure else "",
            )


if __name__ == "__main__":
    unittest.main()
