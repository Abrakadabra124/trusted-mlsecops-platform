import io
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import load_exchange as exchange
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json


class ExchangeContracts(unittest.TestCase):
    def test_delayed_ack_and_module_command_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            value = {"phase": "start", "campaign": "a" * 32, "payload": {}}
            ack = {
                "phase": "start",
                "request_sha256": digest(canonical(value)),
                "status": "pass",
                "result": {},
            }
            with patch.object(
                exchange.time,
                "sleep",
                side_effect=lambda _: write_json(directory / "start-ack.json", ack),
            ):
                self.assertEqual(exchange.send(directory, "start", "a" * 32, {}), {})
        with (
            patch.object(exchange.sys, "argv", ["exchange", "unknown"]),
            self.assertRaises(Rejected),
        ):
            runpy.run_path(exchange.__file__, run_name="__main__")

    def test_bound_acknowledgement_is_required_and_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            request = {"phase": "start", "campaign": "a" * 32, "payload": {"one": 1}}
            ack = {
                "phase": "start",
                "request_sha256": digest(canonical(request)),
                "status": "pass",
                "result": {"observed": True},
            }
            write_json(directory / "start-ack.json", ack)
            self.assertEqual(
                exchange.send(directory, "start", "a" * 32, {"one": 1}), {"observed": True}
            )
            self.assertEqual(read_json(directory / "request.json"), request)
            for field, value in (
                ("phase", "finish"),
                ("request_sha256", "b" * 64),
                ("status", "fail"),
                ("result", None),
            ):
                write_json(directory / "start-ack.json", {**ack, field: value})
                with self.assertRaises(Rejected):
                    exchange.send(directory, "start", "a" * 32, {"one": 1})

    def test_invalid_requests_and_timeout_do_not_succeed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for phase, campaign, payload in (
                ("../bad", "a" * 32, {}),
                ("start", "private", {}),
                ("start", "a" * 32, []),
            ):
                with self.assertRaises(Rejected):
                    exchange.send(directory, phase, campaign, payload)
            with patch.object(exchange, "MAX_PACKET", 10), self.assertRaises(Rejected):
                exchange.send(directory, "start", "a" * 32, {})
            with (
                patch.object(exchange.time, "monotonic", side_effect=[0, 46]),
                self.assertRaisesRegex(Rejected, "load_operator_deadline"),
            ):
                exchange.send(directory, "start", "a" * 32, {})

    def test_fixed_channel_read_and_ack(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(exchange, "DIRECTORY", Path(temporary)),
        ):
            output = io.StringIO()
            with (
                patch.object(exchange.sys, "argv", ["load-exchange", "read"]),
                patch.object(exchange.sys, "stdout", output),
            ):
                self.assertEqual(exchange.main(), 0)
            self.assertEqual(output.getvalue(), "null\n")
            value = {"phase": "finish", "campaign": "a" * 32, "payload": {"measurements": []}}
            write_json(Path(temporary) / "request.json", value)
            output = io.StringIO()
            with (
                patch.object(exchange.sys, "argv", ["load-exchange", "read"]),
                patch.object(exchange.sys, "stdout", output),
            ):
                self.assertEqual(exchange.main(), 0)
            self.assertEqual(output.getvalue().encode(), canonical(value) + b"\n")
            ack = {
                "phase": "finish",
                "request_sha256": digest(canonical(value)),
                "status": "pass",
                "result": {},
            }
            stdin = io.TextIOWrapper(io.BytesIO(canonical(ack)))
            with (
                patch.object(exchange.sys, "argv", ["load-exchange", "ack"]),
                patch.object(exchange.sys, "stdin", stdin),
            ):
                self.assertEqual(exchange.main(), 0)
            self.assertEqual(read_json(Path(temporary) / "finish-ack.json"), ack)
            with (
                patch.object(exchange.sys, "argv", ["load-exchange", "unknown"]),
                self.assertRaises(Rejected),
            ):
                exchange.main()


if __name__ == "__main__":
    unittest.main()
