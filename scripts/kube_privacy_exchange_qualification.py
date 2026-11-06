import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from scripts import kube_privacy_exchange as exchange


class PrivateExchangeContracts(unittest.TestCase):
    def test_exact_ack_is_bound_to_private_request_without_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def respond(_delay):
                request = read_json(root / "request.json")
                write_json(
                    root / "worker-ack.json",
                    {
                        "phase": "worker",
                        "request_sha256": digest(canonical(request)),
                        "status": "pass",
                        "result": {"bytes": 10},
                    },
                )

            with (
                patch.object(exchange.time, "sleep", side_effect=respond),
                patch("builtins.print") as output,
            ):
                result = exchange.send(root, "worker", "a" * 32, {"private": "canary"})
            self.assertEqual(result, {"bytes": 10})
            output.assert_not_called()

    def test_wrong_ack_and_failure_never_authorize_continuation(self):
        for change in (
            {"phase": "audit"},
            {"request_sha256": "b" * 64},
            {"status": "fail", "result": None},
            {"extra": "private"},
        ):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)

                def respond(_delay):
                    request = read_json(root / "request.json")
                    ack = {
                        "phase": "worker",
                        "request_sha256": digest(canonical(request)),
                        "status": "pass",
                        "result": {"bytes": 10},
                        **change,
                    }
                    write_json(root / "worker-ack.json", ack)

                with (
                    self.subTest(change=change),
                    patch.object(exchange.time, "sleep", side_effect=respond),
                    self.assertRaises(Rejected),
                ):
                    exchange.send(root, "worker", "a" * 32, {})

    def test_timeout_and_invalid_input_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch.object(exchange.time, "monotonic", side_effect=[0, 46]),
                self.assertRaisesRegex(Rejected, "privacy_operator_deadline"),
            ):
                exchange.send(root, "worker", "a" * 32, {})
            for phase, campaign, payload in (
                ("other", "a" * 32, {}),
                ("worker", "bad", {}),
                ("worker", "a" * 32, []),
                ("worker", "a" * 32, {"large": "x" * exchange.MAX_REQUEST}),
            ):
                with self.subTest(phase=phase), self.assertRaises(Rejected):
                    exchange.send(root, phase, campaign, payload)


if __name__ == "__main__":
    unittest.main()
