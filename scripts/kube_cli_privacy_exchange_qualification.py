"""Private synthetic-canary transfer, no real SQL or Kubernetes operations."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from mlsecops.signing import encode64
from scripts import kube_cli_privacy_exchange as handoff


class CanaryHandoffContracts(unittest.TestCase):
    def setUp(self):
        self.needles = tuple(f"private-canary-{i}".encode() for i in range(9))
        self.pod = {
            "metadata": {"name": "owned-probe", "namespace": "ml-serving", "uid": "pod-uid"}
        }
        self.request = {
            "phase": "audit",
            "campaign": "a" * 32,
            "payload": {"needles": [encode64(v) for v in self.needles]},
        }

    def test_probe_sends_private_request_and_removes_both_files_without_logging(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "handoff"

            def reply(_delay):
                request = read_json(directory / "request.json")
                self.assertEqual(request["payload"]["needles"], self.request["payload"]["needles"])
                write_json(
                    directory / "audit-ack.json",
                    {
                        "phase": "audit",
                        "request_sha256": digest(canonical(request)),
                        "status": "pass",
                        "result": {"accepted_canaries": 9},
                    },
                )

            with (
                patch.object(handoff.exchange.time, "sleep", side_effect=reply),
                patch("builtins.print") as output,
            ):
                handoff.provide(self.needles, directory=directory)
            output.assert_not_called()
            self.assertFalse(directory.exists())

    def test_timeout_wrong_ack_and_foreign_directory_do_not_pass_or_remove_foreign_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "handoff"
            with (
                patch.object(handoff.exchange.time, "monotonic", side_effect=[0, 46]),
                self.assertRaises(Rejected),
            ):
                handoff.provide(self.needles, directory=directory)
            self.assertFalse(directory.exists())
            with (
                patch.object(handoff.exchange, "send", return_value={"accepted_canaries": True}),
                self.assertRaises(Rejected),
            ):
                handoff.provide(self.needles, directory=directory)
            self.assertFalse(directory.exists())
            directory.mkdir()
            (directory / "original").write_bytes(b"preserve")
            with self.assertRaises(Rejected):
                handoff.provide(self.needles, directory=directory)
            self.assertEqual((directory / "original").read_bytes(), b"preserve")

    def test_parent_observes_only_verified_pod_exec_and_acknowledges_exact_private_digest(self):
        receiver = handoff.Receiver(Path("owned"))
        with patch.object(
            handoff,
            "kubectl",
            side_effect=[
                SimpleNamespace(returncode=0, stdout=b"null"),
                SimpleNamespace(returncode=0, stdout=canonical(self.request)),
                SimpleNamespace(returncode=0),
            ],
        ) as command:
            receiver.observe(self.pod)
            self.assertIsNone(receiver.needles)
            receiver.observe(self.pod)
            receiver.observe(self.pod)
        self.assertEqual(command.call_count, 3)
        self.assertEqual(
            command.call_args.args[2],
            {
                "phase": "audit",
                "request_sha256": digest(canonical(self.request)),
                "status": "pass",
                "result": {"accepted_canaries": 9},
            },
        )
        self.assertEqual(receiver.finish(b'{"status":"pass"}\n'), self.needles)

    def test_noncanonical_or_missing_duplicate_unbounded_canaries_and_wrong_phase_fail(self):
        for payload in (
            None,
            [],
            {},
            {"needles": []},
            {"needles": ["YQ=="] * 9},
            {"needles": ["!invalid!"] + self.request["payload"]["needles"][1:]},
            {"needles": [encode64(b"x" * 4097)] + self.request["payload"]["needles"][1:]},
            {**self.request["payload"], "extra": "private"},
        ):
            with (
                self.subTest(payload=type(payload).__name__),
                patch.object(
                    handoff,
                    "kubectl",
                    return_value=SimpleNamespace(
                        returncode=0, stdout=canonical({**self.request, "payload": payload})
                    ),
                ),
                self.assertRaises(Rejected),
            ):
                handoff.Receiver(Path("owned")).observe(self.pod)
        for change in ({"phase": "worker"}, {"campaign": "bad"}, {"extra": 1}):
            with (
                self.subTest(change=change),
                patch.object(
                    handoff,
                    "kubectl",
                    return_value=SimpleNamespace(
                        returncode=0, stdout=canonical({**self.request, **change})
                    ),
                ),
                self.assertRaises(Rejected),
            ):
                handoff.Receiver(Path("owned")).observe(self.pod)

    def test_missing_handoff_exec_failure_and_needle_in_raw_or_encoded_stdout_refuse(self):
        receiver = handoff.Receiver(Path("owned"))
        with self.assertRaises(Rejected):
            receiver.finish(b"{}")
        with (
            patch.object(handoff, "kubectl", return_value=SimpleNamespace(returncode=1)),
            self.assertRaises(Rejected),
        ):
            receiver.observe(self.pod)
        receiver.needles = self.needles
        for raw in (self.needles[0], encode64(self.needles[0]).encode(), None):
            with self.subTest(raw=type(raw).__name__), self.assertRaises(Rejected):
                receiver.finish(raw)

    def test_ack_write_failure_never_sets_received_canaries(self):
        receiver = handoff.Receiver(Path("owned"))
        with (
            patch.object(
                handoff,
                "kubectl",
                side_effect=[
                    SimpleNamespace(returncode=0, stdout=canonical(self.request)),
                    SimpleNamespace(returncode=1),
                ],
            ),
            self.assertRaisesRegex(Rejected, "cli_privacy_handoff_exec"),
        ):
            receiver.observe(self.pod)
        self.assertIsNone(receiver.needles)

    def test_noncanonical_base64_and_unconfirmed_file_cleanup_are_refused(self):
        request = {
            **self.request,
            "payload": {"needles": ["AB=="] + self.request["payload"]["needles"][1:]},
        }
        with (
            patch.object(
                handoff,
                "kubectl",
                return_value=SimpleNamespace(returncode=0, stdout=canonical(request)),
            ),
            self.assertRaisesRegex(Rejected, "cli_privacy_canary_encoding"),
        ):
            handoff.Receiver(Path("owned")).observe(self.pod)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "handoff"
            with (
                patch.object(handoff.exchange, "send", return_value={"accepted_canaries": 9}),
                patch.object(Path, "rmdir", side_effect=OSError("controlled cleanup refusal")),
                self.assertRaisesRegex(Rejected, "cli_privacy_handoff_cleanup"),
            ):
                handoff.provide(self.needles, directory=directory)

    def test_changed_pod_or_foreign_namespace_cannot_reuse_acknowledgement(self):
        receiver = handoff.Receiver(Path("owned"))
        with patch.object(
            handoff,
            "kubectl",
            side_effect=[
                SimpleNamespace(returncode=0, stdout=canonical(self.request)),
                SimpleNamespace(returncode=0),
            ],
        ):
            receiver.observe(self.pod)
        for change in ({"uid": "foreign"}, {"namespace": "foreign"}, {"name": "other"}):
            with self.subTest(change=change), self.assertRaises(Rejected):
                receiver.observe({"metadata": {**self.pod["metadata"], **change}})


if __name__ == "__main__":
    unittest.main()
