"""Controlled orchestration failures; native Kubernetes is a separate hosted run."""

import io
import sys
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import monitoring_probe as probe
from mlsecops import signing
from mlsecops.contracts import Rejected
from scripts.monitoring_qualification import reference
from scripts.monitoring_stream_qualification import context


class ProbeContracts(unittest.TestCase):
    def test_http_status_and_transport_failure_always_close_connection(self):
        for fault in (None, "status", "transport", "oversize"):
            connection = Mock()
            connection.getresponse.return_value.status = 401 if fault == "status" else 200
            connection.getresponse.return_value.read.return_value = (
                b"x" * 262145 if fault == "oversize" else b"{}"
            )
            if fault == "transport":
                connection.request.side_effect = OSError("PRIVATE")
            with patch.object(probe.http.client, "HTTPConnection", return_value=connection):
                if fault:
                    with self.assertRaises((Rejected, OSError)):
                        probe.request(1234, "token", "/monitoring")
                else:
                    self.assertEqual(probe.request(1234, "token", "/monitoring"), {})
            connection.close.assert_called_once()

    def test_native_composition_and_failures_require_worker_and_monitor_shutdown(self):
        for fault in (None, "initial", "worker", "task", "pending", "fault", "ack", "campaign"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                key = root / "reference.pem"
                public = signing.create_key(key)
                supplied = {
                    "monitoring": {
                        "reference": signing.sign(reference(), "monitor-reference", key),
                        "reference_public": public,
                        "rows": [],
                    }
                }
                engine = Mock(audit_context=context())
                runtime = Mock()
                runtime.task.done.return_value = fault != "pending"
                runtime.snapshot.return_value = {
                    "faults": ["scheduler"] if fault == "fault" else []
                }
                if fault == "task":
                    runtime.task = None
                api = Mock()
                api.request.side_effect = [
                    {"items": [1] if fault == "initial" else []},
                    {"items": [1] if fault == "worker" else []},
                ]
                summary = {"packet_sha256": "a" * 64, "status": "pass", "release_ready": False}
                with (
                    patch.object(probe, "Client", return_value=api),
                    patch.object(probe, "candidate") as candidate,
                    patch.object(probe, "Worker") as worker,
                    patch.object(probe.serving, "Engine", return_value=engine) as factory,
                    patch.object(probe, "listen", side_effect=lambda app: nullcontext(12345)),
                    patch.object(probe.serving_http, "create_app"),
                    patch.object(probe.monitoring_config, "producer", return_value=runtime),
                    patch.object(
                        probe,
                        "campaign",
                        return_value={},
                        side_effect=Rejected("PRIVATE") if fault == "campaign" else None,
                    ),
                    patch.object(probe.monitoring_packet, "verify", return_value=summary),
                    patch.object(probe, "DIRECTORY", root / "exchange"),
                    patch.object(
                        probe,
                        "send",
                        return_value={} if fault == "ack" else {"packet_sha256": "a" * 64},
                    ) as send,
                ):
                    config = {"kubernetes_worker": {}, "expected_campaign": "b" * 32}
                    if fault:
                        with self.assertRaises(Rejected):
                            probe.qualify(config, supplied)
                    else:
                        result = probe.qualify(config, supplied)
                        self.assertTrue(result["worker_cleanup_verified"])
                        self.assertFalse(result["release_ready"])
                        factory.call_args.kwargs["worker_factory"](b"model", "image")
                        worker.assert_called_once_with(b"model", "image", {})
                    if fault == "initial":
                        candidate.assert_not_called()
                    else:
                        engine.close.assert_called_once()
                    if fault not in (None, "ack"):
                        send.assert_not_called()

    def test_campaign_faults_and_waits_cannot_become_complete_observation(self):
        for fault in (None, "windows", "timeout", "support", "quality", "status"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                key = Path(temporary) / "label.pem"
                signing.create_key(key)
                runtime = Mock()
                runtime._reference_sha256 = "a" * 64
                windows = [
                    {
                        "document": {},
                        "predictions": [[str(i), fault == "support"] for i in range(200)],
                    }
                    for _ in range(12)
                ]
                base = {
                    "windows": windows,
                    "receipts": [],
                    "state": {"windows_evaluated": 12, "alerts_delivered": 2, "faults": []},
                }
                waiting = {
                    **base,
                    "state": {"windows_evaluated": 0, "alerts_delivered": 0, "faults": []},
                }
                broken = {
                    **waiting,
                    "state": {
                        **waiting["state"],
                        "faults": ["scheduler"] if fault != "timeout" else [],
                    },
                }
                finished = {**base, "state": {**base["state"], "alerts_delivered": 3}}
                states = iter(
                    [broken]
                    if fault in ("windows", "timeout")
                    else [waiting, base, broken]
                    if fault == "quality"
                    else [waiting, base, base, finished]
                )

                def capture(coroutine, loop):
                    coroutine.close()
                    return Mock(result=Mock(return_value=next(states)))

                status = {
                    "release_ready": fault == "status",
                    "observations": 12000,
                    "healthy": True,
                }
                with (
                    patch.object(
                        probe,
                        "request",
                        side_effect=lambda port, token, path, document=None: (
                            status if path == "/monitoring" else {}
                        ),
                    ),
                    patch.object(probe.asyncio, "run_coroutine_threadsafe", side_effect=capture),
                    patch.object(probe.time, "sleep"),
                    patch.object(
                        probe.time,
                        "monotonic",
                        side_effect=[0, 11] if fault == "timeout" else None,
                        return_value=0,
                    ),
                ):
                    if fault:
                        with self.assertRaises(Rejected):
                            probe.campaign(
                                1,
                                "token",
                                "operator",
                                runtime,
                                [{"features": [0.5] * 6}] * 1000,
                                key,
                            )
                    else:
                        self.assertEqual(
                            len(
                                probe.campaign(
                                    1,
                                    "token",
                                    "operator",
                                    runtime,
                                    [{"features": [0.5] * 6}] * 1000,
                                    key,
                                )["http"]
                            ),
                            120,
                        )

    def test_main_redacts_arbitrary_exception_and_enforces_process_privacy(self):
        for fault in (None, "privacy", "qualify"):
            with (
                patch.object(
                    probe,
                    "enforce",
                    side_effect=Rejected("PRIVATE") if fault == "privacy" else None,
                ),
                patch.object(sys, "argv", ["probe", "--config", "config", "--request", "request"]),
                patch.object(probe, "read_json", return_value={}),
                patch.object(
                    probe,
                    "qualify",
                    return_value={"status": "pass"},
                    side_effect=Rejected("PRIVATE") if fault == "qualify" else None,
                ),
                patch.object(sys, "stdout", io.StringIO()) as output,
            ):
                self.assertEqual(probe.main(), int(fault is not None))
                self.assertNotIn("PRIVATE", output.getvalue())


if __name__ == "__main__":
    unittest.main()
