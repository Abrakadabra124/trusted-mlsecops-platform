"""Actual loopback HTTP campaign, controlled predictor, signed packet reconciliation."""

import copy
import dataclasses
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops import (
    monitoring_alerts,
    monitoring_delivery,
    monitoring_packet,
    monitoring_probe,
    monitoring_runtime,
    serving,
    serving_audit,
    serving_http,
    signing,
)
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from mlsecops.load_probe import listen
from scripts import kube_monitoring_native as native
from scripts import kube_monitoring_operator as operator
from scripts.monitoring_qualification import reference
from scripts.monitoring_stream_qualification import context


class PacketContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            producer, sink_key, label_key = (
                root / name for name in ("producer.pem", "sink.pem", "label.pem")
            )
            producer_public, sink_public, label_public = (
                signing.create_key(path) for path in (producer, sink_key, label_key)
            )
            ref, trace = reference(), context()
            pin, epoch = digest(canonical(ref)), "b" * 32
            sink = monitoring_alerts.Sink(
                producer_public, sink_key, reference_sha256=pin, epoch=epoch
            )
            journal = serving_audit.Journal(root / "audit.jsonl")
            journal.start()
            try:
                with listen(monitoring_delivery.App(sink)) as sink_port:
                    client = monitoring_delivery.Client(
                        producer, sink_public, port=sink_port, reference_sha256=pin, epoch=epoch
                    )
                    runtime = monitoring_runtime.Runtime(
                        ref, pin, label_public, client, interval=0.02
                    )
                    engine = Mock()
                    generation = threading.Event()
                    engine.response_budget.side_effect = lambda: serving.ResponseBudget(
                        generation, time.monotonic() + 30
                    )
                    engine.predict_result.side_effect = lambda rows, *, generation: (
                        serving.ServingResult(
                            {
                                "schema_version": 1,
                                "model_sha256": trace.model_sha256,
                                "bundle_sha256": trace.bundle_sha256,
                                "predictions": [
                                    {"decision": "score", "reason": None, "score": row[0]}
                                    for row in rows
                                ],
                            },
                            trace,
                            generation,
                        )
                    )
                    app = serving_http.create_app(
                        engine, "a" * 64, audit=journal, metrics_token="c" * 64, monitor=runtime
                    )
                    with listen(app) as port:
                        rows = [
                            {"features": [(index % 10 + 0.5) / 10] * 6} for index in range(1000)
                        ]
                        cls.packet = monitoring_probe.campaign(
                            port, "a" * 64, "c" * 64, runtime, rows, label_key
                        )
                    if not runtime.task.done() or runtime.snapshot()["faults"]:
                        raise AssertionError("owned monitoring shutdown unconfirmed")
                cls.arguments = {
                    "reference": ref,
                    "reference_sha256": pin,
                    "context": trace,
                    "sink_public": sink_public,
                    "label_public": label_public,
                    "epoch": epoch,
                }
            finally:
                journal.close()

    def test_real_http_windows_labels_and_receipts_reconcile_after_shutdown(self):
        result = monitoring_packet.verify(self.packet, **self.arguments)
        self.assertEqual(
            (result["clean_windows"], result["shift_windows"], result["delivered_alerts"]),
            (10, 2, 3),
        )
        self.assertEqual(result["observations"], 12000)
        self.assertLess(result["max_delivery_seconds"], 120)
        self.assertFalse(result["release_ready"])

    def test_missing_primary_records_or_extra_records_cannot_be_counted_as_complete(self):
        for key in ("windows", "http", "labels", "receipts"):
            packet = copy.deepcopy(self.packet)
            packet[key].pop()
            with self.subTest(key=key), self.assertRaises(Rejected):
                monitoring_packet.verify(packet, **self.arguments)

    def test_changed_http_identity_scores_or_window_counts_are_rejected(self):
        for variant in ("model", "bundle", "request", "score", "window", "ledger", "size"):
            packet = copy.deepcopy(self.packet)
            response = packet["http"][0]["response"]
            if variant in ("model", "bundle"):
                response[variant + "_sha256"] = "f" * 64
            elif variant == "request":
                response["request_id"] = packet["http"][1]["response"]["request_id"]
            elif variant == "score":
                response["predictions"][0]["score"] = 0.99
            elif variant == "window":
                packet["windows"][0]["document"]["observations"] = 999
            elif variant == "ledger":
                packet["windows"][0]["predictions"][0][1] = not packet["windows"][0]["predictions"][
                    0
                ][1]
            else:
                packet["http"][0]["features"].pop()
            with self.subTest(variant=variant), self.assertRaises(Rejected):
                monitoring_packet.verify(packet, **self.arguments)

    def test_fake_quality_result_receipt_signature_time_or_reference_is_rejected(self):
        for variant in ("labels", "signature", "timing", "evidence", "epoch", "public"):
            packet = copy.deepcopy(self.packet)
            arguments = dict(self.arguments)
            if variant == "labels":
                packet["labels"][0]["response"]["accepted_labels"] = 199
            elif variant == "signature":
                packet["receipts"][0]["envelope"]["signatures"][0]["sig"] = signing.encode64(
                    b"x" * 64
                )
            elif variant == "timing":
                packet["receipts"][0]["finished_ns"] = (
                    packet["receipts"][0]["admitted_ns"] + 120000000000
                )
                packet["receipts"][0]["delivery_seconds"] = 120
            elif variant == "evidence":
                packet["receipts"][0]["event"]["evidence_sha256"] = "f" * 64
            elif variant == "epoch":
                arguments["epoch"] = "f" * 32
            else:
                arguments["sink_public"] = self.arguments["label_public"]
            with self.subTest(variant=variant), self.assertRaises(Rejected):
                monitoring_packet.verify(packet, **arguments)

    def test_changed_reference_distribution_or_unknown_signed_label_window_is_rejected(self):
        arguments = copy.deepcopy(self.arguments)
        arguments["reference"]["histograms"]["prediction"] = [0, 1000] + [0] * 10
        arguments["reference_sha256"] = digest(canonical(arguments["reference"]))
        packet = copy.deepcopy(self.packet)
        for item in packet["windows"]:
            item["document"]["reference_sha256"] = arguments["reference_sha256"]
        with self.assertRaisesRegex(Rejected, "drift_profile"):
            monitoring_packet.verify(packet, **arguments)
        with tempfile.TemporaryDirectory() as temporary:
            key = Path(temporary) / "labels.pem"
            public = signing.create_key(key)
            packet = copy.deepcopy(self.packet)
            packet["labels"][0]["envelope"] = signing.sign(
                {"window_sha256": "f" * 64}, "monitor-labels", key
            )
            with self.assertRaisesRegex(Rejected, "label_window"):
                monitoring_packet.verify(packet, **{**self.arguments, "label_public": public})

    def payload(self):
        return {
            "packet": copy.deepcopy(self.packet),
            "summary": monitoring_packet.verify(self.packet, **self.arguments),
            "context": dataclasses.asdict(self.arguments["context"]),
            "sink_public": self.arguments["sink_public"],
            "label_public": self.arguments["label_public"],
        }

    def coordinator(self, state):
        return operator.Coordinator(
            state,
            {},
            self.arguments["epoch"],
            self.arguments["reference"],
            self.arguments["context"],
        )

    def test_operator_retains_primary_packet_and_reverifies_after_transport_is_gone(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(operator, "hosted") as hosted:
            state = Path(temporary)
            op = self.coordinator(state)
            op.start()
            hosted.assert_called_once()
            payload = self.payload()
            request = {"phase": "finish", "campaign": op.campaign, "payload": payload}
            pod = {"metadata": {"name": "owned", "uid": "owned-uid"}}
            with patch.object(
                operator,
                "kubectl",
                return_value=SimpleNamespace(stdout=canonical(request), returncode=0),
            ) as api:
                op.observe(pod)
                op.observe(pod)
                self.assertEqual(api.call_count, 2)  # One read, one ack; no replay.
            self.assertEqual(op.reverify(), payload["summary"])
            report = {
                **payload["summary"],
                "worker_cleanup_verified": True,
                "model_sha256": op.context.model_sha256,
                "subject_sha256": op.context.bundle_sha256,
            }
            self.assertEqual(op.finish(report, canonical(report) + b"\n"), report)
            pin = op.retain_binding()
            public = {
                "campaign": op.campaign,
                "binding_sha256": pin,
                "native": {"operator_retained_reverified": op.summary},
                "feedback_quarantine": {},
            }
            write_json(state / "evidence/kubernetes-monitoring-public.json", public)
            # This isolates primary monitoring transport. Quarantine's real primary
            # records and failures are covered by feedback_native_qualification.
            with patch.object(native.feedback_native, "reverify", return_value={}) as feedback:
                self.assertTrue(native.reverify(state)["post_cleanup_reverified"])
            feedback.assert_called_once_with(state, op.campaign, {}, payload["packet"])
            with patch.object(
                native.feedback_native, "reverify", side_effect=Rejected("missing_feedback")
            ):
                with self.assertRaisesRegex(Rejected, "missing_feedback"):
                    native.reverify(state)
            binding = read_json(op.destination / "binding.json")
            for changed_context in (False, True):
                modified = copy.deepcopy(payload)
                modified["context"] = {}
                write_json(op.destination / "packet.json", modified)
                replacement = dict(binding)
                if changed_context:
                    replacement["packet_hash"] = digest(
                        (op.destination / "packet.json").read_bytes()
                    )
                write_json(op.destination / "binding.json", replacement)
                changed_public = {
                    **public,
                    "binding_sha256": digest((op.destination / "binding.json").read_bytes()),
                }
                write_json(state / "evidence/kubernetes-monitoring-public.json", changed_public)
                with self.assertRaises(Rejected):
                    native.reverify(state)
            write_json(op.destination / "packet.json", payload)
            write_json(op.destination / "binding.json", binding)
            write_json(state / "evidence/kubernetes-monitoring-public.json", public)
            with patch.object(operator, "kubectl") as api:
                for name in ("context", "summary"):
                    changed = copy.deepcopy(payload)
                    changed[name] = {}
                    with self.subTest(name=name), self.assertRaises(Rejected):
                        op.verify(changed)
                with self.assertRaises(Rejected):
                    op.observe({"metadata": {"name": "owned", "uid": "replacement"}})
                api.assert_not_called()
            with self.assertRaises(Rejected):
                op.finish(report, b"unexpected\n")
            with self.assertRaises(Rejected):
                op.finish(
                    {**report, "worker_cleanup_verified": False},
                    canonical({**report, "worker_cleanup_verified": False}) + b"\n",
                )
            op.summary = {}
            with self.assertRaises(Rejected):
                op.reverify()
            op.summary = payload["summary"]
            public["native"]["operator_retained_reverified"] = {}
            write_json(state / "evidence/kubernetes-monitoring-public.json", public)
            with self.assertRaises(Rejected):
                native.reverify(state)
            write_json(op.destination / "binding.json", {})
            with self.assertRaises(Rejected):
                native.reverify(state)
            write_json(op.destination / "packet.json", {})
            with self.assertRaises(Rejected):
                op.reverify()

    def test_operator_missing_partial_changed_or_wrong_campaign_never_acknowledges(self):
        for variant in ("missing", "waiting", "wrong", "write", "exec", "grace", "expired"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                op = self.coordinator(Path(temporary))
                pod = {"metadata": {"name": "owned", "uid": "uid"}}
                if variant == "missing":
                    with self.assertRaises(Rejected):
                        op.reverify()
                    continue
                request = {"phase": "finish", "campaign": op.campaign, "payload": self.payload()}
                if variant == "waiting":
                    request = None
                if variant == "wrong":
                    request["campaign"] = "wrong"
                failed = variant in ("exec", "grace", "expired")
                result = SimpleNamespace(
                    stdout=canonical(request),
                    returncode=int(failed),
                    stderr=b"container not found" if variant != "exec" else b"PRIVATE",
                )
                if variant == "expired":
                    op.exit_deadline = 0
                with patch.object(operator, "kubectl", return_value=result) as api:
                    if variant in ("waiting", "grace"):
                        op.observe(pod)
                    elif variant == "write":
                        with (
                            patch.object(operator, "bounded_read", return_value=b"{}"),
                            self.assertRaises(Rejected),
                        ):
                            op.observe(pod)
                    else:
                        with self.assertRaises(Rejected):
                            op.observe(pod)
                    self.assertEqual(api.call_count, 1)
                    self.assertIsNone(op.request_hash)


if __name__ == "__main__":
    unittest.main()
