"""Privacy qualification failures must be observable, never a fabricated pass."""

import copy
import logging
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import monitoring_alerts, monitoring_delivery, monitoring_runtime, serving, signing
from mlsecops import monitoring_dashboard as dashboard
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.datasets import FEATURES
from mlsecops.load_probe import listen
from scripts import load_monitoring_qualification as load_fixtures
from scripts import monitoring_privacy_probe as probe
from scripts.audit_http_observation import Ledger
from scripts.monitoring_qualification import reference
from scripts.monitoring_stream_qualification import context
from scripts.serving_native import site
from scripts.serving_native_qualification import engine_fixture
from scripts.serving_privacy_probe import LifecycleCapture, inputs


def replay():
    """Controlled probe-failure fixture, separate from the real loopback test."""
    state = {"healthy": True, "observations": 0, "pending_windows": 0, "windows_evaluated": 0}
    frozen = reference()
    returned = {
        **state,
        "observations": 1000,
        "windows_evaluated": 1,
        "reference_sha256": digest(canonical(frozen)),
        "reports": [{"window_sha256": "c" * 64}],
        "release_ready": False,
        "label_reports": [
            {"accepted_labels": 0, "labelled_observations": 1, "release_ready": False}
        ],
    }
    order = {"monitor": 0, "label": 0, "quota": 0}

    def request(path, payload=None, **options):
        route = path.split("?", 1)[0]
        if route in dashboard.ASSETS:
            content = b"" if "?" in path else dashboard.ASSETS[route].encode()
            headers = list(dashboard.HEADERS.items()) + [
                ("content-length", str(len(content))),
                ("date", "Sat, 07 Nov 2026 00:00:00 GMT"),
            ]
            if "?" not in path:
                media = dashboard.MEDIA[route]
                headers.append(
                    (
                        "content-type",
                        media + ("; charset=utf-8" if media.startswith("text/") else ""),
                    )
                )
            return (400 if "?" in path else 200), headers, content
        status, value = 200, {}
        if options.get("authorized") is False or options.get("credential") == "client":
            status, value = 401, {"error": {"code": "unauthorized"}}
        elif path == "/v1/predict":
            value = {
                "request_id": "d" * 32,
                "model_sha256": "a" * 64,
                "bundle_sha256": "b" * 64,
                "predictions": [{}] * 100,
            }
        elif path.startswith("/monitoring/labels"):
            order["label"] += 1
            if order["label"] <= 2:
                value = {
                    "accepted_labels": 1 if order["label"] == 1 else 0,
                    "labelled_observations": 1,
                    "release_ready": False,
                }
            else:
                status, value = 400, {"error": {"code": "invalid_labels"}}
        elif "?" in path:
            status, value = 400, {"error": {"code": "invalid_request"}}
        else:
            order["monitor"] += 1
            value = copy.deepcopy(state if order["monitor"] == 1 else returned)
            if 3 <= order["monitor"] <= 22:
                order["quota"] += 1
                if order["quota"] > 8:
                    status, value = 429, {"error": {"code": "client_limited"}}
        status, value = request.change(
            path, payload, options, status, copy.deepcopy(value), order.copy()
        )
        content = canonical(value)
        return (
            status,
            [
                ("content-type", "application/json"),
                ("content-length", str(len(content))),
                ("date", "Sat, 07 Nov 2026 00:00:00 GMT"),
            ],
            content,
        )

    request.privacy_credential = "client"
    request.metrics_credential = "operator"
    request.change = lambda path, payload, options, status, value, order: (status, value)
    return request, frozen


class MonitoringPrivacyContracts(unittest.TestCase):
    def test_retained_monitoring_proof_requires_exact_actual_reference_count_and_summary(self):
        expected = load_fixtures.expected()
        expected["features"] = [[0.5] * 6] * 3
        primary = load_fixtures.proof(observations=1014)
        observed = probe.load_monitoring.verify(
            primary, probe.load_monitoring.reference(expected), "a" * 32, 1014
        )
        baseline = {
            "monitoring_privacy": probe.summary(
                operator_requests=20, quota_accepted=8, quota_limited=12
            ),
            "monitoring_proof": primary,
            "monitoring_observation": observed,
        }
        self.assertEqual(probe.reverify(baseline, expected, "a" * 32), observed)
        for fault in ("reference", "count", "epoch", "summary", "matrix"):
            value, golden, epoch = copy.deepcopy(baseline), copy.deepcopy(expected), "a" * 32
            if fault == "reference":
                golden["model"] = "f" * 64
            if fault == "count":
                value["monitoring_proof"]["state"]["observations"] = 1013
            if fault == "epoch":
                epoch = "f" * 32
            if fault == "summary":
                value["monitoring_observation"]["proof_sha256"] = "f" * 64
            if fault == "matrix":
                value["monitoring_privacy"]["label_retry_accepted"] = 1
            with self.subTest(fault=fault), self.assertRaises(Rejected):
                probe.reverify(value, golden, epoch)

    def test_operator_wire_rejects_plain_and_json_escaped_canaries(self):
        for content in (b'{"private":"secret-canary"}', b'{"private":"secret-\\u0063anary"}'):
            headers = [
                ("content-type", "application/json"),
                ("content-length", str(len(content))),
                ("date", "Sat, 07 Nov 2026 00:00:00 GMT"),
            ]
            with self.subTest(content=content), self.assertRaisesRegex(Rejected, "canary"):
                probe.wire((200, headers, content), (b"secret-canary",))

    def test_operator_wire_requires_bounded_json_and_safe_headers(self):
        for response in (
            (200, [("content-type", "application/json"), ("X-Private", "secret")], b"{}"),
            (200, [], b"{}"),
            (200, [], b"x" * 131073),
            (200, [("content-type", "application/json")], b"not-json"),
        ):
            with self.subTest(response=response[0]), self.assertRaises(Rejected):
                probe.wire(response, (b"secret",))

    def test_captured_leaks_overflow_and_ambient_signals_refuse(self):
        for fault in ("canary", "overflow", "signals"):
            capture = LifecycleCapture()
            if fault == "canary":
                capture.write("secret-canary")
            if fault == "overflow":
                capture.write("x" * 65537)
            with self.subTest(fault=fault), self.assertRaises(Rejected):
                probe.clean([capture], Mock(used=lambda: fault == "signals"), (b"secret-canary",))

    def test_public_summary_rejects_incomplete_fake_and_identifier_bearing_evidence(self):
        baseline = probe.summary(operator_requests=20, quota_accepted=8, quota_limited=12)
        self.assertNotIn("sha256", canonical(baseline).decode())
        for key, value in (
            ("status", "inconclusive"),
            ("label_retry_accepted", 1),
            ("label_accepted", True),
            ("metric_series", 70),
            ("quota_limited", 0),
            ("quota_accepted", 20),
            ("release_ready", True),
            ("private_url", "https://private.invalid"),
        ):
            candidate = copy.deepcopy(baseline)
            candidate[key] = value
            with self.subTest(key=key), self.assertRaises(Rejected):
                probe.checked(candidate)
        for key in baseline:
            candidate = copy.deepcopy(baseline)
            del candidate[key]
            with self.subTest(missing=key), self.assertRaises(Rejected):
                probe.checked(candidate)

    def test_operator_exemption_is_explicit_exact_and_cannot_hide_prediction_admission(self):
        ledger = Ledger(operator_routes=True)
        for path in ("/metrics", "/monitoring", "/monitoring/labels?private=canary"):
            ledger.response(path, 200, b"operator-private-output")
        self.assertEqual(ledger.snapshot(), [])
        for path in ("/monitoring", "/monitoring/labels"):
            with self.subTest(default=path), self.assertRaises(Rejected):
                Ledger().response(path, 200, b"{}")
        for path in ("/monitoring/labels/private", "/monitoring/", "/v1/predict"):
            with self.subTest(path=path), self.assertRaises(Rejected):
                Ledger(operator_routes=True).response(path, 200, b"{}")

    def test_controlled_wire_failures_cannot_fabricate_a_successful_matrix(self):
        faults = (
            "auth",
            "operator-status",
            "initial-health",
            "initial-pending",
            "prediction-status",
            "prediction-model",
            "prediction-count",
            "window-timeout",
            "observation-count",
            "reference",
            "accepted-labels",
            "label-count",
            "label-release",
            "rejected-framing",
            "error-code",
            "quota-status",
            "quota-error",
            "quota-unlimited",
            "quota-all-limited",
            "quota-slow",
            "recovery-count",
            "recovery-health",
            "recovery-release",
            "recovery-labels",
        )
        for fault in faults:
            request, frozen = replay()

            def change(path, payload, options, status, value, order):
                if fault == "auth" and status == 401:
                    return 200, value
                if path == "/v1/predict":
                    if fault == "prediction-status":
                        return 503, value
                    if fault == "prediction-model":
                        value["model_sha256"] = "f" * 64
                    if fault == "prediction-count":
                        value["predictions"] = []
                if path == "/monitoring" and status == 200 and order["monitor"] == 1:
                    if fault == "operator-status":
                        return 503, value
                    if fault == "initial-health":
                        value["healthy"] = False
                    if fault == "initial-pending":
                        value["pending_windows"] = 1
                if path == "/monitoring" and status == 200 and order["monitor"] == 2:
                    if fault == "observation-count":
                        value["observations"] = 999
                    if fault == "reference":
                        value["reference_sha256"] = "f" * 64
                if fault == "window-timeout" and path == "/monitoring" and order["monitor"] >= 2:
                    return 200, {**value, "windows_evaluated": 0}
                if path == "/monitoring/labels" and status == 200:
                    if fault == "accepted-labels":
                        value["accepted_labels"] = 99
                    if fault == "label-count":
                        value["labelled_observations"] = 99
                    if fault == "label-release":
                        value["release_ready"] = True
                if status == 400:
                    if fault == "rejected-framing":
                        return 200, value
                    if fault == "error-code":
                        value["error"]["code"] = "wrong"
                if path == "/monitoring" and 3 <= order["monitor"] <= 22:
                    if fault == "quota-status":
                        return 503, value
                    if fault == "quota-error" and status == 429:
                        value["error"]["code"] = "wrong"
                    if fault == "quota-unlimited":
                        return 200, value
                    if fault == "quota-all-limited":
                        return 429, {"error": {"code": "client_limited"}}
                if path == "/monitoring" and order["monitor"] == 23:
                    if fault == "recovery-count":
                        value["observations"] = 999
                    if fault == "recovery-health":
                        value["healthy"] = False
                    if fault == "recovery-release":
                        value["release_ready"] = True
                    if fault == "recovery-labels":
                        value["label_reports"] = []
                return status, value

            request.change = change
            times = (
                [0, 6]
                if fault == "window-timeout"
                else [0, 0, 2]
                if fault == "quota-slow"
                else [0, 0, 0.1]
            )
            with (
                self.subTest(fault=fault),
                patch.object(probe.time, "sleep"),
                patch.object(probe.time, "monotonic", side_effect=times),
                patch.object(probe.signing, "sign", return_value={"payload": "e30="}),
                self.assertRaises(Rejected),
            ):
                probe.matrix(
                    request, {"instances": [{}]}, frozen, "controlled", (b"secret-canary",)
                )

    def test_output_and_audit_capture_are_mandatory_for_the_matrix(self):
        for fault in (
            "empty-audit",
            "metric-cardinality",
            "accepted-count",
            "durable-count",
            "invalid-canaries",
            "log-canary",
        ):
            request = Mock(audit_scan=Mock(return_value={"files": 1, "bytes": 10}))
            before, after = {"accepted": 4, "durable": 4}, {"accepted": 44, "durable": 44}
            metrics, needles = {"series": 69}, (b"secret-canary",)
            if fault == "empty-audit":
                request.audit_scan.return_value["files"] = 0
            if fault == "metric-cardinality":
                metrics["series"] = 70
            if fault == "accepted-count":
                after["accepted"] = 43
            if fault == "durable-count":
                after["durable"] = 43
            if fault == "invalid-canaries":
                needles = ()

            def matrix(*args):
                if fault == "log-canary":
                    logging.getLogger("controlled-monitor-privacy").warning("secret-canary")
                return {}

            with (
                self.subTest(fault=fault),
                patch.object(probe, "drained", side_effect=[before, after]),
                patch.object(probe, "matrix", side_effect=matrix),
                patch.object(probe.serving_metrics_probe, "scan", return_value=metrics),
                patch.object(probe.time, "sleep"),
                self.assertRaises(Rejected),
            ):
                probe.exercise(request, {}, {}, "controlled", needles)

    def test_real_loopback_matrix_observes_signed_labels_quota_audit_and_bounded_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            keys = {role: root / (role + ".pem") for role in ("producer", "sink", "label")}
            publics = {role: signing.create_key(key) for role, key in keys.items()}
            frozen = reference()
            ref = digest(canonical(frozen))
            sink = monitoring_alerts.Sink(
                publics["producer"], keys["sink"], reference_sha256=ref, epoch="b" * 32
            )
            with listen(monitoring_delivery.App(sink)) as port:
                client = monitoring_delivery.Client(
                    keys["producer"],
                    publics["sink"],
                    port=port,
                    reference_sha256=ref,
                    epoch="b" * 32,
                )
                runtime = monitoring_runtime.Runtime(
                    frozen, ref, publics["label"], client, interval=0.02
                )
                engine = engine_fixture()
                generation = threading.Event()
                engine.response_budget.side_effect = lambda: serving.ResponseBudget(
                    generation, time.monotonic() + 10
                )
                engine.check.return_value = {"ready": True}
                engine.predict.side_effect = lambda rows, **kw: {
                    "schema_version": 1,
                    "predictions": [
                        {"decision": "score", "reason": None, "score": 0.75} for row in rows
                    ],
                }
                engine.predict_result.side_effect = lambda rows, *, generation: (
                    serving.ServingResult(
                        {
                            "model_sha256": "a" * 64,
                            "bundle_sha256": "b" * 64,
                            **engine.predict(rows),
                        },
                        context(),
                        generation,
                    )
                )
                ledger = Ledger(operator_routes=True)
                with site(engine, monitor=runtime, http_ledger=ledger) as request:
                    body = {"schema_version": 1, "instances": [dict.fromkeys(FEATURES, 0.5)]}
                    needles = inputs(body, request.privacy_credential)[2] + (
                        request.metrics_credential.encode(),
                    )
                    result = probe.exercise(request, body, frozen, keys["label"], needles)
                self.assertEqual(probe.checked(result), result)
                self.assertEqual(len(ledger.snapshot()), 10)
                self.assertEqual(runtime.snapshot()["state"], "stopped")
                self.assertEqual(runtime.snapshot()["faults"], [])
                self.assertTrue(runtime.task.done())


if __name__ == "__main__":
    unittest.main()
