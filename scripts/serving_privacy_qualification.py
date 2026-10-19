import logging
import os
import sys
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi import FastAPI
from opentelemetry import trace

from mlsecops import serving, serving_http
from mlsecops.contracts import Rejected, canonical
from mlsecops.datasets import FEATURES
from scripts import serving_privacy_probe as probe
from scripts.serving_native import site
from scripts.serving_native_qualification import engine_fixture
from scripts.serving_privacy_probe import Signals


async def invoke(app, *, path="/livez", query=b"", headers=None, method="GET"):
    outgoing = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        outgoing.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": query,
            "headers": headers or [],
            "server": ("127.0.0.1", 8080),
            "client": ("127.0.0.1", 12345),
        },
        receive,
        send,
    )
    started = next(message for message in outgoing if message["type"] == "http.response.start")
    content = b"\n".join(
        [value for _, value in started["headers"]]
        + [message.get("body", b"") for message in outgoing]
    )
    return started["status"], content


class ServingPrivacyContracts(unittest.IsolatedAsyncioTestCase):
    async def test_probe_control_observes_default_global_provider_emission(self):
        marker = "synthetic_privacy_probe"
        signals = Signals()
        with ExitStack() as stack:
            signals.install(stack)
            await invoke(FastAPI(), path="/unknown/" + marker, query=("email=" + marker).encode())
        self.assertTrue(signals.used(), "privacy_probe_control_not_observed")
        self.assertTrue(
            any(marker in str(attributes) for attributes in signals.spans),
            "privacy_probe_control_canary_not_observed",
        )

    async def test_serving_does_not_use_global_trace_metric_or_log_providers(self):
        signals = Signals()
        with ExitStack() as stack:
            signals.install(stack)
            app = serving_http.create_app(Mock(), "a" * 64)
            for path, query in (
                ("/livez", b"email=synthetic_privacy_probe"),
                ("/unknown/synthetic_privacy_probe", b""),
                ("/readyz", b""),
                ("/v1/predict", b""),
            ):
                await invoke(app, path=path, query=query)
        self.assertFalse(signals.used(), "serving_ambient_telemetry_used")

    async def test_noncanonical_routes_do_not_reflect_query_or_host_into_redirect(self):
        app = serving_http.create_app(Mock(), "a" * 64)
        marker = b"synthetic_privacy_probe"
        for path, method in (("/livez/", "GET"), ("/readyz/", "GET"), ("/v1/predict/", "POST")):
            with self.subTest(path=path):
                status, content = await invoke(
                    app,
                    path=path,
                    method=method,
                    query=b"email=" + marker,
                    headers=[(b"host", marker + b".invalid")],
                )
                self.assertEqual(status, 404)
                self.assertFalse(marker in content, "privacy_canary_in_response")

    async def test_environment_cannot_enable_native_exporter_setup(self):
        from fastapi.telemetry import _runtime

        configured = []
        original = _runtime._configure_from_environment

        def inspect(config):
            configured.append(dict(config))
            if config["auto_configure"]:
                return
            original(config)

        with (
            patch.dict(os.environ, {"FASTAPI_OTEL_AUTO_CONFIGURE": "true"}),
            patch.object(_runtime, "_configure_from_environment", inspect),
        ):
            app = serving_http.create_app(Mock(), "a" * 64)
            messages = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
            outgoing = []

            async def receive():
                return next(messages)

            async def send(message):
                outgoing.append(message["type"])

            await app({"type": "lifespan", "asgi": {"version": "3.0"}}, receive, send)
        self.assertEqual(outgoing, ["lifespan.startup.complete", "lifespan.shutdown.complete"])
        self.assertEqual(len(configured), 1)
        for field in ("tracing", "metrics", "logs", "operation_spans", "auto_configure"):
            with self.subTest(field=field):
                self.assertIs(configured[0][field], False)


class PrivacyProbeContracts(unittest.TestCase):
    def test_response_headers_reject_unapproved_duplicate_and_oversized_fields(self):
        valid = [
            ("Date", "Mon, 19 Oct 2026 00:00:00 GMT"),
            ("content-type", "application/json"),
            ("content-length", "2"),
        ]
        probe.response_headers(valid, b"{}", [b"private"])
        malformed = [
            None,
            [],
            valid * 3,
            [1],
            [("name",)],
            [("name", 1)],
            valid + [("DATE", "duplicate")],
            valid[1:],
            valid + [("x-debug", "features")],
            [("date", "private-data"), *valid[1:]],
            [*valid[:2], ("content-length", "3")],
        ]
        for index, headers in enumerate(malformed):
            with self.subTest(index=index), self.assertRaises(Rejected):
                probe.response_headers(headers, b"{}", [b"private"])
        with self.assertRaisesRegex(Rejected, "privacy_response_overflow"):
            probe.response_headers(valid + [("x-debug", "x" * probe.MAX_CAPTURE)], b"{}", [])

    def test_response_contract_rejects_unapproved_shapes_and_accepts_score_collision(self):
        valid = {
            "schema_version": 1,
            "request_id": "b" * 32,
            "model_sha256": "c" * 64,
            "bundle_sha256": "d" * 64,
            "predictions": [{"decision": "score", "reason": None, "score": 0.3183098861837907}],
        }
        probe.response_contract(valid, "/v1/predict", 200)
        malformed = [
            None,
            {},
            {**valid, "request_id": "not-hex"},
            {**valid, "schema_version": True},
            {**valid, "schema_version": 2},
            {**valid, "predictions": None},
        ]
        for prediction in (
            None,
            {},
            {**valid["predictions"][0], "features": [0.5]},
            {"decision": "abstain", "reason": None, "score": 0.5},
            {"decision": "score", "reason": "private", "score": 0.5},
            {"decision": "score", "reason": None, "score": True},
            {"decision": "score", "reason": None, "score": 1.1},
        ):
            malformed.append({**valid, "predictions": [prediction]})
        for index, value in enumerate(malformed):
            with self.subTest(index=index), self.assertRaises(Rejected):
                probe.response_contract(value, "/v1/predict", 200)
        with self.assertRaisesRegex(Rejected, "privacy_response_schema"):
            probe.response_contract({"detail": "raw input"}, "/unknown", 404)
        ready = {
            key: value
            for key, value in valid.items()
            if key in ("request_id", "bundle_sha256", "model_sha256")
        }
        with self.assertRaisesRegex(Rejected, "privacy_response_schema"):
            probe.response_contract({**ready, "ready": 1}, "/readyz", 200)
        body = {"schema_version": 1, "instances": [dict.fromkeys(FEATURES, 0.5)]}
        for credential in (None, "not-hex"):
            request = self.simulated_request()
            request.privacy_credential = credential
            with self.assertRaisesRegex(Rejected, "privacy_credential_missing"):
                probe.exercise(request, body)

    def test_real_http_detector_rejects_active_bearer_in_headers_and_logs(self):
        original = serving_http.create_app
        for channel in ("headers", "logs", "features"):
            with self.subTest(channel=channel):
                engine = engine_fixture()
                generation = threading.Event()
                engine.response_budget.side_effect = lambda: serving.ResponseBudget(
                    generation, time.monotonic() + 10
                )
                engine.predict.return_value = {
                    "schema_version": 1,
                    "predictions": [{"decision": "score", "reason": None, "score": 0.75}],
                }

                def wrapped(*arguments, **keywords):
                    app = original(*arguments, **keywords)

                    async def respond(scope, receive, send):
                        async def observed(message):
                            if (
                                message["type"] == "http.response.start"
                                and message["status"] == 200
                            ):
                                credential = dict(scope["headers"])[b"authorization"]
                                if channel == "headers":
                                    message = {
                                        **message,
                                        "headers": [
                                            *message["headers"],
                                            (b"x-debug-authorization", credential),
                                        ],
                                    }
                                elif channel == "features":
                                    feature_row = {
                                        **dict.fromkeys(FEATURES, 0.5),
                                        "change_size": 0.3183098861837907,
                                    }
                                    message = {
                                        **message,
                                        "headers": [
                                            *message["headers"],
                                            (b"x-debug-features", canonical(feature_row)),
                                        ],
                                    }
                                else:
                                    logging.getLogger("uvicorn.error").warning(
                                        "%s", credential.decode()
                                    )
                            await send(message)

                        await app(scope, receive, observed)

                    return respond

                with patch.object(serving_http, "create_app", wrapped), site(engine) as request:
                    body = {"schema_version": 1, "instances": [dict.fromkeys(FEATURES, 0.5)]}
                    reason = (
                        "privacy_response_canary"
                        if channel in ("headers", "features")
                        else "privacy_output_canary"
                    )
                    engine.check.return_value = {"ready": True}
                    with self.assertRaisesRegex(Rejected, "^" + reason + "$"):
                        probe.exercise(request, body)

    def test_signal_probe_bounds_retained_attributes(self):
        signals = Signals()
        with ExitStack() as stack:
            signals.install(stack)
            tracer = trace.get_tracer("controlled-probe")
            for _index in range(129):
                tracer.start_span("probe", attributes={"synthetic": True})
        self.assertEqual(len(signals.spans), 128)
        self.assertTrue(signals.used())

    def simulated_request(self, fault=None):
        statuses = (200, 200, 422, 422, 422, 422, 422, 401, 404, 404, 413, 200)
        calls = []

        def request(path, payload, **options):
            status = statuses[len(calls)]
            calls.append(path)
            base = {"request_id": "b" * 32, "model_sha256": "c" * 64, "bundle_sha256": "d" * 64}
            if status == 200 and path == "/v1/predict":
                value = {
                    **base,
                    "schema_version": 1,
                    "predictions": [{"decision": "score", "reason": None, "score": 0.75}],
                }
            elif status == 200:
                value = {**base, "ready": True}
            elif status == 404:
                value = {"detail": "Not Found"}
            else:
                value = {
                    "schema_version": 1,
                    "request_id": base["request_id"],
                    "error": {
                        "code": {
                            401: "unauthorized",
                            413: "body_too_large",
                            422: "invalid_request",
                        }[status]
                    },
                }
            content = canonical(value)
            headers = []
            if len(calls) == 2:
                marker = options["headers"]["X-Request-Id"]
                if fault == "stdout":
                    print(marker)
                elif fault == "stderr":
                    print(marker, file=sys.stderr)
                elif fault == "logging":
                    logging.getLogger("uvicorn.error").warning("%s", marker)
                elif fault == "response":
                    headers = [("X-Private", marker)]
                elif fault == "active-credential-response":
                    headers = [("X-Debug-Authorization", "Bearer " + request.privacy_credential)]
                elif fault == "active-credential-log":
                    logging.getLogger("uvicorn.error").warning("%s", request.privacy_credential)
                elif fault == "flat-features":
                    content = canonical({**value, **payload["instances"][0]})
                elif fault == "vector-features":
                    content = canonical(
                        {**value, "features": list(payload["instances"][0].values())}
                    )
                elif fault == "feature-response":
                    content = canonical({"predictions": [{"score": 0.75}], **payload})
                elif fault == "formatted-feature-response":
                    import json

                    content = json.dumps(
                        {"predictions": [{"score": 0.75}], **payload}, indent=2
                    ).encode()
                elif fault == "signal":
                    trace.get_tracer_provider().get_tracer("probe")
                elif fault == "overflow":
                    print("x" * (probe.MAX_CAPTURE + 1))
                elif fault == "status":
                    status = 503
                elif fault == "missing-prediction":
                    content = canonical({**value, "predictions": []})
                elif fault == "response-overflow":
                    content = b"x" * 131073
            headers = [
                ("date", "Mon, 19 Oct 2026 00:00:00 GMT"),
                ("content-type", "application/json"),
                ("content-length", str(len(content))),
                *headers,
            ]
            return status, headers, content

        idle = {"healthy": True, "unconfirmed": 0, "pending": 0, "reservations": 0}
        request.audit_status = Mock(
            side_effect=[
                {**idle, "accepted": 0, "durable": 0},
                {**idle, "accepted": 36, "durable": 35 if fault == "accounting" else 36},
            ]
        )
        request.audit_scan = Mock(return_value={"files": 1, "bytes": 100})
        request.privacy_credential = "f" * 64
        return request

    def test_checker_rejects_canary_or_missing_evidence_in_each_observed_channel(self):
        body = {"schema_version": 1, "instances": [dict.fromkeys(FEATURES, 0.5)]}
        for fault, reason in (
            ("stdout", "privacy_output_canary"),
            ("stderr", "privacy_output_canary"),
            ("logging", "privacy_output_canary"),
            ("response", "privacy_response_canary"),
            ("active-credential-response", "privacy_response_canary"),
            ("active-credential-log", "privacy_output_canary"),
            ("flat-features", "privacy_response_schema"),
            ("vector-features", "privacy_response_schema"),
            ("feature-response", "privacy_response_canary"),
            ("formatted-feature-response", "privacy_response_canary"),
            ("signal", "privacy_ambient_signals_used"),
            ("overflow", "privacy_capture_overflow"),
            ("status", "privacy_http_status"),
            ("missing-prediction", "privacy_prediction_missing"),
            ("response-overflow", "privacy_response_overflow"),
            ("accounting", "privacy_audit_accounting"),
        ):
            with self.subTest(fault=fault), self.assertRaisesRegex(Rejected, "^" + reason + "$"):
                probe.exercise(self.simulated_request(fault), body)
        self.assertEqual(probe.exercise(self.simulated_request(), body)["status"], "pass")

    def test_drain_rejects_failure_or_timeout_and_waits_for_owned_reservations(self):
        idle = {"healthy": True, "unconfirmed": 0, "pending": 0, "reservations": 0}
        for change in ({"healthy": False}, {"unconfirmed": 1}):
            request = Mock(audit_status=Mock(return_value={**idle, **change}))
            with self.assertRaisesRegex(Rejected, "privacy_audit_unavailable"):
                probe.drained(request)
        request = Mock(audit_status=Mock(return_value={**idle, "reservations": 1}))
        with patch.object(probe.time, "monotonic", side_effect=[0, 5]):
            with self.assertRaisesRegex(Rejected, "privacy_audit_pending"):
                probe.drained(request)
        request.audit_status.side_effect = [{**idle, "pending": 1}, idle]
        with patch.object(probe.time, "sleep") as sleep:
            self.assertEqual(probe.drained(request), idle)
        sleep.assert_called_once_with(0.01)

    def test_checker_rejects_invalid_audit_scan_receipt(self):
        body = {"schema_version": 1, "instances": [dict.fromkeys(FEATURES, 0.5)]}
        for receipt in (
            None,
            {},
            {"files": 1, "bytes": 100, "payload": "private"},
            {"files": "private", "bytes": 100},
            {"files": True, "bytes": 100},
            {"files": 0, "bytes": 100},
            {"files": 67, "bytes": 100},
            {"files": 1, "bytes": False},
            {"files": 1, "bytes": 0},
            {"files": 1, "bytes": probe.MAX_AUDIT_BYTES + 1},
        ):
            with self.subTest(receipt=receipt):
                request = self.simulated_request()
                request.audit_scan.return_value = receipt
                with self.assertRaisesRegex(Rejected, "^privacy_audit_receipt_invalid$"):
                    probe.exercise(request, body)

    def test_owned_scanner_rejects_invalid_needles_links_and_file_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file = root / "audit.jsonl"
            file.write_bytes(b"redacted")
            for needles in (None, [], [b"x"] * 17, ["x"], [b""], [b"x" * 4097]):
                with self.subTest(needles_type=type(needles).__name__):
                    with self.assertRaisesRegex(Rejected, "^privacy_audit_source_invalid$"):
                        probe.scan_owned_audit(root, needles)
            link = root / "duplicate"
            link.hardlink_to(file)
            with self.assertRaisesRegex(Rejected, "^privacy_audit_source_invalid$"):
                probe.scan_owned_audit(root, [b"marker"])
            link.unlink()
            for index in range(66):
                (root / str(index)).write_bytes(b"redacted")
            with self.assertRaisesRegex(Rejected, "^privacy_audit_source_invalid$"):
                probe.scan_owned_audit(root, [b"marker"])

    def test_owned_scanner_checks_filename_canary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "synthetic-private-name").write_bytes(b"redacted")
            with self.assertRaisesRegex(Rejected, "^privacy_private_audit_canary$"):
                probe.scan_owned_audit(root, [b"synthetic-private-name"])

    def test_capture_overflow_is_visible_and_storage_stays_bounded(self):
        capture = probe.Capture(limit=32)
        self.assertEqual(capture.write("a" * 20), 20)
        self.assertEqual(capture.write("b" * 20), 20)
        self.assertTrue(capture.overflow)
        self.assertEqual(len(capture.getvalue()), 32)
        for _index in range(100):
            capture.write("")
        self.assertEqual(len(capture.parts), 2)

    def test_private_scan_finds_canary_without_including_it_in_error(self):
        marker = b"synthetic-owned-private-canary"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file = root / "audit.jsonl"
            file.write_bytes(b'{"event":"redacted"}\n')
            self.assertEqual(probe.scan_owned_audit(root, (marker,))["files"], 1)
            file.write_bytes(marker)
            with self.assertRaises(Rejected) as failed:
                probe.scan_owned_audit(root, (marker,))
            self.assertEqual(str(failed.exception), "privacy_private_audit_canary")

    def test_private_scan_rejects_missing_empty_nested_or_oversized_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(Rejected):
                probe.scan_owned_audit(root, (b"marker",))
            with self.assertRaises(Rejected):
                probe.scan_owned_audit(root / "missing", (b"marker",))
            nested = root / "nested"
            nested.mkdir()
            with self.assertRaises(Rejected):
                probe.scan_owned_audit(root, (b"marker",))
            file = nested / "audit.jsonl"
            file.write_bytes(b"x" * 33)
            with patch.object(probe, "MAX_AUDIT_BYTES", 32), self.assertRaises(Rejected):
                probe.scan_owned_audit(nested, (b"marker",))

    def test_real_http_privacy_matrix_checks_owned_audit_and_returns_only_summary(self):
        engine = engine_fixture()
        generation = threading.Event()
        engine.response_budget.side_effect = lambda: serving.ResponseBudget(
            generation, time.monotonic() + 10
        )
        engine.check.return_value = {"ready": True}
        engine.predict.return_value = {
            "schema_version": 1,
            "predictions": [{"decision": "score", "reason": None, "score": 0.75}],
        }
        with site(engine) as request:
            body = {"schema_version": 1, "instances": [dict.fromkeys(FEATURES, 0.5)]}
            result = probe.exercise(request, body)
        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["release_ready"])
        self.assertEqual(result["request_cases"], 12)
        self.assertFalse(result["ambient_signals_used"])
        self.assertGreater(result["audit_files_scanned"], 0)
        self.assertNotIn("canaries", result)


if __name__ == "__main__":
    unittest.main()
