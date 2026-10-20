import hashlib
import io
import logging
import os
import re
import secrets
import stat
import threading
import time
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from opentelemetry import _logs, metrics, trace

from mlsecops.contracts import Rejected, bounded_read, canonical, decode

MAX_CAPTURE = 65536
MAX_AUDIT_BYTES = 17 * 1024 * 1024


class Capture(io.TextIOBase):
    def __init__(self, limit=MAX_CAPTURE):
        self.limit = limit
        self.parts = []
        self.size = 0
        self.overflow = False
        self.lock = threading.Lock()

    def write(self, value):
        with self.lock:
            accepted = value[: max(0, self.limit - self.size)]
            if accepted:
                self.parts.append(accepted)
                self.size += len(accepted)
            self.overflow |= len(accepted) != len(value)
        return len(value)

    def getvalue(self):
        with self.lock:
            return "".join(self.parts)


class LifecycleCapture(Capture):
    def __init__(self):
        super().__init__()
        self.phase_lock = threading.Lock()
        self.sealed = False

    def write(self, value):
        with self.phase_lock:
            if self.sealed and value:
                os.write(2, b"serving_output_late_write\n")
                return len(value)
            return super().write(value)

    def seal(self):
        with self.phase_lock:
            self.sealed = True


class Signals:
    def __init__(self):
        self.spans = []
        capture = self

        class Recorder(trace.NoOpTracer):
            def start_span(self, name, *arguments, **keywords):
                if len(capture.spans) < 128:
                    capture.spans.append(dict(keywords.get("attributes") or {}))
                return super().start_span(name, *arguments, **keywords)

        self.tracer = Mock()
        self.tracer.get_tracer.return_value = Recorder()
        self.meter = Mock(wraps=metrics.NoOpMeterProvider())
        self.logger = Mock(wraps=_logs.NoOpLoggerProvider())

    def install(self, stack):
        for module, method, provider in (
            (trace, "get_tracer_provider", self.tracer),
            (metrics, "get_meter_provider", self.meter),
            (_logs, "get_logger_provider", self.logger),
        ):
            stack.enter_context(patch.object(module, method, return_value=provider))

    def used(self):
        return bool(
            self.spans
            or self.tracer.get_tracer.called
            or self.meter.get_meter.called
            or self.logger.get_logger.called
        )


def scan_owned_audit(path, needles):
    path = Path(path)
    if (
        path.is_symlink()
        or not path.is_dir()
        or not isinstance(needles, (tuple, list))
        or not 1 <= len(needles) <= 16
        or any(type(value) is not bytes or not 1 <= len(value) <= 4096 for value in needles)
    ):
        raise Rejected("privacy_audit_source_invalid")
    files = total = 0
    for child in path.iterdir():
        files += 1
        state = child.lstat()
        if files > 66 or not stat.S_ISREG(state.st_mode) or state.st_nlink != 1:
            raise Rejected("privacy_audit_source_invalid")
        content = bounded_read(child, MAX_AUDIT_BYTES - total)
        total += len(content)
        if any(needle in content or needle in child.name.encode() for needle in needles):
            raise Rejected("privacy_private_audit_canary")
    if not files or not total:
        raise Rejected("privacy_audit_source_invalid")
    return {"files": files, "bytes": total}


def drained(request):
    deadline = time.monotonic() + 5
    while True:
        state = request.audit_status()
        if not state["healthy"] or state["unconfirmed"]:
            raise Rejected("privacy_audit_unavailable")
        if state["pending"] == state["reservations"] == 0:
            return state
        if time.monotonic() >= deadline:
            raise Rejected("privacy_audit_pending")
        time.sleep(0.01)


def response_headers(headers, content, needles):
    if type(headers) not in (list, tuple) or not 1 <= len(headers) <= 8:
        raise Rejected("privacy_response_headers")
    values = {}
    for pair in headers:
        if (
            type(pair) not in (list, tuple)
            or len(pair) != 2
            or any(type(field) is not str for field in pair)
            or pair[0].lower() in values
        ):
            raise Rejected("privacy_response_headers")
        values[pair[0].lower()] = pair[1]
    raw = "\n".join(name + ":" + value for name, value in values.items()).encode()
    if len(raw) > MAX_CAPTURE:
        raise Rejected("privacy_response_overflow")
    if any(needle in raw for needle in needles):
        raise Rejected("privacy_response_canary")
    formats = {
        "content-type": "application/json",
        "content-length": str(len(content)),
        "cache-control": "no-store",
        "connection": "close",
        "date": r"[A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT",
    }
    if not {"content-type", "content-length", "date"} <= values.keys() or any(
        name not in formats or re.fullmatch(formats[name], value) is None
        for name, value in values.items()
    ):
        raise Rejected("privacy_response_headers")


def response_contract(value, path, status):
    if type(value) is not dict:
        raise Rejected("privacy_response_schema")
    if status == 404:
        if value != {"detail": "Not Found"}:
            raise Rejected("privacy_response_schema")
        return
    fields = {"request_id": 32}
    if status == 200:
        fields.update(bundle_sha256=64, model_sha256=64)
    for name, length in fields.items():
        field = value.get(name)
        if type(field) is not str or re.fullmatch(f"[a-f0-9]{{{length}}}", field) is None:
            raise Rejected("privacy_response_schema")
    expected = {name: value[name] for name in fields}
    if status == 200 and path.startswith("/readyz"):
        if value.get("ready") is not True:
            raise Rejected("privacy_response_schema")
        expected["ready"] = True
    else:
        if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
            raise Rejected("privacy_response_schema")
        expected["schema_version"] = 1
        if status == 200:
            predictions = value.get("predictions")
            if type(predictions) is not list or len(predictions) != 1:
                raise Rejected("privacy_prediction_missing")
            prediction = predictions[0]
            if (
                type(prediction) is not dict
                or set(prediction) != {"decision", "reason", "score"}
                or prediction["decision"] != "score"
                or prediction["reason"] is not None
                or type(prediction["score"]) not in (int, float)
                or not 0 <= prediction["score"] <= 1
            ):
                raise Rejected("privacy_response_schema")
            expected["predictions"] = predictions
        else:
            expected["error"] = {
                "code": {401: "unauthorized", 413: "body_too_large", 422: "invalid_request"}[status]
            }
    if value != expected:
        raise Rejected("privacy_response_schema")


def exercise(request, body, *, metrics_check=None, input_observer=None):
    marker = secrets.token_hex(16)
    secret = secrets.token_hex(32)
    feature = 0.3183098861837907
    valid = {**body, "instances": [{**body["instances"][0], "change_size": feature}]}
    credential = getattr(request, "privacy_credential", None)
    if type(credential) is not str or re.fullmatch("[a-f0-9]{64}", credential) is None:
        raise Rejected("privacy_credential_missing")
    needles = tuple(
        value.encode()
        for value in (marker, secret, credential, hashlib.sha256(marker.encode()).hexdigest())
    )
    response_needles = needles + (canonical(valid["instances"][0]),)
    private_needles = response_needles + (str(feature).encode(),)
    if input_observer is not None:
        input_observer(private_needles)
    cases = (
        ("/v1/predict", valid, {}, 200),
        (
            "/v1/predict",
            valid,
            {
                "headers": {
                    "X-Request-Id": marker,
                    "Cookie": "private=" + marker,
                    "Baggage": "private=" + marker,
                    "Traceparent": f"00-{marker}-{marker[:16]}-01",
                }
            },
            200,
        ),
        ("/v1/predict", {**valid, "private": marker}, {}, 422),
        (
            "/v1/predict",
            {**valid, "instances": [{**valid["instances"][0], "change_size": marker}]},
            {},
            422,
        ),
        ("/v1/predict", ('{"private":"' + marker).encode(), {}, 422),
        ("/v1/predict?email=" + marker, valid, {}, 422),
        ("/v1/predict", valid, {"headers": {"Content-Type": marker}}, 422),
        ("/v1/predict", valid, {"credential": secret}, 401),
        ("/unknown/" + marker, None, {}, 404),
        (
            "/v1/predict/?email=" + marker,
            valid,
            {"headers": {"Host": marker + ".invalid"}},
            404,
        ),
        ("/v1/predict", marker.encode() + b"x" * 65536, {}, 413),
        ("/readyz?email=" + marker, None, {}, 200),
    )
    before = drained(request)
    captures = {name: LifecycleCapture() for name in ("stdout", "stderr", "logs")}
    signals = Signals()
    formatter = logging.Formatter("%(levelname)s:%(name)s:%(message)s")

    def observe_log(logger, record):
        captures["logs"].write(formatter.format(record) + "\n")

    with ExitStack() as stack:
        for capture in captures.values():
            stack.callback(capture.seal)
        signals.install(stack)
        stack.enter_context(redirect_stdout(captures["stdout"]))
        stack.enter_context(redirect_stderr(captures["stderr"]))
        stack.enter_context(patch.object(logging.Logger, "handle", observe_log))
        for path, payload, options, expected in cases:
            status, headers, content = request(path, payload, raw=True, **options)
            if status != expected:
                raise Rejected("privacy_http_status")
            wire = canonical(headers) + content
            if len(wire) > 131072:
                raise Rejected("privacy_response_overflow")
            response_headers(headers, content, private_needles)
            value = decode(content)
            normalized = canonical(value)
            if any(needle in wire or needle in normalized for needle in response_needles):
                raise Rejected("privacy_response_canary")
            response_contract(value, path, status)
        after = drained(request)
        scanned = request.audit_scan(private_needles)
        if metrics_check is not None:
            metrics_check(request, private_needles)
    if (
        type(scanned) is not dict
        or set(scanned) != {"files", "bytes"}
        or type(scanned["files"]) is not int
        or not 1 <= scanned["files"] <= 66
        or type(scanned["bytes"]) is not int
        or not 1 <= scanned["bytes"] <= MAX_AUDIT_BYTES
    ):
        raise Rejected("privacy_audit_receipt_invalid")
    if signals.used():
        raise Rejected("privacy_ambient_signals_used")
    for capture in captures.values():
        if capture.overflow:
            raise Rejected("privacy_capture_overflow")
        content = capture.getvalue().encode()
        if any(needle in content for needle in private_needles):
            raise Rejected("privacy_output_canary")
    if after["accepted"] - before["accepted"] != 36 or after["durable"] - before["durable"] != 36:
        raise Rejected("privacy_audit_accounting")
    return {
        "scope": "existing-serving-output-privacy-not-full-M13",
        "status": "pass",
        "request_cases": len(cases),
        "ambient_signals_used": False,
        "audit_files_scanned": scanned["files"],
        "audit_events_confirmed": 36,
        "release_ready": False,
    }
