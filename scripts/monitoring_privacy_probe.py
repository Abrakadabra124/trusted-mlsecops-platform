"""Bounded operator/label privacy matrix through the ordinary HTTP transport.

Private runtime references stay inside the caller's primary evidence. This
module returns finite counters only; it never supplies release authorization.
"""

import copy
import logging
import math
import time
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from unittest.mock import patch

from mlsecops import load_monitoring, monitoring_stream, signing
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from scripts import serving_metrics_probe
from scripts.serving_privacy_probe import LifecycleCapture, Signals, drained, response_headers

FIXED = {
    "schema_version": 1,
    "status": "pass",
    "scope": "operator-monitoring-privacy-component-not-full-M13",
    "release_ready": False,
    "prediction_requests": 10,
    "observations_added": 1000,
    "unauthorized_requests": 4,
    "rejected_labels_or_framing": 9,
    "label_accepted": 1,
    "label_retry_accepted": 0,
    "quota_requests": 20,
    "quota_recovered": True,
    "audit_events_confirmed": 40,
    "metric_series": 69,
    "ambient_signals_used": False,
}


def checked(value):
    require_fields(value, (*FIXED, "operator_requests", "quota_accepted", "quota_limited"))
    if (
        canonical({key: value[key] for key in FIXED}) != canonical(FIXED)
        or any(
            type(value[key]) is not int or not low <= value[key] <= high
            for key, low, high in (
                ("operator_requests", 17, 40),
                ("quota_accepted", 1, 13),
                ("quota_limited", 1, 19),
            )
        )
        or value["quota_accepted"] + value["quota_limited"] != 20
    ):
        raise Rejected("monitor_privacy_evidence")
    return copy.deepcopy(value)


def summary(**counts):
    return checked({**FIXED, **counts})


def reverify(native, expected, epoch):
    checked(native["monitoring_privacy"])
    # Initial golden + context prediction + two quota-refill predictions each
    # use the actual three-row golden batch; the old privacy matrix adds two
    # one-row predictions. Direct engine/context calls are not HTTP observations.
    wanted = 4 * len(expected["features"]) + 2 + FIXED["observations_added"]
    result = load_monitoring.verify(
        native["monitoring_proof"], load_monitoring.reference(expected), epoch, wanted
    )
    if canonical(result) != canonical(native["monitoring_observation"]):
        raise Rejected("monitor_privacy_primary_binding")
    return result


def wire(response, needles):
    status, headers, content = response
    if len(content) + len(canonical(headers)) > 131072:
        raise Rejected("monitor_privacy_response_overflow")
    response_headers(headers, content, needles)
    value = decode(content, 65536)
    if any(needle in content or needle in canonical(value) for needle in needles):
        raise Rejected("monitor_privacy_response_canary")
    return status, value


def clean(captures, signals, needles):
    if signals.used():
        raise Rejected("monitor_privacy_ambient_signals")
    for capture in captures:
        if capture.overflow:
            raise Rejected("monitor_privacy_capture_overflow")
        if any(needle in capture.getvalue().encode() for needle in needles):
            raise Rejected("monitor_privacy_output_canary")


def exercise(request, body, reference, label_key, needles):
    if (
        type(needles) not in (list, tuple)
        or not 1 <= len(needles) <= 16
        or any(type(value) is not bytes or not 1 <= len(value) <= 4096 for value in needles)
    ):
        raise Rejected("monitor_privacy_canaries")
    before = drained(request)
    captures = [LifecycleCapture() for _ in range(3)]
    signals = Signals()
    formatter = logging.Formatter("%(levelname)s:%(name)s:%(message)s")

    def log(logger, record):
        captures[2].write(formatter.format(record) + "\n")

    with ExitStack() as stack:
        for capture in captures:
            stack.callback(capture.seal)
        signals.install(stack)
        stack.enter_context(redirect_stdout(captures[0]))
        stack.enter_context(redirect_stderr(captures[1]))
        stack.enter_context(patch.object(logging.Logger, "handle", log))
        result = matrix(request, body, reference, label_key, tuple(needles))
        after = drained(request)
        scanned = request.audit_scan(needles)
        if not scanned["files"] or not scanned["bytes"]:
            raise Rejected("monitor_privacy_audit_empty")
        # The same operator quota protects /metrics, status and labels.
        time.sleep(0.27)
        if serving_metrics_probe.scan(request, needles)["series"] != 69:
            raise Rejected("monitor_privacy_metric_cardinality")
    clean(captures, signals, needles)
    if any(after[key] - before[key] != 40 for key in ("accepted", "durable")):
        raise Rejected("monitor_privacy_audit_accounting")
    return result


def matrix(request, body, reference, label_key, needles):
    count = 0
    private = needles

    def call(path, payload=None, *, expected=200, **options):
        nonlocal count
        time.sleep(0.27)
        status, value = wire(
            request(path, payload, raw=True, credential=request.metrics_credential, **options),
            private,
        )
        count += 1
        if status != expected:
            raise Rejected("monitor_privacy_http_status")
        if expected != 200:
            code = "invalid_labels" if path.startswith("/monitoring/labels") else "invalid_request"
            if value.get("error") != {"code": code}:
                raise Rejected("monitor_privacy_error_shape")
        return value

    for path, payload in (
        ("/monitoring", None),
        ("/monitoring/labels", {"private": needles[0].decode()}),
    ):
        for options in ({"authorized": False}, {"credential": request.privacy_credential}):
            status, value = wire(request(path, payload, raw=True, **options), private)
            count += 1
            if status != 401 or value.get("error") != {"code": "unauthorized"}:
                raise Rejected("monitor_privacy_operator_access")
    start = call("/monitoring")
    if start.get("healthy") is not True or start.get("pending_windows") != 0:
        raise Rejected("monitor_privacy_initial_state")
    row = {**body["instances"][0], "change_size": 0.3183098861837907}
    batch = {"schema_version": 1, "instances": [row] * 100}
    first = None
    for _ in range(10):
        status, response = wire(request("/v1/predict", batch, raw=True), private)
        if (
            status != 200
            or (response.get("model_sha256"), response.get("bundle_sha256"))
            != (reference["model_sha256"], reference["bundle_sha256"])
            or len(response.get("predictions", [])) != 100
        ):
            raise Rejected("monitor_privacy_prediction_binding")
        first = first or response["request_id"]
    identifier = monitoring_stream.observation_id(first, 0)
    private += (first.encode(), identifier.encode())
    deadline = time.monotonic() + 5
    while True:
        state = call("/monitoring")
        if state.get("windows_evaluated") == start["windows_evaluated"] + 1:
            break
        if time.monotonic() >= deadline:
            raise Rejected("monitor_privacy_window_pending")
    if state.get("observations") != start["observations"] + 1000 or state.get(
        "reference_sha256"
    ) != digest(canonical(reference)):
        raise Rejected("monitor_privacy_observation_binding")
    issued = time.time_ns() // 1000000
    document = {
        "schema_version": 1,
        "reference_sha256": state["reference_sha256"],
        "window_sha256": state["reports"][-1]["window_sha256"],
        "issued_at_ms": issued,
        "expires_at_ms": issued + 60000,
        "labels": [{"observation_id": identifier, "label": 1}],
    }

    def signed(value):
        return signing.sign(value, "monitor-labels", label_key)

    envelope = signed(document)
    for accepted in (1, 0):
        reply = call("/monitoring/labels", envelope)
        if (
            reply.get("accepted_labels") != accepted
            or reply.get("labelled_observations") != 1
            or reply.get("release_ready") is not False
        ):
            raise Rejected("monitor_privacy_label_retry")
    marker = needles[0].decode()
    changed = copy.deepcopy(envelope)
    changed["payload"] = signing.encode64(canonical({"private": marker}))
    unmatched = {**document, "labels": [{"observation_id": "f" * 64, "label": 1}]}
    invalid_label = {**document, "labels": [{"observation_id": identifier, "label": marker}]}
    cases = (
        ("/monitoring/labels", changed, {}),
        ("/monitoring/labels", signed({**document, "private": marker}), {}),
        ("/monitoring/labels", signed(unmatched), {}),
        ("/monitoring/labels", signed(invalid_label), {}),
        ("/monitoring/labels?private=" + marker, envelope, {}),
        ("/monitoring/labels", envelope, {"headers": {"Content-Type": marker}}),
        ("/monitoring/labels", marker.encode() + b"x" * 262144, {}),
        ("/monitoring/labels", ('{"private":"' + marker).encode(), {}),
        ("/monitoring?private=" + marker, None, {}),
    )
    for path, payload, options in cases:
        call(path, payload, expected=400, **options)
    started = time.monotonic()
    statuses = []
    for _ in range(20):
        status, value = wire(
            request("/monitoring", credential=request.metrics_credential, raw=True), private
        )
        if (
            status not in (200, 429)
            or status == 429
            and value.get("error") != {"code": "client_limited"}
        ):
            raise Rejected("monitor_privacy_quota_status")
        statuses.append(status)
    elapsed = time.monotonic() - started
    accepted = statuses.count(200)
    if (
        not 0 <= elapsed < 1.5
        or not 0 < accepted <= 8 + math.floor(4 * elapsed)
        or 429 not in statuses
    ):
        raise Rejected("monitor_privacy_quota_window")
    final = call("/monitoring")
    if (
        final["observations"] != state["observations"]
        or final["healthy"] is not True
        or final["release_ready"] is not False
        or final.get("label_reports") != [reply]
    ):
        raise Rejected("monitor_privacy_recovery")
    return summary(operator_requests=count, quota_accepted=accepted, quota_limited=20 - accepted)
