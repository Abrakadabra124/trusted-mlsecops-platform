"""Hosted readback of the actual long-running HTTP service and its retained event identity."""

import time

from mlsecops import kube_security_events
from mlsecops import kube_serving_service as service
from mlsecops.contracts import Rejected, canonical
from scripts import kube_security_native as audit
from scripts.kube_trust_native import hosted


def observe(state, expected):
    hosted()
    code = (
        "from mlsecops.contracts import canonical, decode; "
        "from mlsecops.kube_serving_service_probe import qualify; "
        "print(canonical(qualify(decode(" + repr(canonical(expected)) + "))).decode())"
    )
    marker = service.validate(state)
    before = service.pod(state, marker)["metadata"]["uid"]
    result = service.execute(state, code)
    if service.pod(state, marker)["metadata"]["uid"] != before:
        raise Rejected("kube_serving_service_probe_replaced")
    return {**result, "pod_uid": before}


def snapshot(state):
    hosted()
    return service.execute(state, audit.SERVING)


def replace(state):
    hosted()
    marker = kube_security_events.validate(state)
    before = snapshot(state)
    deadline = time.monotonic() + 40
    while True:
        sequence = audit.collector(state, marker)["heartbeats"].get("serving", 0)
        if sequence > 0:
            break
        if time.monotonic() >= deadline:
            raise Rejected("kube_serving_service_initial_heartbeat_missing")
        time.sleep(0.5)
    started = time.monotonic()
    result = service.restart(state)
    after = snapshot(state)
    deadline = started + 120
    while True:
        observed = audit.collector(state, marker)["heartbeats"].get("serving", 0)
        if observed > sequence:
            break
        if time.monotonic() >= deadline:
            raise Rejected("kube_serving_service_heartbeat_deadline")
        time.sleep(0.5)
    elapsed = time.monotonic() - started
    if elapsed > 120:
        raise Rejected("kube_serving_service_heartbeat_deadline")
    if before != after or before["pin"] != marker["pins"]["serving"]:
        raise Rejected("kube_serving_service_state_changed")
    return {
        **result,
        "heartbeat_before": sequence,
        "heartbeat_after": observed,
        "elapsed_seconds": round(elapsed, 6),
        "outbox_retained": True,
    }
