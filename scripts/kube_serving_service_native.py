"""Hosted readback of the actual long-running HTTP service and its retained event identity."""

import time

from mlsecops import kube_security_events, kube_serving_handoff
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


def handoff(state, profile, promotion, expected):
    """Exercise the actual qualification HTTP owner between two verified Deployments."""
    from scripts.kube_serving_native import invoke, serving_configuration

    hosted()
    if expected.get("ready") is not True:
        raise Rejected("kube_serving_handoff_expected_active")
    marker = kube_security_events.validate(state, profile=profile)
    before = snapshot(state)
    config = serving_configuration(promotion)
    config.update(
        minimum_sequence=1,
        audit_directory="/tmp/audit",
        token_file="/tmp/token",
        kubernetes_worker=profile,
    )
    with kube_serving_handoff.transfer(state) as transfer:
        qualified = invoke(state, profile, config, expected)
        sequence = audit.collector(state, marker)["heartbeats"].get("serving", 0)
        if sequence <= 0:
            raise Rejected("kube_serving_handoff_heartbeat_missing")
        returned = time.monotonic()
    restored = observe(state, expected)
    after = snapshot(state)
    deadline = returned + 120
    while True:
        inbox = audit.collector(state, marker)
        counter = inbox["heartbeats"].get("serving", 0)
        if counter > sequence:
            break
        if time.monotonic() >= deadline:
            raise Rejected("kube_serving_handoff_heartbeat_deadline")
        time.sleep(0.5)
    elapsed = time.monotonic() - returned
    if elapsed > 120 or restored["pod_uid"] != transfer["after"]:
        raise Rejected("kube_serving_handoff_return_changed")
    if before["pin"] != marker["pins"]["serving"] or before["permissions"] != after["permissions"]:
        raise Rejected("kube_serving_handoff_identity_changed")
    receipts = audit.identity_receipts(before, after, inbox)
    return {
        "transfer": transfer,
        "qualification": qualified,
        "restored": restored,
        "return_seconds": round(elapsed, 6),
        "return_heartbeat_before": sequence,
        "return_heartbeat_after": counter,
        "identity_events_delivered": receipts,
        "outbox_retained": True,
        "release_ready": False,
    }


def change_configuration(state, promotion, expected):
    """Measure a real config replacement and independent post-return heartbeat."""
    hosted()
    prior = service.validate(state)
    before = snapshot(state)
    marker = kube_security_events.validate(state, profile=prior["profile"])
    started = time.monotonic()
    ticket = kube_serving_handoff.suspend(state)
    rebound = kube_serving_handoff.reconfigure(state, ticket, promotion)
    # Sample only after the old owner and its child are confirmed gone. Its final
    # heartbeat cannot be mistaken for availability of the replacement process.
    sequence = audit.collector(state, marker)["heartbeats"].get("serving", 0)
    if sequence <= 0:
        raise Rejected("kube_serving_configuration_heartbeat_missing")
    replacement = kube_serving_handoff.resume(state, rebound)
    observed = observe(state, expected)
    current = service.validate(state)
    after = snapshot(state)
    deadline = started + 120
    while True:
        inbox = audit.collector(state, marker)
        counter = inbox["heartbeats"].get("serving", 0)
        if counter > sequence:
            break
        if time.monotonic() >= deadline:
            raise Rejected("kube_serving_configuration_heartbeat_deadline")
        time.sleep(0.5)
    elapsed = time.monotonic() - started
    mapping, deployment = service.documents(
        prior["workspace_id"], prior["profile"], prior["config"]
    )
    mapping_key = service.kube_storage.reference(mapping)
    deployment_key = service.kube_storage.reference(deployment)
    if (
        elapsed > 120
        or current["config"] != service.configuration(promotion, prior["profile"])
        or current["config_sha256"] == prior["config_sha256"]
        or current["resources"][mapping_key] == prior["resources"][mapping_key]
        or current["resources"][deployment_key] != prior["resources"][deployment_key]
        or observed["pod_uid"] != replacement["after"]
        or service.pod(state, current)["metadata"]["uid"] != replacement["after"]
        or before["pin"] != marker["pins"]["serving"]
        or before["pin"] != after["pin"]
        or before["permissions"] != after["permissions"]
    ):
        raise Rejected("kube_serving_configuration_binding")
    if expected["ready"]:
        receipts = audit.identity_receipts(before, after, inbox)
    elif before != after:
        raise Rejected("kube_serving_configuration_refusal_state_changed")
    else:
        receipts = 0
    return {
        "replacement": replacement,
        "observation": observed,
        "configuration_before": prior["config_sha256"],
        "configuration_after": current["config_sha256"],
        "configmap_before": prior["resources"][mapping_key],
        "configmap_after": current["resources"][mapping_key],
        "deployment_retained": True,
        "heartbeat_before": sequence,
        "heartbeat_after": counter,
        "elapsed_seconds": round(elapsed, 6),
        "identity_events_delivered": receipts,
        "outbox_retained": True,
        "release_ready": False,
    }
