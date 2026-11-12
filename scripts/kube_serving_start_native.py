"""Prove the real HTTP owner and a fresh signed heartbeat before admission."""

import time

from mlsecops import kube_security_events as audit_state
from mlsecops import kube_serving_service as service
from mlsecops.contracts import Rejected
from mlsecops.datasets import FEATURES
from scripts import kube_security_native as audit
from scripts import kube_serving_service_native as observations
from scripts.kube_trust_native import hosted


def start(state, profile, promotion, *, expected=None):
    hosted()
    started = time.monotonic()
    marker = audit_state.validate(state, profile=profile)
    sequence = audit.collector(state, marker)["heartbeats"].get("serving", 0)
    current = service.bootstrap(state, profile, promotion)
    owner = service.pod(state, current)["metadata"]["uid"]
    expected = expected or {"ready": False, "features": [[0.0] * len(FEATURES)], "scores": [0.0]}
    observed = observations.observe(state, expected)
    snapshot = observations.snapshot(state)
    while True:
        counter = audit.collector(state, marker)["heartbeats"].get("serving", 0)
        elapsed = time.monotonic() - started
        if elapsed >= 120:
            raise Rejected("serving_start_heartbeat_deadline")
        if counter > sequence:
            break
        time.sleep(0.5)
    if (
        observed["pod_uid"] != owner
        or service.pod(state, current)["metadata"]["uid"] != owner
        or snapshot["pin"] != marker["pins"]["serving"]
    ):
        raise Rejected("serving_start_identity_binding")
    elapsed = time.monotonic() - started
    if elapsed > 120:
        raise Rejected("serving_start_heartbeat_deadline")
    return {
        "pod_uid": owner,
        "observation": observed,
        "heartbeat_before": sequence,
        "heartbeat_after": counter,
        "elapsed_seconds": round(elapsed, 6),
        "release_ready": False,
    }


def select(state, profile, promotion, *, expected):
    """Explicit controlled context transition; never adopt an incomplete marker."""
    hosted()
    if service.directory(state).exists():
        current = service.validate(state)
        if current["profile"] != profile:
            raise Rejected("serving_start_profile_changed")
        if current["config"] != service.configuration(promotion, profile):
            return observations.change_configuration(state, promotion, expected)
    return start(state, profile, promotion, expected=expected)
