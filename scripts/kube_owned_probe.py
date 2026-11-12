"""Hosted qualification within serialized ownership of a persistent serving identity."""

import time

from mlsecops import kube_security_events as audit_state
from mlsecops import kube_serving_handoff as handoff
from mlsecops import kube_serving_service as service
from mlsecops.contracts import Rejected
from scripts import kube_security_native as audit
from scripts import kube_serving_service_native as observations
from scripts.kube_trust_native import hosted


def run(state, profile, operation, *, after_return=None, restore_failure=None):
    """Return ownership even after a failed probe; successful recovery is not acceptance."""
    hosted()
    marker = audit_state.validate(state, profile=profile)
    before = observations.snapshot(state)
    failure = None
    value = None
    with handoff.transfer(state) as transfer:
        try:
            value = operation()
        except Exception as error:
            failure = error
            if restore_failure is not None:
                restore_failure()
        # A probe's finally block has completed. Resume still independently
        # refuses remaining Jobs/Pods or a changed suspension ticket.
        returned = time.monotonic()
        marker = audit_state.validate(state, profile=profile)
        sequence = audit.collector(state, marker)["heartbeats"].get("serving", 0)
        if sequence <= 0:
            raise Rejected("owned_probe_return_heartbeat_missing")
    observation = after_return() if failure is None and after_return is not None else None
    after = observations.snapshot(state)
    while True:
        inbox = audit.collector(state, marker)
        counter = inbox["heartbeats"].get("serving", 0)
        if counter > sequence:
            break
        if time.monotonic() >= returned + 120:
            raise Rejected("owned_probe_return_heartbeat_deadline")
        time.sleep(0.5)
    elapsed = time.monotonic() - returned
    if (
        elapsed > 120
        or service.pod(state, service.validate(state))["metadata"]["uid"] != transfer["after"]
        or observation is not None
        and observation.get("pod_uid") != transfer["after"]
        or before["pin"] != marker["pins"]["serving"]
        or before["pin"] != after["pin"]
        or before["permissions"] != after["permissions"]
    ):
        raise Rejected("owned_probe_return_binding")
    receipts = 0 if before == after else audit.identity_receipts(before, after, inbox)
    # UID binding and independent receipt reads are part of the return, too.
    elapsed = time.monotonic() - returned
    if elapsed > 120:
        raise Rejected("owned_probe_return_binding")
    if failure is not None:
        raise failure
    return {
        "value": value,
        "ownership": {
            "transfer": transfer,
            "observation": observation,
            "heartbeat_before": sequence,
            "heartbeat_after": counter,
            "return_seconds": round(elapsed, 6),
            "identity_events_delivered": receipts,
            "outbox_retained": True,
            "release_ready": False,
        },
    }


def invoke(state, profile, config, expected, *, restore_failure=None, **options):
    """Keep legacy preparation usable before bootstrap; never ignore an existing marker."""
    from scripts.kube_serving_native import invoke as probe

    hosted()

    def operation():
        return probe(state, profile, config, expected, **options)

    if not service.directory(state).exists():
        return operation()
    result = run(state, profile, operation, restore_failure=restore_failure)
    return {**result["value"], "ownership_return": result["ownership"]}
