"""Explicit, serialized transfer between real serving HTTP owners in an owned lab."""

import secrets
from contextlib import contextmanager

from mlsecops import kube_serving_service as service
from mlsecops.cluster import kubectl
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.storage import object_id


def jobs_empty(state):
    # Unknown jobs are blockers, never adopted or deleted by a transfer.
    items = decode(
        kubectl(state, ["get", "jobs", "-n", service.NAMESPACE, "-o", "json"]).stdout
    ).get("items")
    if type(items) is not list or items:
        raise Rejected("kube_serving_handoff_jobs_present")


def suspend(state):
    marker = service.validate(state)
    jobs_empty(state)
    before = service.pod(state, marker)["metadata"]["uid"]
    marker.update(ready=False, handoff=secrets.token_hex(16))
    service.kube_security_events.save(service.directory(state), marker)
    # Any interrupted transition stays unready. No second process starts until
    # disappearance of the old HTTP owner and its inference worker is verified.
    service.set_replicas(state, marker, 1, 0)
    service.wait_empty(state)
    jobs_empty(state)
    verified = service.validate(state, suspended=marker["handoff"])
    return {
        "nonce": marker["handoff"],
        "marker_sha256": digest(canonical(verified)),
        "previous": before,
    }


def resume(state, ticket):
    require_fields(ticket, ("nonce", "marker_sha256", "previous"))
    reference = object_id(ticket["marker_sha256"])
    if (
        type(ticket["nonce"]) is not str
        or len(ticket["nonce"]) != 32
        or any(character not in "0123456789abcdef" for character in ticket["nonce"])
        or type(ticket["previous"]) is not str
        or not ticket["previous"]
    ):
        raise Rejected("kube_serving_handoff_ticket")
    marker = service.validate(state, suspended=ticket["nonce"])
    if digest(canonical(marker)) != reference:
        raise Rejected("kube_serving_handoff_marker_changed")
    service.wait_empty(state)
    jobs_empty(state)
    service.set_replicas(state, marker, 0, 1)
    after = service.wait_live(state, marker, previous=ticket["previous"])
    marker["ready"] = True
    del marker["handoff"]
    service.kube_security_events.save(service.directory(state), marker)
    service.validate(state)
    return {"before": ticket["previous"], "after": after, "release_ready": False}


@contextmanager
def transfer(state):
    ticket = suspend(state)
    report = {"before": ticket["previous"]}
    try:
        yield report
    finally:
        # A failed qualification remains failed even when ownership is safely
        # returned. Cleanup or state uncertainty prevents starting another owner.
        report.update(resume(state, ticket))
