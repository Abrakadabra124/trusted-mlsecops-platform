"""Explicit, serialized transfer between real serving HTTP owners in an owned lab."""

import secrets
import time
from contextlib import contextmanager

from mlsecops import kube_observer_readback
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


def verified_observer(state, *, marker=None):
    if marker is None:
        marker = service.kube_security_events.validate(state)
    return kube_observer_readback.pod(state, marker, "trust")


def remaining_pods(items, namespace, observer):
    if type(items) is not list:
        raise Rejected("kube_serving_handoff_pod_inventory")
    if namespace != service.NAMESPACE:
        return items
    known = [
        item for item in items if item.get("metadata", {}).get("uid") == observer["metadata"]["uid"]
    ]
    if len(known) > 1 or any(
        item.get("spec") != observer["spec"]
        or kube_observer_readback.instance(item) != kube_observer_readback.instance(observer)
        for item in known
    ):
        raise Rejected("kube_serving_handoff_observer_changed")
    return [item for item in items if item not in known]


def confirm_observer(state, before, *, marker=None):
    if kube_observer_readback.instance(
        verified_observer(state, marker=marker)
    ) != kube_observer_readback.instance(before):
        raise Rejected("kube_serving_handoff_observer_changed")


def wait_pods_absent(state):
    # Job deletion can finish before its Pods. The independently verified trust
    # observer shares ml-serving but owns a DIFFERENT identity and outbox.
    marker = service.kube_security_events.validate(state)
    observer = verified_observer(state, marker=marker)
    deadline = time.monotonic() + 45
    while True:
        inventories = [
            remaining_pods(
                decode(kubectl(state, ["get", "pods", "-n", namespace, "-o", "json"]).stdout).get(
                    "items"
                ),
                namespace,
                observer,
            )
            for namespace in (service.NAMESPACE, "ml-serve")
        ]
        if not any(inventories):
            confirm_observer(state, observer, marker=marker)
            return
        if time.monotonic() >= deadline:
            raise Rejected("kube_serving_handoff_pods_present")
        time.sleep(0.5)


def require_probe_slot(state, *, marker=None):
    """A native probe cannot overlap an existing HTTP owner or inference worker."""
    # A caller may reuse its just-validated audit inventory for this single
    # preflight. Never reuse it across a Job or a root/configuration transition.
    if marker is None:
        marker = service.kube_security_events.validate(state)
    observer = verified_observer(state, marker=marker)
    for namespace in (service.NAMESPACE, "ml-serve"):
        for kind in ("pods", "jobs"):
            items = decode(kubectl(state, ["get", kind, "-n", namespace, "-o", "json"]).stdout).get(
                "items"
            )
            if kind == "pods":
                items = remaining_pods(items, namespace, observer)
            if type(items) is not list or items:
                raise Rejected("kube_serving_handoff_probe_owner_present")
    confirm_observer(state, observer, marker=marker)


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
    wait_pods_absent(state)
    verified = service.validate(state, suspended=marker["handoff"])
    return {
        "nonce": marker["handoff"],
        "marker_sha256": digest(canonical(verified)),
        "previous": before,
    }


def ticket_marker(state, ticket):
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
    if digest(canonical(marker)) != reference or "configuration_change" in marker:
        raise Rejected("kube_serving_handoff_marker_changed")
    return marker


def resume(state, ticket):
    marker = ticket_marker(state, ticket)
    service.wait_empty(state)
    jobs_empty(state)
    wait_pods_absent(state)
    service.set_replicas(state, marker, 0, 1)
    after = service.wait_live(state, marker, previous=ticket["previous"])
    marker["ready"] = True
    del marker["handoff"]
    service.kube_security_events.save(service.directory(state), marker)
    service.validate(state)
    return {"before": ticket["previous"], "after": after, "release_ready": False}


def reconfigure(state, ticket, promotion):
    """Replace only the owned immutable config while HTTP remains suspended."""
    marker = ticket_marker(state, ticket)
    config = service.configuration(promotion, marker["profile"])
    previous = marker["config"]
    environment = previous["context"]["policy"]["environment"]
    if config["context"]["policy"]["environment"] != environment or any(
        config[key] != previous[key] for key in ("storage_client", "trust_client")
    ):
        raise Rejected("kube_serving_handoff_configuration_scope")
    audit = service.kube_security_events.validate(
        state,
        profile=marker["profile"],
        environment=environment,
        authority_root=config["trust_root"],
    )
    if audit["pins"]["serving"] != marker["audit_pin"] or config[
        "trust_root"
    ] != service.kube_security_events.kube_observer_profile.current_root(
        audit.get("observer"), audit["context"]
    ):
        raise Rejected("kube_serving_handoff_configuration_identity")
    if config == previous:
        return dict(ticket)
    old_mapping, old_deployment = service.documents(
        marker["workspace_id"], marker["profile"], previous
    )
    mapping, deployment = service.documents(marker["workspace_id"], marker["profile"], config)
    if deployment != old_deployment:
        raise Rejected("kube_serving_handoff_configuration_scope")
    service.wait_empty(state)
    jobs_empty(state)
    wait_pods_absent(state)
    key = service.kube_storage.reference(old_mapping)
    uid = marker["resources"][key]
    observed = service.kube_storage.get(state, old_mapping)
    service.kube_storage.verify_resource(old_mapping, observed, uid)
    version = observed["metadata"].get("resourceVersion")
    if type(version) is not str or not version:
        raise Rejected("kube_serving_handoff_configuration_version")
    local = service.directory(state)
    marker["configuration_change"] = {
        "from": marker["config_sha256"],
        "to": digest(canonical(config)),
    }
    service.kube_security_events.save(local, marker)
    endpoint = f"/api/v1/namespaces/{service.NAMESPACE}/configmaps/{service.NAME}"
    kubectl(
        state,
        ["delete", "--raw=" + endpoint, "-f", "-"],
        {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "preconditions": {"uid": uid, "resourceVersion": version},
            "propagationPolicy": "Foreground",
        },
    )
    deadline = time.monotonic() + 45
    while (observed := service.kube_storage.get(state, old_mapping)) is not None:
        service.kube_storage.verify_resource(old_mapping, observed, uid)
        if time.monotonic() >= deadline:
            raise Rejected("kube_serving_handoff_configuration_cleanup")
        time.sleep(0.5)
    # A crash from here onward leaves suspended, non-resumable state until the
    # operator proves the replacement. Never adopt another creator's ConfigMap.
    del marker["resources"][key]
    marker.update(config=config, config_sha256=digest(canonical(config)))
    service.kube_security_events.save(local, marker)
    service.kube_security_events.create(state, local, marker, mapping)
    verified = service.validate(state, suspended=ticket["nonce"])
    if verified != marker:
        raise Rejected("kube_serving_handoff_configuration_readback")
    del verified["configuration_change"]
    service.kube_security_events.save(local, verified)
    return {**ticket, "marker_sha256": digest(canonical(verified))}


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
