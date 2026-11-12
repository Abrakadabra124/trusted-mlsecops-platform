"""Serialize an owned observer transition after a committed dual-signed root rotation."""

import copy
import sys
import time

from mlsecops import kube_observer_profile as profiles
from mlsecops import kube_observer_readback as io
from mlsecops import kube_security_events as audit
from mlsecops import kube_storage as storage
from mlsecops.cluster import kubectl
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest
from mlsecops.private_cli import Arguments


def replace(state, marker, before, after):
    key = storage.reference(before)
    if storage.reference(after) != key:
        raise Rejected("kube_observer_deployment_changed")
    uid = marker["resources"][key]
    observed = storage.get(state, before)
    storage.verify_resource(before, observed, uid)
    version = observed["metadata"].get("resourceVersion")
    if type(version) is not str or not version:
        raise Rejected("kube_observer_resource_version")
    updated = copy.deepcopy(after)
    updated["metadata"].update(uid=uid, resourceVersion=version)
    result = decode(kubectl(state, ["replace", "-f", "-", "-o", "json"], updated).stdout)
    storage.verify_resource(after, result, uid)


def wait_empty(state, document):
    deadline = time.monotonic() + 45
    namespace = document["metadata"]["namespace"]
    selector = ",".join(
        f"{key}={value}" for key, value in document["spec"]["selector"]["matchLabels"].items()
    )
    while True:
        items = decode(
            kubectl(state, ["get", "pods", "-n", namespace, "-l", selector, "-o", "json"]).stdout
        )["items"]
        if not items:
            return
        if time.monotonic() >= deadline:
            raise Rejected("kube_observer_stop_deadline")
        time.sleep(0.5)


def remove(state, local, marker, document):
    key = storage.reference(document)
    uid = marker["resources"][key]
    storage.verify_resource(document, storage.get(state, document), uid)
    metadata = document["metadata"]
    endpoint = f"/api/v1/namespaces/{metadata['namespace']}/configmaps/{metadata['name']}"
    kubectl(
        state,
        ["delete", "--raw", endpoint, "-f", "-"],
        {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "preconditions": {"uid": uid},
        },
    )
    if storage.get(state, document) is not None:
        raise Rejected("kube_observer_config_cleanup_unconfirmed")
    del marker["resources"][key]
    audit.save(local, marker)


def retained(before, after, pin):
    if (
        before["pin"] != pin
        or after["pin"] != pin
        or any(before[key] != after[key] for key in ("producer_id", "count", "prefix_sha256"))
        or after["heartbeat"] <= before["heartbeat"]
    ):
        raise Rejected("kube_observer_state_changed")


def wait_observed(state, marker, before, previous, *, pin, started):
    deadline = started + 120
    while True:
        try:
            identity = io.success(state, marker, pin)
            if identity[0] == previous:
                raise Rejected("kube_observer_not_replaced")
            after = io.outbox(state, marker, count=before["count"])
            receipt = io.collector(state, marker)
            retained(before, after, marker["pins"]["trust"])
            if (
                receipt["pin"] != marker["pins"]["collector"]
                or receipt["heartbeat"] < after["heartbeat"]
            ):
                raise Rejected("kube_observer_delivery_unconfirmed")
            if io.instance(io.pod(state, marker, "trust")) != identity:
                raise Rejected("kube_observer_container_changed")
            elapsed = time.monotonic() - started
            if elapsed <= 120:
                return dict(
                    before=previous,
                    after=identity[0],
                    elapsed_seconds=round(elapsed, 6),
                    heartbeat_before=before["heartbeat"],
                    heartbeat_after=receipt["heartbeat"],
                    outbox_retained=True,
                    first_source_check_confirmed=True,
                )
        except Rejected:
            pass
        if time.monotonic() >= deadline:
            raise Rejected("kube_observer_transition_deadline")
        time.sleep(0.5)


def update(state, package, *, next_root):
    marker = audit.validate(state)
    current = marker.get("observer")
    candidate = profiles.advance(
        current, marker["context"], io.history(state, marker), package, next_root=next_root
    )
    if candidate == current:
        return dict(reused=True, release_ready=False)
    before = io.outbox(state, marker)
    if before["pin"] != marker["pins"]["trust"]:
        raise Rejected("kube_observer_outbox_pin")
    previous = io.pod(state, marker, "trust")["metadata"]["uid"]
    old = audit.runtime(marker, "trust")
    old_config = (
        None
        if current is None
        else profiles.mapping(marker["workspace_id"], current, marker["context"])
    )
    mapping = profiles.mapping(marker["workspace_id"], candidate, marker["context"])
    local = audit.directory(state)
    marker = copy.deepcopy(marker)
    marker.update(ready=False, observer=candidate)
    audit.save(local, marker)
    started = time.monotonic()
    try:
        audit.create(state, local, marker, mapping)
        desired = audit.runtime(marker, "trust")
        stopped = copy.deepcopy(desired)
        stopped["spec"]["replicas"] = 0
        replace(state, marker, old, stopped)
        wait_empty(state, stopped)
        replace(state, marker, stopped, desired)
        proof = wait_observed(
            state,
            marker,
            before,
            previous,
            pin=digest(mapping["data"]["observer.json"].encode()),
            started=started,
        )
        if old_config is not None:
            remove(state, local, marker, old_config)
        marker["ready"] = True
        audit.save(local, marker)
        audit.validate(state, authority_root=next_root)
    except BaseException:
        marker["ready"] = False
        audit.save(local, marker)
        raise
    return dict(**proof, reused=False, release_ready=False)


def main(arguments=None):
    parser = Arguments()
    parser.add_argument("--state", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--next-root", required=True)
    try:
        options = parser.parse_args(arguments)
        package = decode(bounded_read(options.package, 65536), 65536)
        print(canonical(update(options.state, package, next_root=options.next_root)).decode())
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print("kube_observer_transition_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
