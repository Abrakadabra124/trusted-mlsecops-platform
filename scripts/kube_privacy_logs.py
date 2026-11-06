"""Private operator observation; grants no log-reading rights to serving Pods.

The caller supplies a Pod already bound to its owned Job/StatefulSet and the
verified image contract. This reader rechecks that exact identity before and
after the bounded log request. Terminal worker logs also require an exact
complete stream observed by the protocol peer; a tail or missing prefix fails.
Service snapshots are explicitly windows, not complete process lifecycles.
"""

import re

from mlsecops.cluster import kubectl, validate_cluster
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.controller_api import identifier
from scripts.kube_trust_native import hosted

MAX_BYTES = 1024 * 1024
NAMESPACES = {"ml-serve", "ml-serving", "ml-storage", "ml-trust"}


def pin(pod, owner_uid, container, terminal):
    try:
        meta, spec, status = pod["metadata"], pod["spec"], pod["status"]
        name = identifier(meta["name"])
        rows = status["containerStatuses"]
        if (
            meta["namespace"] not in NAMESPACES
            or type(meta["uid"]) is not str
            or not 1 <= len(meta["uid"]) <= 128
            or type(owner_uid) is not str
            or not 1 <= len(owner_uid) <= 128
            or len(meta["ownerReferences"]) != 1
            or meta["ownerReferences"][0]["uid"] != owner_uid
            or meta["ownerReferences"][0]["controller"] is not True
            or len(spec["containers"]) != 1
            or spec["containers"][0]["name"] != container
            or container not in {"worker", "postgres"}
            or len(rows) != 1
            or rows[0]["name"] != container
            or type(rows[0]["restartCount"]) is not int
            or rows[0]["restartCount"] != 0
            or re.fullmatch(r"containerd://[a-f0-9]{64}", rows[0]["containerID"]) is None
            or re.search(r"sha256:[a-f0-9]{64}$", rows[0]["imageID"]) is None
            or status["phase"] != ("Succeeded" if terminal else "Running")
            or set(rows[0]["state"]) != ({"terminated"} if terminal else {"running"})
            or terminal
            and (
                type(rows[0]["state"]["terminated"]["exitCode"]) is not int
                or rows[0]["state"]["terminated"]["exitCode"] != 0
            )
        ):
            raise Rejected("privacy_log_identity")
        return {
            "namespace": meta["namespace"],
            "pod": name,
            "pod_uid": meta["uid"],
            "owner_uid": owner_uid,
            "container": container,
            "container_id": rows[0]["containerID"],
            "runtime_image": rows[0]["imageID"],
            "spec_sha256": digest(canonical(spec)),
        }
    except (KeyError, TypeError, IndexError, AttributeError, ValueError):
        raise Rejected("privacy_log_identity") from None


def capture(state, pod, *, owner_uid, container, needles, expected_output=None, terminal=False):
    hosted()
    if (
        type(terminal) is not bool
        or type(needles) is not tuple
        or not 1 <= len(needles) <= 16
        or any(type(value) is not bytes or not 1 <= len(value) <= 4096 for value in needles)
        or expected_output is not None
        and (type(expected_output) is not bytes or not 1 <= len(expected_output) <= MAX_BYTES)
        or terminal
        and expected_output is None
    ):
        raise Rejected("privacy_log_request")
    expected = pin(pod, owner_uid, container, terminal)
    validate_cluster(state)
    arguments = ["pod", expected["pod"], "-n", expected["namespace"]]

    def current():
        value = decode(kubectl(state, ["get", *arguments, "-o", "json"]).stdout)
        if pin(value, owner_uid, container, terminal) != expected:
            raise Rejected("privacy_log_identity_changed")

    current()
    content = kubectl(
        state,
        [
            "logs",
            expected["pod"],
            "-n",
            expected["namespace"],
            "-c",
            container,
            "--limit-bytes=" + str(MAX_BYTES + 1),
        ],
    ).stdout
    current()
    if type(content) is not bytes or len(content) > MAX_BYTES:
        raise Rejected("privacy_log_limit")
    if any(value in content for value in needles):
        raise Rejected("privacy_log_canary")
    if expected_output is not None and content != expected_output:
        raise Rejected("privacy_log_incomplete_stream")
    return {
        "schema_version": 1,
        "scope": "private-owned-pod-log-window-not-M13",
        "status": "pass",
        "release_ready": False,
        **expected,
        "terminal": terminal,
        "exact_output": expected_output is not None,
        "bytes": len(content),
        "sha256": digest(content),
    }, content
