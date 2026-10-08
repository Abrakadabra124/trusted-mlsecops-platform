import gzip
import re
import time
import uuid

from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.controller_api import MAX_LOG, TARGETS, APIError, Client
from mlsecops.kube_worker import job_document, pod_spec
from mlsecops.signing import encode64
from mlsecops.worker_transport import unwrap


def validate_profile(profile):
    require_fields(
        profile,
        ("image", "image_id", "config_id", "manifest_id", "source_fingerprint", "source_revision"),
    )
    for name in ("image_id", "config_id", "manifest_id"):
        if not isinstance(profile[name], str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", profile[name]
        ):
            raise Rejected("controller_image_profile_invalid")
    if not isinstance(profile["image"], str) or not re.fullmatch(
        r"[a-z0-9./_-]+@" + profile["manifest_id"], profile["image"]
    ):
        raise Rejected("controller_image_profile_invalid")
    for name, length in (("source_fingerprint", 64), ("source_revision", 40)):
        if not isinstance(profile[name], str) or not re.fullmatch(
            f"[0-9a-f]{{{length}}}", profile[name]
        ):
            raise Rejected("controller_image_profile_invalid")


def documents(profile, role, request, timeout=600):
    validate_profile(profile)
    if (
        role not in TARGETS
        or not isinstance(request, dict)
        or request.get("action") != {"publisher": "train", "scorer": "predict"}[role]
    ):
        raise Rejected("controller_worker_action_mismatch")
    if type(timeout) is not int or not 1 <= timeout <= 600:
        raise Rejected("controller_worker_deadline_invalid")
    content = canonical(request)
    if len(content) > MAX_LOG:
        raise Rejected("controller_worker_request_limit")
    compressed = gzip.compress(content, mtime=0)
    if len(compressed) > 700 * 1024:
        raise Rejected("controller_worker_compressed_limit")
    namespace, identity = TARGETS[role]
    name = f"controller-worker-{uuid.uuid4().hex}"
    config = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": namespace},
        "immutable": True,
        "binaryData": {"request.gz": encode64(compressed)},
    }
    memory = "4Gi" if role == "publisher" else "1Gi"
    spec = pod_spec(
        profile["image"],
        identity,
        ["mlsecops.worker_transport", "--request-file", "/input/request.gz"],
        memory=memory,
    )
    spec["containers"][0]["resources"]["requests"]["memory"] = memory
    spec["volumes"].append({"name": "request", "configMap": {"name": name, "defaultMode": 292}})
    spec["containers"][0]["volumeMounts"].append(
        {"name": "request", "mountPath": "/input", "readOnly": True}
    )
    job = job_document(name, namespace, spec, timeout)
    job["spec"].update(parallelism=1, completions=1)
    return config, job


def remove(client, resource, name, uid):
    options = {
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {"uid": uid},
        "propagationPolicy": "Foreground",
    }
    try:
        client.request(resource, name, method="DELETE", value=options)
    except APIError as error:
        if error.status != 404:
            raise


def run(profile, role, request, timeout=600):
    config, document = documents(profile, role, request, timeout)
    client = Client(role)
    name = document["metadata"]["name"]
    created = []
    started = time.monotonic()
    try:
        for resource, value in (("configmaps", config), ("jobs", document)):
            observed = client.request(resource, method="POST", value=value)
            created.append((resource, observed["metadata"]["uid"]))
        job_uid = created[1][1]
        while time.monotonic() - started <= timeout + 40:
            job = client.request("jobs", name)
            if job["metadata"]["uid"] != job_uid:
                raise Rejected("controller_worker_job_identity_changed")
            terminal = next(
                (
                    item
                    for item in job.get("status", {}).get("conditions", [])
                    if item.get("status") == "True" and item.get("type") in {"Complete", "Failed"}
                ),
                None,
            )
            if terminal:
                if terminal["type"] != "Complete":
                    raise Rejected("controller_worker_failed")
                break
            time.sleep(1)
        else:
            raise Rejected("controller_worker_wait_deadline")
        pods = client.request("pods", job=name)["items"]
        if len(pods) != 1:
            raise Rejected("controller_worker_pod_count")
        pod = pods[0]
        if not any(
            owner.get("uid") == job_uid and owner.get("controller") is True
            for owner in pod["metadata"].get("ownerReferences", [])
        ):
            raise Rejected("controller_worker_pod_owner")
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if (
            len(statuses) != 1
            or statuses[0].get("state", {}).get("terminated", {}).get("exitCode") != 0
        ):
            raise Rejected("controller_worker_exit_invalid")
        observed_image = statuses[0].get("imageID", "")
        actual = re.search(r"sha256:[0-9a-f]{64}$", observed_image)
        if actual is None or actual.group() not in {profile["manifest_id"], profile["config_id"]}:
            raise Rejected("controller_worker_image_mismatch")
        output = client.request("logs", pod["metadata"]["name"])
        result, diagnostics = unwrap(decode(output, MAX_LOG))
        return result, {
            "backend": "scoped-kubernetes-controller",
            "image_id": profile["image_id"],
            "runtime_image_id": observed_image,
            "worker_diagnostics": diagnostics,
            "namespace": client.namespace,
            "job_uid": job_uid,
            "pod_uid": pod["metadata"]["uid"],
            "input_digest": digest(canonical(request)),
            "pod_spec_digest": digest(canonical(pod["spec"])),
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "network": "Cilium-deny-all",
            "memory_limit_bytes": (4 if role == "publisher" else 1) * 1024**3,
            "cpu_limit": 2,
            "deadline_seconds": timeout,
        }
    finally:
        for resource, uid in reversed(created):
            remove(client, resource, name, uid)
