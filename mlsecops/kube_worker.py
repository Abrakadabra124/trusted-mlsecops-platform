import gzip
import re
import subprocess
import time
import uuid

from mlsecops.cluster import NAME, NODE, kubectl, validate_cluster
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.inventory import command
from mlsecops.sandbox import MAX_PROTOCOL, resolve_image
from mlsecops.signing import encode64


def load_image(state, image):
    validate_cluster(state)
    identifier = resolve_image(image)
    tag = f"trusted-mlsecops:sha-{identifier.removeprefix('sha256:')}"
    command(["docker", "tag", identifier, tag])
    command(["kind", "load", "docker-image", "--name", NAME, tag], timeout=180)
    return tag, identifier


def pod_spec(image, identity, arguments, memory="4Gi"):
    return {
        "serviceAccountName": identity,
        "automountServiceAccountToken": False,
        "enableServiceLinks": False,
        "restartPolicy": "Never",
        "terminationGracePeriodSeconds": 2,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 65532,
            "runAsGroup": 65532,
            "fsGroup": 65532,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [
            {
                "name": "worker",
                "image": image,
                "imagePullPolicy": "Never",
                "command": ["python", "-m", *arguments],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": {
                    "requests": {"cpu": "100m", "memory": "128Mi"},
                    "limits": {"cpu": "2", "memory": memory, "ephemeral-storage": "64Mi"},
                },
                "volumeMounts": [{"name": "scratch", "mountPath": "/tmp"}],
            }
        ],
        "volumes": [{"name": "scratch", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}}],
    }


def job_document(name, namespace, spec, timeout):
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"trusted-mlsecops/job": name},
        },
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": timeout,
            "ttlSecondsAfterFinished": 300,
            "template": {"metadata": {"labels": {"trusted-mlsecops/job": name}}, "spec": spec},
        },
    }


def wait_job(state, namespace, name, timeout):
    started = time.monotonic()
    observed = None
    while time.monotonic() - started <= timeout + 40:
        job = decode(kubectl(state, ["get", "job", name, "-n", namespace, "-o", "json"]).stdout)
        pods = decode(
            kubectl(
                state, ["get", "pods", "-n", namespace, "-l", f"job-name={name}", "-o", "json"]
            ).stdout
        )["items"]
        if len(pods) > 1:
            raise Rejected("unexpected_job_pod_count")
        if pods:
            observed = pods[0]
        conditions = job.get("status", {}).get("conditions", [])
        terminal = next(
            (
                condition
                for condition in conditions
                if condition["type"] in {"Complete", "Failed"} and condition["status"] == "True"
            ),
            None,
        )
        if terminal:
            if not observed or (not pods and terminal.get("reason") != "DeadlineExceeded"):
                raise Rejected("unexpected_job_pod_count")
            terminal["pod_deleted"] = not pods
            return terminal, observed, round(time.monotonic() - started, 6)
        time.sleep(1)
    raise Rejected("kubernetes_job_wait_deadline")


def image_document(identifier):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", identifier):
        raise Rejected("invalid_image_descriptor")
    result = subprocess.run(
        ["docker", "exec", NODE, "ctr", "-n", "k8s.io", "content", "get", identifier],
        capture_output=True,
        timeout=30,
        check=False,
    )
    if result.returncode or digest(result.stdout) != identifier.removeprefix("sha256:"):
        raise Rejected("image_descriptor_digest_mismatch")
    return decode(result.stdout, 1024 * 1024)


def image_config(identifier):
    document = image_document(identifier)
    for depth in range(4):
        if "manifests" not in document:
            break
        matches = [
            entry
            for entry in document["manifests"]
            if entry.get("platform", {}).get("os") == "linux"
            and entry["platform"].get("architecture") == "amd64"
        ]
        if not matches and len(document["manifests"]) == 1:
            entry = document["manifests"][0]
            if "platform" not in entry and entry.get("mediaType") in {
                "application/vnd.oci.image.index.v1+json",
                "application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json",
                "application/vnd.docker.distribution.manifest.v2+json",
            }:
                matches = [entry]
        if len(matches) != 1:
            raise Rejected("ambiguous_image_platform")
        identifier = matches[0]["digest"]
        document = image_document(identifier)
    if "manifests" in document:
        raise Rejected("image_index_depth_exceeded")
    if "rootfs" in document:
        config_id, config = identifier, document
    elif isinstance(document.get("config"), dict) and isinstance(
        document["config"].get("digest"), str
    ):
        config_id = document["config"]["digest"]
        config = image_document(config_id)
    else:
        raise Rejected("invalid_image_descriptor_structure")
    if (
        config.get("os") != "linux"
        or config.get("architecture") != "amd64"
        or not config.get("rootfs", {}).get("diff_ids")
    ):
        raise Rejected("invalid_image_configuration")
    return config_id


def verify_running_image(pod, image_id):
    statuses = pod.get("status", {}).get("containerStatuses", [])
    if len(statuses) != 1:
        raise Rejected("worker_image_not_observed")
    runtime_id = statuses[0].get("imageID", "")
    match = re.search(r"sha256:[0-9a-f]{64}$", runtime_id)
    if not match:
        raise Rejected("invalid_runtime_image_digest")
    if image_config(match.group()) != image_config(image_id):
        raise Rejected("runtime_image_config_mismatch")
    return runtime_id


def run_worker(state, image, request, timeout=600):
    if not isinstance(request, dict) or request.get("action") not in {"train", "predict"}:
        raise Rejected("unknown_worker_action")
    payload = canonical(request)
    if len(payload) > MAX_PROTOCOL or type(timeout) is not int or not 1 <= timeout <= 600:
        raise Rejected("worker_request_limit")
    compressed = gzip.compress(payload, mtime=0)
    if len(compressed) > 700 * 1024:
        raise Rejected("kubernetes_request_configmap_limit")
    tag, image_id = load_image(state, image)
    namespace, identity = (
        ("ml-train", "trainer") if request["action"] == "train" else ("ml-eval", "evaluator")
    )
    name = f"worker-{uuid.uuid4().hex}"
    config = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": namespace},
        "immutable": True,
        "binaryData": {"request.gz": encode64(compressed)},
    }
    memory = "4Gi" if request["action"] == "train" else "1Gi"
    spec = pod_spec(
        tag, identity, ["mlsecops.worker", "--request-file", "/input/request.gz"], memory=memory
    )
    spec["containers"][0]["resources"]["requests"]["memory"] = memory
    spec["volumes"].append({"name": "request", "configMap": {"name": name, "defaultMode": 292}})
    spec["containers"][0]["volumeMounts"].append(
        {"name": "request", "mountPath": "/input", "readOnly": True}
    )
    job = job_document(name, namespace, spec, timeout)
    try:
        kubectl(state, ["create", "-f", "-"], config)
        kubectl(state, ["create", "-f", "-"], job)
        condition, pod, elapsed = wait_job(state, namespace, name, timeout)
        if condition["type"] != "Complete":
            raise Rejected("kubernetes_worker_failed")
        runtime_id = verify_running_image(pod, image_id)
        output = kubectl(
            state,
            ["logs", "-n", namespace, pod["metadata"]["name"], f"--limit-bytes={MAX_PROTOCOL + 1}"],
        ).stdout
        return decode(output, MAX_PROTOCOL), {
            "backend": "kubernetes",
            "image_id": image_id,
            "runtime_image_id": runtime_id,
            "namespace": namespace,
            "job_uid": pod["metadata"]["ownerReferences"][0]["uid"],
            "pod_uid": pod["metadata"]["uid"],
            "input_digest": digest(payload),
            "pod_spec_digest": digest(canonical(pod["spec"])),
            "elapsed_seconds": elapsed,
            "network": "Cilium-deny-all",
            "memory_limit_bytes": (4 if request["action"] == "train" else 1) * 1024**3,
            "cpu_limit": 2,
            "deadline_seconds": timeout,
        }
    finally:
        kubectl(
            state,
            [
                "delete",
                "job",
                name,
                "-n",
                namespace,
                "--ignore-not-found",
                "--wait=true",
                "--timeout=30s",
            ],
            check=False,
        )
        kubectl(
            state, ["delete", "configmap", name, "-n", namespace, "--ignore-not-found"], check=False
        )
