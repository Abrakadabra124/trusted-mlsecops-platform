import uuid

from mlsecops.cluster import kubectl
from mlsecops.contracts import Rejected, canonical, decode
from mlsecops.kube_storage_resources import CLIENT_NAMESPACES, client_pod_spec
from mlsecops.kube_worker import job_document, verify_running_image, wait_job


def read(state, image, image_id, request):
    if request.get("role") not in {"publisher", "scorer"} or len(canonical(request)) > 16384:
        raise Rejected("migration_reader_request_invalid")
    role = request["role"]
    namespace = CLIENT_NAMESPACES[role]
    name = f"migration-read-{uuid.uuid4().hex}"
    config = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": namespace},
        "immutable": True,
        "data": {"request.json": canonical(request).decode()},
    }
    spec = client_pod_spec(
        image, role, ["mlsecops.kube_artifact_probe", "--request", "/request.json"]
    )
    spec["volumes"].append({"name": "request", "configMap": {"name": name, "defaultMode": 292}})
    spec["containers"][0]["volumeMounts"].append(
        {
            "name": "request",
            "mountPath": "/request.json",
            "subPath": "request.json",
            "readOnly": True,
        }
    )
    job = job_document(name, namespace, spec, 120)
    config_created = job_created = False
    try:
        kubectl(state, ["create", "-f", "-"], config)
        config_created = True
        kubectl(state, ["create", "-f", "-"], job)
        job_created = True
        terminal, pod, _ = wait_job(state, namespace, name, 120)
        verify_running_image(pod, image_id)
        if terminal["type"] != "Complete":
            raise Rejected(f"migration_artifact_reader_failed:{role}")
        content = kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-c",
                "worker",
                "-n",
                namespace,
                "--limit-bytes=16777217",
            ],
        ).stdout
        return decode(content)
    finally:
        if job_created:
            kubectl(state, ["delete", "job", name, "-n", namespace, "--wait=true", "--timeout=30s"])
        if config_created:
            kubectl(state, ["delete", "configmap", name, "-n", namespace])
