import argparse
import copy
import sys
import uuid
from pathlib import Path

from mlsecops import kube_storage
from mlsecops.cluster import kubectl
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.controller_api import TARGETS
from mlsecops.controller_bootstrap import verify_saved
from mlsecops.controller_resources import mount_api
from mlsecops.inventory import source_fingerprint
from mlsecops.kube_storage_resources import WORKSPACE, client_pod_spec
from mlsecops.kube_worker import job_document, verify_running_image, wait_job
from mlsecops.signing import encode64, load_key
from mlsecops.storage_pki import workspace_id


def signer(state):
    content = bounded_read(safe_child(state, "keys/evaluator.pem"), 4096)
    public = encode64(load_key(state / "keys/evaluator.pem").public_key().public_bytes_raw())
    if public != read_json(state / "trusted-keys.json")["evaluator"]:
        raise Rejected("controller_signer_trust_mismatch")
    document = {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "immutable": True,
        "metadata": {
            "name": "evaluator-signer",
            "namespace": "ml-scorer",
            "labels": {WORKSPACE: workspace_id(state)},
        },
        "data": {"key.pem": encode64(content)},
    }
    path = state / "controllers/signer.json"
    observed = kube_storage.get(state, document)
    if path.exists():
        marker = read_json(path)
        kube_storage.verify_resource(document, observed, marker["uid"])
        if marker["sha256"] != digest(content):
            raise Rejected("controller_signer_rotation_requires_migration")
    else:
        if observed is not None:
            raise Rejected("controller_signer_unowned")
        observed = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], document).stdout)
        write_json(path, {"uid": observed["metadata"]["uid"], "sha256": digest(content)})
        kube_storage.verify_resource(document, observed, observed["metadata"]["uid"])


def controller_spec(profile, role, name, arguments):
    if role not in TARGETS:
        raise Rejected("controller_role_invalid")
    spec = mount_api(client_pod_spec(profile["image"], role, arguments))
    spec["containers"][0]["resources"]["requests"]["memory"] = "512Mi"
    spec["containers"][0]["resources"]["limits"]["memory"] = "512Mi"
    spec["volumes"].append({"name": "request", "configMap": {"name": name, "defaultMode": 292}})
    spec["containers"][0]["volumeMounts"].append(
        {
            "name": "request",
            "mountPath": "/request.json",
            "subPath": "request.json",
            "readOnly": True,
        }
    )
    if role == "scorer":
        spec["volumes"].extend(
            [
                {
                    "name": "signer-source",
                    "secret": {"secretName": "evaluator-signer", "defaultMode": 416},
                },
                {"name": "signer", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}},
            ]
        )
        initializer = copy.deepcopy(spec["initContainers"][0])
        initializer.update(
            name="signer-files",
            command=[
                "sh",
                "-eu",
                "-c",
                "umask 077; cp /source/key.pem /signer/key.pem; chmod 600 /signer/key.pem",
            ],
            volumeMounts=[
                {"name": "signer-source", "mountPath": "/source", "readOnly": True},
                {"name": "signer", "mountPath": "/signer"},
            ],
        )
        spec["initContainers"].append(initializer)
        spec["containers"][0]["volumeMounts"].append(
            {"name": "signer", "mountPath": "/signer", "readOnly": True}
        )
    return spec


def invoke(root, state, request):
    marker = verify_saved(state, read_json(state / "controllers/resources.json"))
    if not marker.get("ready") or marker["profile"]["source_fingerprint"] != source_fingerprint(
        root
    ):
        raise Rejected("controller_profile_not_ready_or_stale")
    role = request["role"]
    if role not in TARGETS:
        raise Rejected("controller_role_invalid")
    profile = marker["profile"]
    request = {**request, "profile": profile, "schema_version": 1}
    name = f"controller-run-{uuid.uuid4().hex}"
    namespace = f"ml-{role}"
    config = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": namespace},
        "immutable": True,
        "data": {"request.json": canonical(request).decode()},
    }
    spec = controller_spec(
        profile, role, name, ["mlsecops.controller", "--request", "/request.json"]
    )
    if role == "scorer":
        signer(state)
    document = job_document(name, namespace, spec, 720)
    created_config = created_job = False
    try:
        kubectl(state, ["create", "-f", "-"], config)
        created_config = True
        kubectl(state, ["create", "-f", "-"], document)
        created_job = True
        terminal, pod, elapsed = wait_job(state, namespace, name, 720)
        verify_running_image(pod, profile["image_id"])
        if terminal["type"] != "Complete":
            output = kubectl(
                state,
                [
                    "logs",
                    pod["metadata"]["name"],
                    "-c",
                    "worker",
                    "-n",
                    namespace,
                    "--limit-bytes=16385",
                ],
                check=False,
            ).stdout
            write_json(
                state / "evidence/controller-failure.json",
                {
                    "role": role,
                    "pod": pod["metadata"]["name"],
                    "diagnostic_sha256": digest(output),
                    "bytes": len(output),
                },
            )
            atomic_write(state / "evidence/controller-diagnostic.log", output)
            raise Rejected(f"controller_job_failed:{role}")
        content = kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-c",
                "worker",
                "-n",
                namespace,
                "--limit-bytes=1048577",
            ],
        ).stdout
        return {
            **decode(content, 1024 * 1024),
            "controller": {
                "job_uid": pod["metadata"]["ownerReferences"][0]["uid"],
                "pod_uid": pod["metadata"]["uid"],
                "image_id": profile["image_id"],
                "elapsed_seconds": elapsed,
            },
        }
    finally:
        if created_job:
            kubectl(state, ["delete", "job", name, "-n", namespace, "--wait=true", "--timeout=30s"])
        if created_config:
            kubectl(state, ["delete", "configmap", name, "-n", namespace])


def demo(root, state):
    state = Path(state).resolve()
    kube_storage.validate(state)
    inputs = read_json(state / "kubernetes-storage/migration-inputs.json")
    published = invoke(
        root,
        state,
        {
            "role": "publisher",
            "trust": inputs["trust"],
            "dataset_reference": inputs["dataset_reference"],
            "candidate_reference": None,
        },
    )
    evaluated = invoke(
        root,
        state,
        {
            "role": "scorer",
            "trust": inputs["trust"],
            "dataset_reference": None,
            "candidate_reference": published["result"]["candidate_reference"],
        },
    )
    result = {
        "schema_version": 1,
        "status": "scoped-controller-preview-not-full-R1",
        "observed_at": now(),
        "publisher": published,
        "scorer": evaluated,
        "release_ready": False,
    }
    write_json(state / "evidence/controller-demo.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Sequential publisher and scorer Jobs using private SQL and scoped API identities"
    )
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    arguments = parser.parse_args()
    try:
        result = demo(Path(__file__).resolve().parents[1], arguments.state)
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        print(f"Controller demo rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
