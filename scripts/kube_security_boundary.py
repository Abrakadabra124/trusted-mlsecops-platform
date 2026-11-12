"""Scoped promoter Job for the explicitly controlled audit-boundary fixture."""

import uuid
from pathlib import Path

from mlsecops import kube_promotion, kube_security_resources, kube_storage
from mlsecops import kube_security_events as audit_state
from mlsecops.cluster import kubectl
from mlsecops.contracts import Rejected, canonical, decode, safe_child
from mlsecops.kube_storage_resources import client_pod_spec
from mlsecops.kube_worker import job_document, verify_running_image, wait_job
from scripts.kube_privacy_bundle import manifest
from scripts.kube_privacy_diagnostic import validated
from scripts.kube_trust_native import hosted

NAMESPACE = "ml-promoter"


def failure_diagnostic(content):
    if len(content) > 65536:
        return None
    for line in content.splitlines():
        try:
            value = decode(line, 65536)
        except Rejected:
            continue
        if (
            type(value) is dict
            and set(value) == {"status", "release_ready", "code", "location"}
            and value["status"] == "fail"
            and value["release_ready"] is False
            and value["code"] == "security_audit_boundary_probe_rejected"
            and validated(value["location"]) is not None
        ):
            return value
    return None


def materials(root, profile, workspace, name):
    bundle = manifest(root, name + "-code", workspace, entry="security_audit_boundary_probe")
    bundle["metadata"]["namespace"] = NAMESPACE
    spec = kube_security_resources.promoter_spec(client_pod_spec(profile["image"], "promoter", []))
    spec["containers"][0]["command"] = ["python", "-m", "scripts.security_audit_boundary_probe"]
    spec["volumes"].append(
        {
            "name": "qualification-code",
            "configMap": {
                "name": bundle["metadata"]["name"],
                "defaultMode": 292,
                "items": [
                    {"key": filename, "path": "source/" + filename}
                    for filename in sorted(bundle["data"])
                ],
            },
        }
    )
    spec["containers"][0]["volumeMounts"].append(
        {
            "name": "qualification-code",
            "mountPath": "/app/scripts",
            # Bind regular entries below AtomicWriter's symlink layer so fixture
            # __file__.resolve() still locates the image's /app policy and lock.
            "subPath": "source",
            "readOnly": True,
        }
    )
    return bundle, spec


def invoke(state, profile):
    hosted()
    marker = audit_state.validate(state, profile=profile)
    name = "audit-boundary-" + uuid.uuid4().hex
    bundle, spec = materials(
        Path(__file__).resolve().parents[1], profile, marker["workspace_id"], name
    )
    job = job_document(name, NAMESPACE, spec, 90)
    job["metadata"]["labels"][kube_security_resources.WORKSPACE] = marker["workspace_id"]
    created = []
    try:
        for document in (bundle, job):
            observed = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], document).stdout)
            created.append((document, observed["metadata"]["uid"]))
            kube_storage.verify_resource(document, observed, created[-1][1])
        terminal, pod, _ = wait_job(state, NAMESPACE, name, 90)
        audit_state.pod_spec(spec, pod["spec"])
        verify_running_image(pod, profile["image_id"])
        statuses = pod.get("status", {}).get("containerStatuses", [])
        exit_code = (
            statuses[0].get("state", {}).get("terminated", {}).get("exitCode")
            if len(statuses) == 1
            else None
        )
        if pod["metadata"]["ownerReferences"][0]["uid"] != created[-1][1]:
            raise Rejected("audit_boundary_job_replaced")
        content = kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-n",
                NAMESPACE,
                "-c",
                "worker",
                "--limit-bytes=65537",
            ],
        ).stdout
        if terminal["type"] != "Complete" or type(exit_code) is not int or exit_code != 0:
            safe_child(state, "evidence/" + name + "-private.log").write_bytes(content)
            diagnostic = failure_diagnostic(content)
            if diagnostic is not None:
                print(
                    canonical({"stage": "audit-boundary-failed", "probe": diagnostic}).decode(),
                    flush=True,
                )
            raise Rejected("audit_boundary_job_failed")
        report = decode(content, 65536)
        if (
            report.get("status") != "pass"
            or report.get("release_ready") is not False
            or report.get("scope") != "controlled-authorization-and-trust-real-sql-audit-boundary"
        ):
            raise Rejected("audit_boundary_job_report")
        return report
    finally:
        kube_promotion.cleanup(state, created, namespace=NAMESPACE)
