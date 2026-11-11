"""Owned loopback serving Deployment. Replacement preserves the audit PVC and identity."""

import copy
import time
from pathlib import Path

from mlsecops import kube_promotion, kube_security_events, kube_security_resources, kube_storage
from mlsecops.cluster import kubectl
from mlsecops.contracts import (
    Rejected,
    canonical,
    decode,
    digest,
    read_json,
    safe_child,
)
from mlsecops.controller_resources import mount_api
from mlsecops.controller_worker import validate_profile
from mlsecops.kube_storage_resources import WORKSPACE, resource
from mlsecops.storage_pki import workspace_id

NAMESPACE = "ml-serving"
NAME = "release-risk-advisor"
PROBE = (
    "import http.client; from pathlib import Path; "
    "c=http.client.HTTPConnection('127.0.0.1',8080,timeout=4); "
    "c.request('GET',PATH,headers=HEADERS); r=c.getresponse(); "
    "status=r.status; r.read(4096); c.close(); raise SystemExit(0 if status==200 else 1)"
)


def configuration(promotion, profile):
    kube_promotion.validate_config(promotion)
    validate_profile(profile)
    if promotion["expected_serving_image"] != profile["image_id"]:
        raise Rejected("kube_serving_service_image")
    return {
        **{
            name: copy.deepcopy(value)
            for name, value in promotion.items()
            if name not in ("schema_version", "security_audit_config")
        },
        "minimum_sequence": 1,
        "identity_audit_file": "/security/identity-audit.json",
        "token_file": "/security/service.token",
        "audit_directory": "/tmp/http-audit",
        "kubernetes_worker": copy.deepcopy(profile),
    }


def probe(path):
    headers = (
        "{'Authorization':'Bearer '+Path('/security/service.token').read_text().strip()}"
        if path == "/readyz"
        else "{}"
    )
    return {
        "exec": {
            "command": [
                "python",
                "-c",
                PROBE.replace("PATH", repr(path)).replace("HEADERS", headers),
            ]
        },
        "timeoutSeconds": 5,
        "periodSeconds": 10,
        "failureThreshold": 3,
    }


def documents(workspace, profile, config):
    promotion = {
        **{
            key: value
            for key, value in config.items()
            if key
            not in (
                "minimum_sequence",
                "identity_audit_file",
                "token_file",
                "audit_directory",
                "kubernetes_worker",
            )
        },
        "schema_version": 2,
        "security_audit_config": "/security/audit.json",
    }
    if config != configuration(promotion, profile):
        raise Rejected("kube_serving_service_configuration")
    mapping = resource(
        "ConfigMap",
        NAME,
        workspace,
        NAMESPACE,
        immutable=True,
        data={"config.json": canonical(config).decode()},
    )
    spec = kube_promotion.credential_spec(profile, NAME, NAME)
    spec["serviceAccountName"] = "serving"
    spec["volumes"] = [v for v in spec["volumes"] if v["name"] != "request"]
    container = spec["containers"][0]
    container["volumeMounts"] = [m for m in container["volumeMounts"] if m["name"] != "request"]
    container["command"] = ["python", "-m", "mlsecops.serving_http", "--config", "/config.json"]
    container["resources"]["limits"]["memory"] = "1Gi"
    container["resources"]["requests"]["memory"] = "256Mi"
    next(v for v in spec["volumes"] if v["name"] == "scratch")["emptyDir"]["sizeLimit"] = "640Mi"
    spec = kube_security_resources.serving_spec(mount_api(spec))
    initializer = copy.deepcopy(spec["containers"][0])
    initializer.update(
        name="http-audit-directory",
        command=["sh", "-ec", "umask 077; mkdir -m 700 /tmp/http-audit"],
        volumeMounts=[{"name": "scratch", "mountPath": "/tmp"}],
    )
    spec["initContainers"].append(initializer)
    container = spec["containers"][0]
    container["readinessProbe"] = probe("/readyz")
    container["livenessProbe"] = probe("/livez")
    container["startupProbe"] = {**probe("/livez"), "failureThreshold": 24, "periodSeconds": 5}
    spec.update(restartPolicy="Always", terminationGracePeriodSeconds=30)
    labels = {"app": NAME, WORKSPACE: workspace}
    deployment = resource(
        "Deployment",
        NAME,
        workspace,
        NAMESPACE,
        apiVersion="apps/v1",
        spec={
            "replicas": 1,
            "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": labels},
            "template": {"metadata": {"labels": labels}, "spec": spec},
        },
    )
    return mapping, deployment


def directory(state):
    return safe_child(state, "kubernetes-serving-service")


def validate(state):
    marker = read_json(safe_child(directory(state), "resources.json"))
    if (
        marker.get("schema_version") != 1
        or marker.get("ready") is not True
        or marker.get("workspace_id") != workspace_id(state)
        or marker.get("config_sha256") != digest(canonical(marker.get("config")))
    ):
        raise Rejected("kube_serving_service_marker")
    config, profile = marker["config"], marker["profile"]
    audit = kube_security_events.validate(
        state,
        profile=profile,
        environment=config["context"]["policy"]["environment"],
        initial_root=config["trust_root"],
    )
    if marker.get("audit_pin") != audit["pins"]["serving"]:
        raise Rejected("kube_serving_service_audit_pin")
    desired = documents(marker["workspace_id"], profile, config)
    if set(marker["resources"]) != {kube_storage.reference(d) for d in desired}:
        raise Rejected("kube_serving_service_inventory")
    for document in desired:
        kube_storage.verify_resource(
            document,
            kube_storage.get(state, document),
            marker["resources"][kube_storage.reference(document)],
        )
    return marker


def pod(state, marker):
    document = documents(marker["workspace_id"], marker["profile"], marker["config"])[1]
    uid = kube_security_events.live(state, document, marker, require_ready=False)
    items = decode(
        kubectl(state, ["get", "pods", "-n", NAMESPACE, "-l", "app=" + NAME, "-o", "json"]).stdout
    )["items"]
    if len(items) != 1 or items[0]["metadata"]["uid"] != uid:
        raise Rejected("kube_serving_service_pod_changed")
    return items[0]


def execute(state, code):
    marker = validate(state)
    before = pod(state, marker)
    content = kubectl(
        state,
        [
            "exec",
            before["metadata"]["name"],
            "-n",
            NAMESPACE,
            "-c",
            "worker",
            "--",
            "python",
            "-c",
            code,
        ],
    ).stdout
    if pod(state, marker)["metadata"]["uid"] != before["metadata"]["uid"]:
        raise Rejected("kube_serving_service_pod_changed")
    return decode(content, 65536)


def wait_live(state, marker, *, previous=None):
    deadline = time.monotonic() + 120
    while True:
        try:
            current = pod(state, marker)
            if previous is not None and current["metadata"]["uid"] == previous:
                raise Rejected("kube_serving_service_not_replaced")
            result = kubectl(
                state,
                [
                    "exec",
                    current["metadata"]["name"],
                    "-n",
                    NAMESPACE,
                    "-c",
                    "worker",
                    "--",
                    *probe("/livez")["exec"]["command"],
                ],
                check=False,
            )
            if result.returncode == 0:
                return current["metadata"]["uid"]
        except Rejected:
            pass
        if time.monotonic() >= deadline:
            raise Rejected("kube_serving_service_start_deadline")
        time.sleep(0.5)


def bootstrap(state, profile, promotion):
    state = Path(state).resolve()
    config = configuration(promotion, profile)
    audit = kube_security_events.validate(
        state,
        profile=profile,
        environment=config["context"]["policy"]["environment"],
        initial_root=config["trust_root"],
    )
    local = directory(state)
    if local.exists():
        marker = validate(state)
        if marker["config"] != config or marker["profile"] != profile:
            raise Rejected("kube_serving_service_context_changed")
        wait_live(state, marker)
        return marker
    local.mkdir(mode=0o700)
    marker = dict(
        schema_version=1,
        ready=False,
        workspace_id=workspace_id(state),
        profile=profile,
        config=config,
        config_sha256=digest(canonical(config)),
        audit_pin=audit["pins"]["serving"],
        resources={},
    )
    kube_security_events.save(local, marker)
    for document in documents(marker["workspace_id"], profile, config):
        kube_security_events.create(state, local, marker, document)
    wait_live(state, marker)
    marker["ready"] = True  # Operator resources and HTTP liveness, never model readiness.
    kube_security_events.save(local, marker)
    return validate(state)


def restart(state):
    marker = validate(state)
    before = pod(state, marker)["metadata"]
    endpoint = f"/api/v1/namespaces/{NAMESPACE}/pods/{before['name']}"
    kubectl(
        state,
        ["delete", "--raw=" + endpoint, "-f", "-"],
        {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "preconditions": {"uid": before["uid"]},
            "gracePeriodSeconds": 30,
            "propagationPolicy": "Foreground",
        },
    )
    after = wait_live(state, marker, previous=before["uid"])
    if (
        kube_storage.get(
            state, {"kind": "Pod", "metadata": {"name": before["name"], "namespace": NAMESPACE}}
        )
        is not None
    ):
        raise Rejected("kube_serving_service_old_pod_present")
    validate(state)
    return {"before": before["uid"], "after": after}


def stop(state):
    marker = validate(state)
    for document in reversed(
        documents(marker["workspace_id"], marker["profile"], marker["config"])
    ):
        key = kube_storage.reference(document)
        metadata = document["metadata"]
        kind = document["kind"]
        api = "apis/apps/v1" if kind == "Deployment" else "api/v1"
        endpoint = f"/{api}/namespaces/{NAMESPACE}/{kind.lower()}s/{metadata['name']}"
        kubectl(
            state,
            ["delete", "--raw=" + endpoint, "-f", "-"],
            {
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "preconditions": {"uid": marker["resources"][key]},
                "propagationPolicy": "Foreground",
            },
        )
        deadline = time.monotonic() + 45
        while kube_storage.get(state, document) is not None:
            if time.monotonic() >= deadline:
                raise Rejected("kube_serving_service_cleanup_deadline")
            time.sleep(0.5)
    items = decode(
        kubectl(state, ["get", "pods", "-n", NAMESPACE, "-l", "app=" + NAME, "-o", "json"]).stdout
    )["items"]
    workers = decode(kubectl(state, ["get", "jobs", "-n", "ml-serve", "-o", "json"]).stdout)[
        "items"
    ]
    if items or workers:
        raise Rejected("kube_serving_service_cleanup_incomplete")
    marker["ready"] = False
    marker["stopped"] = True
    kube_security_events.save(directory(state), marker)
    return {"service_pods": 0, "worker_jobs": 0, "audit_state_retained": True}
