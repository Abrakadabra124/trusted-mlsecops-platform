"""Audit deployment plans. Operator bootstrap must verify ownership before creating them."""

import copy

from mlsecops import kube_trust, kube_worker
from mlsecops.contracts import Rejected
from mlsecops.kube_storage_resources import (
    ACCOUNT,
    CLASS,
    POD_NAMESPACE,
    WORKSPACE,
    namespace_resources,
    resource,
)
from mlsecops.signing import encode64

NAMESPACE = "ml-audit"
PORT = 8443
ROLES = {
    "collector": (NAMESPACE, "collector"),
    "trust": ("ml-serving", "serving"),
    "promoter": ("ml-promoter", "promoter"),
}
COMMON = ("registry.json", "ca.crt", "tls.crt", "tls.key", "ingress.token")
FILES = {
    "collector": (*COMMON, "collector.json", "receipt.pem", "collector.pem", "operator.token"),
    "trust": (*COMMON, "producer.json", "observer.json", "producer.pem"),
    "promoter": (*COMMON, "audit.json", "producer.pem"),
}


def identity(role):
    if type(role) is not str or role not in ROLES:
        raise Rejected("kube_security_role")
    return ROLES[role]


def secret(workspace, role, files):
    namespace, _ = identity(role)
    if (
        type(files) is not dict
        or set(files) != set(FILES[role])
        or any(type(value) is not bytes or not 0 < len(value) <= 32768 for value in files.values())
        or sum(map(len, files.values())) > 128 * 1024
    ):
        raise Rejected("kube_security_secret_inventory")
    return resource(
        "Secret",
        "security-" + role,
        workspace,
        namespace,
        immutable=True,
        type="Opaque",
        data={name: encode64(value) for name, value in files.items()},
    )


def private_files(spec, name, names, *, public=False):
    # Fixed names supplied only by this module; no input-generated shell fragments.
    source = (
        {"configMap": {"name": name, "defaultMode": 416}}
        if public
        else {"secret": {"secretName": name, "defaultMode": 416}}
    )
    spec["volumes"].extend(
        [
            {"name": "security-source", **source},
            {"name": "security-private", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}},
        ]
    )
    initializer = copy.deepcopy(spec["containers"][0])
    initializer.update(
        name="security-files",
        command=[
            "sh",
            "-ec",
            "umask 077; mkdir -m 700 /private/security; cp "
            + " ".join("/source/" + filename for filename in names)
            + " /private/security/; chmod 600 /private/security/*",
        ],
        volumeMounts=[
            {"name": "security-source", "mountPath": "/source", "readOnly": True},
            {"name": "security-private", "mountPath": "/private"},
        ],
    )
    spec.setdefault("initContainers", []).append(initializer)
    spec["containers"][0]["volumeMounts"].append(
        {
            "name": "security-private",
            "mountPath": "/security",
            "subPath": "security",
            "readOnly": True,
        }
    )


def persistent(spec):
    # Do not recursively grant group access to existing 0700/0600 journal contents.
    # Actual PVC/root permissions and preservation must be checked in hosted native tests.
    spec["securityContext"]["fsGroupChangePolicy"] = "OnRootMismatch"
    spec["volumes"].append(
        {
            "name": "security-state",
            "persistentVolumeClaim": {"claimName": "security-events"},
        }
    )
    spec["containers"][0]["volumeMounts"].append({"name": "security-state", "mountPath": "/audit"})
    return spec


def provision_spec(image, role, config_name):
    _, account = identity(role)
    spec = kube_worker.pod_spec(
        image,
        account,
        ["mlsecops.security_event_provision", "--config", "/security/provision.json"],
        memory="256Mi",
    )
    private_files(spec, config_name, ("provision.json",), public=True)
    return persistent(spec)


def promoter_spec(spec):
    if spec.get("serviceAccountName") != "promoter":
        raise Rejected("kube_security_promoter_identity")
    result = copy.deepcopy(spec)
    private_files(result, "security-promoter", FILES["promoter"])
    return persistent(result)


def runtime_spec(image, role):
    identity(role)
    if role == "collector":
        spec = kube_worker.pod_spec(
            image,
            "collector",
            ["mlsecops.security_event_server", "--config", "/security/collector.json"],
            memory="256Mi",
        )
    elif role == "trust":
        spec = kube_trust.client_spec(
            image,
            "serving",
            ["mlsecops.security_trust_service", "--config", "/security/observer.json"],
        )
    else:
        raise Rejected("kube_security_runtime_role")
    spec["restartPolicy"] = "Always"
    spec["terminationGracePeriodSeconds"] = 10
    for container in (*spec.get("initContainers", []), *spec["containers"]):
        container["resources"]["limits"].update(cpu="1", memory="256Mi")
    private_files(spec, "security-" + role, FILES[role])
    return persistent(spec)


def deployment(workspace, image, role):
    namespace, _ = identity(role)
    labels = {"app": "collector" if role == "collector" else "security-trust", WORKSPACE: workspace}
    return resource(
        "Deployment",
        labels["app"],
        workspace,
        namespace,
        apiVersion="apps/v1",
        spec={
            "replicas": 1,
            "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": labels},
            "template": {"metadata": {"labels": labels}, "spec": runtime_spec(image, role)},
        },
    )


def base_resources(workspace):
    documents = namespace_resources(NAMESPACE, "collector", workspace)
    ports = [{"ports": [{"port": str(PORT), "protocol": "TCP"}]}]
    collector = {POD_NAMESPACE: NAMESPACE, ACCOUNT: "collector", "k8s:app": "collector"}
    clients = [
        {POD_NAMESPACE: namespace, ACCOUNT: account}
        for role, (namespace, account) in ROLES.items()
        if role != "collector"
    ]
    documents.extend(
        [
            resource(
                "Service",
                "collector",
                workspace,
                NAMESPACE,
                spec={
                    "type": "ClusterIP",
                    "selector": {"app": "collector", WORKSPACE: workspace},
                    "ports": [
                        {"name": "audit-tls", "port": PORT, "targetPort": PORT, "protocol": "TCP"}
                    ],
                },
            ),
            resource(
                "CiliumNetworkPolicy",
                "security-collector",
                workspace,
                NAMESPACE,
                spec={
                    "endpointSelector": {"matchLabels": {ACCOUNT: "collector"}},
                    "egressDeny": [{"toEntities": ["all"]}],
                    "ingress": [
                        {
                            "fromEndpoints": [{"matchLabels": client} for client in clients],
                            "toPorts": ports,
                        }
                    ],
                },
            ),
        ]
    )
    for role, (namespace, account) in ROLES.items():
        documents.append(
            resource(
                "PersistentVolumeClaim",
                "security-events",
                workspace,
                namespace,
                spec={
                    "storageClassName": CLASS,
                    "accessModes": ["ReadWriteOnce"],
                    "resources": {"requests": {"storage": "64Mi"}},
                },
            )
        )
        if role != "collector":
            documents.append(
                resource(
                    "CiliumNetworkPolicy",
                    "security-collector",
                    workspace,
                    namespace,
                    spec={
                        "endpointSelector": {"matchLabels": {ACCOUNT: account}},
                        "egress": [{"toEndpoints": [{"matchLabels": collector}], "toPorts": ports}],
                    },
                )
            )
    return documents
