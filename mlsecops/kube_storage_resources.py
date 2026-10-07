from mlsecops.storage_bootstrap import IMAGE, MOUNT, PGDATA
from mlsecops.storage_pki import ROLES

NAMESPACE = "ml-storage"
CLASS = "trusted-mlsecops-storage"
CLIENT_NAMESPACES = {role: f"ml-{role}" for role in ROLES}
WORKSPACE = "trusted-mlsecops/workspace"
ACCOUNT = "io.cilium.k8s.policy.serviceaccount"
POD_NAMESPACE = "k8s:io.kubernetes.pod.namespace"


def resource(kind, name, workspace, namespace=None, **fields):
    versions = {
        "StatefulSet": "apps/v1",
        "NetworkPolicy": "networking.k8s.io/v1",
        "CiliumNetworkPolicy": "cilium.io/v2",
        "StorageClass": "storage.k8s.io/v1",
    }
    metadata = {"name": name, "labels": {WORKSPACE: workspace}}
    if namespace:
        metadata["namespace"] = namespace
    return {
        "apiVersion": versions.get(kind, "v1"),
        "kind": kind,
        "metadata": metadata,
        **fields,
    }


def namespace_resources(namespace, account, workspace):
    document = resource("Namespace", namespace, workspace)
    document["metadata"]["labels"].update(
        {
            "trusted-mlsecops/scope": "storage-controller",
            "pod-security.kubernetes.io/enforce": "restricted",
            "pod-security.kubernetes.io/enforce-version": "v1.36",
        }
    )
    return [
        document,
        resource(
            "ServiceAccount", account, workspace, namespace, automountServiceAccountToken=False
        ),
        resource(
            "NetworkPolicy",
            "default-deny",
            workspace,
            namespace,
            spec={"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
        ),
        resource(
            "ResourceQuota",
            "storage-budget",
            workspace,
            namespace,
            spec={
                "hard": {
                    "pods": "3",
                    "requests.cpu": "1",
                    "limits.cpu": "2",
                    "requests.memory": "512Mi",
                    "limits.memory": "1Gi",
                    "requests.storage": "2Gi",
                    "persistentvolumeclaims": "1",
                    "count/secrets": "2",
                    "count/configmaps": "4",
                    "count/jobs.batch": "3",
                }
            },
        ),
    ]


def network_resources(workspace):
    server = resource(
        "CiliumNetworkPolicy",
        "postgres-boundary",
        workspace,
        NAMESPACE,
        spec={
            "endpointSelector": {},
            "egressDeny": [{"toEntities": ["all"]}],
            "ingress": [
                {
                    "fromEndpoints": [
                        {"matchLabels": {POD_NAMESPACE: namespace, ACCOUNT: role}}
                        for role, namespace in CLIENT_NAMESPACES.items()
                    ],
                    "toPorts": [{"ports": [{"port": "5432", "protocol": "TCP"}]}],
                }
            ],
        },
    )
    clients = [
        resource(
            "CiliumNetworkPolicy",
            "storage-client",
            workspace,
            namespace,
            spec={
                "endpointSelector": {"matchLabels": {ACCOUNT: role}},
                "egress": [
                    {
                        "toEndpoints": [
                            {
                                "matchLabels": {
                                    POD_NAMESPACE: NAMESPACE,
                                    "k8s:app": "postgres",
                                    ACCOUNT: "postgres",
                                }
                            }
                        ],
                        "toPorts": [{"ports": [{"port": "5432", "protocol": "TCP"}]}],
                    },
                    {
                        "toEndpoints": [
                            {
                                "matchLabels": {
                                    POD_NAMESPACE: "kube-system",
                                    "k8s:k8s-app": "kube-dns",
                                }
                            }
                        ],
                        "toPorts": [
                            {
                                "ports": [
                                    {"port": "53", "protocol": "UDP"},
                                    {"port": "53", "protocol": "TCP"},
                                ]
                            }
                        ],
                    },
                ],
            },
        )
        for role, namespace in CLIENT_NAMESPACES.items()
    ]
    return [server, *clients]


def postgres(workspace):
    security = {
        "runAsNonRoot": True,
        "runAsUser": 999,
        "runAsGroup": 999,
        "fsGroup": 999,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    return resource(
        "StatefulSet",
        "postgres",
        workspace,
        NAMESPACE,
        spec={
            "serviceName": "postgres",
            "replicas": 1,
            "selector": {"matchLabels": {"app": "postgres"}},
            "template": {
                "metadata": {"labels": {"app": "postgres", WORKSPACE: workspace}},
                "spec": {
                    "serviceAccountName": "postgres",
                    "automountServiceAccountToken": False,
                    "enableServiceLinks": False,
                    "hostNetwork": False,
                    "hostPID": False,
                    "hostIPC": False,
                    "shareProcessNamespace": False,
                    "securityContext": security,
                    "terminationGracePeriodSeconds": 30,
                    "containers": [
                        {
                            "name": "postgres",
                            "image": IMAGE,
                            "imagePullPolicy": "IfNotPresent",
                            "command": [
                                "sh",
                                "-eu",
                                "-c",
                                f"if [ ! -s {PGDATA}/PG_VERSION ]; then "
                                f"initdb -D {PGDATA} --auth-local=peer --auth-host=reject "
                                "--encoding=UTF8 --locale=C.UTF-8 --data-checksums; fi; "
                                f"exec postgres -D {PGDATA} -c config_file={MOUNT}/tls/postgresql.conf",
                            ],
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                            "resources": {
                                "requests": {"cpu": "100m", "memory": "128Mi"},
                                "limits": {
                                    "cpu": "1",
                                    "memory": "512Mi",
                                    "ephemeral-storage": "128Mi",
                                },
                            },
                            "volumeMounts": [
                                {"name": "data", "mountPath": MOUNT},
                                {"name": "tls", "mountPath": f"{MOUNT}/tls", "readOnly": True},
                                {"name": "scratch", "mountPath": "/tmp"},
                            ],
                            "readinessProbe": {
                                "exec": {"command": ["pg_isready", "-h", "/tmp", "-U", "postgres"]},
                                "periodSeconds": 2,
                                "timeoutSeconds": 2,
                            },
                        }
                    ],
                    "volumes": [
                        {"name": "data", "persistentVolumeClaim": {"claimName": "postgres-data"}},
                        {
                            "name": "tls",
                            "secret": {"secretName": "postgres-tls", "defaultMode": 416},
                        },
                        {"name": "scratch", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}},
                    ],
                },
            },
        },
    )


def resources(workspace, server_files, client_files):
    from mlsecops.signing import encode64

    items = namespace_resources(NAMESPACE, "postgres", workspace)
    for role, namespace in CLIENT_NAMESPACES.items():
        items.extend(namespace_resources(namespace, role, workspace))
    items.extend(network_resources(workspace))
    items.extend(
        [
            resource(
                "StorageClass",
                CLASS,
                workspace,
                provisioner="rancher.io/local-path",
                reclaimPolicy="Retain",
                volumeBindingMode="WaitForFirstConsumer",
            ),
            resource(
                "PersistentVolumeClaim",
                "postgres-data",
                workspace,
                NAMESPACE,
                spec={
                    "storageClassName": CLASS,
                    "accessModes": ["ReadWriteOnce"],
                    "resources": {"requests": {"storage": "2Gi"}},
                },
            ),
            resource(
                "Secret",
                "postgres-tls",
                workspace,
                NAMESPACE,
                immutable=True,
                type="Opaque",
                data={name: encode64(content) for name, content in server_files.items()},
            ),
            resource(
                "Service",
                "postgres",
                workspace,
                NAMESPACE,
                spec={
                    "type": "ClusterIP",
                    "selector": {"app": "postgres"},
                    "ports": [
                        {"name": "postgres", "port": 5432, "targetPort": 5432, "protocol": "TCP"}
                    ],
                },
            ),
        ]
    )
    for role, files in client_files.items():
        items.append(
            resource(
                "Secret",
                "storage-client",
                workspace,
                CLIENT_NAMESPACES[role],
                immutable=True,
                type="Opaque",
                data={name: encode64(content) for name, content in files.items()},
            )
        )
    items.append(postgres(workspace))
    return items
