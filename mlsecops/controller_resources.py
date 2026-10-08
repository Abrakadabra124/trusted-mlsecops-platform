from mlsecops.controller_api import TARGETS
from mlsecops.kube_storage_resources import ACCOUNT, WORKSPACE


def resources(workspace, image):
    documents = []

    def add(kind, version, name, namespace=None, **fields):
        metadata = {"name": name, "labels": {WORKSPACE: workspace}}
        if namespace:
            metadata["namespace"] = namespace
        documents.append({"apiVersion": version, "kind": kind, "metadata": metadata, **fields})

    for role, (namespace, worker) in TARGETS.items():
        controller_namespace = f"ml-{role}"
        add(
            "CiliumNetworkPolicy",
            "cilium.io/v2",
            "controller-api",
            controller_namespace,
            spec={
                "endpointSelector": {"matchLabels": {ACCOUNT: role}},
                "egress": [
                    {
                        "toEntities": ["kube-apiserver"],
                        "toPorts": [
                            {
                                "ports": [
                                    {"port": "443", "protocol": "TCP"},
                                    {"port": "6443", "protocol": "TCP"},
                                ]
                            }
                        ],
                    }
                ],
            },
        )
        rules = [
            ("job-name", "object.metadata.name.matches('^controller-worker-[0-9a-f]{32}$')"),
            (
                "job-budget",
                "has(object.spec.activeDeadlineSeconds) && object.spec.activeDeadlineSeconds > 0 && object.spec.activeDeadlineSeconds <= 600 && object.spec.backoffLimit == 0 && object.spec.parallelism == 1 && object.spec.completions == 1 && object.spec.ttlSecondsAfterFinished == 300",
            ),
            (
                "job-mode",
                "(!has(object.spec.suspend) || !object.spec.suspend) && (!has(object.spec.manualSelector) || !object.spec.manualSelector)",
            ),
            (
                "worker-identity",
                f"variables.pod.serviceAccountName == '{worker}' && variables.pod.automountServiceAccountToken == false && variables.pod.restartPolicy == 'Never'",
            ),
            (
                "worker-containers",
                "variables.pod.containers.size() == 1 && (!has(variables.pod.initContainers) || variables.pod.initContainers.size() == 0) && (!has(variables.pod.ephemeralContainers) || variables.pod.ephemeralContainers.size() == 0)",
            ),
            (
                "worker-host",
                "(!has(variables.pod.hostNetwork) || !variables.pod.hostNetwork) && (!has(variables.pod.hostPID) || !variables.pod.hostPID) && (!has(variables.pod.hostIPC) || !variables.pod.hostIPC) && (!has(variables.pod.shareProcessNamespace) || !variables.pod.shareProcessNamespace) && !has(variables.pod.hostAliases) && !has(variables.pod.nodeName)",
            ),
            (
                "worker-security",
                "variables.pod.securityContext.runAsNonRoot && variables.pod.securityContext.runAsUser == 65532 && variables.pod.securityContext.runAsGroup == 65532 && variables.pod.securityContext.fsGroup == 65532 && variables.pod.securityContext.seccompProfile.type == 'RuntimeDefault' && !has(variables.pod.securityContext.sysctls)",
            ),
            (
                "worker-image",
                f"variables.container.image == '{image}' && variables.container.imagePullPolicy == 'Never'",
            ),
            (
                "worker-command",
                "variables.container.name == 'worker' && variables.container.command == ['python','-m','mlsecops.worker_transport','--request-file','/input/request.gz'] && (!has(variables.container.args) || variables.container.args.size() == 0) && (!has(variables.container.env) || variables.container.env.size() == 0) && (!has(variables.container.envFrom) || variables.container.envFrom.size() == 0) && !has(variables.container.lifecycle)",
            ),
            (
                "container-security",
                "variables.container.securityContext.readOnlyRootFilesystem && variables.container.securityContext.allowPrivilegeEscalation == false && variables.container.securityContext.capabilities.drop == ['ALL'] && (!has(variables.container.securityContext.privileged) || !variables.container.securityContext.privileged) && !has(variables.container.securityContext.capabilities.add) && (!has(variables.container.securityContext.runAsUser) || variables.container.securityContext.runAsUser == 65532)",
            ),
            (
                "worker-resources",
                f"variables.container.resources.limits.cpu == '2' && variables.container.resources.limits.memory == '{'4Gi' if role == 'publisher' else '1Gi'}' && variables.container.resources.requests.memory == variables.container.resources.limits.memory && variables.container.resources.requests.cpu == '100m' && variables.container.resources.limits['ephemeral-storage'] == '64Mi'",
            ),
            (
                "worker-volumes",
                "variables.pod.volumes.size() == 2 && variables.pod.volumes.exists(volume, volume.name == 'scratch' && has(volume.emptyDir) && volume.emptyDir.medium == 'Memory' && volume.emptyDir.sizeLimit == '64Mi') && variables.pod.volumes.exists(volume, volume.name == 'request' && has(volume.configMap) && volume.configMap.name == object.metadata.name && volume.configMap.defaultMode == 292)",
            ),
            (
                "worker-mounts",
                "variables.container.volumeMounts.size() == 2 && variables.container.volumeMounts.exists(volume, volume.name == 'scratch' && volume.mountPath == '/tmp' && !has(volume.subPath) && !has(volume.subPathExpr)) && variables.container.volumeMounts.exists(volume, volume.name == 'request' && volume.mountPath == '/input' && volume.readOnly && !has(volume.subPath) && !has(volume.subPathExpr))",
            ),
        ]
        policy_name = f"ml-{role}-jobs"
        add(
            "ValidatingAdmissionPolicy",
            "admissionregistration.k8s.io/v1",
            policy_name,
            spec={
                "failurePolicy": "Fail",
                "matchConstraints": {
                    "resourceRules": [
                        {
                            "apiGroups": ["batch"],
                            "apiVersions": ["v1"],
                            "operations": ["CREATE", "UPDATE"],
                            "resources": ["jobs"],
                        }
                    ],
                },
                "matchConditions": [
                    {
                        "name": "controller-identity",
                        "expression": f"request.userInfo.username == 'system:serviceaccount:{controller_namespace}:{role}'",
                    }
                ],
                "variables": [
                    {"name": "pod", "expression": "object.spec.template.spec"},
                    {"name": "container", "expression": "variables.pod.containers[0]"},
                ],
                "validations": [
                    {
                        "expression": f"request.namespace == '{namespace}'",
                        "message": "controller-target-namespace",
                    },
                    *[
                        {"expression": expression, "message": f"controller-{name}"}
                        for name, expression in rules
                    ],
                ],
            },
        )
        add(
            "ValidatingAdmissionPolicyBinding",
            "admissionregistration.k8s.io/v1",
            policy_name,
            spec={"policyName": policy_name, "validationActions": ["Deny"]},
        )
        add(
            "Role",
            "rbac.authorization.k8s.io/v1",
            "controller-worker",
            namespace,
            rules=[
                {
                    "apiGroups": ["batch"],
                    "resources": ["jobs"],
                    "verbs": ["create", "get", "delete"],
                },
                {
                    "apiGroups": [""],
                    "resources": ["configmaps"],
                    "verbs": ["create", "get", "delete"],
                },
                {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
                {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]},
            ],
        )
        add(
            "RoleBinding",
            "rbac.authorization.k8s.io/v1",
            "controller-worker",
            namespace,
            roleRef={
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "controller-worker",
            },
            subjects=[{"kind": "ServiceAccount", "name": role, "namespace": controller_namespace}],
        )
    return documents


def mount_api(spec):
    spec["volumes"].append(
        {
            "name": "api",
            "projected": {
                "defaultMode": 292,
                "sources": [
                    {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                    {
                        "configMap": {
                            "name": "kube-root-ca.crt",
                            "items": [{"key": "ca.crt", "path": "ca.crt"}],
                        }
                    },
                ],
            },
        }
    )
    spec["containers"][0]["volumeMounts"].append(
        {"name": "api", "mountPath": "/api", "readOnly": True}
    )
    return spec
