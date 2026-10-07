import argparse
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

from mlsecops.contracts import (
    Rejected,
    atomic_write,
    canonical,
    decode,
    digest,
    now,
    read_json,
    write_json,
)
from mlsecops.inventory import command

NAME = "trusted-mlsecops"
CONTEXT = f"kind-{NAME}"
NODE = f"{NAME}-control-plane"
CHART_VERSION = "1.20.2"
CHART_SHA256 = "b2afd87b7f75f875f92a14559f14f59b7babbb479d968e3fd625a20bf30ec20e"
NAMESPACES = {
    "ml-train": "trainer",
    "ml-eval": "evaluator",
    "ml-serve": "serving",
    "ml-control": "controller",
}
MEMORY_BUDGETS = {"ml-train": "4Gi", "ml-eval": "1Gi", "ml-serve": "1Gi", "ml-control": "512Mi"}
ROOT = Path(__file__).resolve().parents[1]


def kubectl(state, arguments, value=None, timeout=60, check=True, config=None):
    path = Path(config) if config else Path(state) / "kubeconfig"
    if path.is_symlink() or not path.is_file():
        raise Rejected("cluster_kubeconfig_unavailable")
    result = subprocess.run(
        [
            "kubectl",
            "--kubeconfig",
            str(path.resolve()),
            "--context",
            CONTEXT,
            "--request-timeout=30s",
            *arguments,
        ],
        input=canonical(value) if value is not None else None,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode:
        raise Rejected("kubernetes_request_failed")
    return result


def apply(state, value):
    return kubectl(state, ["apply", "-f", "-"], value)


def resources(workspace_id):
    items = []
    for namespace, identity in NAMESPACES.items():
        worker = namespace in {"ml-train", "ml-eval"}
        items.extend(
            [
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {
                        "name": namespace,
                        "labels": {
                            "trusted-mlsecops/workspace": workspace_id,
                            "trusted-mlsecops/scope": "worker" if worker else "control",
                            "pod-security.kubernetes.io/enforce": "restricted",
                            "pod-security.kubernetes.io/enforce-version": "v1.36",
                        },
                    },
                },
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {"name": identity, "namespace": namespace},
                    "automountServiceAccountToken": False,
                },
                {
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "NetworkPolicy",
                    "metadata": {"name": "default-deny", "namespace": namespace},
                    "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
                },
                {
                    "apiVersion": "v1",
                    "kind": "ResourceQuota",
                    "metadata": {"name": "namespace-budget", "namespace": namespace},
                    "spec": {
                        "hard": {
                            "pods": "4",
                            "requests.cpu": "3",
                            "requests.memory": MEMORY_BUDGETS[namespace],
                            "limits.cpu": "4",
                            "limits.memory": MEMORY_BUDGETS[namespace],
                            "count/jobs.batch": "8",
                            "count/configmaps": "16",
                        }
                    },
                },
            ]
        )
        if worker:
            items.append(
                {
                    "apiVersion": "v1",
                    "kind": "LimitRange",
                    "metadata": {"name": "worker-budget", "namespace": namespace},
                    "spec": {
                        "limits": [
                            {
                                "type": "Container",
                                "max": {"cpu": "2", "memory": "4Gi"},
                                "default": {"cpu": "2", "memory": "4Gi"},
                                "defaultRequest": {"cpu": "100m", "memory": "128Mi"},
                            }
                        ]
                    },
                }
            )
            items.append(
                {
                    "apiVersion": "cilium.io/v2",
                    "kind": "CiliumNetworkPolicy",
                    "metadata": {"name": "offline-worker", "namespace": namespace},
                    "spec": {"endpointSelector": {}, "egressDeny": [{"toEntities": ["all"]}]},
                }
            )
    return {"apiVersion": "v1", "kind": "List", "items": items}


def validate_cluster(state):
    state = Path(state)
    workspace = read_json(state / "workspace.json")
    marker = read_json(state / "cluster.json")
    if marker.get("workspace_id") != workspace["workspace_id"] or marker.get("name") != NAME:
        raise Rejected("cluster_ownership_mismatch")
    observed = decode(kubectl(state, ["get", "namespace", "ml-control", "-o", "json"]).stdout)
    if observed["metadata"]["uid"] != marker.get("namespace_uid"):
        raise Rejected("cluster_identity_changed")
    return marker


def bootstrap(state):
    state = Path(state).resolve()
    workspace = read_json(state / "workspace.json")
    for tool in ("kind", "helm", "kubectl", "docker"):
        if not shutil.which(tool):
            raise Rejected(f"required_tool_missing:{tool}")
    if "v0.33.0" not in command(["kind", "version"]):
        raise Rejected("kind_version_mismatch")
    engine = decode(command(["docker", "info", "--format", "{{json .}}"]).encode())
    if (
        engine["MemTotal"] < 15 * 1024**3
        or engine["NCPU"] < 4
        or shutil.disk_usage(state).free < 12 * 1024**3
    ):
        raise Rejected("kubernetes_lab_capacity_insufficient")
    if "v4.2.4" not in command(["helm", "version", "--short"]):
        raise Rejected("helm_version_mismatch")
    clusters = command(["kind", "get", "clusters"]).splitlines()
    if NAME in clusters:
        validate_cluster(state)
    else:
        if (state / "cluster.json").exists() or (state / "kubeconfig").exists():
            raise Rejected("cluster_state_exists_manual_recovery_required")
        command(
            [
                "kind",
                "create",
                "cluster",
                "--name",
                NAME,
                "--config",
                str(ROOT / "infra/kind.yaml"),
                "--kubeconfig",
                str(state / "kubeconfig"),
                "--retain",
            ],
            timeout=900,
        )
    command(["docker", "update", "--cpus", "4", "--memory", "12g", "--memory-swap", "12g", NODE])
    chart = state / "downloads" / f"cilium-{CHART_VERSION}.tgz"
    if not chart.exists():
        with urllib.request.urlopen(
            f"https://helm.cilium.io/cilium-{CHART_VERSION}.tgz", timeout=60
        ) as response:
            content = response.read(1024 * 1024 + 1)
        if digest(content) != CHART_SHA256:
            raise Rejected("cilium_chart_digest_mismatch")
        atomic_write(chart, content)
    if chart.is_symlink() or digest(chart.read_bytes()) != CHART_SHA256:
        raise Rejected("cilium_chart_digest_mismatch")
    command(
        [
            "helm",
            "upgrade",
            "--install",
            "cilium",
            str(chart),
            "--kubeconfig",
            str(state / "kubeconfig"),
            "--kube-context",
            CONTEXT,
            "--namespace",
            "kube-system",
            "--values",
            str(ROOT / "infra/cilium-values.yaml"),
            "--wait",
            "--timeout",
            "5m",
        ],
        timeout=330,
    )
    apply(state, resources(workspace["workspace_id"]))
    kubectl(state, ["apply", "-f", str(ROOT / "infra/worker-admission.yaml")])
    kubectl(
        state, ["wait", "nodes", "--all", "--for=condition=Ready", "--timeout=120s"], timeout=150
    )
    namespace = decode(kubectl(state, ["get", "namespace", "ml-control", "-o", "json"]).stdout)
    version = decode(kubectl(state, ["version", "-o", "json"]).stdout)
    report = {
        "schema_version": 1,
        "name": NAME,
        "workspace_id": workspace["workspace_id"],
        "namespace_uid": namespace["metadata"]["uid"],
        "server_version": version["serverVersion"]["gitVersion"],
        "chart_sha256": CHART_SHA256,
        "observed_at": now(),
    }
    write_json(state / "cluster.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description="Dedicated local Kubernetes lab")
    parser.add_argument("action", choices=["bootstrap", "status"])
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    arguments = parser.parse_args()
    try:
        result = (
            bootstrap(arguments.state)
            if arguments.action == "bootstrap"
            else validate_cluster(arguments.state)
        )
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError, subprocess.TimeoutExpired) as error:
        print(f"Cluster operation rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
