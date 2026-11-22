"""Verify the rolled-out CoreDNS and query kube-dns from the kind node network."""

from ipaddress import IPv4Address
from pathlib import Path

from mlsecops.cluster import NODE, kubectl, validate_cluster
from mlsecops.contracts import Rejected, decode
from mlsecops.inventory import command
from scripts.image_audit_contract import (
    COREDNS_CONFIG,
    COREDNS_MANIFEST,
    COREDNS_REFERENCE,
    COREDNS_SPEC_IMAGE,
)

_DNS_NAME = "kubernetes.default.svc.cluster.local."


def _pinned_container(spec, image, policy):
    containers = [c for c in spec["containers"] if c["name"] == "coredns"]
    return (
        len(containers) == 1
        and containers[0].get("image") == image
        and (policy is None or containers[0].get("imagePullPolicy") == policy)
    )


def get(state, resource, *args, namespace="kube-system"):
    return decode(kubectl(state, ["get", resource, "-n", namespace, *args, "-o", "json"]).stdout)


def ready_replicas(state, image, policy=None):
    validate_cluster(state)
    kubectl(
        state,
        ["rollout", "status", "deployment/coredns", "-n", "kube-system", "--timeout=120s"],
        timeout=135,
    )
    deployment = get(state, "deployment/coredns")["spec"]
    replicas = deployment["replicas"]
    pods = [
        p
        for p in get(state, "pods", "-l", "k8s-app=kube-dns")["items"]
        if not p["metadata"].get("deletionTimestamp")
    ]
    if (
        type(replicas) is not int
        or replicas < 1
        or len(pods) != replicas
        or not _pinned_container(deployment["template"]["spec"], image, policy)
    ):
        raise Rejected("coredns_rollout_mismatch")
    result = []
    for pod in pods:
        spec, status = pod["spec"], pod["status"]
        running = [
            s
            for s in status["containerStatuses"]
            if s["name"] == "coredns"
            and s["ready"] is True
            and isinstance(s["state"].get("running"), dict)
        ]
        if (
            spec.get("nodeName") != NODE
            or status["phase"] != "Running"
            or not _pinned_container(spec, image, policy)
            or len(running) != 1
        ):
            raise Rejected("coredns_pod_mismatch")
        result.append((pod, running[0]))
    return result


def verify_upstream(status):
    image_id = status["imageID"].removeprefix("docker-pullable://")
    if image_id not in (COREDNS_MANIFEST, COREDNS_CONFIG, COREDNS_REFERENCE, COREDNS_SPEC_IMAGE):
        raise Rejected("coredns_image_id_mismatch")
    cri = decode(command(["docker", "exec", NODE, "crictl", "inspecti", image_id]).encode())[
        "status"
    ]
    if (
        cri["id"] != COREDNS_CONFIG
        or not isinstance(cri["repoDigests"], list)
        or COREDNS_REFERENCE not in cri["repoDigests"]
    ):
        raise Rejected("coredns_runtime_identity_mismatch")


def service_answer(state):
    dns = get(state, "service/kube-dns")["spec"]
    if dns["selector"] != {"k8s-app": "kube-dns"}:
        raise Rejected("coredns_service_selector_mismatch")
    server = IPv4Address(dns["clusterIP"])
    expected = IPv4Address(
        get(state, "service/kubernetes", namespace="default")["spec"]["clusterIP"]
    )
    pid = command(["docker", "inspect", "--format", "{{.State.Pid}}", NODE])
    if not pid.isdecimal() or int(pid) <= 1:
        raise Rejected("coredns_node_pid_invalid")
    # Only enter the network namespace. dig comes from the runner's filesystem.
    answer = command(
        [
            "sudo",
            "-n",
            "nsenter",
            "--target",
            pid,
            "--net",
            "--",
            "dig",
            "-r",
            f"@{server}",
            _DNS_NAME,
            "A",
            "+short",
            "+time=3",
            "+tries=3",
        ]
    )
    if answer != str(expected):
        raise Rejected("coredns_service_answer_mismatch")
    return f"dns={server} {_DNS_NAME} A {expected}"


def verify(state=Path(".runtime")):
    replicas = ready_replicas(state, COREDNS_SPEC_IMAGE)
    for _, status in replicas:
        verify_upstream(status)
    return f"coredns={COREDNS_SPEC_IMAGE} config={COREDNS_CONFIG} ready={len(replicas)} {service_answer(state)}"


if __name__ == "__main__":
    print(verify())
