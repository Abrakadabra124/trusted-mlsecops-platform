"""Verify the rolled-out CoreDNS and query kube-dns from the kind node network."""

import subprocess
import time
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
    runtime_coredns,
)

# The hosted rollback qualification imports the upstream identities from this module.
__all__ = [
    "COREDNS_CONFIG",
    "COREDNS_MANIFEST",
    "COREDNS_REFERENCE",
    "COREDNS_SPEC_IMAGE",
    "verify",
]

_DNS_NAME = "kubernetes.default.svc.cluster.local."


def _pinned_container(spec, pin):
    return [c.get("image") for c in spec["containers"] if c["name"] == "coredns"] == [
        pin.spec_image
    ]


def _query_service(pid, server, expected):
    # Enter only the verified node's network namespace. dig runs from the runner.
    args = [
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
        "+tries=1",
    ]
    for attempt in range(1, 11):
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise Rejected("coredns_dns_tool_unavailable") from error
        if result.returncode == 0:
            if result.stdout.strip() != str(expected):
                raise Rejected("coredns_service_answer_mismatch")
            return attempt
        # BIND dig exits with 9 when the server sent no reply.
        if result.returncode != 9:
            raise Rejected(f"coredns_dns_tool_exit_{result.returncode}")
        if attempt < 10:
            time.sleep(1)
    raise Rejected("coredns_dns_no_reply_after_10_attempts")


def verify(state=Path(".runtime")):
    pin = runtime_coredns()
    validate_cluster(state)

    def get(resource, *args, namespace="kube-system"):
        return decode(
            kubectl(state, ["get", resource, "-n", namespace, *args, "-o", "json"]).stdout
        )

    kubectl(
        state,
        ["rollout", "status", "deployment/coredns", "-n", "kube-system", "--timeout=120s"],
        timeout=135,
    )
    deployment = get("deployment/coredns")["spec"]
    replicas = deployment["replicas"]
    pods = [
        p
        for p in get("pods", "-l", "k8s-app=kube-dns")["items"]
        if not p["metadata"].get("deletionTimestamp")
    ]
    if (
        type(replicas) is not int
        or replicas != 2
        or len(pods) != replicas
        or not _pinned_container(deployment["template"]["spec"], pin)
    ):
        raise Rejected("coredns_rollout_mismatch")
    verified = {}
    for pod in pods:
        name = pod["metadata"].get("name")
        spec, status = pod["spec"], pod["status"]
        running = [
            s
            for s in status["containerStatuses"]
            if s["name"] == "coredns"
            and s["ready"] is True
            and isinstance(s["state"].get("running"), dict)
        ]
        if (
            not isinstance(name, str)
            or not name
            or name in verified
            or spec.get("nodeName") != NODE
            or status["phase"] != "Running"
            or not _pinned_container(spec, pin)
            or len(running) != 1
        ):
            raise Rejected("coredns_pod_mismatch")
        image_id = running[0]["imageID"].removeprefix("docker-pullable://")
        if image_id not in (
            pin.manifest,
            pin.config,
            pin.reference,
            pin.spec_image,
        ):
            raise Rejected("coredns_image_id_mismatch")
        cri = decode(command(["docker", "exec", NODE, "crictl", "inspecti", image_id]).encode())[
            "status"
        ]
        if (
            cri["id"] != pin.config
            or not isinstance(cri["repoDigests"], list)
            or pin.reference not in cri["repoDigests"]
        ):
            raise Rejected("coredns_runtime_identity_mismatch")
        verified[name] = f"pod={name} imageID={image_id} manifest={pin.manifest} config={cri['id']}"

    dns = get("service/kube-dns")["spec"]
    if dns["selector"] != {"k8s-app": "kube-dns"}:
        raise Rejected("coredns_service_selector_mismatch")
    server = IPv4Address(dns["clusterIP"])
    expected = IPv4Address(get("service/kubernetes", namespace="default")["spec"]["clusterIP"])
    pid = command(["docker", "inspect", "--format", "{{.State.Pid}}", NODE])
    if not pid.isdecimal() or int(pid) <= 1:
        raise Rejected("coredns_node_pid_invalid")
    attempts = _query_service(pid, server, expected)
    summary = f"coredns={pin.spec_image} config={pin.config} ready={replicas} dns_attempts={attempts} dns={server} {_DNS_NAME} A {expected}"
    return "\n".join([*verified.values(), summary])


if __name__ == "__main__":
    print(verify())
