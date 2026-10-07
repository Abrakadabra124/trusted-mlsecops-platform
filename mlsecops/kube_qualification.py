import argparse
import copy
import tempfile
import uuid
from pathlib import Path

from mlsecops.cluster import CONTEXT, NAMESPACES, apply, kubectl, validate_cluster
from mlsecops.contracts import Rejected, canonical, decode, digest, now, write_json
from mlsecops.inventory import command, source_fingerprint
from mlsecops.kube_worker import job_document, load_image, pod_spec, verify_running_image, wait_job


def probe(state, image, image_id, action, namespace="ml-train", address=None, deadline=60):
    name = f"probe-{uuid.uuid4().hex}"
    arguments = ["mlsecops.isolation_probe", action]
    if address:
        arguments.extend(["--address", address])
    spec = pod_spec(image, NAMESPACES[namespace], arguments, memory="256Mi")
    job = job_document(name, namespace, spec, deadline)
    try:
        kubectl(state, ["create", "-f", "-"], job)
        condition, pod, elapsed = wait_job(state, namespace, name, deadline)
        verify_running_image(pod, image_id)
        statuses = pod["status"].get("containerStatuses", [])
        terminated = statuses[0].get("state", {}).get("terminated", {}) if statuses else {}
        result = {
            "pod_deleted": condition.get("pod_deleted", False),
            "condition": condition["type"],
            "reason": condition.get("reason"),
            "termination": terminated.get("reason"),
            "exit_code": terminated.get("exitCode"),
            "elapsed_seconds": elapsed,
            "pod_spec_digest": digest(canonical(pod["spec"])),
        }
        if condition["type"] == "Complete":
            result["output"] = decode(
                kubectl(
                    state, ["logs", pod["metadata"]["name"], "-n", namespace, "--limit-bytes=16385"]
                ).stdout,
                16384,
            )
        return result
    finally:
        kubectl(
            state,
            [
                "delete",
                "job",
                name,
                "-n",
                namespace,
                "--ignore-not-found",
                "--wait=true",
                "--timeout=30s",
            ],
            check=False,
        )


def identity_checks(state, check):
    original = decode(kubectl(state, ["config", "view", "--raw", "-o", "json"]).stdout)
    for namespace, identity in NAMESPACES.items():
        token = (
            kubectl(state, ["create", "token", identity, "-n", namespace, "--duration=10m"])
            .stdout.decode()
            .strip()
        )
        config = {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": original["clusters"],
            "users": [{"name": "probe", "user": {"token": token}}],
            "contexts": [{"name": CONTEXT, "context": {"cluster": CONTEXT, "user": "probe"}}],
            "current-context": CONTEXT,
        }
        with tempfile.NamedTemporaryFile(
            dir=state, prefix="identity-", suffix=".json", delete=False
        ) as temporary:
            path = Path(temporary.name)
        try:
            write_json(path, config)
            for resource, target in (
                ("secrets", "ml-control"),
                ("configmaps", "ml-eval"),
                ("configmaps", "ml-train"),
            ):
                response = kubectl(state, ["get", resource, "-n", target], config=path, check=False)
                check(
                    f"identity-{identity}-read-{target}-{resource}",
                    response.returncode != 0 and b"Forbidden" in response.stderr,
                )
            response = kubectl(
                state,
                ["create", "-f", "-"],
                {
                    "apiVersion": "batch/v1",
                    "kind": "Job",
                    "metadata": {"name": "unauthorized", "namespace": namespace},
                    "spec": {
                        "template": {
                            "spec": {
                                "restartPolicy": "Never",
                                "containers": [
                                    {
                                        "name": "bad",
                                        "image": "invalid.invalid/no-image",
                                        "securityContext": {"privileged": True},
                                    }
                                ],
                            }
                        }
                    },
                },
                config=path,
                check=False,
            )
            check(
                f"identity-{identity}-create-job",
                response.returncode != 0 and b"Forbidden" in response.stderr,
            )
        finally:
            if path.resolve().parent != state.resolve():
                raise Rejected("credential_cleanup_path_escape")
            path.unlink(missing_ok=True)


def admission_checks(state, image, check):
    base = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "admission-probe", "namespace": "ml-train"},
        "spec": pod_spec(image, "trainer", ["mlsecops.isolation_probe", "environment"]),
    }
    mutations = {
        "root": lambda spec: spec["securityContext"].update(runAsUser=0),
        "privileged": lambda spec: spec["containers"][0]["securityContext"].update(privileged=True),
        "writable-root": lambda spec: spec["containers"][0]["securityContext"].update(
            readOnlyRootFilesystem=False
        ),
        "token": lambda spec: spec.update(automountServiceAccountToken=True),
        "host-mount": lambda spec: spec["volumes"].append(
            {"name": "host", "hostPath": {"path": "/"}}
        ),
        "secret-mount": lambda spec: spec["volumes"].append(
            {"name": "secret", "secret": {"secretName": "signer"}}
        ),
        "memory-limit": lambda spec: spec["containers"][0]["resources"]["limits"].update(
            memory="5Gi"
        ),
        "cpu-limit": lambda spec: spec["containers"][0]["resources"]["limits"].update(cpu="3"),
    }
    response = kubectl(state, ["create", "--dry-run=server", "-f", "-"], base, check=False)
    check("admission-positive", response.returncode == 0)
    for name, mutate in mutations.items():
        fixture = copy.deepcopy(base)
        mutate(fixture["spec"])
        response = kubectl(state, ["create", "--dry-run=server", "-f", "-"], fixture, check=False)
        check(
            f"admission-deny-{name}",
            response.returncode != 0
            and any(
                reason in response.stderr
                for reason in (b"Forbidden", b"denied request", b"Invalid")
            ),
        )


def qualify(state, image):
    state = Path(state)
    cluster = validate_cluster(state)
    tag, image_id = load_image(state, image)
    cases = []
    probes = {}

    def check(identifier, passed):
        cases.append(
            {
                "id": identifier,
                "expected": True,
                "actual": bool(passed),
                "status": "pass" if passed else "fail",
            }
        )

    admission_checks(state, tag, check)
    identity_checks(state, check)
    for namespace in ("ml-train", "ml-eval"):
        result = probe(state, tag, image_id, "environment", namespace)
        probes[namespace] = result
        output = result.get("output", {})
        for key, expected in {
            "uid": 65532,
            "read_only_root": True,
            "capabilities": "0000000000000000",
            "no_new_privileges": "1",
            "memory_max": str(256 * 1024**2),
            "cpu_max": "200000 100000",
            "pid1_is_probe": True,
            "onnx_telemetry_disabled": True,
        }.items():
            check(f"{namespace}-{key}", output.get(key) == expected)
        check(
            f"{namespace}-no-host-secrets",
            bool(output.get("absent")) and all(output["absent"].values()),
        )
        result = probe(state, tag, image_id, "pids", namespace)
        probes[f"pids-{namespace}"] = result
        output = result.get("output", {})
        check(
            f"{namespace}-pod-pid-limit",
            output.get("failure_errno") == 11 and 1 <= output.get("started", 80) <= 63,
        )
    name = "isolation-control"
    spec = pod_spec(tag, "serving", ["mlsecops.isolation_probe", "serve"], memory="256Mi")
    server = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": "ml-serve", "labels": {"app": name}},
        "spec": spec,
    }
    policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": "ml-serve"},
        "spec": {
            "podSelector": {"matchLabels": {"app": name}},
            "policyTypes": ["Ingress"],
            "ingress": [{"ports": [{"port": 8080, "protocol": "TCP"}]}],
        },
    }
    positive_policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": "ml-control"},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Egress"],
            "egress": [
                {
                    "to": [
                        {
                            "namespaceSelector": {
                                "matchLabels": {"kubernetes.io/metadata.name": "ml-serve"}
                            },
                            "podSelector": {"matchLabels": {"app": name}},
                        }
                    ],
                    "ports": [{"port": 8080, "protocol": "TCP"}],
                }
            ],
        },
    }
    try:
        kubectl(state, ["create", "-f", "-"], server)
        apply(state, policy)
        apply(state, positive_policy)
        kubectl(
            state,
            ["wait", "pod", name, "-n", "ml-serve", "--for=condition=Ready", "--timeout=60s"],
            timeout=75,
        )
        snapshot = decode(
            kubectl(state, ["get", "pod", name, "-n", "ml-serve", "-o", "json"]).stdout
        )
        address = snapshot["status"]["podIP"]
        before = probe(state, tag, image_id, "connect", "ml-control", address)
        check("network-positive-control-before", before.get("output", {}).get("reachable") is True)
        for namespace in ("ml-train", "ml-eval"):
            result = probe(state, tag, image_id, "connect", namespace, address)
            probes[f"egress-{namespace}"] = result
            check(f"egress-denied-{namespace}", result.get("output", {}).get("reachable") is False)
        result = probe(state, tag, image_id, "deadline", deadline=10)
        probes["deadline"] = result
        check(
            "deadline-enforced",
            result["condition"] == "Failed"
            and result["reason"] == "DeadlineExceeded"
            and result["pod_deleted"]
            and result["elapsed_seconds"] <= 45,
        )
        result = probe(state, tag, image_id, "oom")
        probes["oom"] = result
        check(
            "oom-enforced", result["condition"] == "Failed" and result["termination"] == "OOMKilled"
        )
        after = probe(state, tag, image_id, "connect", "ml-control", address)
        final = decode(kubectl(state, ["get", "pod", name, "-n", "ml-serve", "-o", "json"]).stdout)
        check("network-positive-control-after", after.get("output", {}).get("reachable") is True)
        check(
            "control-server-not-restarted",
            final["metadata"]["uid"] == snapshot["metadata"]["uid"]
            and final["status"]["containerStatuses"][0]["restartCount"] == 0,
        )
    finally:
        kubectl(
            state,
            [
                "delete",
                "pod",
                name,
                "-n",
                "ml-serve",
                "--ignore-not-found",
                "--wait=true",
                "--timeout=30s",
            ],
            check=False,
        )
        for namespace in ("ml-control", "ml-serve"):
            kubectl(
                state,
                ["delete", "networkpolicy", name, "-n", namespace, "--ignore-not-found"],
                check=False,
            )
    root = Path(__file__).resolve().parents[1]
    report = {
        "schema_version": 1,
        "scope": "kubernetes-components-not-full-M04-M05-M20",
        "status": "pass" if all(case["status"] == "pass" for case in cases) else "fail",
        "full_acceptance": "inconclusive",
        "observed_at": now(),
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "source_fingerprint": source_fingerprint(root),
        "cluster": cluster,
        "image_id": image_id,
        "cases": cases,
        "probes": probes,
        "limitations": [
            "Host/cluster administrator trusted",
            "Control HTTP server is not the future inference service",
            "No actual data/registry service storage ACL coverage yet",
            "No independent human reviewer",
            "M04/M05/M20 remain incomplete",
        ],
    }
    write_json(state / "evidence/kubernetes-qualification.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description="Exercise Kubernetes isolation boundaries")
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    try:
        report = qualify(arguments.state, arguments.image)
    except (Rejected, OSError) as error:
        report = {
            "schema_version": 1,
            "scope": "kubernetes-components-not-full-M04-M05-M20",
            "status": "inconclusive",
            "full_acceptance": "inconclusive",
            "observed_at": now(),
            "cases": [],
            "reason": str(error),
        }
        write_json(arguments.state / "evidence/kubernetes-qualification.json", report)
    print(
        canonical(
            {
                "status": report["status"],
                "cases": len(report["cases"]),
                "full_acceptance": report["full_acceptance"],
                "reason": report.get("reason"),
                "failed_cases": [
                    case["id"] for case in report["cases"] if case["status"] != "pass"
                ],
            }
        ).decode()
    )
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
