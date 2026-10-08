import argparse
import re
import subprocess
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from mlsecops import boundary_probe, controller_runtime, kube_storage
from mlsecops.boundary_probe_qualification import qualify as unit_checks
from mlsecops.cluster import NODE, kubectl
from mlsecops.contracts import Rejected, canonical, decode, digest, now, read_json, write_json
from mlsecops.controller_bootstrap import verify_saved
from mlsecops.inventory import command, source_fingerprint
from mlsecops.kube_storage_migration import ledger
from mlsecops.kube_worker import job_document, pod_spec, verify_running_image, wait_job


def delete_options(uid):
    return {
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {"uid": uid},
        "propagationPolicy": "Foreground",
    }


def isolated_spec(expected, pod):
    observed = pod.get("spec", {})
    return (
        kube_storage.matches({"spec": expected}, pod)
        and not any(
            observed.get(name)
            for name in (
                "hostPID",
                "hostIPC",
                "hostNetwork",
                "shareProcessNamespace",
                "ephemeralContainers",
            )
        )
        and len(observed.get("initContainers", [])) == len(expected.get("initContainers", []))
    )


@contextmanager
def temporary_resource(state, document):
    created = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], document).stdout)
    metadata = created["metadata"]
    resource = "jobs" if document["kind"] == "Job" else "configmaps"
    prefix = "/apis/batch/v1" if resource == "jobs" else "/api/v1"
    endpoint = f"{prefix}/namespaces/{metadata['namespace']}/{resource}/{metadata['name']}"
    try:
        yield created, endpoint
    finally:
        kubectl(state, ["delete", f"--raw={endpoint}", "-f", "-"], delete_options(metadata["uid"]))
        kubectl(
            state,
            [
                "wait",
                "--for=delete",
                f"{resource}/{metadata['name']}",
                "-n",
                metadata["namespace"],
                "--timeout=30s",
            ],
        )


def pod_for_job(state, namespace, name, uid):
    pods = decode(
        kubectl(
            state,
            [
                "get",
                "pods",
                "-n",
                namespace,
                "-l",
                f"job-name={name}",
                "-o",
                "json",
            ],
        ).stdout
    )["items"]
    if len(pods) > 1:
        raise Rejected("boundary_ambiguous_pod")
    if not pods:
        return None
    pod = pods[0]
    if not any(
        owner.get("uid") == uid and owner.get("controller") is True
        for owner in pod["metadata"].get("ownerReferences", [])
    ):
        raise Rejected("boundary_pod_owner_mismatch")
    return pod


def node_process(pod):
    statuses = pod.get("status", {}).get("containerStatuses", [])
    if len(statuses) != 1 or not statuses[0].get("state", {}).get("running"):
        raise Rejected("boundary_witness_not_running")
    container = statuses[0].get("containerID", "")
    if not re.fullmatch(r"containerd://[0-9a-f]{64}", container):
        raise Rejected("boundary_invalid_container_id")
    inspected = decode(
        command(
            [
                "docker",
                "exec",
                NODE,
                "crictl",
                "inspect",
                container.split("://")[1],
            ]
        ),
        1024 * 1024,
    )
    status = inspected["status"]
    labels = status.get("labels", {})
    if (
        status.get("state") != "CONTAINER_RUNNING"
        or status.get("metadata", {}).get("name") != "worker"
        or labels.get("io.kubernetes.pod.uid") != pod["metadata"]["uid"]
        or labels.get("io.kubernetes.pod.namespace") != "ml-scorer"
    ):
        raise Rejected("boundary_cri_identity_mismatch")
    node_pid = inspected["info"]["pid"]
    boundary_probe.paths(node_pid)
    namespace = command(["docker", "exec", NODE, "readlink", f"/proc/{node_pid}/ns/pid"])
    if not re.fullmatch(r"pid:\[[0-9]+\]", namespace):
        raise Rejected("boundary_pid_namespace_unavailable")
    return {"node_pid": node_pid, "pid_namespace": namespace, "container_id": container}


def logs(state, pod):
    return decode(
        kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-n",
                pod["metadata"]["namespace"],
                "-c",
                "worker",
                "--limit-bytes=65537",
            ],
        ).stdout,
        65536,
    )


def wait_witness(state, name, uid):
    started = time.monotonic()
    while time.monotonic() - started < 60:
        pod = pod_for_job(state, "ml-scorer", name, uid)
        if pod and pod.get("status", {}).get("phase") in ("Failed", "Succeeded"):
            raise Rejected("boundary_witness_ended_before_ready")
        if pod and pod.get("status", {}).get("phase") == "Running":
            result = kubectl(
                state,
                [
                    "exec",
                    pod["metadata"]["name"],
                    "-n",
                    "ml-scorer",
                    "-c",
                    "worker",
                    "--",
                    "cat",
                    boundary_probe.READY.as_posix(),
                ],
                check=False,
            )
            if result.returncode == 0:
                return pod, decode(result.stdout, 16384)
        time.sleep(1)
    raise Rejected("boundary_witness_ready_deadline")


def qualify(root, state):
    root, state = Path(root).resolve(), Path(state).resolve()
    kube_storage.validate(state)
    marker = verify_saved(state, read_json(state / "controllers/resources.json"))
    profile = marker["profile"]
    if not marker.get("ready") or profile["source_fingerprint"] != source_fingerprint(root):
        raise Rejected("boundary_controller_profile_stale")
    cases = unit_checks()["cases"]

    def confirmed(name, condition):
        if not condition:
            raise Rejected(f"boundary_qualification_failed:{name}")
        cases.append({"id": name, "status": "pass"})

    before_ledger = ledger(state)
    inputs = read_json(state / "kubernetes-storage/migration-inputs.json")
    addresses, services = {}, {}
    for key, namespace, name in (
        ("sql_address", "ml-storage", "postgres"),
        ("api_address", "default", "kubernetes"),
    ):
        service = decode(
            kubectl(state, ["get", "service", name, "-n", namespace, "-o", "json"]).stdout
        )
        addresses[key] = service["spec"]["clusterIP"]
        services[key] = {
            "uid": service["metadata"]["uid"],
            "address": addresses[key],
            "namespace": namespace,
            "name": name,
        }
    request = {
        "profile": profile,
        "dataset_reference": inputs["dataset_reference"],
        "trust": inputs["trust"],
        **addresses,
    }
    controller_runtime.signer(state)
    name = f"boundary-{uuid.uuid4().hex}"
    config = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "immutable": True,
        "metadata": {"name": name, "namespace": "ml-scorer"},
        "data": {"request.json": canonical(request).decode()},
    }
    witness_spec = controller_runtime.controller_spec(
        profile,
        "scorer",
        name,
        [
            "mlsecops.boundary_probe",
            "witness",
            "--request",
            "/request.json",
        ],
    )
    witness_job = job_document(name, "ml-scorer", witness_spec, 240)
    observations = []
    with temporary_resource(state, config) as (created_config, endpoint):
        wrong = kubectl(
            state,
            ["delete", f"--raw={endpoint}", "-f", "-"],
            delete_options(str(uuid.uuid4())),
            check=False,
        )
        confirmed(
            "delete-wrong-uid-rejected", wrong.returncode != 0 and b"Conflict" in wrong.stderr
        )
        kept = decode(
            kubectl(state, ["get", "configmap", name, "-n", "ml-scorer", "-o", "json"]).stdout
        )
        confirmed(
            "delete-wrong-uid-preserves-resource",
            kept["metadata"]["uid"] == created_config["metadata"]["uid"],
        )
        with temporary_resource(state, witness_job) as (created_job, _):
            job_uid = created_job["metadata"]["uid"]
            witness_pod, ready = wait_witness(state, name, job_uid)
            verify_running_image(witness_pod, profile["image_id"])
            confirmed("witness-production-spec", isolated_spec(witness_spec, witness_pod))
            process = node_process(witness_pod)
            confirmed(
                "witness-node-pid-binding",
                ready["pid_namespace"] == process["pid_namespace"] and ready["pid"] == 1,
            )
            confirmed(
                "witness-positive-controls-before",
                ready["status"] == "pass"
                and ready["holdout_rows"] > 0
                and len(ready["checks"]) == 6,
            )
            for namespace, identity in (("ml-train", "trainer"), ("ml-eval", "evaluator")):
                worker_name = f"boundary-{uuid.uuid4().hex}"
                spec = pod_spec(
                    profile["image"],
                    identity,
                    [
                        "mlsecops.boundary_probe",
                        "worker",
                        "--node-pid",
                        str(process["node_pid"]),
                        "--sql-address",
                        addresses["sql_address"],
                        "--api-address",
                        addresses["api_address"],
                    ],
                    memory="256Mi",
                )
                document = job_document(worker_name, namespace, spec, 90)
                with temporary_resource(state, document) as (worker_job, _):
                    terminal, worker_pod, elapsed = wait_job(state, namespace, worker_name, 90)
                    confirmed(f"{identity}:completed", terminal["type"] == "Complete")
                    confirmed(
                        f"{identity}:pod-owner",
                        pod_for_job(state, namespace, worker_name, worker_job["metadata"]["uid"])[
                            "metadata"
                        ]["uid"]
                        == worker_pod["metadata"]["uid"],
                    )
                    verify_running_image(worker_pod, profile["image_id"])
                    confirmed(f"{identity}:worker-spec", isolated_spec(spec, worker_pod))
                    report = logs(state, worker_pod)
                    confirmed(
                        f"{identity}:unprivileged",
                        report["schema_version"] == 1 and report["uid"] == 65532,
                    )
                    confirmed(
                        f"{identity}:separate-pid-namespace",
                        re.fullmatch(r"pid:\[[0-9]+\]", report["pid_namespace"])
                        and report["pid_namespace"] != process["pid_namespace"],
                    )
                    confirmed(
                        f"{identity}:complete-path-matrix",
                        set(report["reads"]) == set(boundary_probe.paths(process["node_pid"])),
                    )
                    for path, result in report["reads"].items():
                        confirmed(
                            f"{identity}:denied:{path}", result in {"ENOENT", "EACCES", "EPERM"}
                        )
                    for service in ("sql", "api"):
                        confirmed(
                            f"{identity}:{service}-network-denied", report[service] == "timeout"
                        )
                    current = pod_for_job(state, "ml-scorer", name, job_uid)
                    confirmed(
                        f"{identity}:witness-still-running",
                        current["metadata"]["uid"] == witness_pod["metadata"]["uid"]
                        and node_process(current) == process,
                    )
                    observations.append(
                        {
                            "identity": f"system:serviceaccount:{namespace}:{identity}",
                            "pod_uid": worker_pod["metadata"]["uid"],
                            "job_uid": worker_job["metadata"]["uid"],
                            "pod_spec_digest": digest(canonical(worker_pod["spec"])),
                            "elapsed_seconds": elapsed,
                            "report": report,
                        }
                    )
            kubectl(
                state,
                [
                    "exec",
                    witness_pod["metadata"]["name"],
                    "-n",
                    "ml-scorer",
                    "-c",
                    "worker",
                    "--",
                    "touch",
                    boundary_probe.STOP.as_posix(),
                ],
            )
            terminal, final_pod, _ = wait_job(state, "ml-scorer", name, 240)
            confirmed(
                "witness-completed",
                terminal["type"] == "Complete"
                and final_pod["metadata"]["uid"] == witness_pod["metadata"]["uid"],
            )
            final = logs(state, final_pod)
            confirmed(
                "witness-positive-controls-after",
                final["before"] == ready
                and final["after"]["status"] == "pass"
                and final["after"]["checks"] == ready["checks"]
                and final["after"]["holdout_rows"] == ready["holdout_rows"],
            )
    confirmed("private-ledger-unchanged", ledger(state) == before_ledger)
    verify_saved(state, marker)
    confirmed("owned-controller-specs-unchanged", True)
    for namespace in ("ml-scorer", "ml-train", "ml-eval"):
        for resource in ("jobs", "pods", "configmaps"):
            items = decode(kubectl(state, ["get", resource, "-n", namespace, "-o", "json"]).stdout)[
                "items"
            ]
            confirmed(
                f"cleanup:{namespace}:{resource}",
                not any(item["metadata"]["name"].startswith("boundary-") for item in items),
            )
    return {
        "schema_version": 1,
        "status": "pass",
        "scope": "live-worker-access-component-not-full-M20",
        "observed_at": now(),
        "source_fingerprint": source_fingerprint(root),
        "image_id": profile["image_id"],
        "dataset_reference": inputs["dataset_reference"],
        "controller_profile_digest": digest(canonical(profile)),
        "witness": {
            "pod_uid": witness_pod["metadata"]["uid"],
            "job_uid": job_uid,
            **process,
            **final,
        },
        "workers": observations,
        "services": services,
        "checks": len(cases),
        "cases": cases,
        "release_ready": False,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Live scorer witness, proc and worker credential boundary"
    )
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    arguments = parser.parse_args()
    state = arguments.state.resolve()
    required = (
        "workspace.json",
        "controllers/resources.json",
        "kubernetes-storage/migration-inputs.json",
        "kubeconfig",
    )
    if not all((state / name).is_file() for name in required):
        report = {
            "status": "inconclusive",
            "reason": "boundary-prerequisites-missing",
            "observed_at": now(),
            "release_ready": False,
        }
        if (state / "workspace.json").is_file():
            write_json(state / "evidence/boundary-qualification.json", report)
        print(canonical(report).decode())
        return 2
    path = state / "evidence/boundary-qualification.json"
    write_json(
        path,
        {
            "status": "inconclusive",
            "reason": "qualification-running",
            "observed_at": now(),
            "release_ready": False,
        },
    )
    try:
        report = qualify(Path(__file__).resolve().parents[1], state)
    except (Rejected, OSError, subprocess.TimeoutExpired):
        write_json(
            path,
            {
                "status": "fail",
                "reason": "boundary-qualification-failed",
                "observed_at": now(),
                "release_ready": False,
            },
        )
        raise
    write_json(path, report)
    print(canonical(report).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
