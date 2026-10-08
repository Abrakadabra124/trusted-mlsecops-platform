import argparse
import copy
import sys
import tempfile
import uuid
from pathlib import Path

from mlsecops import controller_runtime, kube_artifact_reader
from mlsecops.cluster import CONTEXT, kubectl
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
from mlsecops.controller_api import TARGETS
from mlsecops.controller_api_qualification import qualify as qualify_api
from mlsecops.controller_bootstrap import bootstrap, verify_saved
from mlsecops.controller_resources import mount_api
from mlsecops.controller_worker import documents
from mlsecops.inventory import source_fingerprint
from mlsecops.kube_storage_migration import ledger
from mlsecops.kube_storage_resources import client_pod_spec
from mlsecops.kube_worker import job_document, verify_running_image, wait_job
from mlsecops.signing import verify
from mlsecops.storage_bootstrap import validate as validate_source
from mlsecops.storage_restore import ledger as source_ledger


def identity_checks(state, profile, confirmed):
    original = decode(kubectl(state, ["config", "view", "--raw", "-o", "json"]).stdout)
    for role, (namespace, worker) in TARGETS.items():
        token = (
            kubectl(state, ["create", "token", role, "-n", f"ml-{role}", "--duration=10m"])
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
        with tempfile.TemporaryDirectory(prefix="controller-rbac-", dir=state) as temporary:
            path = Path(temporary) / "config.json"
            write_json(path, config)
            _, valid = documents(
                profile, role, {"action": "train" if role == "publisher" else "predict"}
            )
            response = kubectl(
                state, ["create", "--dry-run=server", "-f", "-"], valid, config=path, check=False
            )
            confirmed(f"{role}:admission-positive", response.returncode == 0)
            mutations = (
                ("privileged", ("containers", 0, "securityContext", "privileged"), True),
                ("wrong-identity", ("serviceAccountName",), "default"),
                ("token", ("automountServiceAccountToken",), True),
                ("host-network", ("hostNetwork",), True),
                ("host-pid", ("hostPID",), True),
                ("shared-pid", ("shareProcessNamespace",), True),
                (
                    "root-write",
                    ("containers", 0, "securityContext", "readOnlyRootFilesystem"),
                    False,
                ),
                (
                    "capability",
                    ("containers", 0, "securityContext", "capabilities", "add"),
                    ["NET_ADMIN"],
                ),
                ("command", ("containers", 0, "command"), ["sh", "-c", "id"]),
                ("extra-args", ("containers", 0, "args"), ["--untrusted"]),
                ("image", ("containers", 0, "image"), "invalid.invalid/not-pulled"),
                ("memory", ("containers", 0, "resources", "limits", "memory"), "8Gi"),
                ("cpu", ("containers", 0, "resources", "limits", "cpu"), "3"),
                (
                    "env-secret",
                    ("containers", 0, "envFrom"),
                    [{"secretRef": {"name": "storage-client"}}],
                ),
                ("seccomp", ("securityContext", "seccompProfile", "type"), "Unconfined"),
            )
            invalid_documents = []
            for name, keys, value in mutations:
                invalid = copy.deepcopy(valid)
                target = invalid["spec"]["template"]["spec"]
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                if name == "privileged":
                    target["allowPrivilegeEscalation"] = True
                invalid_documents.append((name, invalid))
            for name, volume in (
                ("secret-volume", {"name": "extra", "secret": {"secretName": "evaluator-signer"}}),
                (
                    "projected-token",
                    {
                        "name": "extra",
                        "projected": {"sources": [{"serviceAccountToken": {"path": "token"}}]},
                    },
                ),
                ("host-path", {"name": "extra", "hostPath": {"path": "/"}}),
            ):
                invalid = copy.deepcopy(valid)
                invalid["spec"]["template"]["spec"]["volumes"].append(volume)
                invalid_documents.append((name, invalid))
            invalid = copy.deepcopy(valid)
            invalid["spec"].pop("activeDeadlineSeconds")
            invalid_documents.append(("missing-deadline", invalid))
            invalid = copy.deepcopy(valid)
            invalid["spec"]["template"]["spec"]["containers"].append(
                {"name": "extra", "image": profile["image"]}
            )
            invalid_documents.append(("sidecar", invalid))
            reasons = {
                "privileged": "container-security",
                "wrong-identity": "worker-identity",
                "token": "worker-identity",
                "host-network": "worker-host",
                "host-pid": "worker-host",
                "shared-pid": "worker-host",
                "root-write": "container-security",
                "capability": "container-security",
                "command": "worker-command",
                "extra-args": "worker-command",
                "image": "worker-image",
                "memory": "worker-resources",
                "cpu": "worker-resources",
                "env-secret": "worker-command",
                "seccomp": "worker-security",
                "secret-volume": "worker-volumes",
                "projected-token": "worker-volumes",
                "host-path": "worker-volumes",
                "missing-deadline": "job-budget",
                "sidecar": "worker-containers",
            }
            for name, invalid in invalid_documents:
                response = kubectl(
                    state,
                    ["create", "--dry-run=server", "-f", "-"],
                    invalid,
                    config=path,
                    check=False,
                )
                confirmed(
                    f"{role}:admission-denied:{name}",
                    response.returncode != 0
                    and (
                        f"ValidatingAdmissionPolicy 'ml-{role}-jobs' with binding "
                        f"'ml-{role}-jobs' denied request: controller-{reasons[name]}"
                    ).encode()
                    in response.stderr,
                )
            other = "ml-eval" if namespace == "ml-train" else "ml-train"
            denied = [
                (f"secret-list:{target}", ["get", "secrets", "-n", target])
                for target in (namespace, f"ml-{role}", "ml-storage", "ml-control")
            ]
            denied.extend(
                [
                    ("foreign-worker-zone", ["get", "pods", "-n", other]),
                    ("nodes", ["get", "nodes"]),
                    ("roles", ["get", "roles", "-n", namespace]),
                    (
                        "token-request",
                        ["create", "token", worker, "-n", namespace, "--duration=10m"],
                    ),
                ]
            )
            for name, arguments in denied:
                response = kubectl(state, arguments, config=path, check=False)
                confirmed(
                    f"{role}:rbac-denied:{name}",
                    response.returncode != 0
                    and b"is forbidden" in response.stderr
                    and f"system:serviceaccount:ml-{role}:{role}".encode() in response.stderr,
                )
            pod = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "controller-negative", "namespace": namespace},
                "spec": valid["spec"]["template"]["spec"],
            }
            response = kubectl(
                state, ["create", "--dry-run=server", "-f", "-"], pod, config=path, check=False
            )
            confirmed(
                f"{role}:rbac-denied:direct-pod",
                response.returncode != 0 and b"Forbidden" in response.stderr,
            )


def live_api(state, profile, role):
    name = f"controller-api-{uuid.uuid4().hex}"
    namespace = f"ml-{role}"
    spec = mount_api(
        client_pod_spec(profile["image"], role, ["mlsecops.controller_probe", "--role", role])
    )
    document = job_document(name, namespace, spec, 90)
    created = False
    try:
        kubectl(state, ["create", "-f", "-"], document)
        created = True
        terminal, pod, _ = wait_job(state, namespace, name, 90)
        verify_running_image(pod, profile["image_id"])
        output = kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-c",
                "worker",
                "-n",
                namespace,
                "--limit-bytes=16385",
            ],
            check=False,
        ).stdout
        if terminal["type"] != "Complete":
            atomic_write(state / "evidence/controller-probe-diagnostic.log", output)
            raise Rejected(f"controller_live_api_probe_failed:{role}")
        return decode(output, 16384)
    finally:
        if created:
            kubectl(state, ["delete", "job", name, "-n", namespace, "--wait=true", "--timeout=30s"])


def qualify(root, state, image):
    root, state = Path(root).resolve(), Path(state).resolve()
    before = verify_saved(state, read_json(state / "controllers/resources.json"))
    cases = qualify_api(state)

    def confirmed(name, condition):
        if not condition:
            raise Rejected(f"controller_qualification_failed:{name}")
        cases.append({"id": name, "status": "pass"})

    repeated = bootstrap(root, state, image)
    after = read_json(state / "controllers/resources.json")
    confirmed(
        "bootstrap-preserves-resource-identities",
        {key: value["uid"] for key, value in before["resources"].items()}
        == {key: value["uid"] for key, value in after["resources"].items()},
    )
    confirmed(
        "bootstrap-profile-current",
        repeated["profile"]["source_fingerprint"] == source_fingerprint(root),
    )
    profile = after["profile"]
    identity_checks(state, profile, confirmed)
    verify_saved(state, after)
    confirmed("denials-preserve-resource-specs", True)
    for role in TARGETS:
        report = live_api(state, profile, role)
        confirmed(
            f"{role}:live-api-suite",
            report.get("role") == role
            and report.get("status") == "pass"
            and len(report.get("checks", [])) == 4,
        )
        cases.extend({"id": f"{role}:{name}", "status": "pass"} for name in report["checks"])
    protected = ledger(state)
    source = validate_source(state)
    source_before = source_ledger(source["name"])
    result = controller_runtime.demo(root, state)
    publisher, scorer = result["publisher"], result["scorer"]
    metadata = publisher["result"]["metadata"]
    evaluation = scorer["result"]["evaluation"]
    for role, item in (("publisher", publisher), ("scorer", scorer)):
        observed = item["process"]
        confirmed(
            f"{role}:process-boundary",
            observed["uid"] == 65532
            and observed["api_token_present"] is True
            and observed["signer_present"] == (role == "scorer")
            and not observed["host_socket_present"]
            and not observed["model_parser_loaded"],
        )
        confirmed(
            f"{role}:measured-memory-below-limit", 0 < observed["peak_memory_kib"] < 512 * 1024
        )
        confirmed(
            f"{role}:actual-controller-image", item["controller"]["image_id"] == profile["image_id"]
        )
    execution = metadata["execution"]
    confirmed(
        "scoped-training-worker",
        execution["backend"] == "scoped-kubernetes-controller"
        and execution["namespace"] == "ml-train"
        and execution["image_id"] == profile["image_id"],
    )
    confirmed(
        "image-bound-training-provenance",
        metadata["source_fingerprint"] == profile["source_fingerprint"]
        and metadata["source_revision"] == profile["source_revision"],
    )
    confirmed(
        "separate-controller-and-worker-pods",
        publisher["controller"]["pod_uid"] != execution["pod_uid"]
        and publisher["controller"]["pod_uid"] != scorer["controller"]["pod_uid"],
    )
    confirmed(
        "evaluation-bound-to-candidate",
        evaluation["candidate_reference"] == publisher["result"]["candidate_reference"]
        and evaluation["report"]["model_digest"] == metadata["model_digest"]
        and evaluation["report"]["image_id"] == profile["image_id"],
    )
    prediction = evaluation["report"]["prediction_execution"]
    protocol = evaluation["report"]["prediction_protocol"]
    confirmed(
        "scoped-prediction-worker",
        prediction["backend"] == "scoped-kubernetes-controller"
        and prediction["namespace"] == "ml-eval"
        and prediction["image_id"] == profile["image_id"],
    )
    confirmed(
        "separate-scorer-and-prediction-worker",
        prediction["pod_uid"] != scorer["controller"]["pod_uid"]
        and prediction["pod_uid"] != execution["pod_uid"],
    )
    confirmed(
        "prediction-protocol-bound-to-executed-request",
        protocol["schema_version"] == 2
        and protocol["rows"] == evaluation["report"]["rows"]
        and protocol["request_digest"] == prediction["input_digest"]
        and protocol["model_digest"] == metadata["model_digest"],
    )
    policy = read_json(root / "policies/local-cpu.json")
    confirmed(
        "synthetic-quality-component",
        evaluation["report"]["quality_component"] == "pass"
        and evaluation["report"]["validation_parity_max_error"] <= policy["parity_tolerance"],
    )
    inputs = read_json(state / "kubernetes-storage/migration-inputs.json")
    request = {
        "schema_version": 1,
        "role": "scorer",
        "candidate_reference": publisher["result"]["candidate_reference"],
        "evaluation_reference": scorer["result"]["evaluation_reference"],
        "trust": inputs["trust"],
        "policy_digest": digest(canonical(policy)),
    }
    stored = kube_artifact_reader.read(state, profile["image"], profile["image_id"], request)
    signed = verify(
        stored["evaluation"],
        "stored-evaluation",
        read_json(state / "trusted-keys.json")["evaluator"],
    )
    confirmed("persisted-evaluation-signature-and-bytes", signed == evaluation)
    current = ledger(state)
    confirmed(
        "protected-splits-and-release-history-unchanged",
        all(
            current[name] == value
            for name, value in protected.items()
            if name not in {"candidates", "evaluations"}
        ),
    )
    confirmed(
        "new-candidate-and-evaluation-history",
        current["candidates"]["rows"] > protected["candidates"]["rows"]
        and current["evaluations"]["rows"] == protected["evaluations"]["rows"] + 1,
    )
    confirmed(
        "host-source-untouched",
        source_ledger(source["name"]) == source_before
        and validate_source(state)["container_id"] == source["container_id"],
    )
    for namespace in ("ml-publisher", "ml-scorer", "ml-train", "ml-eval"):
        for resource in ("jobs", "configmaps"):
            observed = decode(
                kubectl(state, ["get", resource, "-n", namespace, "-o", "json"]).stdout
            )["items"]
            confirmed(
                f"cleanup:{namespace}:{resource}",
                not any(
                    item["metadata"]["name"].startswith(
                        ("controller-run-", "controller-worker-", "controller-api-")
                    )
                    for item in observed
                ),
            )
    return {
        "schema_version": 1,
        "status": "pass",
        "scope": "scoped-controllers-not-full-M04-M20",
        "observed_at": now(),
        "source_fingerprint": source_fingerprint(root),
        "image_id": profile["image_id"],
        "candidate_reference": publisher["result"]["candidate_reference"],
        "evaluation_reference": scorer["result"]["evaluation_reference"],
        "auprc": evaluation["report"]["auprc"],
        "parity_max_error": evaluation["report"]["validation_parity_max_error"],
        "publisher_peak_kib": publisher["process"]["peak_memory_kib"],
        "scorer_peak_kib": scorer["process"]["peak_memory_kib"],
        "checks": len(cases),
        "cases": cases,
        "release_ready": False,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Scoped controller API, TLS, admission and real ML workflow qualification"
    )
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    path = arguments.state / "evidence/controller-qualification.json"
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
        report = qualify(Path(__file__).resolve().parents[1], arguments.state, arguments.image)
        write_json(path, report)
        print(canonical(report).decode())
        return 0
    except (Rejected, OSError) as error:
        write_json(
            path,
            {"status": "fail", "reason": str(error), "observed_at": now(), "release_ready": False},
        )
        print(f"Controller qualification rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
