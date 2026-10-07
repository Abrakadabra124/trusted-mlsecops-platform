import argparse
import copy
import ipaddress
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from mlsecops import kube_storage, storage, storage_pki
from mlsecops.cluster import CONTEXT, NAMESPACES, kubectl
from mlsecops.contracts import Rejected, canonical, decode, digest, now, read_json, write_json
from mlsecops.inventory import source_fingerprint
from mlsecops.kube_storage_resources import CLIENT_NAMESPACES, NAMESPACE, client_pod_spec, postgres
from mlsecops.kube_worker import job_document, load_image, pod_spec, verify_running_image, wait_job
from mlsecops.sandbox import resolve_image
from mlsecops.storage_bootstrap import IMAGE, export_clients
from mlsecops.storage_snapshot import ledger_sql, validate_ledger


def probe(state, image, image_id, namespace, identity, action, address=None, port=5432):
    name = f"storage-probe-{uuid.uuid4().hex}"
    arguments = ["mlsecops.kube_storage_probe", action]
    if address:
        arguments.extend(["--address", address, "--port", str(port)])
    if action in {"sql", "maintenance"}:
        arguments.extend(["--role", identity])
    spec = pod_spec(image, identity, arguments, memory="256Mi")
    if action in {"sql", "maintenance"}:
        spec = client_pod_spec(image, identity, arguments)
    job = job_document(name, namespace, spec, 90)
    created = False
    try:
        kubectl(state, ["create", "-f", "-"], job)
        created = True
        terminal, pod, _ = wait_job(state, namespace, name, 90)
        verify_running_image(pod, image_id)
        output = kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-c",
                "worker",
                "-n",
                namespace,
                "--limit-bytes=65537",
            ],
        ).stdout
        if terminal["type"] != "Complete":
            raise Rejected(f"cluster_storage_probe_failed:{identity}:{action}")
        return decode(output, 65536)
    finally:
        if created:
            kubectl(
                state,
                ["delete", "job", name, "-n", namespace, "--wait=true", "--timeout=30s"],
            )


def identity_checks(state, confirmed):
    original = decode(kubectl(state, ["config", "view", "--raw", "-o", "json"]).stdout)
    for role, namespace in CLIENT_NAMESPACES.items():
        token = (
            kubectl(state, ["create", "token", role, "-n", namespace, "--duration=10m"])
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
        with tempfile.TemporaryDirectory(prefix="storage-api-probe-", dir=state) as temporary:
            path = Path(temporary) / "config.json"
            write_json(path, config)
            for target in (namespace, NAMESPACE, "ml-control"):
                result = kubectl(state, ["get", "secrets", "-n", target], config=path, check=False)
                confirmed(
                    f"{role}:api-read-secrets:{target}",
                    result.returncode != 0 and b"Forbidden" in result.stderr,
                )
            result = kubectl(
                state,
                ["create", "-f", "-"],
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "unauthorized-probe", "namespace": namespace},
                    "spec": {
                        "containers": [
                            {
                                "name": "bad",
                                "image": "invalid.invalid/never-pulled",
                                "securityContext": {"privileged": True},
                            }
                        ]
                    },
                },
                config=path,
                check=False,
            )
            confirmed(
                f"{role}:api-create-privileged-pod",
                result.returncode != 0 and b"Forbidden" in result.stderr,
            )


def configuration_checks(state, confirmed):
    with tempfile.TemporaryDirectory(prefix="storage-config-probe-", dir=state) as temporary:
        directory = Path(temporary)
        write_json(
            directory / "workspace.json",
            {"schema_version": 1, "product": "trusted-mlsecops", "workspace_id": uuid.uuid4().hex},
        )
        before = storage_pki.initialize(directory, storage_pki.CLUSTER_HOST)
        confirmed(
            "pki-dns-idempotent",
            storage_pki.initialize(directory, storage_pki.CLUSTER_HOST) == before,
        )
        try:
            storage_pki.validate(directory)
        except Rejected as error:
            confirmed(
                "pki-cross-profile-rejected", str(error) == "storage_certificate_host_mismatch"
            )
        else:
            confirmed("pki-cross-profile-rejected", False)
        export_clients(directory, 5432, storage_pki.CLUSTER_HOST)
        client = directory / "storage-clients/publisher"
        settings = read_json(client / "connection.json")
        parameters = storage.connection_parameters(client)
        confirmed(
            "client-verify-full-fixed-dns",
            parameters["host"] == storage_pki.CLUSTER_HOST
            and parameters["hostaddr"] == ""
            and parameters["sslmode"] == "verify-full",
        )
        for host, port in (
            ("evil.invalid", 5432),
            ("127.0.0.2", 5432),
            (storage_pki.CLUSTER_HOST, 15439),
        ):
            write_json(client / "connection.json", {**settings, "host": host, "port": port})
            try:
                storage.connection_parameters(client)
            except Rejected as error:
                confirmed(
                    f"invalid-client-endpoint:{host}:{port}",
                    str(error) == "storage_client_config_invalid",
                )
            else:
                confirmed("invalid-client-endpoint", False)
        write_json(client / "connection.json", settings)
        (client / ".no-passwords").write_bytes(b"")
        try:
            storage.connection_parameters(client)
        except Rejected as error:
            confirmed(
                "unexpected-password-file-rejected", str(error) == "storage_password_file_forbidden"
            )
        else:
            confirmed("unexpected-password-file-rejected", False)


def qualify(root, state, image):
    state = Path(state).resolve()
    cases = []

    def confirmed(name, condition):
        if not condition:
            raise Rejected(f"cluster_storage_qualification_failed:{name}")
        cases.append({"id": name, "status": "pass"})

    image_id = resolve_image(image)
    configuration_checks(state, confirmed)
    marker = kube_storage.validate(state)
    before_pki = read_json(kube_storage.local_state(state) / "storage-pki/identity.json")
    repeated = kube_storage.bootstrap(state)
    after = kube_storage.validate(state)
    confirmed("bootstrap-resource-uids", marker["resources"] == after["resources"])
    confirmed(
        "bootstrap-volume-and-pod",
        marker["volume_uid"] == repeated["volume_uid"] and marker["pod_uid"] == repeated["pod_uid"],
    )
    confirmed(
        "bootstrap-certificates",
        before_pki == read_json(kube_storage.local_state(state) / "storage-pki/identity.json"),
    )
    expected = postgres("a" * 32)
    for name, change in (
        ("identity", lambda item: item["metadata"].update(uid="foreign")),
        (
            "image",
            lambda item: item["spec"]["template"]["spec"]["containers"][0].update(image="other"),
        ),
        (
            "sidecar",
            lambda item: item["spec"]["template"]["spec"]["containers"].append({"name": "other"}),
        ),
        ("host-network", lambda item: item["spec"]["template"]["spec"].update(hostNetwork=True)),
        (
            "token",
            lambda item: item["spec"]["template"]["spec"].update(automountServiceAccountToken=True),
        ),
    ):
        observed = copy.deepcopy(expected)
        observed["metadata"]["uid"] = "owned"
        change(observed)
        try:
            kube_storage.verify_resource(expected, observed, "owned")
        except Rejected:
            confirmed(f"spec-fixture:{name}", True)
        else:
            confirmed(f"spec-fixture:{name}", False)
    baseline = validate_ledger(decode(kube_storage.admin(state, ledger_sql())))
    tag, loaded = load_image(state, image)
    confirmed("loaded-image", loaded == image_id)
    for role, namespace in CLIENT_NAMESPACES.items():
        result = probe(state, tag, image_id, namespace, role, "sql")
        confirmed(
            f"{role}:suite-complete",
            result.get("status") == "pass"
            and result.get("role") == role
            and result.get("count") == len(result.get("cases", []))
            and result["count"] == 63,
        )
        cases.extend(result["cases"])
    confirmed(
        "sql-probes-rolled-back",
        baseline == validate_ledger(decode(kube_storage.admin(state, ledger_sql()))),
    )
    identity_checks(state, confirmed)
    service = decode(
        kubectl(state, ["get", "service", "postgres", "-n", NAMESPACE, "-o", "json"]).stdout
    )
    address = str(ipaddress.ip_address(service["spec"]["clusterIP"]))
    confirmed(
        "clusterip-no-public-port",
        service["spec"]["type"] == "ClusterIP"
        and not service["spec"].get("externalIPs")
        and not any(port.get("nodePort") for port in service["spec"]["ports"]),
    )
    for namespace, identity in (
        ("ml-train", NAMESPACES["ml-train"]),
        ("ml-eval", NAMESPACES["ml-eval"]),
        (CLIENT_NAMESPACES["publisher"], "default"),
    ):
        result = probe(state, tag, image_id, namespace, identity, "network", address)
        confirmed(f"network-denied:{namespace}:{identity}", result == {"result": "timeout"})
    result = probe(
        state, tag, image_id, CLIENT_NAMESPACES["publisher"], "publisher", "network", address
    )
    confirmed("network-positive-same-endpoint", result == {"result": "connected"})
    dns = decode(
        kubectl(state, ["get", "service", "kube-dns", "-n", "kube-system", "-o", "json"]).stdout
    )
    dns_address = str(ipaddress.ip_address(dns["spec"]["clusterIP"]))
    if ipaddress.ip_address(dns_address) not in ipaddress.ip_network("10.79.0.0/16"):
        raise Rejected("storage_dns_probe_target_invalid")
    result = probe(
        state,
        tag,
        image_id,
        CLIENT_NAMESPACES["publisher"],
        "publisher",
        "network",
        dns_address,
        port=53,
    )
    confirmed("dns-tcp-positive-control", result == {"result": "connected"})
    result = kubectl(
        state,
        [
            "exec",
            "postgres-0",
            "-n",
            NAMESPACE,
            "-c",
            "postgres",
            "--",
            "bash",
            "-c",
            'timeout 3 bash -c \'exec 3<>/dev/tcp/"$1"/53\' probe "$1"; printf "%s" "$?"',
            "probe",
            dns_address,
        ],
    )
    confirmed("postgres-egress-dns-denied", result.stdout == b"124")
    payload = canonical({"kind": "kubernetes-persistence-probe", "nonce": uuid.uuid4().hex})
    identifier = digest(payload)
    kube_storage.admin(
        state,
        f"INSERT INTO ml.quarantine (sha256,payload) VALUES ('{identifier}',decode('{payload.hex()}','hex'));",
    )
    try:
        kube_storage.validate(state)
        kubectl(
            state,
            ["delete", "pod", "postgres-0", "-n", NAMESPACE, "--wait=true", "--timeout=60s"],
            timeout=75,
        )
        kubectl(
            state,
            ["rollout", "status", "statefulset/postgres", "-n", NAMESPACE, "--timeout=120s"],
            timeout=150,
        )
        restored = kube_storage.validate(state)
        confirmed(
            "replacement-pod-same-volume",
            restored["pod_uid"] != marker["pod_uid"]
            and restored["volume_uid"] == marker["volume_uid"],
        )
        confirmed(
            "persistent-object-bytes",
            kube_storage.admin(
                state,
                f"SELECT encode(payload,'hex') FROM ml.quarantine WHERE sha256='{identifier}';",
            )
            == payload.hex(),
        )
    finally:
        kube_storage.admin(
            state,
            f"DELETE FROM ml.quarantine WHERE sha256='{identifier}' AND payload=decode('{payload.hex()}','hex');",
        )
    confirmed(
        "persistence-probe-cleaned",
        baseline == validate_ledger(decode(kube_storage.admin(state, ledger_sql()))),
    )
    server_pod = decode(
        kubectl(state, ["get", "pod", "postgres-0", "-n", NAMESPACE, "-o", "json"]).stdout
    )
    verify_running_image(server_pod, IMAGE.split("@", 1)[1])
    confirmed("actual-postgres-image", True)
    return {
        "schema_version": 1,
        "observed_at": now(),
        "status": "pass",
        "scope": "private-cluster-storage-component-not-M04-or-M20",
        "release_ready": False,
        "source_fingerprint": source_fingerprint(root),
        "worker_image": image_id,
        "postgres_image": IMAGE,
        "volume_uid": marker["volume_uid"],
        "cases": cases,
        "count": len(cases),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    output = arguments.state / "evidence/kubernetes-storage-qualification.json"
    try:
        report = qualify(Path(__file__).resolve().parents[1], arguments.state, arguments.image)
        write_json(output, report)
        print(canonical(report).decode())
        return 0
    except (Rejected, OSError, subprocess.TimeoutExpired) as error:
        write_json(
            output,
            {"status": "fail", "observed_at": now(), "reason": str(error), "release_ready": False},
        )
        print(f"Cluster storage qualification rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
