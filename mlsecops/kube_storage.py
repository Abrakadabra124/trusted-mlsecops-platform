import argparse
import subprocess
import sys
from pathlib import Path

from mlsecops import storage_pki
from mlsecops.cluster import CONTEXT, kubectl, validate_cluster
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.kube_storage_resources import CLASS, NAMESPACE, resources
from mlsecops.storage_bootstrap import IMAGE, configuration, export_clients, migrate
from mlsecops.storage_schema import DATABASE
from mlsecops.storage_snapshot import binary_command


def local_state(state):
    return safe_child(state, "kubernetes-storage")


def matches(expected, actual):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            (name in actual and matches(value, actual[name]))
            or (
                name not in actual
                and name in {"hostNetwork", "hostPID", "hostIPC"}
                and value is False
            )
            for name, value in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(expected) == len(actual)
            and all(matches(left, right) for left, right in zip(expected, actual, strict=True))
        )
    return type(expected) is type(actual) and expected == actual


def desired(state):
    directory = local_state(state)
    identity = storage_pki.workspace_id(state)
    if storage_pki.workspace_id(directory) != identity:
        raise Rejected("cluster_storage_workspace_mismatch")
    storage_pki.validate(directory, storage_pki.CLUSTER_HOST)
    server = configuration()
    for name in ("ca.crt", "server.crt", "server.key"):
        server[name] = bounded_read(safe_child(directory, f"storage-pki/{name}"), 4096)
    clients = {
        role: {
            name: bounded_read(safe_child(directory, f"storage-clients/{role}/{name}"), 4096)
            for name in ("ca.crt", "client.crt", "client.key", "connection.json")
        }
        for role in storage_pki.ROLES
    }
    return resources(identity, server, clients)


def reference(document):
    metadata = document["metadata"]
    return "/".join((document["kind"], metadata.get("namespace", "_"), metadata["name"]))


def get(state, document):
    metadata = document["metadata"]
    arguments = ["get", document["kind"], metadata["name"], "-o", "json", "--ignore-not-found"]
    if metadata.get("namespace"):
        arguments.extend(["-n", metadata["namespace"]])
    content = kubectl(state, arguments).stdout
    return decode(content) if content.strip() else None


def verify_resource(document, observed, expected_uid):
    if not observed or observed.get("metadata", {}).get("uid") != expected_uid:
        raise Rejected(f"cluster_storage_resource_identity_changed:{reference(document)}")
    if not matches(document, observed):
        raise Rejected(f"cluster_storage_resource_drift:{reference(document)}")
    if document["kind"] in {"NetworkPolicy", "CiliumNetworkPolicy"} and document[
        "spec"
    ] != observed.get("spec"):
        raise Rejected("cluster_storage_network_rules_changed")
    if document["kind"] == "Secret" and document["data"] != observed.get("data"):
        raise Rejected("cluster_storage_secret_contents_changed")
    if document["kind"] == "StatefulSet":
        spec = observed["spec"]["template"]["spec"]
        if spec.get("initContainers") or spec.get("ephemeralContainers"):
            raise Rejected("cluster_storage_injected_container")
    if document["kind"] == "Service" and (
        observed["spec"].get("externalIPs") or observed["spec"].get("externalName")
    ):
        raise Rejected("cluster_storage_external_service_forbidden")


def command_arguments(state, arguments):
    return [
        "kubectl",
        "--kubeconfig",
        str((Path(state) / "kubeconfig").resolve()),
        "--context",
        CONTEXT,
        "--request-timeout=30s",
        "exec",
        "-i",
        "postgres-0",
        "-n",
        NAMESPACE,
        "-c",
        "postgres",
        "--",
        *arguments,
    ]


def execute(state, arguments, content=None, timeout=30, limit=65536):
    return binary_command(
        command_arguments(state, arguments),
        content=content,
        timeout=timeout,
        output_limit=limit,
    )


def admin(state, statement, database=DATABASE):
    return (
        execute(
            state,
            [
                "psql",
                "-X",
                "-qAt",
                "-v",
                "ON_ERROR_STOP=1",
                "-h",
                "/tmp",
                "-U",
                "postgres",
                "-d",
                database,
            ],
            statement.encode(),
        )
        .decode()
        .strip()
    )


def live_state(state, marker):
    claim = decode(
        kubectl(state, ["get", "pvc", "postgres-data", "-n", NAMESPACE, "-o", "json"]).stdout
    )
    volume_name = claim.get("spec", {}).get("volumeName")
    if claim.get("status", {}).get("phase") != "Bound" or not volume_name:
        raise Rejected("cluster_storage_volume_unbound")
    volume = decode(kubectl(state, ["get", "pv", volume_name, "-o", "json"]).stdout)
    binding = volume["spec"].get("claimRef", {})
    if (
        volume["spec"].get("persistentVolumeReclaimPolicy") != "Retain"
        or volume["spec"].get("storageClassName") != CLASS
        or binding.get("uid") != claim["metadata"]["uid"]
        or binding.get("namespace") != NAMESPACE
        or binding.get("name") != "postgres-data"
        or (marker.get("volume_uid") and marker["volume_uid"] != volume["metadata"]["uid"])
    ):
        raise Rejected("cluster_storage_volume_identity_or_retention_changed")
    pod = decode(kubectl(state, ["get", "pod", "postgres-0", "-n", NAMESPACE, "-o", "json"]).stdout)
    template = next(document for document in desired(state) if document["kind"] == "StatefulSet")
    if (
        not matches(template["spec"]["template"]["spec"], pod["spec"])
        or pod["spec"].get("initContainers")
        or pod["spec"].get("ephemeralContainers")
        or not any(
            condition["type"] == "Ready" and condition["status"] == "True"
            for condition in pod.get("status", {}).get("conditions", [])
        )
    ):
        raise Rejected("cluster_storage_pod_not_ready_or_policy_changed")
    if (
        admin(
            state,
            "SELECT current_setting('server_version_num') || ':' || current_setting('data_checksums');",
        )
        != "180006:on"
    ):
        raise Rejected("cluster_storage_server_version_or_checksums_invalid")
    if admin(state, "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL;") != "0":
        raise Rejected("cluster_storage_hba_invalid")
    return {"volume_uid": volume["metadata"]["uid"], "pod_uid": pod["metadata"]["uid"]}


def validate(state):
    validate_cluster(state)
    marker = read_json(safe_child(local_state(state), "resources.json"))
    documents = desired(state)
    if marker.get("spec_digest") != digest(canonical(documents)):
        raise Rejected("cluster_storage_spec_change_requires_migration")
    if set(marker.get("resources", {})) != {reference(document) for document in documents}:
        raise Rejected("cluster_storage_resource_inventory_incomplete")
    for document in documents:
        verify_resource(document, get(state, document), marker["resources"][reference(document)])
    return {**marker, **live_state(state, marker)}


def bootstrap(state):
    state = Path(state).resolve()
    validate_cluster(state)
    directory = local_state(state)
    workspace = read_json(safe_child(state, "workspace.json"))
    if not directory.exists():
        write_json(directory / "workspace.json", workspace)
    if read_json(safe_child(directory, "workspace.json")) != workspace:
        raise Rejected("cluster_storage_workspace_mismatch")
    storage_pki.initialize(directory, storage_pki.CLUSTER_HOST)
    export_clients(directory, 5432, storage_pki.CLUSTER_HOST)
    documents = desired(state)
    marker_path = safe_child(directory, "resources.json")
    fingerprint = digest(canonical(documents))
    if marker_path.exists():
        marker = read_json(marker_path)
        if marker.get("spec_digest") != fingerprint:
            raise Rejected("cluster_storage_spec_change_requires_migration")
    else:
        if any(get(state, document) is not None for document in documents):
            raise Rejected("cluster_storage_unowned_resources")
        marker = {"schema_version": 1, "spec_digest": fingerprint, "resources": {}, "ready": False}
        write_json(marker_path, marker)
    for document in documents:
        key = reference(document)
        observed = get(state, document)
        if key in marker["resources"]:
            verify_resource(document, observed, marker["resources"][key])
        else:
            if observed is not None:
                raise Rejected(f"cluster_storage_unowned_resource:{key}")
            created = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], document).stdout)
            marker["resources"][key] = created["metadata"]["uid"]
            write_json(marker_path, marker)
            verify_resource(document, created, marker["resources"][key])
    kubectl(
        state,
        ["rollout", "status", "statefulset/postgres", "-n", NAMESPACE, "--timeout=180s"],
        timeout=210,
    )
    migration = migrate(state, execute=admin)
    marker.update(live_state(state, marker))
    marker["ready"] = True
    write_json(marker_path, marker)
    validate(state)
    return {
        "schema_version": 1,
        "observed_at": now(),
        "status": "ready",
        "scope": "private-cluster-storage-component",
        "image": IMAGE,
        "host": storage_pki.CLUSTER_HOST,
        "port": 5432,
        "migration": migration,
        "spec_digest": fingerprint,
        "resource_count": len(documents),
        "volume_uid": marker["volume_uid"],
        "pod_uid": marker["pod_uid"],
        "release_ready": False,
    }


def main():
    parser = argparse.ArgumentParser(description="Private, additive Kubernetes storage profile")
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    arguments = parser.parse_args()
    try:
        report = bootstrap(arguments.state)
        write_json(arguments.state / "evidence/kubernetes-storage-bootstrap.json", report)
        print(canonical(report).decode())
        return 0
    except (Rejected, OSError, subprocess.TimeoutExpired) as error:
        print(f"Cluster storage rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
