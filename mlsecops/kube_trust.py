"""Separate, owned Kubernetes trust authority using the existing PostgreSQL image."""

import sys
from pathlib import Path

from mlsecops import kube_storage, storage_pki
from mlsecops.cluster import kubectl, validate_cluster
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.kube_storage_resources import (
    ACCOUNT,
    CLASS,
    POD_NAMESPACE,
    client_pod_spec,
    namespace_resources,
    postgres,
    resource,
)
from mlsecops.private_cli import Arguments
from mlsecops.signing import encode64
from mlsecops.storage_bootstrap import IMAGE, configuration, export_clients, migrate
from mlsecops.storage_schema import DATABASE
from mlsecops.storage_snapshot import binary_command

NAMESPACE = "ml-trust"
READERS = ("promoter", "serving")


def server_configuration():
    files = configuration()
    files["pg_hba.conf"] = (
        b"local all postgres peer\nlocal all all reject\n"
        b"hostssl mlsecops ml_promoter,ml_serving 0.0.0.0/0 cert\n"
        b"hostssl mlsecops ml_promoter,ml_serving ::/0 cert\n"
        b"host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n"
    )
    return files


def resources(workspace, server_files, clients):
    items = namespace_resources(NAMESPACE, "postgres", workspace)
    items.extend(
        [
            resource(
                "CiliumNetworkPolicy",
                "trust-boundary",
                workspace,
                NAMESPACE,
                spec={
                    "endpointSelector": {},
                    "egressDeny": [{"toEntities": ["all"]}],
                    "ingress": [
                        {
                            "fromEndpoints": [
                                {
                                    "matchLabels": {
                                        POD_NAMESPACE: f"ml-{role}",
                                        ACCOUNT: role,
                                    }
                                }
                                for role in READERS
                            ],
                            "toPorts": [{"ports": [{"port": "5432", "protocol": "TCP"}]}],
                        }
                    ],
                },
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
    for role in READERS:
        items.extend(
            [
                resource(
                    "Secret",
                    "trust-client",
                    workspace,
                    f"ml-{role}",
                    immutable=True,
                    type="Opaque",
                    data={name: encode64(content) for name, content in clients[role].items()},
                ),
                resource(
                    "CiliumNetworkPolicy",
                    "trust-client",
                    workspace,
                    f"ml-{role}",
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
                            }
                        ],
                    },
                ),
            ]
        )
    server = postgres(workspace)
    server["metadata"]["namespace"] = NAMESPACE
    items.append(server)
    return items


def client_spec(image, role, arguments):
    if role not in READERS:
        raise Rejected("trust_reader_role")
    spec = client_pod_spec(image, role, arguments)
    spec["volumes"][1]["secret"]["secretName"] = "trust-client"
    return spec


def directory(state):
    return safe_child(state, "kubernetes-trust")


def desired(state):
    local = directory(state)
    workspace = storage_pki.workspace_id(state)
    if storage_pki.workspace_id(local) != workspace:
        raise Rejected("trust_workspace_mismatch")
    storage_pki.validate(local, storage_pki.TRUST_HOST)
    server = server_configuration()
    for name in ("ca.crt", "server.crt", "server.key"):
        server[name] = bounded_read(safe_child(local, f"storage-pki/{name}"), 4096)
    clients = {
        role: {
            name: bounded_read(safe_child(local, f"storage-clients/{role}/{name}"), 4096)
            for name in ("ca.crt", "client.crt", "client.key", "connection.json")
        }
        for role in READERS
    }
    return resources(workspace, server, clients)


def admin(state, statement, database=DATABASE):
    arguments = kube_storage.command_arguments(
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
        namespace=NAMESPACE,
    )
    return (
        binary_command(arguments, content=statement.encode(), timeout=30, output_limit=65536)
        .decode()
        .strip()
    )


def live(state, marker):
    claim = kube_storage.get(
        state, {"kind": "pvc", "metadata": {"name": "postgres-data", "namespace": NAMESPACE}}
    )
    volume_name = (claim or {}).get("spec", {}).get("volumeName")
    if not volume_name or claim.get("status", {}).get("phase") != "Bound":
        raise Rejected("trust_volume_unbound")
    volume = kube_storage.get(state, {"kind": "pv", "metadata": {"name": volume_name}})
    spec = (volume or {}).get("spec", {})
    if (
        spec.get("persistentVolumeReclaimPolicy") != "Retain"
        or spec.get("storageClassName") != CLASS
        or spec.get("claimRef", {}).get("uid") != claim["metadata"]["uid"]
        or spec.get("claimRef", {}).get("namespace") != NAMESPACE
        or spec.get("claimRef", {}).get("name") != "postgres-data"
        or (marker.get("volume_uid") and marker["volume_uid"] != volume["metadata"]["uid"])
    ):
        raise Rejected("trust_volume_binding_changed")
    pod = kube_storage.get(
        state, {"kind": "pod", "metadata": {"name": "postgres-0", "namespace": NAMESPACE}}
    )
    template = postgres(storage_pki.workspace_id(state))["spec"]["template"]["spec"]
    if (
        not pod
        or not kube_storage.matches(template, pod["spec"])
        or pod["spec"].get("initContainers")
        or pod["spec"].get("ephemeralContainers")
        or not any(
            c["type"] == "Ready" and c["status"] == "True"
            for c in pod.get("status", {}).get("conditions", [])
        )
    ):
        raise Rejected("trust_pod_not_ready_or_changed")
    if (
        admin(
            state,
            "SELECT current_setting('server_version_num') || ':' || current_setting('data_checksums');",
        )
        != "180006:on"
    ):
        raise Rejected("trust_server_version_or_checksums")
    if admin(state, "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL;") != "0":
        raise Rejected("trust_hba_invalid")
    if (
        admin(
            state,
            "SELECT has_schema_privilege('ml_promoter','ml','USAGE') OR has_schema_privilege('ml_serving','ml','USAGE');",
        )
        != "f"
    ):
        raise Rejected("trust_reader_has_model_storage_access")
    return {"volume_uid": volume["metadata"]["uid"], "pod_uid": pod["metadata"]["uid"]}


def validate(state):
    validate_cluster(state)
    marker = read_json(safe_child(directory(state), "resources.json"))
    documents = desired(state)
    if (
        not marker.get("ready")
        or marker.get("spec_digest") != digest(canonical(documents))
        or set(marker.get("resources", {})) != {kube_storage.reference(d) for d in documents}
    ):
        raise Rejected("trust_resources_incomplete_or_changed")
    for document in documents:
        kube_storage.verify_resource(
            document,
            kube_storage.get(state, document),
            marker["resources"][kube_storage.reference(document)],
        )
    return {**marker, **live(state, marker)}


def binding(state):
    validate(state)
    return state, admin


def bootstrap(state):
    state = Path(state).resolve()
    kube_storage.validate(state)  # Own shared reader namespaces and Retain storage class first.
    local = directory(state)
    workspace = read_json(safe_child(state, "workspace.json"))
    if not local.exists():
        write_json(local / "workspace.json", workspace)
    if read_json(safe_child(local, "workspace.json")) != workspace:
        raise Rejected("trust_workspace_mismatch")
    storage_pki.initialize(local, storage_pki.TRUST_HOST)
    export_clients(local, 5432, storage_pki.TRUST_HOST)
    documents = desired(state)
    fingerprint = digest(canonical(documents))
    path = safe_child(local, "resources.json")
    if path.exists():
        marker = read_json(path)
        if marker.get("spec_digest") != fingerprint:
            raise Rejected("trust_change_requires_migration")
    else:
        if any(kube_storage.get(state, d) is not None for d in documents):
            raise Rejected("trust_unowned_resources")
        marker = {"schema_version": 1, "spec_digest": fingerprint, "resources": {}, "ready": False}
        write_json(path, marker)
    for document in documents:
        key = kube_storage.reference(document)
        observed = kube_storage.get(state, document)
        if key in marker["resources"]:
            kube_storage.verify_resource(document, observed, marker["resources"][key])
        else:
            if observed is not None:
                raise Rejected("trust_unowned_resource")
            observed = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], document).stdout)
            marker["resources"][key] = observed["metadata"]["uid"]
            write_json(path, marker)
            kube_storage.verify_resource(document, observed, marker["resources"][key])
    kubectl(
        state,
        ["rollout", "status", "statefulset/postgres", "-n", NAMESPACE, "--timeout=180s"],
        timeout=210,
    )
    migration = migrate(state, execute=admin)
    admin(state, "REVOKE ALL ON SCHEMA ml FROM ml_promoter, ml_serving;")
    marker.update(live(state, marker), ready=True)
    write_json(path, marker)
    validate(state)
    return {
        "status": "ready",
        "host": storage_pki.TRUST_HOST,
        "image": IMAGE,
        "spec_digest": fingerprint,
        "migration": migration,
        "release_ready": False,
    }


def main(arguments=None):
    try:
        parser = Arguments(prog="kubernetes-trust")
        parser.add_argument("--state", type=Path, required=True)
        options = parser.parse_args(arguments)
        print(canonical(bootstrap(options.state)).decode())
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print("kubernetes_trust_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
