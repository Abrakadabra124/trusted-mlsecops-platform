"""Owned Kubernetes audit bootstrap; existing state is validated, never reset or adopted."""

import sys
import uuid
from pathlib import Path

from mlsecops import kube_observer_profile, kube_storage, kube_trust
from mlsecops import kube_security_materials as materials
from mlsecops import kube_security_resources as resources
from mlsecops.cluster import kubectl
from mlsecops.contracts import (
    Rejected,
    canonical,
    decode,
    digest,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.controller_bootstrap import image_profile
from mlsecops.kube_worker import job_document, verify_running_image, wait_job
from mlsecops.private_cli import Arguments
from mlsecops.storage_pki import workspace_id


def directory(state):
    return safe_child(state, "kubernetes-security")


def save(local, marker):
    write_json(safe_child(local, "resources.json"), marker)


def create(state, local, marker, document):
    key = kube_storage.reference(document)
    observed = kube_storage.get(state, document)
    if key in marker["resources"]:
        kube_storage.verify_resource(document, observed, marker["resources"][key])
        return observed
    if observed is not None:
        raise Rejected("kube_security_unowned_resource")
    observed = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], document).stdout)
    uid = observed.get("metadata", {}).get("uid")
    if type(uid) is not str or not uid:
        raise Rejected("kube_security_resource_uid")
    marker["resources"][key] = uid
    save(local, marker)
    kube_storage.verify_resource(document, observed, uid)
    return observed


def service_address(state, workspace, marker):
    expected = next(d for d in resources.base_resources(workspace) if d["kind"] == "Service")
    observed = kube_storage.get(state, expected)
    kube_storage.verify_resource(
        expected, observed, marker["resources"][kube_storage.reference(expected)]
    )
    spec = observed["spec"]
    address = materials.address(spec.get("clusterIP"))
    if spec.get("clusterIPs") != [address] or spec.get("ipFamilies") != ["IPv4"]:
        raise Rejected("kube_security_service_family")
    return address


def volume(state, document, claim_uid):
    claim = kube_storage.get(state, document)
    kube_storage.verify_resource(document, claim, claim_uid)
    name = claim["spec"].get("volumeName")
    if not name or claim.get("status", {}).get("phase") != "Bound":
        raise Rejected("kube_security_volume_unbound")
    observed = kube_storage.get(state, {"kind": "PersistentVolume", "metadata": {"name": name}})
    spec = (observed or {}).get("spec", {})
    binding = spec.get("claimRef", {})
    if (
        spec.get("persistentVolumeReclaimPolicy") != "Retain"
        or spec.get("storageClassName") != resources.CLASS
        or binding.get("uid") != claim_uid
        or binding.get("namespace") != document["metadata"]["namespace"]
        or binding.get("name") != document["metadata"]["name"]
    ):
        raise Rejected("kube_security_volume_binding")
    return {"uid": observed["metadata"]["uid"], "spec_sha256": digest(canonical(spec))}


def pod_spec(expected, observed):
    if (
        not kube_storage.matches(expected, observed)
        or observed.get("ephemeralContainers")
        or any(observed.get(name) for name in ("hostNetwork", "hostPID", "hostIPC"))
    ):
        raise Rejected("kube_security_pod_changed")
    for container in (*observed.get("initContainers", []), *observed["containers"]):
        if any(container.get(name) for name in ("env", "envFrom", "volumeDevices", "lifecycle")):
            raise Rejected("kube_security_container_changed")


def cleanup(state, local, marker, documents):
    failed = False
    for document in reversed(documents):
        key = kube_storage.reference(document)
        if key not in marker["resources"]:
            continue
        try:
            kube_storage.verify_resource(
                document, kube_storage.get(state, document), marker["resources"][key]
            )
            metadata = document["metadata"]
            kubectl(
                state,
                [
                    "delete",
                    document["kind"],
                    metadata["name"],
                    "-n",
                    metadata["namespace"],
                    "--wait=true",
                    "--timeout=30s",
                ],
            )
            if kube_storage.get(state, document) is not None:
                raise Rejected("kube_security_cleanup_incomplete")
            del marker["resources"][key]
            save(local, marker)
        except Exception:
            failed = True
    if failed:
        raise Rejected("kube_security_cleanup_unconfirmed")


def provision(state, local, marker, owned, role):
    namespace, _ = resources.identity(role)
    name = "audit-init-" + uuid.uuid4().hex
    value = owned.provision(role)
    config = resources.resource(
        "ConfigMap",
        name,
        marker["workspace_id"],
        namespace,
        immutable=True,
        data={"provision.json": canonical(value).decode()},
    )
    spec = resources.provision_spec(marker["profile"]["image"], role, name)
    job = job_document(name, namespace, spec, 120)
    job["metadata"]["labels"][resources.WORKSPACE] = marker["workspace_id"]
    documents = [config, job]
    try:
        for document in documents:
            create(state, local, marker, document)
        terminal, pod, _ = wait_job(state, namespace, name, 120)
        pod_spec(spec, pod["spec"])
        verify_running_image(pod, marker["profile"]["image_id"])
        statuses = pod.get("status", {}).get("containerStatuses", [])
        code = (
            statuses[0].get("state", {}).get("terminated", {}).get("exitCode")
            if len(statuses) == 1
            else None
        )
        if (
            terminal["type"] != "Complete"
            or type(code) is not int
            or code != 0
            or pod["metadata"].get("ownerReferences", [{}])[0].get("uid")
            != marker["resources"][kube_storage.reference(job)]
        ):
            raise Rejected("kube_security_provision_failed")
        content = kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-c",
                "worker",
                "-n",
                namespace,
                "--limit-bytes=4097",
            ],
        ).stdout
        report = decode(content, 4096)
        from mlsecops import security_events as events

        events.shape(
            report,
            (
                "schema_version",
                "role",
                "producer_id",
                "registry_sha256",
                "state_sha256",
                "release_ready",
            ),
        )
        events.version(report["schema_version"])
        pin = events.hexadecimal(report["state_sha256"])
        if (
            any(report[k] != value[k] for k in ("role", "producer_id", "registry_sha256"))
            or report["release_ready"] is not False
        ):
            raise Rejected("kube_security_provision_receipt")
        claim = next(
            d
            for d in resources.base_resources(marker["workspace_id"])
            if d["kind"] == "PersistentVolumeClaim"
            and d["metadata"]["namespace"] == namespace
            and d["metadata"]["name"] == resources.claim_name(role)
        )
        marker["volumes"][role] = volume(
            state, claim, marker["resources"][kube_storage.reference(claim)]
        )
        marker["pins"][role] = pin
        save(local, marker)
    finally:
        cleanup(state, local, marker, documents)


def runtime(marker, role):
    workspace, image = marker["workspace_id"], marker["profile"]["image"]
    if role == "trust" and marker.get("observer") is not None:
        return kube_observer_profile.deployment(
            workspace, image, marker["observer"], marker["context"]
        )
    return resources.deployment(workspace, image, role)


def desired(marker, owned):
    workspace = marker["workspace_id"]
    return [
        *resources.base_resources(workspace),
        *(
            [kube_observer_profile.mapping(workspace, marker["observer"], marker["context"])]
            if marker.get("observer") is not None
            else []
        ),
        *(
            resources.secret(
                workspace, role, owned.runtime_files(role, marker["pins"][role], marker["address"])
            )
            for role in resources.ROLES
        ),
        *(runtime(marker, role) for role in ("collector", "trust")),
    ]


def live(state, document, marker, *, require_ready=True):
    if type(require_ready) is not bool:
        raise Rejected("kube_security_readiness_mode")
    namespace = document["metadata"]["namespace"]
    selector = ",".join(
        f"{key}={value}" for key, value in document["spec"]["selector"]["matchLabels"].items()
    )
    items = decode(
        kubectl(state, ["get", "pods", "-n", namespace, "-l", selector, "-o", "json"]).stdout
    )["items"]
    if len(items) != 1:
        raise Rejected("kube_security_pod_count")
    pod = items[0]
    pod_spec(document["spec"]["template"]["spec"], pod["spec"])
    verify_running_image(pod, marker["profile"]["image_id"])
    owners = pod["metadata"].get("ownerReferences", [])
    if (
        len(owners) != 1
        or owners[0].get("kind") != "ReplicaSet"
        or owners[0].get("controller") is not True
    ):
        raise Rejected("kube_security_pod_owner")
    replica = kube_storage.get(
        state,
        {"kind": "ReplicaSet", "metadata": {"namespace": namespace, "name": owners[0]["name"]}},
    )
    parent = (replica or {}).get("metadata", {})
    owners_above = parent.get("ownerReferences", [])
    if (
        parent.get("uid") != owners[0]["uid"]
        or len(owners_above) != 1
        or owners_above[0].get("uid") != marker["resources"][kube_storage.reference(document)]
        or owners_above[0].get("kind") != "Deployment"
        or owners_above[0].get("controller") is not True
        or require_ready
        and not any(
            c.get("type") == "Ready" and c.get("status") == "True"
            for c in pod.get("status", {}).get("conditions", [])
        )
        or pod["metadata"].get("deletionTimestamp")
    ):
        raise Rejected("kube_security_runtime_not_owned_or_ready")
    return pod["metadata"]["uid"]


def validate(state, *, profile=None, environment=None, initial_root=None, authority_root=None):
    kube_storage.validate(state)
    kube_trust.validate(state)
    local = directory(state)
    marker = read_json(safe_child(local, "resources.json"))
    if (
        type(marker.get("schema_version")) is not int
        or marker.get("schema_version") != 1
        or marker.get("ready") is not True
        or marker.get("workspace_id") != workspace_id(state)
        or profile is not None
        and marker.get("profile") != profile
        or environment is not None
        and marker["context"]["environment"] != environment
        or initial_root is not None
        and marker["context"]["initial_root"] != initial_root
    ):
        raise Rejected("kube_security_profile_incomplete_or_changed")
    roots = kube_observer_profile.authorized_roots(marker.get("observer"), marker["context"])
    if authority_root is not None and authority_root not in roots:
        raise Rejected("kube_security_authority_root_unproven")
    owned = materials.load(
        safe_child(local, "materials"), workspace=marker["workspace_id"], **marker["context"]
    )
    if set(marker.get("pins", {})) != set(resources.ROLES) or set(marker.get("volumes", {})) != set(
        resources.ROLES
    ):
        raise Rejected("kube_security_state_inventory")
    documents = desired(marker, owned)
    if set(marker.get("resources", {})) != {kube_storage.reference(d) for d in documents}:
        raise Rejected("kube_security_resource_inventory")
    for document in documents:
        kube_storage.verify_resource(
            document,
            kube_storage.get(state, document),
            marker["resources"][kube_storage.reference(document)],
        )
    if service_address(state, marker["workspace_id"], marker) != marker["address"]:
        raise Rejected("kube_security_service_changed")
    for role, (namespace, _) in resources.ROLES.items():
        claim = next(
            d
            for d in documents
            if d["kind"] == "PersistentVolumeClaim"
            and d["metadata"]["namespace"] == namespace
            and d["metadata"]["name"] == resources.claim_name(role)
        )
        if (
            volume(state, claim, marker["resources"][kube_storage.reference(claim)])
            != marker["volumes"][role]
        ):
            raise Rejected("kube_security_volume_changed")
    for document in documents:
        if document["kind"] == "Deployment":
            live(state, document, marker)
    return marker


def bootstrap(root, state, *, environment, initial_root, policy, image="trusted-mlsecops:dev"):
    context = {"environment": environment, "initial_root": initial_root, "policy": policy}
    workspace = workspace_id(state)
    materials.context(workspace, **context)
    kube_storage.validate(state)
    kube_trust.validate(state)
    profile = image_profile(root, state, image)
    local = directory(state)
    if local.exists():
        materials.load(safe_child(local, "materials"), workspace=workspace, **context)
        return validate(state, profile=profile, environment=environment, initial_root=initial_root)
    base = resources.base_resources(workspace)
    if any(kube_storage.get(state, d) is not None for d in base):
        raise Rejected("kube_security_unowned_profile")
    marker = dict(
        schema_version=1,
        workspace_id=workspace,
        context=context,
        profile=profile,
        ready=False,
        resources={},
        pins={},
        volumes={},
        address=None,
    )
    save(local, marker)
    owned = materials.create(safe_child(local, "materials"), workspace=workspace, **context)
    for document in base:
        create(state, local, marker, document)
    marker["address"] = service_address(state, workspace, marker)
    save(local, marker)
    for role in resources.ROLES:
        provision(state, local, marker, owned, role)
    for document in desired(marker, owned):
        create(state, local, marker, document)
    for role in ("collector", "trust"):
        document = resources.deployment(workspace, profile["image"], role)
        kubectl(
            state,
            [
                "rollout",
                "status",
                "deployment/" + document["metadata"]["name"],
                "-n",
                document["metadata"]["namespace"],
                "--timeout=180s",
            ],
            timeout=210,
        )
    marker["ready"] = True
    save(local, marker)
    return validate(state, profile=profile, environment=environment, initial_root=initial_root)


def main(arguments=None):
    try:
        parser = Arguments(prog="kubernetes-security-events")
        parser.add_argument("--state", type=Path, required=True)
        parser.add_argument("--environment", required=True)
        parser.add_argument("--initial-root", required=True)
        parser.add_argument("--policy", required=True)
        parser.add_argument("--image", default="trusted-mlsecops:dev")
        args = parser.parse_args(arguments)
        marker = bootstrap(
            Path(__file__).resolve().parents[1],
            args.state,
            environment=args.environment,
            initial_root=args.initial_root,
            policy=args.policy,
            image=args.image,
        )
        print(
            canonical(
                dict(
                    status="provisioned",
                    registry_sha256=materials.load(
                        directory(args.state) / "materials",
                        workspace=marker["workspace_id"],
                        **marker["context"],
                    ).registry.sha256,
                    release_ready=False,
                )
            ).decode()
        )
        return 0
    except (Exception, KeyboardInterrupt, SystemExit) as error:
        print("kube_security_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
