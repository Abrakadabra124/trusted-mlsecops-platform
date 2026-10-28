"""Read-only image inventory for an owned lab; snapshots stay in private evidence."""

import re
from pathlib import Path

from mlsecops import storage_bootstrap
from mlsecops.cluster import NAME, NODE, kubectl, validate_cluster
from mlsecops.contracts import Rejected, canonical, decode, read_json, safe_child
from mlsecops.controller_bootstrap import verify_saved
from mlsecops.controller_worker import validate_profile
from mlsecops.foundation import image_inventory, pod_inventory
from mlsecops.inventory import command, source_fingerprint
from mlsecops.kube_worker import image_config
from mlsecops.storage_bootstrap import WORKSPACE_LABEL
from mlsecops.storage_pki import workspace_id
from scripts import tracking_service


def image_digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
        raise Rejected("image_scope_digest_invalid")
    return value


def registry_reference(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9./:_-]{0,511}@sha256:[a-f0-9]{64}", value
    ):
        raise Rejected("image_scope_registry_reference_invalid")
    return value


def local_reference(value):
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]{0,511}", value)
        or ":" not in value
        or "://" in value
    ):
        raise Rejected("image_scope_local_reference_invalid")
    return value


def observe(stage, operation, *arguments):
    try:
        return operation(*arguments)
    except Rejected as error:
        if str(error) in {"required_tool_failed", "required_tool_unavailable"}:
            raise Rejected("image_scope_" + str(error) + ":" + stage) from error
        raise


def collect(root, state):
    try:
        return _collect(Path(root).resolve(), Path(state).resolve())
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("image_scope_observation_invalid") from error


def _collect(root, state):
    owner = workspace_id(state)
    cluster = observe("cluster-ownership", validate_cluster, state)
    if cluster["workspace_id"] != owner:
        raise Rejected("image_scope_workspace_changed")
    controllers = observe(
        "controller-resources",
        verify_saved,
        state,
        read_json(safe_child(state, "controllers/resources.json")),
    )
    profile = controllers["profile"]
    validate_profile(profile)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    fingerprint = source_fingerprint(root)
    if (
        controllers["ready"] is not True
        or not controllers["resources"]
        or profile["source_revision"] != revision
        or profile["source_fingerprint"] != fingerprint
        or observe("controller-image-config", image_config, profile["image_id"])
        != profile["config_id"]
        or observe("controller-manifest-config", image_config, profile["manifest_id"])
        != profile["config_id"]
    ):
        raise Rejected("image_scope_controller_binding_invalid")
    observe("storage-resources", storage_bootstrap.validate, state)
    targets, containers, local_references = {}, [], {}

    def target(reference, config_id=None):
        if config_id is not None:
            image_digest(config_id)
        if reference.startswith("sha256:"):
            image_digest(reference)
        else:
            registry_reference(reference)
        if reference in targets and targets[reference] != config_id:
            raise Rejected("image_scope_ambiguous_target")
        targets[reference] = config_id
        if len(targets) > 64:
            raise Rejected("image_scope_target_limit")

    def container(observed, role):
        identifier = observed["Id"]
        if (
            not isinstance(identifier, str)
            or not re.fullmatch(r"[a-f0-9]{64}", identifier)
            or any(item["id"] == identifier for item in containers)
        ):
            raise Rejected("image_scope_container_identity_invalid")
        reference = observe(
            "host-image-metadata", image_inventory, image_digest(observed["Image"])
        )["image_id"]
        config = profile["config_id"] if reference == profile["image_id"] else None
        target(reference, config)
        containers.append({"id": identifier, "role": role, "image_id": reference})

    target(profile["image_id"], profile["config_id"])
    node = decode(observe("node-inspect", command, ["docker", "inspect", NODE]).encode())[0]
    if node["Config"].get("Labels", {}).get("io.x-k8s.kind.cluster") != NAME:
        raise Rejected("image_scope_node_ownership_invalid")
    container(node, "kind-node")
    identifiers = observe(
        "workspace-container-list",
        command,
        [
            "docker",
            "ps",
            "-a",
            "--no-trunc",
            "--filter",
            f"label={WORKSPACE_LABEL}={owner}",
            "--format",
            "{{.ID}}",
        ],
    ).splitlines()
    if (
        len(identifiers) > 256
        or len(set(identifiers)) != len(identifiers)
        or any(not re.fullmatch(r"[a-f0-9]{64}", value) for value in identifiers)
    ):
        raise Rejected("image_scope_container_list_invalid")
    for identifier in sorted(identifiers):
        observed = decode(
            observe(
                "workspace-container-inspect", command, ["docker", "inspect", identifier]
            ).encode()
        )[0]
        if (
            observed["Id"] != identifier
            or observed["Config"].get("Labels", {}).get(WORKSPACE_LABEL) != owner
        ):
            raise Rejected("image_scope_container_ownership_invalid")
        container(observed, "workspace")
    tracking_state = safe_child(state, "tracking-service")
    tracking = observe(
        "tracking-resources",
        tracking_service.verify,
        tracking_state,
        read_json(safe_child(tracking_state, "configuration.json")),
    )
    for role in ("pg", "server"):
        container(tracking[role], "tracking-" + role)
    document = decode(
        observe("pod-list", kubectl, state, ["get", "pods", "-A", "-o", "json"]).stdout
    )
    if not isinstance(document["items"], list) or not 1 <= len(document["items"]) <= 256:
        raise Rejected("image_scope_pod_limit")
    pods = sorted(pod_inventory(document), key=canonical)
    for pod in pods:
        config = observe("pod-image-config", image_config, pod["image_id"])
        if config == profile["config_id"]:
            target(profile["image_id"], config)
            continue
        status = decode(
            observe(
                "pod-cri-identity",
                command,
                [
                    "docker",
                    "exec",
                    NODE,
                    "crictl",
                    "inspecti",
                    config,
                ],
            ).encode()
        )["status"]
        references = status["repoDigests"]
        if status["id"] != config:
            raise Rejected("image_scope_cri_config_mismatch")
        if not isinstance(references, list) or len(references) > 16:
            raise Rejected("image_scope_cri_references_invalid")
        if not references:
            tags = status.get("repoTags")
            if not isinstance(tags, list) or not 1 <= len(tags) <= 16:
                raise Rejected("image_scope_cri_references_missing")
            alias = min(local_reference(value) for value in tags)
            if config not in targets:
                target(config, config)
                local_references[config] = alias
            elif targets[config] not in {None, config}:
                raise Rejected("image_scope_ambiguous_target")
            targets[config] = config
            if config in local_references and local_references[config] != alias:
                raise Rejected("image_scope_local_reference_changed")
            continue
        reference = min(registry_reference(value) for value in references)
        if observe("pod-manifest-config", image_config, reference.split("@", 1)[1]) != config:
            raise Rejected("image_scope_cri_manifest_mismatch")
        target(reference, config)
        tags = status.get("repoTags")
        if tags:
            if not isinstance(tags, list) or len(tags) > 16:
                raise Rejected("image_scope_cri_references_invalid")
            local_references[reference] = min(local_reference(value) for value in tags)
    return {
        "schema_version": 1,
        "workspace_id": owner,
        "cluster_uid": cluster["namespace_uid"],
        "source_revision": revision,
        "source_fingerprint": fingerprint,
        "controller_profile": profile,
        "containers": sorted(containers, key=canonical),
        "pods": pods,
        "targets": [
            {
                "name": f"runtime-{index:03}",
                "reference": reference,
                "config_id": config,
                **(
                    {"containerd_reference": local_references[reference]}
                    if reference in local_references
                    else {}
                ),
            }
            for index, (reference, config) in enumerate(sorted(targets.items()))
        ],
    }


def coverage(snapshot, components):
    targets = snapshot["targets"]
    covered = 0
    for target in targets:
        matches = [item for item in components if item["name"] == target["name"]]
        if len(matches) != 1:
            continue
        item = matches[0]
        if (
            item.get("scan_executed") is True
            and item.get("sbom_validated") is True
            and item.get("status") in {"pass", "fail"}
            and item.get("coverage_profile") in {"worker", "storage", "tracking"}
            and type(item.get("catalogued_packages")) is int
            and item["catalogued_packages"] > 0
            and (
                item.get("image_config_id") == target["config_id"]
                if target["config_id"] is not None
                else item.get("runtime_image_id") == target["reference"]
            )
        ):
            covered += 1
    return {
        "status": "pass" if targets and covered == len(targets) else "inconclusive",
        "expected_images": len(targets),
        "covered_images": covered,
    }
