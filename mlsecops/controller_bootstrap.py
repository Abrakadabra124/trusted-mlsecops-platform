import argparse
import copy
import re
import sys
import time
from pathlib import Path

from mlsecops import kube_storage
from mlsecops.cluster import NODE, kubectl
from mlsecops.contracts import Rejected, canonical, decode, digest, now, read_json, write_json
from mlsecops.controller_resources import resources
from mlsecops.inventory import command, source_fingerprint
from mlsecops.kube_worker import image_config, image_document, load_image
from mlsecops.storage_pki import workspace_id


def image_profile(root, state, image):
    tag, image_id = load_image(state, image)
    status = decode(command(["docker", "exec", NODE, "crictl", "inspecti", tag]).encode())["status"]
    references = status.get("repoDigests", [])
    if len(references) != 1 or not re.fullmatch(
        r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", references[0]
    ):
        raise Rejected("controller_image_reference_invalid")
    reference = references[0]
    manifest_id = reference.split("@", 1)[1]
    config_id = image_config(manifest_id)
    if config_id != image_config(image_id) or status["id"] != config_id:
        raise Rejected("controller_image_config_mismatch")
    aliases = command(
        [
            "docker",
            "exec",
            NODE,
            "ctr",
            "-n",
            "k8s.io",
            "images",
            "list",
            "--quiet",
            f"name=={reference}",
        ]
    )
    if not aliases:
        command(
            [
                "docker",
                "exec",
                NODE,
                "ctr",
                "-n",
                "k8s.io",
                "images",
                "tag",
                f"docker.io/library/{tag}",
                reference,
            ]
        )
    elif aliases != reference:
        raise Rejected("controller_image_alias_ambiguous")
    cached = decode(command(["docker", "exec", NODE, "crictl", "inspecti", reference]).encode())[
        "status"
    ]
    if cached["id"] != config_id:
        raise Rejected("controller_pinned_image_cache_mismatch")
    labels = image_document(config_id)["config"]["Labels"]
    fingerprint = source_fingerprint(root)
    revision = labels.get("org.opencontainers.image.revision", "")
    if labels.get("org.trusted-mlsecops.source-fingerprint") != fingerprint or not re.fullmatch(
        r"[0-9a-f]{40}", revision
    ):
        raise Rejected("controller_image_provenance_invalid")
    return {
        "image": reference,
        "image_id": image_id,
        "config_id": config_id,
        "manifest_id": manifest_id,
        "source_fingerprint": fingerprint,
        "source_revision": revision,
    }


def body(document):
    return {key: value for key, value in document.items() if key not in {"metadata", "status"}}


def verify_saved(state, marker):
    if marker["workspace_id"] != workspace_id(state):
        raise Rejected("controller_workspace_mismatch")
    for recorded in marker["resources"].values():
        observed = kube_storage.get(state, recorded["document"])
        if (
            not observed
            or observed["metadata"]["uid"] != recorded["uid"]
            or observed["metadata"].get("deletionTimestamp")
            or observed["metadata"].get("labels", {}).get("trusted-mlsecops/workspace")
            != marker["workspace_id"]
            or body(observed) != body(recorded["document"])
        ):
            raise Rejected("controller_resource_identity_or_spec_changed")
    return marker


def no_active_jobs(state):
    for namespace in ("ml-publisher", "ml-scorer", "ml-train", "ml-eval"):
        jobs = decode(kubectl(state, ["get", "jobs", "-n", namespace, "-o", "json"]).stdout)[
            "items"
        ]
        if any(
            not any(
                item.get("status") == "True" and item.get("type") in {"Complete", "Failed"}
                for item in job.get("status", {}).get("conditions", [])
            )
            for job in jobs
        ):
            raise Rejected("controller_profile_change_with_active_jobs")


def check_policy(state, document):
    for _ in range(20):
        observed = kube_storage.get(state, document)
        status = observed.get("status", {})
        if (
            status.get("observedGeneration") == observed["metadata"]["generation"]
            and "typeChecking" in status
        ):
            if status["typeChecking"].get("expressionWarnings"):
                raise Rejected("controller_admission_type_warnings")
            return
        time.sleep(0.5)
    raise Rejected("controller_admission_not_checked")


def bootstrap(root, state, image, replace=False):
    state = Path(state).resolve()
    kube_storage.validate(state)
    profile = image_profile(root, state, image)
    documents = resources(workspace_id(state), profile["image"])
    fingerprint = digest(canonical(documents))
    path = state / "controllers/resources.json"
    if path.exists():
        marker = verify_saved(state, read_json(path))
        if marker["spec_digest"] != fingerprint:
            if not replace:
                raise Rejected("controller_profile_change_requires_replace")
            no_active_jobs(state)
            if set(marker["resources"]) != {kube_storage.reference(item) for item in documents}:
                raise Rejected("controller_resource_set_change_requires_migration")
    else:
        if any(kube_storage.get(state, item) for item in documents):
            raise Rejected("controller_unowned_resources")
        marker = {
            "schema_version": 1,
            "workspace_id": workspace_id(state),
            "spec_digest": fingerprint,
            "resources": {},
            "ready": False,
        }
    marker["ready"] = False
    write_json(path, marker)
    for document in documents:
        key = kube_storage.reference(document)
        observed = kube_storage.get(state, document)
        if key not in marker["resources"]:
            if observed is not None:
                raise Rejected("controller_unowned_resource")
            observed = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], document).stdout)
        elif not kube_storage.matches(document, observed):
            if not replace:
                raise Rejected("controller_resource_update_not_authorized")
            updated = copy.deepcopy(document)
            updated["metadata"].update(
                uid=observed["metadata"]["uid"],
                resourceVersion=observed["metadata"]["resourceVersion"],
            )
            observed = decode(kubectl(state, ["replace", "-f", "-", "-o", "json"], updated).stdout)
        if not kube_storage.matches(document, observed):
            raise Rejected("controller_applied_resource_mismatch")
        marker["resources"][key] = {"uid": observed["metadata"]["uid"], "document": observed}
        write_json(path, marker)
        if document["kind"] == "ValidatingAdmissionPolicy":
            check_policy(state, document)
    marker.update(spec_digest=fingerprint, profile=profile, ready=True, observed_at=now())
    write_json(path, marker)
    verify_saved(state, marker)
    return {
        "status": "ready",
        "scope": "controller-api-bootstrap-not-M04-M20",
        "profile": profile,
        "resources": len(documents),
        "release_ready": False,
    }


def main():
    parser = argparse.ArgumentParser(description="Owned, scoped controller API permissions")
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    parser.add_argument("--replace-profile", action="store_true")
    arguments = parser.parse_args()
    try:
        report = bootstrap(
            Path(__file__).resolve().parents[1],
            arguments.state,
            arguments.image,
            arguments.replace_profile,
        )
        print(canonical(report).decode())
        return 0
    except (Rejected, OSError) as error:
        print(f"Controller bootstrap rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
