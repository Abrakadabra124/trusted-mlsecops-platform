"""Operator entrypoint for the existing verifier in a credential-scoped Kubernetes Job."""

import copy
import sys
import uuid
from pathlib import Path

from mlsecops import (
    kube_storage,
    kube_trust,
    promotion_controller,
    promotion_state,
    release_policy,
    storage,
)
from mlsecops.cluster import kubectl
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, require_fields
from mlsecops.controller_bootstrap import image_profile
from mlsecops.inventory import source_fingerprint
from mlsecops.kube_storage_resources import WORKSPACE, client_pod_spec
from mlsecops.kube_worker import job_document, verify_running_image, wait_job
from mlsecops.private_cli import Arguments
from mlsecops.storage_pki import workspace_id

NAMESPACE = "ml-promoter"
MAX_CONFIG = 512 * 1024
MAX_REQUEST = 64 * 1024


def validate_config(config):
    require_fields(config, promotion_controller.CONFIG_FIELDS)
    decode(canonical(config), MAX_CONFIG)
    if (
        type(config["schema_version"]) is not int
        or config["schema_version"] != 1
        or config["storage_client"] != "/client"
        or config["trust_client"] != "/trust-client"
    ):
        raise Rejected("kube_promotion_configuration")
    release_policy.name(config["context"]["policy"]["environment"])
    storage.object_id(config["expected_policy"])


def validate_inputs(config, request):
    validate_config(config)
    require_fields(request, promotion_controller.REQUEST_FIELDS)
    decode(canonical(request), MAX_REQUEST)
    if type(request["schema_version"]) is not int or request["schema_version"] != 1:
        raise Rejected("kube_promotion_request_schema")
    for name in promotion_controller.REQUEST_FIELDS[1:]:
        if request[name] is not None or name not in ("assurance_reference", "approval_reference"):
            storage.object_id(request[name])


def pod_spec(profile, config_name, request_name):
    spec = client_pod_spec(
        profile["image"],
        "promoter",
        [
            "mlsecops.promotion_controller",
            "--config",
            "/config.json",
            "--request",
            "/request.json",
        ],
    )
    spec["volumes"].extend(
        [
            {
                "name": "trust-credentials",
                "secret": {"secretName": "trust-client", "defaultMode": 416},
            },
            {"name": "trust-client", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}},
        ]
    )
    initializer = copy.deepcopy(spec["initContainers"][0])
    initializer.update(
        name="trust-client-files",
        volumeMounts=[
            {"name": "trust-credentials", "mountPath": "/source", "readOnly": True},
            {"name": "trust-client", "mountPath": "/client"},
        ],
    )
    spec["initContainers"].append(initializer)
    spec["containers"][0]["volumeMounts"].append(
        {"name": "trust-client", "mountPath": "/trust-client", "readOnly": True}
    )
    for field, name in (("config", config_name), ("request", request_name)):
        spec["volumes"].append({"name": field, "configMap": {"name": name, "defaultMode": 292}})
        spec["containers"][0]["volumeMounts"].append(
            {
                "name": field,
                "mountPath": f"/{field}.json",
                "subPath": f"{field}.json",
                "readOnly": True,
            }
        )
    return spec


def configuration_map(state, name, field, value):
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "immutable": True,
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {WORKSPACE: workspace_id(state)},
        },
        "data": {field + ".json": canonical(value).decode()},
    }


def outcome(terminal, pod, content, config, request):
    statuses = pod.get("status", {}).get("containerStatuses", [])
    if len(statuses) != 1:
        raise Rejected("kube_promotion_missing_exit")
    code = statuses[0].get("state", {}).get("terminated", {}).get("exitCode")
    if (
        terminal["type"] == "Failed"
        and type(code) is int
        and code == 1
        and content in (b"promotion_rejected\n", b"promotion_sequence_conflict\n")
    ):
        return {
            "status": "rejected",
            "receipt": None,
            "release_ready": False,
            **(
                {"reason": "promotion_sequence_conflict"}
                if content == b"promotion_sequence_conflict\n"
                else {}
            ),
        }
    if terminal["type"] != "Complete" or type(code) is not int or code != 0:
        raise Rejected("kube_promotion_job_failed")
    receipt = decode(content, MAX_REQUEST)
    if (
        receipt.get("state") != "recorded-not-activated"
        or receipt.get("release_ready") is not False
        or receipt.get("proposal_reference") != request["proposal_reference"]
        or receipt.get("environment") != config["context"]["policy"]["environment"]
        or type(receipt.get("sequence")) is not int
        or receipt["sequence"] < 1
    ):
        raise Rejected("kube_promotion_receipt_invalid")
    for field in ("request_sha256", "subject_sha256"):
        storage.object_id(receipt[field])
    return {"status": "recorded-not-activated", "receipt": receipt, "release_ready": False}


def cleanup(state, created, *, namespace=NAMESPACE):
    failed = False
    for document, uid in reversed(created):
        try:
            kube_storage.verify_resource(document, kube_storage.get(state, document), uid)
            kubectl(
                state,
                [
                    "delete",
                    document["kind"],
                    document["metadata"]["name"],
                    "-n",
                    namespace,
                    "--wait=true",
                    "--timeout=30s",
                ],
            )
            if kube_storage.get(state, document) is not None:
                raise Rejected("kube_promotion_cleanup_incomplete")
        except Exception:
            failed = True
    if failed:
        raise Rejected("kube_promotion_cleanup_unconfirmed")


def invoke(root, state, config, request, image="trusted-mlsecops:dev"):
    config, request = decode(canonical(config), MAX_CONFIG), decode(canonical(request), MAX_REQUEST)
    validate_inputs(config, request)
    kube_storage.validate(state)
    kube_trust.validate(state)
    profile = image_profile(root, state, image)
    if config["expected_serving_image"] != profile["image_id"]:
        raise Rejected("kube_promotion_image_pin_mismatch")
    name = "promotion-" + uuid.uuid4().hex
    maps = [
        configuration_map(state, name + "-" + field, field, value)
        for field, value in (("config", config), ("request", request))
    ]
    spec = pod_spec(profile, maps[0]["metadata"]["name"], maps[1]["metadata"]["name"])
    job = job_document(name, NAMESPACE, spec, 180)
    job["metadata"]["labels"][WORKSPACE] = workspace_id(state)
    created = []
    try:
        for document in [*maps, job]:
            observed = decode(kubectl(state, ["create", "-f", "-", "-o", "json"], document).stdout)
            uid = observed["metadata"]["uid"]
            created.append((document, uid))
            kube_storage.verify_resource(document, observed, uid)
        terminal, pod, elapsed = wait_job(state, NAMESPACE, name, 180)
        verify_running_image(pod, profile["image_id"])
        if (
            not kube_storage.matches(spec, pod["spec"])
            or pod["spec"].get("ephemeralContainers")
            or pod["metadata"]["ownerReferences"][0]["uid"] != created[-1][1]
        ):
            raise Rejected("kube_promotion_pod_changed")
        content = kubectl(
            state,
            [
                "logs",
                pod["metadata"]["name"],
                "-c",
                "worker",
                "-n",
                NAMESPACE,
                "--limit-bytes=65537",
            ],
        ).stdout
        result = outcome(terminal, pod, content, config, request)
        if source_fingerprint(root) != profile["source_fingerprint"]:
            raise Rejected("kube_promotion_source_changed")
        return {
            **result,
            "execution": {
                "image_id": profile["image_id"],
                "source_fingerprint": profile["source_fingerprint"],
                "job_uid": created[-1][1],
                "pod_uid": pod["metadata"]["uid"],
                "elapsed_seconds": elapsed,
            },
        }
    finally:
        cleanup(state, created)


def configure(state, config):
    # Only an explicit operator action can initialize the journal, never a submission.
    validate_config(config)
    kube_trust.validate(state)
    promotion_state.install(state, backend=kube_storage.binding)
    promotion_state.configure(
        state,
        config["context"]["policy"]["environment"],
        config["expected_policy"],
        backend=kube_storage.binding,
    )
    return {"status": "configured", "release_ready": False}


def main(arguments=None):
    try:
        parser = Arguments(prog="kubernetes-promotion")
        parser.add_argument("action", choices=("configure", "submit"))
        parser.add_argument("--state", type=Path, required=True)
        parser.add_argument("--config", type=Path, required=True)
        parser.add_argument("--request", type=Path)
        parser.add_argument("--image", default="trusted-mlsecops:dev")
        options = parser.parse_args(arguments)
        config = decode(bounded_read(options.config, MAX_CONFIG), MAX_CONFIG)
        if options.action == "configure":
            result = configure(options.state, config)
        else:
            if options.request is None:
                raise Rejected("kube_promotion_request_required")
            request = decode(bounded_read(options.request, MAX_REQUEST), MAX_REQUEST)
            result = invoke(
                Path(__file__).resolve().parents[1], options.state, config, request, options.image
            )
        print(canonical(result).decode())
        return 1 if result["status"] == "rejected" else 0
    except (Exception, KeyboardInterrupt) as error:
        print("kubernetes_promotion_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
