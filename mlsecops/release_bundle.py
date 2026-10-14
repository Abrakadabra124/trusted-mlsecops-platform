import re

from mlsecops import material_bundle, release_policy, signing, storage
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.datasets import FEATURES

DOCUMENTS = (
    "dependency-lock",
    "feature-contract",
    "model-card",
    "ml-bom",
    "parameters",
    "runtime-profile",
    "split_manifest",
    "evaluation_policy",
    "asset_projection",
)
ATTRIBUTES = ("release_id", "sequence", "owner", "issued_at", "expires_at", "issuer")
MATERIALS = (
    "capsule",
    "model",
    "preprocessing",
    "dataset_manifest",
    "evaluation_report",
    "provenance",
    *DOCUMENTS,
)


def index(envelope, publisher_public):
    payload = release_policy.checked(envelope, "model-release", publisher_public)
    require_fields(
        payload,
        (
            "schema_version",
            "kind",
            *ATTRIBUTES,
            "environment",
            "intended_use",
            "source_commit",
            "training_image",
            "serving_image",
            "api_contract",
            "compatibility_group",
            "materials",
        ),
    )
    require_fields(payload["materials"], MATERIALS)
    for reference in payload["materials"].values():
        storage.object_id(reference)
    return payload


def documents(capsule, lock, *, context, publisher_public, serving_image):
    verified = material_bundle.verify_bundle(
        capsule, context=context, signer_public=publisher_public
    )
    objects = capsule["objects"]
    record = decode(objects[("candidates", context["candidate_reference"])])
    metadata = decode(objects[("candidates", record["metadata_object"])])
    bindings = verified["projection"]["bindings"]
    lineage = signing.verify(
        decode(objects[("lineage", bindings["lineage_object"])]),
        "data-lineage",
        context["trust"]["curator"],
    )
    dataset = signing.verify(
        decode(objects[("manifests", bindings["dataset_reference"])]),
        "stored-dataset",
        context["trust"]["curator"],
    )
    split = signing.verify(
        decode(objects[("manifests", dataset["manifest_object"])]),
        "dataset",
        context["trust"]["curator"],
    )
    if (
        not isinstance(lock, bytes)
        or not 0 < len(lock) <= release_policy.MAX_DOCUMENT
        or {"sha256": digest(lock), "bytes": len(lock)} != lineage["inputs"]["uv.lock"]
    ):
        raise Rejected("release_dependency_lock_binding")
    evaluation = signing.verify(
        decode(objects[("evaluations", context["evaluation_reference"])]),
        "stored-evaluation",
        context["trust"]["evaluator"],
    )["report"]
    model = digest(verified["model"])
    feature_contract = {
        "schema_version": 1,
        "api_contract": "advisory-core-v1",
        "features": list(FEATURES),
        "finite_numbers_only": True,
        "domain": [0, 1],
        "outside_support": "abstain",
        "maximum_batch_rows": 100,
    }
    card = {
        "schema_version": 1,
        "model": model,
        "intended_use": "synthetic-release-advice",
        "data_classification": "synthetic-only",
        "evaluation_reference": context["evaluation_reference"],
        "quality": {
            field: evaluation[field]
            for field in ("quality_component", "auprc", "auprc_gain", "rows", "positives")
        },
        "limitations": [
            "Not production approval or business utility validation",
            "No universal poisoning, evasion or privacy guarantee",
            "Separate release assurance and explicit approval required",
        ],
    }
    bill = {
        "schema_version": 1,
        "format": "onnx",
        "model": model,
        "preprocessing": "embedded-in-model",
        "dataset_reference": bindings["dataset_reference"],
        "lineage_id": bindings["lineage_id"],
        "training_image": metadata["image_id"],
        "serving_image": serving_image,
        "dependency_lock": digest(lock),
        "versions": metadata["versions"],
    }
    parameters = {
        "schema_version": 1,
        "recipe": "standardscaler-logistic-lbfgs-v1",
        "C": 1.0,
        "max_iter": 300,
        "seed": context["policy"]["training_seed"],
        "training_request_digest": metadata["input_digest"],
        "compute_profile": "linux-amd64-cpu-float32",
        "source_fingerprint": metadata["source_fingerprint"],
    }
    runtime = {
        "schema_version": 1,
        "compatibility_group": "local-cpu-linear-onnx-v2",
        "image": serving_image,
        "api_contract": feature_contract["api_contract"],
        "cpu_millis": 2000,
        "memory_mib": 4096,
        "network": "none",
        "uid": 65532,
        "read_only": True,
    }
    values = {
        "dependency-lock": lock,
        "split_manifest": canonical(split),
        "evaluation_policy": canonical(context["policy"]),
        "asset_projection": canonical(verified["projection"]),
        **{
            name: canonical(value)
            for name, value in (
                ("feature-contract", feature_contract),
                ("model-card", card),
                ("ml-bom", bill),
                ("parameters", parameters),
                ("runtime-profile", runtime),
            )
        },
    }
    materials = {
        "capsule": digest(canonical(capsule["envelope"])),
        "model": model,
        "preprocessing": model,
        "dataset_manifest": bindings["dataset_reference"],
        "evaluation_report": context["evaluation_reference"],
        "provenance": record["metadata_object"],
        **{name: digest(content) for name, content in values.items()},
    }
    return values, materials, verified


def manifest(attributes, materials, *, context, serving_image):
    require_fields(attributes, ATTRIBUTES)
    return {
        "schema_version": 1,
        "kind": "model-release",
        **attributes,
        "environment": context["policy"]["environment"],
        "intended_use": "synthetic-release-advice",
        "source_commit": context["expected"]["source_revision"],
        "training_image": context["expected"]["image_id"],
        "serving_image": serving_image,
        "api_contract": "advisory-core-v1",
        "compatibility_group": "local-cpu-linear-onnx-v2",
        "materials": materials,
    }


def verify(package, *, context, publisher_public, expected_serving_image, clock):
    require_fields(package, ("envelope", "capsule", "documents"))
    if (
        not isinstance(expected_serving_image, str)
        or re.fullmatch(r"sha256:[a-f0-9]{64}", expected_serving_image) is None
    ):
        raise Rejected("release_invalid_runtime_pin")
    payload = index(package["envelope"], publisher_public)
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise Rejected("release_unknown_schema")
    if (
        not isinstance(payload["release_id"], str)
        or re.fullmatch(r"[a-f0-9]{32}", payload["release_id"]) is None
    ):
        raise Rejected("release_invalid_id")
    release_policy.integer(payload["sequence"])
    release_policy.name(payload["issuer"])
    release_policy.name(payload["owner"])
    release_policy.window(payload, clock)
    if payload["owner"] not in context["known_owners"]:
        raise Rejected("release_unknown_owner")
    require_fields(package["documents"], DOCUMENTS)
    if any(
        not isinstance(content, bytes) or not 0 < len(content) <= release_policy.MAX_DOCUMENT
        for content in package["documents"].values()
    ):
        raise Rejected("release_material_size")
    expected, materials, verified = documents(
        package["capsule"],
        package["documents"]["dependency-lock"],
        context=context,
        publisher_public=publisher_public,
        serving_image=expected_serving_image,
    )
    if package["documents"] != expected:
        raise Rejected("release_material_semantics")
    reconstructed = manifest(
        {name: payload[name] for name in ATTRIBUTES},
        materials,
        context=context,
        serving_image=expected_serving_image,
    )
    if canonical(payload) != canonical(reconstructed):
        raise Rejected("release_subject_binding")
    return {
        "manifest": payload,
        "subject_sha256": digest(canonical(payload)),
        "model": verified["model"],
        "quality_component": verified["projection"]["quality_component"],
        "release_ready": False,
    }


def create(
    capsule,
    lock,
    attributes,
    *,
    context,
    publisher_public,
    expected_serving_image,
    clock,
    signing_key,
):
    values, materials, _ = documents(
        capsule,
        lock,
        context=context,
        publisher_public=publisher_public,
        serving_image=expected_serving_image,
    )
    payload = manifest(attributes, materials, context=context, serving_image=expected_serving_image)
    package = {
        "envelope": signing.sign(payload, "model-release", signing_key),
        "capsule": capsule,
        "documents": values,
    }
    verify(
        package,
        context=context,
        publisher_public=publisher_public,
        expected_serving_image=expected_serving_image,
        clock=clock,
    )
    return package


def publish(client, package, **arguments):
    if storage.connection_parameters(client)["user"] != "ml_promoter":
        raise Rejected("release_publisher_storage_identity")
    verified = verify(package, **arguments)
    material_bundle.publish(
        client,
        package["capsule"],
        context=arguments["context"],
        signer_public=arguments["publisher_public"],
    )
    for content in package["documents"].values():
        if storage.put(client, "releases", content) != digest(content):
            raise Rejected("release_storage_receipt_mismatch")
    content = canonical(package["envelope"])
    reference = storage.put(client, "releases", content)
    if reference != digest(content) or read(client, reference, **arguments) != verified:
        raise Rejected("release_storage_readback_mismatch")
    return reference


def load(client, reference, *, publisher_public):
    if storage.connection_parameters(client)["user"] not in ("ml_promoter", "ml_serving"):
        raise Rejected("release_reader_storage_identity")
    envelope = decode(storage.get(client, "releases", reference), release_policy.MAX_DOCUMENT)
    payload = index(envelope, publisher_public)
    capsule_envelope = decode(
        storage.get(client, "releases", payload["materials"]["capsule"]),
        material_bundle.MAX_ENVELOPE_BYTES,
    )
    capsule_index = material_bundle._index(capsule_envelope, publisher_public)
    objects = {}
    for item in capsule_index["objects"]:
        content = storage.get(client, "releases", item["sha256"])
        if len(content) != item["bytes"]:
            raise Rejected("release_storage_material_size")
        objects[(item["namespace"], item["sha256"])] = content
    capsule = {
        "envelope": capsule_envelope,
        "objects": objects,
    }
    values = {}
    for name in DOCUMENTS:
        content = storage.get(client, "releases", payload["materials"][name])
        if not 0 < len(content) <= release_policy.MAX_DOCUMENT:
            raise Rejected("release_storage_material_size")
        values[name] = content
    return {
        "envelope": envelope,
        "capsule": capsule,
        "documents": values,
    }


def read(client, reference, **arguments):
    package = load(client, reference, publisher_public=arguments["publisher_public"])
    return verify(package, **arguments)
