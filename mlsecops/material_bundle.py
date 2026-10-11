from mlsecops import candidate_lineage, signing, storage
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields

KIND = "candidate-materials"
TABLES = {"manifests", "lineage", "candidates", "evaluations"}
CONTEXT_FIELDS = (
    "candidate_reference",
    "evaluation_reference",
    "policy",
    "trust",
    "expected",
    "owners",
    "known_owners",
)
MANIFEST_FIELDS = (
    "schema_version",
    "kind",
    "environment",
    "policy_sha256",
    "candidate_reference",
    "evaluation_reference",
    "projection_sha256",
    "state",
    "objects",
)
MAX_OBJECTS = 16
MAX_OBJECT_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ENVELOPE_BYTES = 64 * 1024


def _context(context, signer_public):
    require_fields(context, CONTEXT_FIELDS)
    require_fields(context["trust"], ("curator", "evaluator", "source_approval_digest"))
    if signer_public in (context["trust"]["curator"], context["trust"]["evaluator"]):
        raise Rejected("bundle_signer_roles_not_separated")


def _index(envelope, signer_public):
    try:
        size = len(canonical(envelope))
    except RecursionError as error:
        raise Rejected("bundle_invalid_envelope") from error
    if size > MAX_ENVELOPE_BYTES:
        raise Rejected("bundle_envelope_too_large")
    manifest = signing.verify(envelope, KIND, signer_public)
    require_fields(manifest, MANIFEST_FIELDS)
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or manifest["kind"] != KIND
        or manifest["state"] != "unapproved"
    ):
        raise Rejected("bundle_unknown_schema_or_state")
    descriptors = manifest["objects"]
    if not isinstance(descriptors, list) or not 1 <= len(descriptors) <= MAX_OBJECTS:
        raise Rejected("bundle_object_count_invalid")
    seen, total = set(), 0
    for descriptor in descriptors:
        require_fields(descriptor, ("namespace", "sha256", "bytes"))
        namespace = descriptor["namespace"]
        if not isinstance(namespace, str) or namespace not in TABLES:
            raise Rejected("bundle_namespace_invalid")
        reference = storage.object_id(descriptor["sha256"])
        length = descriptor["bytes"]
        if type(length) is not int or not 1 <= length <= MAX_OBJECT_BYTES:
            raise Rejected("bundle_object_size_invalid")
        total += length
        key = namespace, reference
        if key in seen or total > MAX_TOTAL_BYTES:
            raise Rejected("bundle_duplicate_or_oversized_materials")
        seen.add(key)
    return manifest


def _manifest(objects, projection, context):
    return {
        "schema_version": 1,
        "kind": KIND,
        "environment": context["policy"]["environment"],
        "policy_sha256": digest(canonical(context["policy"])),
        "candidate_reference": context["candidate_reference"],
        "evaluation_reference": context["evaluation_reference"],
        "projection_sha256": digest(canonical(projection)),
        "state": "unapproved",
        "objects": [
            {"namespace": namespace, "sha256": reference, "bytes": len(content)}
            for (namespace, reference), content in sorted(objects.items())
        ],
    }


def verify_bundle(bundle, *, context, signer_public):
    _context(context, signer_public)
    require_fields(bundle, ("envelope", "objects"))
    manifest = _index(bundle["envelope"], signer_public)
    objects = bundle["objects"]
    if not isinstance(objects, dict):
        raise Rejected("bundle_objects_invalid")
    declared = {(item["namespace"], item["sha256"]): item["bytes"] for item in manifest["objects"]}
    if objects.keys() != declared.keys():
        raise Rejected("bundle_material_set_mismatch")
    for key, length in declared.items():
        content = objects[key]
        if not isinstance(content, bytes) or len(content) != length or digest(content) != key[1]:
            raise Rejected("bundle_material_integrity_failed")
    used = set()
    allowed = {"metadata": {"manifests", "lineage"}, "review": {"candidates", "evaluations"}}

    def read(role, namespace, reference):
        if role not in allowed or namespace not in allowed[role]:
            raise Rejected("bundle_reader_scope")
        key = namespace, reference
        if key not in objects:
            raise Rejected("bundle_dependency_missing")
        used.add(key)
        return objects[key]

    projection = candidate_lineage.reconcile(read, **context)
    if used != objects.keys():
        raise Rejected("bundle_unreferenced_material")
    if canonical(manifest) != canonical(_manifest(objects, projection, context)):
        raise Rejected("bundle_subject_or_context_mismatch")
    model = next(asset for asset in projection["graph"]["assets"] if asset["kind"] == "model")
    return {
        "manifest": manifest,
        "projection": projection,
        "model": objects[("candidates", model["sha256"])],
        "release_ready": False,
        "full_M10": "inconclusive",
    }


def create(metadata_client, review_client, *, context, signing_key, signer_public):
    _context(context, signer_public)
    objects = {}

    def capture(namespace, reference, content):
        objects[(namespace, reference)] = content

    projection = candidate_lineage.collect(
        metadata_client, review_client, material_sink=capture, **context
    )
    bundle = {
        "envelope": signing.sign(_manifest(objects, projection, context), KIND, signing_key),
        "objects": objects,
    }
    verify_bundle(bundle, context=context, signer_public=signer_public)
    return bundle


def publish(client, bundle, *, context, signer_public):
    if storage.connection_parameters(client)["user"] != "ml_promoter":
        raise Rejected("bundle_publisher_identity_invalid")
    verify_bundle(bundle, context=context, signer_public=signer_public)
    for (_, reference), content in sorted(bundle["objects"].items()):
        if storage.put(client, "releases", content) != reference:
            raise Rejected("bundle_storage_integrity_failed")
    content = canonical(bundle["envelope"])
    reference = storage.put(client, "releases", content)
    if reference != digest(content):
        raise Rejected("bundle_storage_integrity_failed")
    read(client, reference, context=context, signer_public=signer_public)
    return reference


def read(client, reference, *, context, signer_public):
    _context(context, signer_public)
    if storage.connection_parameters(client)["user"] not in ("ml_promoter", "ml_serving"):
        raise Rejected("bundle_reader_identity_invalid")
    envelope = decode(storage.get(client, "releases", reference), MAX_ENVELOPE_BYTES)
    manifest = _index(envelope, signer_public)
    objects = {
        (item["namespace"], item["sha256"]): storage.get(client, "releases", item["sha256"])
        for item in manifest["objects"]
    }
    return verify_bundle(
        {"envelope": envelope, "objects": objects}, context=context, signer_public=signer_public
    )
