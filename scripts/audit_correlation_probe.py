from mlsecops import audit_event, audit_export, audit_snapshot, signing
from mlsecops.contracts import Rejected, canonical, decode, digest


def materials(package, context):
    objects = package["capsule"]["objects"]

    def read(kind, reference):
        content = objects[(kind, reference)]
        if digest(content) != reference:
            raise Rejected("audit_correlation_material_digest")
        return decode(content)

    record = read("candidates", context["candidate_reference"])
    metadata = read("candidates", record["metadata_object"])
    dataset = signing.verify(
        read("manifests", record["dataset_reference"]),
        "stored-dataset",
        context["trust"]["curator"],
    )
    provenance = signing.verify(
        read("lineage", dataset["lineage_object"]), "data-lineage", context["trust"]["curator"]
    )
    approval = signing.verify(
        read("manifests", dataset["approval_object"]), "source", context["trust"]["curator"]
    )
    signing.verify(
        read("evaluations", context["evaluation_reference"]),
        "stored-evaluation",
        context["trust"]["evaluator"],
    )
    if provenance["source_sha256"] != dataset["quarantine_object"]:
        raise Rejected("audit_correlation_source_binding")
    return {
        "source_revision": metadata["source_revision"],
        "source_fingerprint": metadata["source_fingerprint"],
        "source_sha256": provenance["source_sha256"],
        "source_approval_sha256": digest(canonical(approval)),
        "dataset_sha256": record["dataset_reference"],
        "lineage_sha256": dataset["lineage_object"],
        "run_sha256": record["metadata_object"],
        "evaluation_sha256": context["evaluation_reference"],
    }


def subject(package, publisher):
    manifest = signing.verify(package["envelope"], "model-release", publisher)
    return digest(canonical(manifest)), manifest["materials"]["model"]


def release(package, context, selection, authorization, trusted_root):
    policy = signing.verify(authorization["policy_envelope"], "promotion-policy", trusted_root)
    identities = policy["identities"]
    bundle, model = subject(package, identities["publisher"]["public_key"])
    assurance = signing.verify(
        authorization["assurance_envelope"],
        "release-assurance",
        identities["assessor"]["public_key"],
    )
    approval = signing.verify(
        authorization["approval_envelope"], "release-approval", identities["approver"]["public_key"]
    )
    reference = digest(canonical(authorization))
    if (
        selection["authorization_reference"] != reference
        or selection["subject_sha256"] != bundle
        or assurance["subject_sha256"] != bundle
        or approval["subject_sha256"] != bundle
        or approval["assurance_sha256"] != digest(canonical(assurance))
    ):
        raise Rejected("audit_correlation_authority_binding")
    return {
        "schema_version": 2,
        "kind": "release-selection",
        "release_ready": False,
        "selection_sha256": digest(canonical(selection)),
        "authorization_sha256": reference,
        "assurance_sha256": digest(canonical(assurance)),
        "approval_sha256": digest(canonical(approval)),
        "bundle_sha256": bundle,
        "model_sha256": model,
        "lineage": materials(package, context),
    }


def candidate(package, context, permit_envelope, permit_public, publisher_public):
    permit = signing.verify(permit_envelope, "candidate-serving-qualification", permit_public)
    bundle, model = subject(package, publisher_public)
    if (
        permit["proposal_sha256"] != digest(canonical(package["envelope"]))
        or permit["subject_sha256"] != bundle
        or permit["model_sha256"] != model
    ):
        raise Rejected("audit_correlation_authority_binding")
    return {
        "schema_version": 2,
        "kind": "candidate-qualification",
        "release_ready": False,
        **{name: permit[name] for name in ("proposal_sha256", "model_sha256")},
        "permit_sha256": digest(canonical(permit)),
        "bundle_sha256": permit["subject_sha256"],
        "lineage": materials(package, context),
    }


def scan(chunks, expected):
    expected = audit_event.checked_context(expected)
    if expected["schema_version"] != 2:
        raise Rejected("audit_correlation_context_required")
    public = audit_export.project(chunks)
    if public["status"] != "pass":
        raise Rejected("audit_correlation_window_unresolved")
    correlated, completed, identifiers = set(), set(), set()
    events = 0
    for chunk in chunks:
        for line in chunk.splitlines():
            record = decode(line)
            if events == 0 and record["sequence"] != 1:
                raise Rejected("audit_correlation_window_start")
            event = record["event"]
            identifier = event["request_id"]
            identifiers.add(identifier)
            events += 1
            if event["context"] is not None:
                if event["context"] != expected:
                    raise Rejected("audit_correlation_context_mismatch")
                correlated.add(identifier)
            if event["stage"] == "response_completed" and event["status"] == 200:
                completed.add(identifier)
    if not correlated or not completed:
        raise Rejected("audit_correlation_no_completed_context")
    return {
        "schema_version": 1,
        "scope": expected["kind"] + "-private-correlation-not-full-M13",
        "status": "pass",
        "release_ready": False,
        "events": events,
        "correlated_requests": len(correlated),
        "completed_200": len(completed),
        "failed_after_intent": len(correlated - completed),
        "without_context": len(identifiers - correlated),
    }


def exercise(path, expected):
    before = audit_snapshot.read_closed(path)
    result = scan(before, expected)
    if before != audit_snapshot.read_closed(path):
        raise Rejected("audit_correlation_source_changed")
    return result
