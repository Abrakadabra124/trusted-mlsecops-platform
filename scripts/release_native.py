import argparse
import sys
import time
import uuid
from contextlib import suppress
from pathlib import Path

from mlsecops import material_bundle, release_authorization, release_bundle, signing
from mlsecops.acceptance import GATES
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.sandbox import resolve_image
from mlsecops.storage_bootstrap import validate
from scripts.candidate_lineage_native import KNOWN_OWNERS, OWNERS, metadata_snapshot
from scripts.material_bundle_native import release_snapshot


def qualify(root, state, image):
    marker = validate(state)
    started = now()
    clock = int(time.time())
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    dirty = command(["git", "-C", str(root), "status", "--porcelain"])
    paths = [
        safe_child(state, name)
        for name in ("storage-trust.json", "storage-demo.json", "trusted-keys.json")
    ]
    files = {path: digest(bounded_read(path)) for path in paths}
    trust, demo, public = (read_json(path) for path in paths)
    expected = {
        "image_id": resolve_image(image),
        "source_fingerprint": source_fingerprint(root),
        "source_revision": revision,
    }
    context = {
        "candidate_reference": demo["candidate"]["candidate_reference"],
        "evaluation_reference": demo["evaluation_reference"],
        "policy": read_json(root / "policies/local-cpu.json"),
        "trust": trust,
        "expected": expected,
        "owners": OWNERS,
        "known_owners": KNOWN_OWNERS,
    }
    clients = {
        role: safe_child(state, f"storage-clients/{role}")
        for role in ("publisher", "promoter", "serving")
    }
    before = metadata_snapshot(state)
    releases_before = release_snapshot(clients["serving"])
    capsule = material_bundle.create(
        clients["publisher"],
        clients["promoter"],
        context=context,
        signing_key=safe_child(state, "keys/approver.pem"),
        signer_public=public["approver"],
    )
    campaign_id = uuid.uuid4().hex
    campaign = safe_child(state, f"release-proposals/{campaign_id}")
    attributes = {
        "release_id": campaign_id,
        "sequence": 1,
        "owner": "platform-owner",
        "issuer": "lab-publisher",
        "issued_at": clock,
        "expires_at": clock + 1800,
    }
    arguments = {
        "context": context,
        "publisher_public": public["approver"],
        "expected_serving_image": expected["image_id"],
        "clock": clock,
    }
    package = release_bundle.create(
        capsule,
        bounded_read(root / "uv.lock"),
        attributes,
        signing_key=safe_child(state, "keys/approver.pem"),
        **arguments,
    )
    verified = release_bundle.verify(package, **arguments)
    cases = ["signed-complete-release-materials"]
    reference = release_bundle.publish(clients["promoter"], package, **arguments)
    published = release_snapshot(clients["serving"])
    if (
        release_bundle.publish(clients["promoter"], package, **arguments) != reference
        or release_snapshot(clients["serving"]) != published
    ):
        raise Rejected("release_native_idempotency_failed")
    cases.append("idempotent-proposal-publication")
    observed = release_bundle.read(clients["serving"], reference, **arguments)
    if observed != verified or observed["release_ready"]:
        raise Rejected("release_native_readback_mismatch")
    cases.append("serving-reads-identical-unapproved-bytes")

    def rejected(name, operation, reason):
        try:
            operation()
        except Rejected as error:
            if str(error) != reason:
                raise Rejected("release_native_negative_wrong_reason") from None
            cases.append(name)
        else:
            raise Rejected("release_native_negative_bypass")

    rejected(
        "wrong-external-runtime-pin",
        lambda: release_bundle.read(
            clients["serving"],
            reference,
            **{**arguments, "expected_serving_image": "sha256:" + "0" * 64},
        ),
        "release_material_semantics",
    )
    rejected(
        "serving-cannot-publish-proposal",
        lambda: release_bundle.publish(clients["serving"], package, **arguments),
        "release_publisher_storage_identity",
    )
    approval_public = signing.create_key(safe_child(campaign, "release-approver.pem"))
    policy = {
        "schema_version": 1,
        "environment": context["policy"]["environment"],
        "version": 1,
        "issued_at": clock,
        "expires_at": clock + 1800,
        "required_gates": list(GATES),
        "identities": {
            role: {"issuer": "lab-" + role, "public_key": key}
            for role, key in (
                ("publisher", public["approver"]),
                ("assessor", public["evaluator"]),
                ("approver", approval_public),
            )
        },
    }
    authorization = {
        "package": package,
        "policy_envelope": signing.sign(
            policy, "promotion-policy", safe_child(state, "keys/trust.pem")
        ),
        "assurance_envelope": None,
        "approval_envelope": None,
        "reports": {},
        "context": context,
        "trusted_root": public["trust"],
        "expected_policy": digest(canonical(policy)),
        "expected_serving_image": expected["image_id"],
        "clock": clock,
    }
    rejected(
        "actual-candidate-without-assurance-denied",
        lambda: release_authorization.verify(**authorization),
        "release_assurance_required",
    )
    empty_assurance = {
        "schema_version": 1,
        "issuer": "lab-assessor",
        "subject_sha256": verified["subject_sha256"],
        "environment": policy["environment"],
        "policy_sha256": authorization["expected_policy"],
        "issued_at": clock,
        "expires_at": clock + 1800,
        "reports": {},
    }
    rejected(
        "signed-empty-evidence-denied",
        lambda: release_authorization.verify(
            **{
                **authorization,
                "assurance_envelope": signing.sign(
                    empty_assurance, "release-assurance", safe_child(state, "keys/evaluator.pem")
                ),
            }
        ),
        "release_gate_set_incomplete",
    )
    after = metadata_snapshot(state)
    if before != after:
        raise Rejected("release_native_metadata_changed")
    cases.append("source-metadata-and-budget-unchanged")
    expected_objects = (
        {key[1] for key in capsule["objects"]}
        | {digest(canonical(capsule["envelope"])), reference}
        | {digest(content) for content in package["documents"].values()}
    )
    if release_snapshot(clients["serving"]) != releases_before | expected_objects:
        raise Rejected("release_native_object_set_mismatch")
    cases.append("exact-release-object-set")
    if (
        source_fingerprint(root) != expected["source_fingerprint"]
        or command(["git", "-C", str(root), "rev-parse", "HEAD"]) != revision
        or command(["git", "-C", str(root), "status", "--porcelain"]) != dirty
        or resolve_image(image) != expected["image_id"]
        or any(digest(bounded_read(path)) != original for path, original in files.items())
        or validate(state)["container_id"] != marker["container_id"]
        or int(time.time()) >= attributes["expires_at"]
    ):
        raise Rejected("release_native_inputs_changed_or_expired")
    cases.append("inputs-and-authority-window-stable")
    report = {
        "schema_version": 1,
        "scope": "release-proposal-and-authorization-denial-not-full-M10",
        "status": "pass",
        "full_M10": "inconclusive",
        "release_ready": False,
        "started_at": started,
        "finished_at": now(),
        "source": expected,
        "source_dirty": bool(dirty),
        "campaign_id": campaign_id,
        "cases": cases,
        "proposal_reference": reference,
        "subject_sha256": verified["subject_sha256"],
        "policy_sha256": authorization["expected_policy"],
        "model_sha256": digest(observed["model"]),
        "objects": len(expected_objects),
        "documents": len(package["documents"]),
        "runner_digest": digest(bounded_read(Path(__file__))),
        "metadata_snapshot": after,
    }
    write_json(safe_child(campaign, "policy-envelope.json"), authorization["policy_envelope"])
    write_json(safe_child(campaign, "report.json"), report)
    return report


def main():
    parser = argparse.ArgumentParser(description="Qualify unapproved releases in owned lab SQL")
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    output = None
    try:
        validate(arguments.state)
        output = safe_child(arguments.state, "evidence/release-native.json")
        write_json(output, {"status": "inconclusive", "release_ready": False})
        report = qualify(Path(__file__).resolve().parents[1], arguments.state, arguments.image)
        write_json(output, report)
        fields = (
            "scope",
            "status",
            "full_M10",
            "release_ready",
            "source",
            "source_dirty",
            "campaign_id",
            "proposal_reference",
            "subject_sha256",
            "policy_sha256",
            "model_sha256",
            "objects",
            "documents",
            "runner_digest",
            "started_at",
            "finished_at",
        )
        print(
            canonical(
                {**{key: report[key] for key in fields}, "cases": len(report["cases"])}
            ).decode()
        )
        return 0
    except (Rejected, OSError, KeyError, TypeError, ValueError):
        if output is not None:
            with suppress(Rejected, OSError):
                write_json(output, {"status": "fail", "release_ready": False})
        print(
            "Release proposal qualification rejected; inspect scoped evidence locally",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
