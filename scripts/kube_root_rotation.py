"""Owned hosted-authority rotation before ordinary serving resumes with explicit pins."""

import copy

from mlsecops import kube_trust, signing, trust, trust_authority, trust_root_store, trust_rotation
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.trust_targets import Target
from scripts.kube_authority_pair import read as authority_snapshot
from scripts.kube_promotion_snapshot import read as model_snapshot

ARTIFACT = digest(b"root-rotation-revoked-artifact-control")
KEY = digest(b"root-rotation-revoked-key-control")


def prepare(before, old_key, new_key):
    old_public = signing.encode64(signing.load_key(old_key).public_key().public_bytes_raw())
    if old_public != before["root_public"]:
        raise Rejected("rotation_fixture_current_root")
    new_public = signing.create_key(new_key)
    prior = trust.validate(before["envelope"], old_public, before["environment"], before["clock"])
    following = {
        **prior,
        "version": prior["version"] + 1,
        "issued_at": before["clock"],
        "revoked_keys": sorted([*prior["revoked_keys"], trust_rotation.key_id(old_public)]),
    }
    document = signing.sign(following, "trust-policy", new_key)
    intent = {
        "schema_version": 1,
        "environment": before["environment"],
        "current_root": old_public,
        "next_root": new_public,
        "previous_version": prior["version"],
        "previous_sha256": before["sha256"],
        "next_version": following["version"],
        "next_sha256": digest(canonical(document)),
        "issued_at": before["clock"],
        "expires_at": min(before["clock"] + 300, prior["expires_at"]),
    }
    return {
        "schema_version": 1,
        "authorization": signing.sign(intent, trust_rotation.KIND, old_key),
        "acceptance": signing.sign(intent, trust_rotation.KIND, new_key),
        "document": document,
    }


def snapshot(state, *, target=Target.PRIMARY):
    options = {} if target is Target.PRIMARY else {"target": target}
    records = decode(
        kube_trust.admin(
            state,
            """SELECT jsonb_build_object(
        'migrations', (SELECT jsonb_agg(jsonb_build_array(version, sha256) ORDER BY version) FROM ml_trust.migrations),
        'documents', (SELECT jsonb_agg(jsonb_build_array(version, sha256) ORDER BY version) FROM ml_trust.documents),
        'rotations', (SELECT coalesce(jsonb_agg(jsonb_build_array(version, sha256) ORDER BY version), '[]'::jsonb) FROM ml_trust.root_rotations));""",
            **options,
        ).encode()
    )
    return {"authority": authority_snapshot(state, target), "records": records}


def transition(before, after, receipt):
    old, new = before["authority"], after["authority"]
    left, right = before["records"], after["records"]
    if (
        new["version"] != old["version"] + 1
        or new["version"] != receipt["version"]
        or new["identity"]["root_sha256"] != receipt["root_sha256"]
        or new["identity"]["root_sha256"] == old["identity"]["root_sha256"]
        or {k: v for k, v in old["identity"].items() if k != "root_sha256"}
        != {k: v for k, v in new["identity"].items() if k != "root_sha256"}
        or new["policy_sha256"] != old["policy_sha256"]
        or new["revoked_artifacts"] != old["revoked_artifacts"]
        or new["revoked_keys"] != sorted([*old["revoked_keys"], old["identity"]["root_sha256"]])
        or right["migrations"] != left["migrations"]
        or right["documents"]
        != [*left["documents"], [receipt["version"], receipt["document_sha256"]]]
        or right["rotations"]
        != [*left["rotations"], [receipt["version"], receipt["rotation_sha256"]]]
    ):
        raise Rejected("rotation_native_transition")


def exercise(state, old_key, new_key):
    models = model_snapshot(state)
    _, initial = trust_authority.current(state, backend=kube_trust.binding)
    policy = trust.validate(initial["envelope"], initial["root_public"], initial["environment"])
    trust_authority.update(
        state,
        policy["promotion_policy_sha256"],
        old_key,
        revoked_artifacts=[ARTIFACT],
        revoked_keys=[KEY],
        backend=kube_trust.binding,
    )
    migration = trust_root_store.migrate(state, backend=kube_trust.binding)
    if trust_root_store.migrate(state, backend=kube_trust.binding).get("reused") is not True:
        raise Rejected("rotation_migration_retry")
    _, current = trust_authority.current(state, backend=kube_trust.binding)
    package = prepare(current, old_key, new_key)
    intent = trust_rotation.authorization(package, current["root_public"])
    arguments = {
        "current_root": current["root_public"],
        "next_root": intent["next_root"],
        "backend": kube_trust.binding,
    }
    before = snapshot(state)
    if (
        ARTIFACT not in before["authority"]["revoked_artifacts"]
        or KEY not in before["authority"]["revoked_keys"]
    ):
        raise Rejected("rotation_revocation_controls_missing")
    negative = {}

    def refuse(label, operation, reason):
        previous = snapshot(state)
        try:
            operation()
        except Rejected as error:
            if str(error) != reason:
                raise Rejected("rotation_native_wrong_refusal") from None
        else:
            raise Rejected("rotation_native_missing_refusal")
        if snapshot(state) != previous:
            raise Rejected("rotation_native_refusal_wrote_history")
        negative[label] = {
            "cause": reason,
            "unchanged_snapshot_sha256": digest(canonical(previous)),
        }

    changed = {**intent, "previous_sha256": "0" * 64}
    bad = {
        **package,
        "authorization": signing.sign(changed, trust_rotation.KIND, old_key),
        "acceptance": signing.sign(changed, trust_rotation.KIND, new_key),
    }
    refuse(
        "previous-reference",
        lambda: trust_root_store.rotate(state, bad, **arguments),
        "rotation_head_changed",
    )
    bad = copy.deepcopy(package)
    bad["acceptance"]["signatures"] = []
    refuse(
        "missing-acceptance",
        lambda: trust_root_store.rotate(state, bad, **arguments),
        "invalid_signature_count",
    )
    following = trust.validate(package["document"], intent["next_root"], current["environment"])
    document = signing.sign({**following, "revoked_artifacts": []}, "trust-policy", new_key)
    changed = {**intent, "next_sha256": digest(canonical(document))}
    bad = {
        **package,
        "document": document,
        "authorization": signing.sign(changed, trust_rotation.KIND, old_key),
        "acceptance": signing.sign(changed, trust_rotation.KIND, new_key),
    }
    refuse(
        "removed-revocation",
        lambda: trust_root_store.rotate(state, bad, **arguments),
        "trust_update_conflict_or_unrevocation",
    )
    receipt = trust_root_store.rotate(state, package, **arguments)
    if (
        receipt.get("state") != "rotated-not-activated"
        or receipt.get("release_ready") is not False
        or receipt.get("reused") is not False
    ):
        raise Rejected("rotation_native_receipt")
    after = snapshot(state)
    transition(before, after, receipt)
    retry = trust_root_store.rotate(state, package, **arguments)
    if retry != {**receipt, "reused": True} or snapshot(state) != after:
        raise Rejected("rotation_native_retry")
    refuse(
        "retired-key-update",
        lambda: trust_authority.update(
            state, policy["promotion_policy_sha256"], old_key, backend=kube_trust.binding
        ),
        "untrusted_key",
    )
    if model_snapshot(state) != models:
        raise Rejected("rotation_native_model_storage_changed")
    return {
        "scope": "planned-authority-root-rotation-not-full-M11",
        "status": "pass",
        "release_ready": False,
        "next_public": intent["next_root"],
        "migration": migration,
        "before": before,
        "after": after,
        "receipt": receipt,
        "retry": retry,
        "negative": negative,
        "model_snapshot_sha256": digest(canonical(models)),
    }
