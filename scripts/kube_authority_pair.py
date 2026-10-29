"""Owned identities plus full trust history for independent revoke experiments."""

from functools import partial

from mlsecops import kube_trust, signing, storage, trust, trust_authority
from mlsecops.contracts import Rejected, bounded_read, canonical, digest, safe_child
from mlsecops.trust_targets import Target, select


def read(state, target):
    target = select(target)
    marker = kube_trust.validate(state, target=target)
    admin = partial(kube_trust.admin, target=target)
    # The immediately preceding validation establishes the owned target binding.
    _, current = trust_authority.current(state, backend=lambda state: (state, admin))
    payload = trust.validate(
        current["envelope"], current["root_public"], current["environment"], current["clock"]
    )
    history = storage.object_id(
        admin(
            state,
            "SELECT encode(sha256(convert_to(jsonb_build_object('settings', "
            "(SELECT to_jsonb(s) FROM ml_trust.settings s), 'documents', "
            "(SELECT jsonb_agg(to_jsonb(d) ORDER BY version) FROM ml_trust.documents d))::text, 'UTF8')), 'hex');",
        )
    )
    return {
        "identity": {
            "target": target.value,
            "host": target.host,
            "ca_sha256": digest(
                bounded_read(
                    safe_child(kube_trust.directory(state, target=target), "storage-pki/ca.crt"),
                    4096,
                )
            ),
            "root_sha256": digest(signing.decode64(current["root_public"])),
            "resources_sha256": digest(canonical(marker["resources"])),
            "volume_uid_sha256": digest(marker["volume_uid"].encode()),
            "spec_digest": marker["spec_digest"],
        },
        "history_sha256": history,
        "version": payload["version"],
        "policy_sha256": payload["promotion_policy_sha256"],
        "revoked_artifacts": payload["revoked_artifacts"],
        "revoked_keys": payload["revoked_keys"],
    }


def capture(state, public, policy):
    result = {target.value: read(state, target) for target in Target}
    for field in ("host", "ca_sha256", "resources_sha256", "volume_uid_sha256", "spec_digest"):
        if len({value["identity"][field] for value in result.values()}) != 2:
            raise Rejected("candidate_authorities_not_independent")
    if any(
        value["identity"]["root_sha256"] != digest(signing.decode64(public))
        or value["policy_sha256"] != policy
        for value in result.values()
    ):
        raise Rejected("candidate_authorities_policy_or_root")
    return result


def transition(before, after, target, field, reference):
    target = select(target)
    if (target, field) not in (
        (Target.PRIMARY, "revoked_keys"),
        (Target.MODEL_REVOCATION, "revoked_artifacts"),
    ):
        raise Rejected("candidate_authority_revoke_target")
    other = Target.MODEL_REVOCATION if target is Target.PRIMARY else Target.PRIMARY
    old, new = before[target.value], after[target.value]
    remaining = "revoked_keys" if field == "revoked_artifacts" else "revoked_artifacts"
    if (
        before[other.value] != after[other.value]
        or old["identity"] != new["identity"]
        or old["policy_sha256"] != new["policy_sha256"]
        or new["version"] != old["version"] + 1
        or old["history_sha256"] == new["history_sha256"]
        or reference in old[field]
        or new[field] != sorted([*old[field], reference])
        or new[remaining] != old[remaining]
    ):
        raise Rejected("candidate_authority_revoke_transition")


def isolation(report, states, target):
    target = select(target)
    other = Target.MODEL_REVOCATION if target is Target.PRIMARY else Target.PRIMARY
    identity = states[target.value]["identity"]
    expected = {
        "target": target.value,
        "host": target.host,
        "ca_sha256": identity["ca_sha256"],
        "other_target": other.value,
        "cross_ca_denied": True,
    }
    if canonical(report.get("authority_isolation")) != canonical(expected):
        raise Rejected("candidate_authority_isolation_binding")
