"""One hosted native serving campaign consumed separately by M11 and M12."""

import os
import sys
from datetime import datetime
from pathlib import Path

from mlsecops import kube_storage, promotion_state, release_policy, signing, trust_delivery
from mlsecops.candidate_serving_reader import KIND
from mlsecops.contracts import Rejected, canonical, digest, safe_child
from mlsecops.security_events import hexadecimal
from mlsecops.trust_targets import Target
from scripts import (
    kube_authority_pair,
    kube_candidate_native,
    kube_serving_native,
    m12_pinned_native,
)
from scripts.canary_rollout_native import publish_pin
from scripts.kube_promotion_snapshot import read as snapshot
from scripts.kube_security_outage_native import failure_report, ownership_return
from scripts.kube_trust_native import hosted

EARLY = "evidence/shared-serving-actual.json"
FULL = "evidence/shared-serving-native.json"
PIN = "M11_M12_NATIVE_SHA256"


def require(test, cause):
    if not test:
        raise Rejected("shared_serving_" + cause)


def pins(env):
    p, q, d = (
        env.get(k) for k in ("M11_PROPOSAL_SHA256", "M12_PROPOSAL_SHA256", "M11_DEMO_SHA256")
    )
    require(p is not None and p == q and d is not None and "M12_EARLY_SHA256" not in env, "pins")
    return hexadecimal(p), hexadecimal(d)


def owner(root, state, image):
    p, d = pins(os.environ)
    value = m12_pinned_native.owner(root, state, image, p)
    require(value["inputs"]["storage-demo.json"] == d, "demo_pin")
    return value


def directory(state, actual):
    return safe_child(
        state, "candidate-inference/" + hexadecimal(actual["qualification_campaign_id"], 32)
    )


def retained(state, early):
    actual = early["actual"]
    root = directory(state, actual)
    expected = {
        "config.json",
        "request.json",
        "reference.json",
        "probe.json",
        "root-rotation.json",
        "independent-authorities.json",
        "outage.json",
        "blackhole.json",
        "policy-change.json",
        "key-revocation.json",
        "model-revocation.json",
    }
    require(set(actual["artifact_hashes"]) == expected, "artifact_set")
    files = {
        k: trust_delivery.pinned(safe_child(root, k), v)
        for k, v in actual["artifact_hashes"].items()
    }
    joined = {
        "probe.json": actual["native"],
        "root-rotation.json": actual["root_rotation"],
        "independent-authorities.json": actual["independent_authorities"],
        "model-revocation.json": actual["model_revocation"],
        "key-revocation.json": actual["key_revocation"],
        **{k + ".json": v["probe"] for k, v in actual["trust_lifecycle"].items()},
    }
    require(all(canonical(files[k]) == canonical(v) for k, v in joined.items()), "primary_bytes")
    binding = early["binding"]
    config = files["config.json"]
    permit = release_policy.checked(config["permit_envelope"], KIND, config["permit_public"])
    signed = {
        "campaign_id": actual["qualification_campaign_id"],
        "purpose": KIND,
        "schema_version": 1,
        "environment": binding["context"]["policy"]["environment"],
        "proposal_sha256": binding["proposal_reference"],
        "subject_sha256": binding["subject_sha256"],
        "model_sha256": binding["model_sha256"],
        **binding["source"],
    }
    require(
        canonical(permit)
        == canonical(
            {**signed, "issued_at": permit["issued_at"], "expires_at": permit["expires_at"]}
        ),
        "permit",
    )
    release_policy.window(permit, permit["issued_at"], maximum=600)
    start, finish = (datetime.fromisoformat(actual[k]) for k in ("started_at", "finished_at"))
    request = files["request.json"]
    require(
        config["context"] == binding["context"]
        and config["publisher_public"] == binding["publisher_public"]
        and config["proposal_reference"] == signed["proposal_sha256"]
        and config["kubernetes_worker"] == early["prepared"]["profile"]
        and request["clock_cache"] is True
        and request["independent_authorities"] is True
        and actual["actual_refusal"]["parent_refusal"] == "release_assurance_required"
        and actual["actual_refusal"]["job_outcome"] == "rejected",
        "actual_inputs",
    )
    require(
        config["expected_campaign"] == signed["campaign_id"]
        and config["expected_permit"]
        == digest(canonical(permit))
        == actual["qualification_permit_sha256"]
        and config["trust_root"] == actual["root_rotation"]["next_public"]
        and binding["proposal_issued_at"] == actual["proposal_issued_at"]
        and start.utcoffset() is not None
        and finish.utcoffset() is not None
        and binding["proposal_issued_at"] <= start.timestamp() <= finish.timestamp()
        and int(start.timestamp())
        <= permit["issued_at"]
        <= finish.timestamp()
        < permit["expires_at"]
        and 240 <= permit["expires_at"] - permit["issued_at"] <= 600
        and permit["expires_at"] <= binding["proposal_expires_at"]
        and actual["source"] == binding["source"] == early["owner"]["source"]
        and actual["actual_refusal"] == early["prepared"]["actual"]
        and all(
            actual[k] == binding[k]
            for k in (
                "model_sha256",
                "subject_sha256",
                "proposal_reference",
                "candidate_reference",
                "evaluation_reference",
            )
        )
        and files["reference.json"]["receipt"]["model_digest"]
        == files["request.json"]["model"]
        == binding["model_sha256"]
        and files["request.json"]["bundle"] == binding["subject_sha256"]
        and digest(canonical(early["sql_snapshot"])) == actual["base_snapshot_sha256"],
        "actual_binding",
    )
    ownership_return(actual["trust_lifecycle_ownership_return"])
    states = actual["independent_authorities"]["states"]
    kube_authority_pair.transition(
        states["before"],
        states["after_model"],
        Target.MODEL_REVOCATION,
        "revoked_artifacts",
        signed["model_sha256"],
    )
    kube_authority_pair.transition(
        states["after_model"],
        states["after_key"],
        Target.PRIMARY,
        "revoked_keys",
        actual["revoked_key_sha256"],
    )
    kube_authority_pair.isolation(actual["native"], states["before"], Target.PRIMARY)
    kube_authority_pair.isolation(
        actual["model_revocation"], states["before"], Target.MODEL_REVOCATION
    )
    require(
        all(
            value == actual["base_snapshot_sha256"]
            for value in (
                actual["root_rotation"]["model_snapshot_sha256"],
                actual["key_revocation_snapshot_sha256"],
                actual["model_revocation_snapshot_sha256"],
                *(r["snapshot_sha256"] for r in actual["trust_lifecycle"].values()),
            )
        ),
        "sql_snapshot",
    )
    return config


def capture(root, state, image):
    hosted()
    trust_delivery.clean_campaign(state)
    owned = owner(root, state, image)
    binding = trust_delivery.freeze(root, state, owned["source"], *pins(os.environ))
    promotion_state.install(state, backend=kube_storage.binding)
    prepared = kube_serving_native.prepare(
        root, state, image, proposal_pin=owned["proposal_sha256"]
    )
    actual = kube_candidate_native.qualify(
        root,
        state,
        image,
        prepared=(prepared["profile"], prepared["actual"]),
        include_key_revocation=True,
        include_trust_lifecycle=True,
    )
    packet = dict(
        owner=owned, binding=binding, prepared=prepared, actual=actual, sql_snapshot=snapshot(state)
    )
    retained(state, packet)
    require(owner(root, state, image) == owned, "owner_changed")
    return packet


def late(root, state, image, early_pin):
    hosted()
    early = trust_delivery.pinned(safe_child(state, EARLY), early_pin)
    require(owner(root, state, image) == early["owner"], "owner_changed")
    config = retained(state, early)
    actual = early["actual"]
    final = actual["independent_authorities"]["states"]["after_key"]
    for target in Target:
        require(kube_authority_pair.read(state, target) == final[target.value], "authority_handoff")
    require(snapshot(state) == early["sql_snapshot"], "sql_handoff")
    key = safe_child(directory(state, actual), "rotated-authority.pem")
    public = signing.encode64(signing.load_key(key).public_key().public_bytes_raw())
    require(public == config["trust_root"], "authority_key")
    controlled = kube_serving_native.qualify(
        root, state, image, prepared=early["prepared"], continued_authority=(key, public)
    )
    after = kube_authority_pair.read(state, Target.PRIMARY)
    require(
        kube_authority_pair.read(state, Target.MODEL_REVOCATION) == final["model-revocation"]
        and actual["revoked_key_sha256"] in after["revoked_keys"]
        and after["identity"]
        == {
            **final["primary"]["identity"],
            "root_sha256": digest(
                signing.decode64(controlled["authority_root_rotation"]["next_public"])
            ),
        },
        "authority_continuity",
    )
    require(owner(root, state, image) == early["owner"], "owner_changed")
    return dict(early_sha256=early_pin, controlled=controlled)


def lookup(root, state, image):
    hosted()
    full = trust_delivery.pinned(safe_child(state, FULL), hexadecimal(os.environ.get(PIN)))
    early_pin = hexadecimal(os.environ.get("M11_M12_ACTUAL_SHA256"))
    require(early_pin == full["early_sha256"], "early_pin")
    early = trust_delivery.pinned(safe_child(state, EARLY), early_pin)
    require(owner(root, state, image) == early["owner"], "owner_changed")
    config = retained(state, early)
    native = full["controlled"]
    require(
        "actual_inference" not in native
        and native["actual"] == early["prepared"]["actual"]
        and all(native[k] == v for k, v in early["owner"]["source"].items()),
        "controlled_binding",
    )
    return early["binding"], {**native, "actual_inference": early["actual"]}, config


def main():
    stage = "arguments"
    try:
        hosted()
        require(sys.argv[1:] in (["actual"], ["controlled"]), "arguments")
        stage = sys.argv[1]
        root = Path(__file__).resolve().parents[1]
        state = root / ".runtime"
        image = "trusted-mlsecops:dev"
        if stage == "actual":
            packet = capture(root, state, image)
            path = EARLY
            print(
                canonical(
                    dict(
                        stage=stage,
                        issued_at=packet["binding"]["proposal_issued_at"],
                        expires_at=packet["binding"]["proposal_expires_at"],
                        finished_at=packet["actual"]["finished_at"],
                    )
                ).decode(),
                flush=True,
            )
        else:
            packet = late(root, state, image, os.environ["M11_M12_ACTUAL_SHA256"])
            path = FULL
        pin = publish_pin(state, path, packet)
        print(canonical(dict(stage=stage, sha256=pin)).decode())
        return 0
    except Exception as error:
        diagnostic = failure_report(error)
        print(
            canonical(
                dict(
                    stage=stage,
                    status="fail",
                    site=diagnostic["site"],
                    callers=diagnostic["callers"],
                    request=diagnostic["request"],
                )
            ).decode()
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
