"""Capture the live proposal once, then run ordinary release controls on PRIMARY."""

import os
import sys
from datetime import datetime
from pathlib import Path

from mlsecops import cluster, kube_storage, promotion_state, signing
from mlsecops.canary_native_evidence import read_pinned
from mlsecops.candidate_serving_reader import KIND
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, now, safe_child
from mlsecops.security_events import hexadecimal
from mlsecops.trust_targets import Target
from scripts import kube_authority_pair, kube_candidate_native, kube_serving_native
from scripts.canary_rollout_native import publish_pin
from scripts.kube_load_native import failure_site
from scripts.kube_security_outage_native import failure_report, ownership_return
from scripts.kube_trust_native import hosted
from scripts.serving_output_native import source

PACKET = "evidence/m12-actual-private.json"
PEER = Target.MODEL_REVOCATION
ARTIFACTS = ("config.json", "request.json", "reference.json", "probe.json")


def require(value):
    if not value:
        raise Rejected("M12_pinned_binding")


def owner(root, state, image, pin):
    proposal = decode(read_pinned(safe_child(state, "evidence/release-native.json"), pin))
    campaign = hexadecimal(proposal["campaign_id"], 32)
    read_pinned(safe_child(state, f"release-proposals/{campaign}/report.json"), pin)
    marker = cluster.validate_cluster(state)
    expected = source(root, image)
    require(proposal["source"] == expected)
    return {
        "proposal_sha256": pin,
        "source": expected,
        "workspace": marker["workspace_id"],
        "cluster": marker["namespace_uid"],
        "runner": {k: os.environ[k] for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")},
        "inputs": {
            name: digest(bounded_read(safe_child(state, name)))
            for name in ("storage-demo.json", "storage-trust.json", "trusted-keys.json")
        },
    }


def verify(state, packet):
    actual, prepared = packet["actual"], packet["prepared"]
    owner = packet["owner"]
    source = owner["source"]
    refusal = prepared["actual"]
    require(
        source == actual["source"]
        and source["image_id"] == prepared["profile"]["image_id"]
        and all(prepared[k] == source[k] for k in ("source_revision", "source_fingerprint"))
        and refusal == actual["actual_refusal"]
        and refusal["parent_refusal"] == "release_assurance_required"
        and refusal["job_outcome"] == "rejected"
        and actual["native"]["authority_target"] == PEER.value
        and actual["status"] == "pass"
        and actual["release_ready"] is False
        and set(actual["artifact_hashes"]) == set(ARTIFACTS)
    )
    ownership_return(actual["native"]["ownership_return"])
    campaign = hexadecimal(actual["qualification_campaign_id"], 32)
    location = safe_child(state, "candidate-inference/" + campaign)
    retained = {
        name: decode(read_pinned(safe_child(location, name), actual["artifact_hashes"][name]))
        for name in ARTIFACTS
    }
    config = retained["config.json"]
    permit = signing.verify(config["permit_envelope"], KIND, config["permit_public"])
    proposal = decode(
        read_pinned(safe_child(state, "evidence/release-native.json"), owner["proposal_sha256"])
    )
    demo = decode(
        read_pinned(safe_child(state, "storage-demo.json"), owner["inputs"]["storage-demo.json"])
    )
    require(
        canonical(retained["probe.json"]) == canonical(actual["native"])
        and permit["campaign_id"] == config["expected_campaign"] == campaign
        and config["trust_target"] == PEER.value
        and packet["peer"]["identity"]["root_sha256"]
        == digest(signing.decode64(config["trust_root"]))
        and packet["peer"]["policy_sha256"]
        == digest(canonical(permit))
        == actual["qualification_permit_sha256"]
        and all(permit[k] == v for k, v in source.items())
        and permit["proposal_sha256"]
        == proposal["proposal_reference"]
        == actual["proposal_reference"]
        == refusal["proposal"]
        and permit["subject_sha256"] == proposal["subject_sha256"] == actual["subject_sha256"]
        and permit["model_sha256"]
        == proposal["model_sha256"]
        == actual["model_sha256"]
        == refusal["model"]
        and demo["candidate"]["candidate_reference"]
        == actual["candidate_reference"]
        == refusal["candidate"]
        and demo["evaluation_reference"] == actual["evaluation_reference"]
        and actual["proposal_issued_at"]
        <= datetime.fromisoformat(packet["started_at"]).timestamp()
        <= permit["issued_at"] + 1
        and 240 <= permit["expires_at"] - permit["issued_at"] <= 600
        and datetime.fromisoformat(actual["finished_at"]).timestamp()
        <= permit["expires_at"]
        <= actual["proposal_expires_at"]
    )
    by_id = {c["id"]: c["actual"] for c in actual["native"]["cases"]}
    require(
        by_id["qualification-permit-payload"]
        == config["expected_permit"]
        == digest(canonical(permit))
    )
    require(by_id["qualification-permit-envelope"] == digest(canonical(config["permit_envelope"])))


def capture(root, state, image, pin):
    hosted()
    binding = owner(root, state, image, pin)
    started = now()
    # Candidate snapshots include the promotion journal even before its first policy.
    promotion_state.install(state, backend=kube_storage.binding)
    prepared = kube_serving_native.prepare(root, state, image, proposal_pin=pin)
    primary = kube_authority_pair.read(state, Target.PRIMARY)
    actual = kube_candidate_native.qualify(
        root, state, image, prepared=(prepared["profile"], prepared["actual"]), pinned_m12=True
    )
    peer = kube_authority_pair.read(state, PEER)
    require(
        all(
            primary["identity"][k] != peer["identity"][k]
            for k in ("host", "volume_uid_sha256", "ca_sha256", "resources_sha256", "root_sha256")
        )
        and primary == kube_authority_pair.read(state, Target.PRIMARY)
        and binding == owner(root, state, image, pin)
    )
    packet = dict(
        owner=binding,
        started_at=started,
        prepared=prepared,
        actual=actual,
        primary=primary,
        peer=peer,
    )
    verify(state, packet)
    print(
        canonical(
            dict(
                stage="M12-pinned-actual-complete",
                cases=len(actual["native"]["cases"]),
                proposal_expires_at=actual["proposal_expires_at"],
                finished_at=actual["finished_at"],
            )
        ).decode(),
        flush=True,
    )
    return packet


def finish(root, state, image, pin, early_pin):
    hosted()
    if early_pin is None:
        packet = capture(root, state, image, pin)
    else:
        packet = decode(read_pinned(safe_child(state, PACKET), early_pin))
    require(packet["owner"] == owner(root, state, image, pin))
    verify(state, packet)
    require(packet["primary"] == kube_authority_pair.read(state, Target.PRIMARY))
    require(packet["peer"] == kube_authority_pair.read(state, PEER))
    # All ordinary production-CLI rotations retain their original primary owner.
    native = kube_serving_native.qualify(root, state, image, prepared=packet["prepared"])
    require(packet["peer"] == kube_authority_pair.read(state, PEER))
    require(packet["owner"] == owner(root, state, image, pin))
    verify(state, packet)
    return packet["actual"]["started_at"], {**native, "actual_inference": packet["actual"]}


def main():
    try:
        hosted()
        require(sys.argv[1:] == ["capture"])
        root = Path(__file__).resolve().parents[1]
        state = root / ".runtime"
        packet = capture(root, state, "trusted-mlsecops:dev", os.environ["M12_PROPOSAL_SHA256"])
        publish_pin(state, PACKET, packet)
        return 0
    except Exception as error:
        print(
            canonical(
                dict(
                    stage="M12-actual",
                    status="fail",
                    location=failure_site(error),
                    callers=failure_report(error)["callers"],
                )
            ).decode()
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
