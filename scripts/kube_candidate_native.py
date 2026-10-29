"""Actual signed proposal -> isolated qualification HTTP. Hosted CI only."""

import copy
import math
import sys
import time
import uuid
from contextlib import suppress
from functools import partial
from pathlib import Path

from mlsecops import (
    controller_bootstrap,
    kube_storage,
    kube_trust,
    release_bundle,
    signing,
    trust_authority,
)
from mlsecops.candidate_serving_reader import KIND
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
from mlsecops.datasets import FEATURES
from mlsecops.inventory import command, source_fingerprint
from mlsecops.kube_storage_migration import ledger
from mlsecops.kube_worker import run_worker
from mlsecops.prediction_protocol import PredictionBatch
from mlsecops.private_cli import Arguments
from mlsecops.trust_targets import Target
from scripts.candidate_serving_reader import bind_proposal
from scripts.kube_candidate_faults import NONTERMINAL
from scripts.kube_candidate_faults import exercise as exercise_faults
from scripts.kube_candidate_root import exercise as exercise_root
from scripts.kube_candidate_terminals import exercise as exercise_terminals
from scripts.kube_promotion_native import actual
from scripts.kube_promotion_snapshot import read as snapshot
from scripts.kube_serving_native import invoke
from scripts.kube_trust_native import hosted


def qualify(
    root,
    state,
    image,
    *,
    prepared=None,
    qualification_key=None,
    include_key_revocation=False,
    include_trust_lifecycle=False,
):
    hosted()
    root, state = Path(root).resolve(), Path(state).resolve()
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("candidate_inference_dirty_source")
    revision, fingerprint = (
        command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        source_fingerprint(root),
    )
    started = now()
    if prepared is None:
        kube_storage.validate(state)
        kube_trust.bootstrap(state)
        profile = controller_bootstrap.bootstrap(root, state, image, serving=True)["profile"]
        print(canonical({"stage": "actual-proposal-refusal"}).decode(), flush=True)
        refusal = actual(root, state, image)
    else:
        profile, refusal = prepared
    print(canonical({"stage": "actual-candidate-bind-proposal"}).decode(), flush=True)
    proposal = read_json(
        safe_child(state, "release-proposals/" + refusal["campaign_id"] + "/report.json")
    )
    public = read_json(state / "trusted-keys.json")["approver"]
    package = release_bundle.load(
        state / "storage-clients/serving", refusal["proposal"], publisher_public=public
    )
    source = {
        "source_revision": revision,
        "source_fingerprint": fingerprint,
        "image_id": profile["image_id"],
    }
    context, verified = bind_proposal(
        proposal,
        package,
        policy=read_json(root / "policies/local-cpu.json"),
        source_trust=read_json(state / "storage-trust.json"),
        publisher_public=public,
        expected=source,
        clock=math.ceil(time.time()),
    )
    campaign = uuid.uuid4().hex
    destination = safe_child(state, "candidate-inference/" + campaign)
    key = destination / "qualification.pem"
    authority_key = (
        destination / "authority.pem" if qualification_key is None else qualification_key
    )
    qualification_public = signing.create_key(key)
    authority_public = signing.create_key(authority_key)
    independent = include_trust_lifecycle and include_key_revocation
    if independent:
        # Provision the second independent authority BEFORE issuing the one permit.
        print(canonical({"stage": "actual-model-authority-bootstrap"}).decode(), flush=True)
        kube_trust.bootstrap(state, target=Target.MODEL_REVOCATION)
        print(canonical({"stage": "actual-model-authority-ready"}).decode(), flush=True)
    # Obtain reference predictions before starting the short permit lifetime.
    features = [[value] * len(FEATURES) for value in (0.1, 0.5, 0.9)]
    batch = PredictionBatch(verified["model"], features)
    output, execution = run_worker(state, image, batch.request)
    scores, _, receipt = batch.consume(output)
    if receipt["model_digest"] != refusal["model"]:
        raise Rejected("candidate_inference_reference_model")
    write_json(
        destination / "reference.json",
        {"response": output, "receipt": receipt, "execution": execution},
    )
    issued = int(time.time())
    permit = {
        "schema_version": 1,
        "purpose": KIND,
        "campaign_id": campaign,
        "environment": context["policy"]["environment"],
        "proposal_sha256": refusal["proposal"],
        "subject_sha256": verified["subject_sha256"],
        "model_sha256": refusal["model"],
        **source,
        "issued_at": issued,
        "expires_at": min(issued + 600, verified["manifest"]["expires_at"]),
    }
    if permit["expires_at"] - issued < 240:
        raise Rejected("candidate_inference_window")
    envelope = signing.sign(permit, KIND, key)
    permit_hash = digest(canonical(permit))
    trust_authority.install(
        state, permit["environment"], authority_public, backend=kube_trust.binding
    )
    trust_authority.update(state, permit_hash, authority_key, backend=kube_trust.binding)
    if independent:
        alternate_backend = partial(kube_trust.binding, target=Target.MODEL_REVOCATION)
        trust_authority.install(
            state, permit["environment"], authority_public, backend=alternate_backend
        )
        trust_authority.update(state, permit_hash, authority_key, backend=alternate_backend)
    config = {
        "context": context,
        "publisher_public": public,
        "proposal_reference": refusal["proposal"],
        "permit_envelope": envelope,
        "permit_public": qualification_public,
        "trust_root": authority_public,
        "minimum_trust_version": 1,
        "expected_permit": permit_hash,
        "expected_campaign": campaign,
        "kubernetes_worker": profile,
    }
    # Preserve the authentic proposal. Add a separate unsigned blob for the negative case.
    unsigned = canonical({**copy.deepcopy(package["envelope"]), "signatures": []})
    unsigned_id = digest(unsigned)
    observed = kube_storage.admin(
        state,
        f"INSERT INTO ml.releases (sha256,payload) VALUES ('{unsigned_id}',decode('{unsigned.hex()}','hex')) ON CONFLICT DO NOTHING; SELECT encode(sha256(payload),'hex') FROM ml.releases WHERE sha256='{unsigned_id}';",
    )
    if observed != unsigned_id:
        raise Rejected("candidate_unsigned_readback")
    unsigned_permit = {**permit, "proposal_sha256": unsigned_id}
    expected = {
        "model": refusal["model"],
        "bundle": verified["subject_sha256"],
        "features": features,
        "scores": scores.tolist(),
        "clock_cache": include_trust_lifecycle,
        "independent_authorities": independent,
        "unsigned_proposal": {
            "proposal_reference": unsigned_id,
            "permit_envelope": signing.sign(unsigned_permit, KIND, key),
            "expected_permit": digest(canonical(unsigned_permit)),
        },
    }
    write_json(destination / "config.json", config)
    write_json(destination / "request.json", expected)
    before = ledger(state)
    base_snapshot = snapshot(state)
    root_rotation = None
    if independent:
        next_key = destination / "rotated-authority.pem"
        root_rotation = exercise_root(
            state,
            profile,
            config,
            expected,
            old_key=authority_key,
            new_key=next_key,
            expires_at=permit["expires_at"],
        )
        config.update(
            trust_root=root_rotation["next_public"],
            minimum_trust_version=root_rotation["minimum_trust_version"],
        )
        authority_key = next_key
        write_json(destination / "root-rotation.json", root_rotation)
        write_json(destination / "config.json", config)
    print(canonical({"stage": "actual-candidate-HTTP-matrix"}).decode(), flush=True)
    result = invoke(state, profile, config, expected, candidate_probe=True)
    if snapshot(state) != base_snapshot:
        raise Rejected("candidate_inference_promotion_state_changed")
    revoked_key = digest(signing.decode64(public))
    faults = NONTERMINAL if include_trust_lifecycle else ()
    if include_key_revocation and not independent:
        faults += ("key-revocation",)
    fault_results = (
        exercise_faults(
            state,
            profile,
            config,
            expected,
            key=authority_key,
            policy=permit_hash,
            revoked_key=revoked_key,
            faults=faults,
            expires_at=permit["expires_at"],
        )
        if faults
        else {}
    )
    terminals = None
    if independent:
        terminals = exercise_terminals(
            state,
            profile,
            config,
            expected,
            base_probe=result,
            key=authority_key,
            revoked_key=revoked_key,
            expires_at=permit["expires_at"],
        )
        fault_results["model-revocation"] = terminals["model"]
        fault_results["key-revocation"] = terminals["key"]
        write_json(
            destination / "independent-authorities.json",
            {name: value for name, value in terminals.items() if name not in ("model", "key")},
        )
    key_result = fault_results.get("key-revocation", {}).get("probe")
    for fault, value in fault_results.items():
        write_json(destination / (fault + ".json"), value["probe"])
    if (
        ledger(state) != before
        or source_fingerprint(root) != fingerprint
        or command(["git", "-C", str(root), "status", "--porcelain"])
        or result["model_sha256"] != refusal["model"]
        or result["subject_sha256"] != verified["subject_sha256"]
    ):
        raise Rejected("candidate_inference_binding_changed")
    write_json(destination / "probe.json", result)
    return {
        "schema_version": 1,
        "status": "pass",
        "scope": "actual-candidate-kubernetes-inference",
        "release_ready": False,
        "full_M12": "inconclusive",
        "source_dirty": False,
        "source": source,
        "started_at": started,
        "finished_at": now(),
        "candidate_reference": refusal["candidate"],
        "proposal_reference": refusal["proposal"],
        "model_sha256": refusal["model"],
        "subject_sha256": verified["subject_sha256"],
        "proposal_issued_at": verified["manifest"]["issued_at"],
        "actual_refusal": refusal,
        "qualification_permit_sha256": permit_hash,
        "native": result,
        "base_snapshot_sha256": digest(canonical(base_snapshot)),
        **({"root_rotation": root_rotation} if root_rotation is not None else {}),
        "trust_lifecycle": {
            name: value for name, value in fault_results.items() if name in NONTERMINAL
        },
        **(
            {
                "model_revocation": terminals["model"]["probe"],
                "model_revocation_snapshot_sha256": terminals["model"]["snapshot_sha256"],
                "independent_authorities": {
                    name: value for name, value in terminals.items() if name not in ("model", "key")
                },
            }
            if terminals is not None
            else {}
        ),
        **(
            {
                "key_revocation": key_result,
                "revoked_key_sha256": revoked_key,
                "key_revocation_snapshot_sha256": fault_results["key-revocation"][
                    "snapshot_sha256"
                ],
            }
            if key_result is not None
            else {}
        ),
        "artifact_hashes": {
            name: digest(bounded_read(destination / name))
            for name in (
                "reference.json",
                "config.json",
                "request.json",
                "probe.json",
                *(("root-rotation.json",) if root_rotation is not None else ()),
                *(name + ".json" for name in fault_results),
                *(("independent-authorities.json",) if terminals is not None else ()),
            )
        },
        "limitations": [
            "Candidate qualification does not authorize release or create assurance",
            "Full M12 requires source-bound controlled contracts and acceptance aggregation",
            "M13-M18, system-image findings and independent M22 review remain open",
        ],
    }


def main(arguments=None):
    path = None
    try:
        hosted()
        parser = Arguments(prog="kubernetes-candidate-inference")
        parser.add_argument("--state", type=Path, required=True)
        parser.add_argument("--image", default="trusted-mlsecops:dev")
        options = parser.parse_args(arguments)
        path = safe_child(options.state, "evidence/kubernetes-candidate-inference.json")
        write_json(path, {"status": "inconclusive", "release_ready": False})
        report = qualify(Path(__file__).resolve().parents[1], options.state, options.image)
        write_json(path, report)
        print(canonical(report).decode())
        return 0
    except (Exception, KeyboardInterrupt) as error:
        if path is not None:
            with suppress(OSError, Rejected):
                write_json(path, {"status": "fail", "release_ready": False})
        print("kubernetes_candidate_inference_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
