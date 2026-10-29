"""Actual signed proposal -> isolated qualification HTTP. Hosted CI only."""

import copy
import math
import sys
import time
import uuid
from contextlib import suppress
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
from scripts.candidate_serving_reader import bind_proposal
from scripts.kube_promotion_native import actual
from scripts.kube_promotion_snapshot import read as promotion_snapshot
from scripts.kube_serving_faults import Coordinator
from scripts.kube_serving_native import invoke
from scripts.kube_trust_native import hosted


def qualify(
    root, state, image, *, prepared=None, qualification_key=None, include_key_revocation=False
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
    key = destination / "qualification.pem" if qualification_key is None else qualification_key
    qualification_public = signing.create_key(key)
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
        state, permit["environment"], qualification_public, backend=kube_trust.binding
    )
    trust_authority.update(state, permit_hash, key, backend=kube_trust.binding)
    config = {
        "context": context,
        "publisher_public": public,
        "proposal_reference": refusal["proposal"],
        "permit_envelope": envelope,
        "permit_public": qualification_public,
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
        "unsigned_proposal": {
            "proposal_reference": unsigned_id,
            "permit_envelope": signing.sign(unsigned_permit, KIND, key),
            "expected_permit": digest(canonical(unsigned_permit)),
        },
    }
    write_json(destination / "config.json", config)
    write_json(destination / "request.json", expected)
    before = ledger(state)
    print(canonical({"stage": "actual-candidate-HTTP-matrix"}).decode(), flush=True)
    result = invoke(state, profile, config, expected, candidate_probe=True)
    key_result = None
    if include_key_revocation:
        journal_before = promotion_snapshot(state)
        revoked_key = digest(signing.decode64(public))
        print(canonical({"stage": "actual-candidate-key-revocation"}).decode(), flush=True)
        with Coordinator(
            state, "key-revocation", permit_hash, key, refusal["model"], revoked_key=revoked_key
        ) as coordinator:
            key_result = invoke(
                state,
                profile,
                config,
                {**expected, "fault": "key-revocation"},
                coordinator=coordinator,
                candidate_probe=True,
            )
        if (
            key_result["model_sha256"] != refusal["model"]
            or key_result["subject_sha256"] != verified["subject_sha256"]
            or promotion_snapshot(state) != journal_before
        ):
            raise Rejected("candidate_key_revocation_binding_changed")
        write_json(destination / "key-revocation.json", key_result)
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
        **(
            {
                "key_revocation": key_result,
                "revoked_key_sha256": revoked_key,
                "key_revocation_snapshot_sha256": digest(canonical(journal_before)),
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
                *(["key-revocation.json"] if key_result is not None else []),
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
