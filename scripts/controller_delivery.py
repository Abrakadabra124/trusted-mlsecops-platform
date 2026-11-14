"""Verify the scoped gates against the joint candidate's frozen delivery inputs."""

import os
from pathlib import Path

from mlsecops.canary_native_evidence import read_pinned
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest


def reconcile(state, *, demo_pin, proposal_pin, revision):
    demo = decode(read_pinned(state / "storage-demo.json", demo_pin))
    evidence = state / "evidence"
    proposal = decode(read_pinned(evidence / "release-native.json", proposal_pin))
    meta = demo["candidate"]["metadata"]
    reference = demo["candidate"]["candidate_reference"]
    evaluation = demo["evaluation_reference"]
    dataset = demo["dataset"]["dataset_reference"]
    source = proposal["source"]
    expected_source = {
        key: meta[key] for key in ("source_revision", "source_fingerprint", "image_id")
    }
    if (
        source != expected_source
        or source["source_revision"] != revision
        or proposal["source_dirty"] is not False
        or proposal["release_ready"] is not False
        or proposal["status"] != "pass"
        or proposal["model_sha256"] != meta["model_digest"]
    ):
        raise Rejected("delivery_scoped_proposal")
    common = dict(
        candidate_reference=reference,
        evaluation_reference=evaluation,
        source_fingerprint=source["source_fingerprint"],
    )
    dataset_inputs = dict(dataset_reference=dataset, worker_image=source["image_id"])
    expected = {
        "M03": dataset_inputs,
        "M07": dataset_inputs
        | dict(model=meta["model_digest"], training_request=meta["input_digest"]),
        "M04": dataset_inputs | dict(model_digest=meta["model_digest"]),
        "M20": dict(
            dataset_reference=dataset,
            image_id=source["image_id"],
            model_digest=meta["model_digest"],
        ),
        "M05": dict(
            worker_image=source["image_id"],
            model_sha256=meta["model_digest"],
            subject_sha256=proposal["subject_sha256"],
            proposal_reference=proposal["proposal_reference"],
            proposal_packet=proposal_pin,
        ),
    }
    hashes = {}
    for gate, bindings in expected.items():
        raw = bounded_read(evidence / (gate + ".json"))
        report = decode(raw)
        if (
            report["gate"] != gate
            or report["status"] != "pass"
            or report["profile"] != "local-cpu"
            or report["source_revision"] != revision
            or report["source_dirty"] is not False
            or type(report["exit_code"]) is not int
            or report["exit_code"] != 0
            or report["policy_digest"] != meta["policy_digest"]
            or any(report["input_digests"].get(k) != v for k, v in (common | bindings).items())
        ):
            raise Rejected("delivery_scoped_gate_mismatch:" + gate)
        hashes[gate] = digest(raw)
    if (
        decode(bounded_read(evidence / "M07.json"))["artifact_hashes"]["signed_evaluation"]
        != evaluation
    ):
        raise Rejected("delivery_scoped_evaluator_reference")
    return hashes


if __name__ == "__main__":
    print(
        canonical(
            reconcile(
                Path(".runtime"),
                demo_pin=os.environ["R1_DEMO_SHA256"],
                proposal_pin=os.environ["R1_ISOLATION_PROPOSAL_SHA256"],
                revision=os.environ["GITHUB_SHA"],
            )
        ).decode()
    )
