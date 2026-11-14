"""Verify the scoped gates against the joint candidate's frozen delivery inputs."""

import argparse
import os
from pathlib import Path

from mlsecops import signing
from mlsecops.canary_native_evidence import read_pinned
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, read_json


def reconcile(state, *, demo_pin, proposal_pin, revision, keys_pin):
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
    public = read_json(state / "trusted-keys.json")
    if digest(canonical(public)) != keys_pin:
        raise Rejected("delivery_scoped_trust_root")
    transfer = signing.verify(
        read_json(evidence / "controller-history-transfer.json"),
        "controller-history-transfer",
        public["trust"],
    )
    authority = digest(bounded_read(evidence / "authority-qualification.json"))
    if transfer["subject"] != {
        "candidate_reference": reference,
        "evaluation_reference": evaluation,
        "dataset_reference": dataset,
        "metadata_sha256": digest(canonical(meta)),
        "evaluation_sha256": digest(canonical(demo["evaluation"])),
        "authority_report": authority,
    }:
        raise Rejected("delivery_scoped_transfer_subject")
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
        if gate in ("M04", "M20"):
            field = "authority" if gate == "M04" else "authority_qualification"
            if report["artifact_hashes"][field] != authority:
                raise Rejected("delivery_scoped_authority_report")
        if gate == "M07" and report["artifact_hashes"]["signed_evaluation"] != evaluation:
            raise Rejected("delivery_scoped_evaluator_reference")
        hashes[gate] = digest(raw)
    return hashes


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--include-recovery", action="store_true")
    args = parser.parse_args()
    state = Path(".runtime")
    pins = dict(
        demo_pin=os.environ["M17_DEMO_SHA256"],
        proposal_pin=os.environ["M17_PROPOSAL_SHA256"],
        revision=os.environ["GITHUB_SHA"],
    )
    reports = reconcile(state, keys_pin=os.environ["M17_KEYS_SHA256"], **pins)
    if args.include_recovery:
        from scripts.delivery_candidate import reconcile as recovery

        summary = recovery(state, **pins)
        if any(reports[gate] != summary["reports"][gate] for gate in ("M03", "M07")):
            raise Rejected("delivery_overlapping_reports_changed")
        summary["reports"].update(reports)
        print(canonical(summary).decode())
    else:
        print(canonical({"reports": reports, "release_ready": False}).decode())
