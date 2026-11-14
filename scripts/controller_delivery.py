"""Verify the scoped gates against the joint candidate's frozen delivery inputs."""

import argparse
import os
from pathlib import Path

from mlsecops import signing
from mlsecops.canary_native_evidence import read_pinned
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, read_json
from scripts import delivery_candidate


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


BASE7 = {"M02", "M03", "M07", "M08", "M09", "M16", "M17"}
PARENT11 = BASE7 | {"M01", "M06", "M10", "M12"}
PARENT12 = PARENT11 | {"M19"}
GATES = tuple(sorted(PARENT12 | {"M04", "M05", "M20"}))


def intake_gates(serving_gate):
    return tuple(
        sorted({*delivery_candidate.campaign_gates(serving_gate), "M04", "M05", "M20", "M21"})
    )


def combine(summary, reports, profile):
    expected = {"base7": BASE7, "parent11": PARENT11, "parent12": PARENT12}[profile]
    if (
        summary["release_ready"] is not False
        or set(summary["reports"]) != expected
        or set(reports) != {"M03", "M04", "M05", "M07", "M20"}
        or any(reports[g] != summary["reports"][g] for g in ("M03", "M07"))
    ):
        raise Rejected("delivery_scoped_report_set_or_overlap")
    return summary | {
        "recovery_profile": profile,
        "recovery_reports": summary["reports"],
        "scoped_reports": reports,
        "reports": summary["reports"] | reports,
    }


def verify_pinned_actual(state, report_pin, capture_pin):
    from scripts.m12_pinned_native import PACKET

    report = decode(read_pinned(state / "evidence/M12.json", report_pin))
    read_pinned(state / PACKET, capture_pin)
    if report["artifact_hashes"]["pinned_actual"] != capture_pin:
        raise Rejected("delivery_m12_capture_mismatch")


def intake_delivery(state, pins, scoped, serving_gate):
    from scripts.controller_intake import verify

    owner = delivery_candidate.owner_inputs()
    parent = delivery_candidate.reconcile(
        state,
        **pins,
        **owner,
        serving_gate=serving_gate,
        joint_pin=os.environ.get("M11_M12_RECEIPT_SHA256"),
    )
    if serving_gate == "M12":
        verify_pinned_actual(state, parent["reports"]["M12"], os.environ["M12_EARLY_SHA256"])
    intake = verify(
        state,
        start_pin=os.environ["M21_START_SHA256"],
        capture_pin=os.environ["M21_CAPTURE_SHA256"],
        demo_pin=pins["demo_pin"],
        gate_pin=os.environ["M21_GATE_SHA256"],
        revision=pins["revision"],
    )
    candidate = parent["candidate"]
    if (
        set(parent["reports"]) != set(delivery_candidate.campaign_gates(serving_gate))
        or set(scoped) != {"M03", "M04", "M05", "M07", "M20"}
        or any(parent["reports"][g] != scoped[g] for g in ("M03", "M07"))
        or parent["release_ready"] is not False
        or intake["candidate_reference"] != candidate["candidate_reference"]
        or intake["original_evaluation"] != candidate["evaluation_reference"]
        or intake["model"] != candidate["qualified_candidate_model"]
    ):
        raise Rejected("delivery_intake_report_binding")
    reports = parent["reports"] | scoped | {"M21": intake["gate_sha256"]}
    return parent | dict(
        recovery_profile=serving_gate,
        scoped_reports=scoped,
        recovery_reports=parent["reports"],
        intake_capture=intake["capture_sha256"],
        reports=reports,
    )


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--with-intake", choices=("M11-M12", "M12", "M13"))
    group.add_argument("--m06-checkpoint", action="store_true")
    group.add_argument(
        "--include-recovery", nargs="?", const="base7", choices=("base7", "parent11", "parent12")
    )
    args = parser.parse_args()
    state = Path(".runtime")
    pins = dict(
        demo_pin=os.environ["M17_DEMO_SHA256"],
        proposal_pin=os.environ["M17_PROPOSAL_SHA256"],
        revision=os.environ["GITHUB_SHA"],
    )
    reports = reconcile(state, keys_pin=os.environ["M17_KEYS_SHA256"], **pins)
    if args.with_intake:
        result = intake_delivery(state, pins, reports, args.with_intake)
    elif args.m06_checkpoint:
        checkpoint = delivery_candidate.frozen_reports(state, profile="m06-checkpoint", **pins)
        result = checkpoint | {
            "scope": "scoped-frozen-M06",
            "reports": reports | checkpoint["reports"],
        }
    elif args.include_recovery:
        if args.include_recovery == "parent12":
            summary = delivery_candidate.reconcile(
                state, **pins, **delivery_candidate.owner_inputs()
            )
            verify_pinned_actual(state, summary["reports"]["M12"], os.environ["M12_EARLY_SHA256"])
        else:
            summary = delivery_candidate.frozen_reports(
                state, profile=args.include_recovery, **pins
            )
        result = combine(summary, reports, args.include_recovery)
    else:
        result = {"reports": reports, "release_ready": False}
    print(canonical(result).decode())


if __name__ == "__main__":
    main()
