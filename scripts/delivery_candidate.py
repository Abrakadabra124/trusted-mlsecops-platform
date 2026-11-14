"""Reconcile the published acceptance reports against the proposal frozen by this job."""

import os
from pathlib import Path

from mlsecops.canary_native_evidence import read_pinned
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest


def reconcile(state, *, demo_pin, proposal_pin, revision):
    evidence = state / "evidence"
    demo = decode(read_pinned(state / "storage-demo.json", demo_pin))
    proposal = decode(read_pinned(evidence / "release-native.json", proposal_pin))
    source = proposal["source"]
    if (
        proposal["status"] != "pass"
        or proposal["source_dirty"] is not False
        or proposal["release_ready"] is not False
        or source["source_revision"] != revision
        or demo["candidate"]["metadata"]["model_digest"] != proposal["model_sha256"]
    ):
        raise Rejected("delivery_original_proposal_mismatch")
    common = dict(
        candidate_reference=demo["candidate"]["candidate_reference"],
        evaluation_reference=demo["evaluation_reference"],
        source_fingerprint=source["source_fingerprint"],
    )
    runtime = dict(
        image_id=source["image_id"],
        source_revision=revision,
        qualified_candidate_subject=proposal["subject_sha256"],
        qualified_candidate_model=proposal["model_sha256"],
        proposal_reference=proposal["proposal_reference"],
    )
    # M08 and M09 qualify the trained candidate before promotion. Each native
    # report distinguishes the actual model from its separate reference model.
    statistical = dict(
        model_digest=proposal["model_sha256"],
        candidate_training_input=demo["candidate"]["metadata"]["input_digest"],
    )
    reports = {}
    raw_lock = bounded_read(state.parent / "data.lock")
    data_lock = digest(raw_lock)
    dataset_source = decode(raw_lock)["output"]["sha256"]
    for gate in ("M02", "M07", "M08", "M09", "M16", "M17"):
        raw = bounded_read(evidence / (gate + ".json"))
        report = decode(raw)
        if gate in ("M16", "M17"):
            if (
                report["artifact_hashes"]["proposal_packet"] != proposal_pin
                or report["release_ready"] is not False
            ):
                raise Rejected("delivery_recovery_proposal_mismatch")
            expected = common | runtime
        elif gate == "M02":
            expected = dict(
                source_fingerprint=source["source_fingerprint"],
                data_lock=data_lock,
                source=dataset_source,
            )
        elif gate == "M07":
            expected = common | dict(
                dataset_source=dataset_source,
                data_lock=data_lock,
                model=proposal["model_sha256"],
                training_request=statistical["candidate_training_input"],
                worker_image=source["image_id"],
                dataset_reference=demo["dataset"]["dataset_reference"],
            )
        else:
            image_field = "image" if gate == "M08" else "image_id"
            expected = common | statistical | {image_field: source["image_id"]}
        if (
            report["gate"] != gate
            or report["profile"] != "local-cpu"
            or report["source_revision"] != revision
            or report["source_dirty"] is not False
            or report["status"] != "pass"
            or type(report["exit_code"]) is not int
            or report["exit_code"] != 0
            or report["policy_digest"] != demo["candidate"]["metadata"]["policy_digest"]
            or any(report["input_digests"].get(k) != value for k, value in expected.items())
        ):
            raise Rejected("delivery_candidate_mismatch_" + gate)
        reports[gate] = digest(raw)
    return dict(
        candidate=common | runtime,
        reports=reports,
        proposal_packet=proposal_pin,
        release_ready=False,
    )


if __name__ == "__main__":
    print(
        canonical(
            reconcile(
                Path(".runtime"),
                demo_pin=os.environ["M17_DEMO_SHA256"],
                proposal_pin=os.environ["M17_PROPOSAL_SHA256"],
                revision=os.environ["GITHUB_SHA"],
            )
        ).decode()
    )
