"""Reconcile the published acceptance reports against the proposal frozen by this job."""

import os
from pathlib import Path

from mlsecops.canary_native_evidence import read_pinned
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, require_fields
from mlsecops.security_events import hexadecimal

GATES = ("M01", "M02", "M03", "M06", "M07", "M08", "M09", "M10", "M12", "M16", "M17", "M19")


def campaign_gates(serving_gate):
    if serving_gate == "M11-M12":
        return tuple(sorted((*GATES, "M11")))
    if serving_gate not in {"M12", "M13"}:
        raise Rejected("delivery_unknown_serving_gate")
    return tuple(serving_gate if gate == "M12" else gate for gate in GATES)


def reconcile(
    state,
    *,
    demo_pin,
    proposal_pin,
    keys_pin,
    trust_pin,
    captures,
    revision,
    serving_gate="M12",
    joint_pin=None,
):
    evidence = state / "evidence"
    demo = decode(read_pinned(state / "storage-demo.json", demo_pin))
    proposal = decode(read_pinned(evidence / "release-native.json", proposal_pin))
    keys = decode(bounded_read(state / "trusted-keys.json"))
    read_pinned(state / "storage-trust.json", trust_pin)
    if digest(canonical(keys)) != hexadecimal(keys_pin):
        raise Rejected("delivery_original_keys_mismatch")
    require_fields(captures, ("canary", "rollback", "recovery", "inventory", "fleet"))
    if len({hexadecimal(value) for value in captures.values()}) != len(captures):
        raise Rejected("delivery_capture_reused")
    artifacts = {
        "M16": dict(traffic_packet=captures["canary"], rollback_packet=captures["rollback"]),
        "M17": dict(recovery_packet=captures["recovery"], demo=demo_pin, public_keys=keys_pin),
        "M19": dict(
            primary=captures["inventory"],
            fleet_inputs=captures["fleet"],
            demo=demo_pin,
            public_keys=keys_pin,
            source_trust=trust_pin,
        ),
    }
    observations = {}
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
    for gate in campaign_gates(serving_gate):
        raw = bounded_read(evidence / (gate + ".json"))
        report = decode(raw)
        if gate in ("M16", "M17", "M19"):
            if (
                report["artifact_hashes"]["proposal_packet"] != proposal_pin
                or report["release_ready"] is not False
            ):
                raise Rejected("delivery_recovery_proposal_mismatch")
            expected = common | runtime
            if any(
                report["artifact_hashes"].get(k) != value for k, value in artifacts[gate].items()
            ):
                raise Rejected("delivery_source_or_capture_mismatch_" + gate)
            if gate in ("M16", "M19"):
                observations[gate] = {
                    hexadecimal(report["artifact_hashes"].get(k))
                    for k in (
                        "traffic_rows",
                        "candidate_source",
                        "candidate_journal",
                        "stable_journal",
                    )
                }
            if gate == "M19":
                expected |= dict(
                    release_subject=proposal["subject_sha256"], model=proposal["model_sha256"]
                )
        elif gate == "M13":
            if (
                report["artifact_hashes"].get("proposal_packet") != proposal_pin
                or report["artifact_hashes"].get("frozen_demo") != demo_pin
            ):
                raise Rejected("delivery_privacy_proposal_mismatch")
            expected = (
                common
                | source
                | dict(
                    model_sha256=proposal["model_sha256"],
                    subject_sha256=proposal["subject_sha256"],
                    proposal_reference=proposal["proposal_reference"],
                )
            )
        elif gate in ("M10", "M11", "M12"):
            if gate == "M10" and (
                report["release_ready"] is not False
                or report["artifact_hashes"]["actual_proposal_report"] != proposal_pin
            ):
                raise Rejected("delivery_promotion_proposal_mismatch")
            expected = common | dict(
                image_id=source["image_id"],
                source_revision=revision,
                model=proposal["model_sha256"],
                release_subject=proposal["subject_sha256"],
                proposal_reference=proposal["proposal_reference"],
            )
        elif gate == "M01":
            expected = dict(
                source_fingerprint=source["source_fingerprint"], worker_image=source["image_id"]
            )
        elif gate == "M02":
            expected = dict(
                source_fingerprint=source["source_fingerprint"],
                data_lock=data_lock,
                source=dataset_source,
            )
        elif gate == "M03":
            expected = common | dict(
                source=dataset_source,
                data_lock=data_lock,
                worker_image=source["image_id"],
                dataset_reference=demo["dataset"]["dataset_reference"],
            )
        elif gate == "M06":
            expected = (
                common
                | statistical
                | dict(
                    frozen_demo=demo_pin,
                    worker_image=source["image_id"],
                    dataset_reference=demo["dataset"]["dataset_reference"],
                )
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
    if not observations["M16"].isdisjoint(observations["M19"]):
        raise Rejected("delivery_canary_observation_reused")
    if serving_gate == "M11-M12":
        joint = decode(
            read_pinned(evidence / "shared-serving-receipt.json", hexadecimal(joint_pin))
        )
        if (
            joint["release_ready"] is not False
            or joint["proposal_packet"] != proposal_pin
            or joint["proposal_reference"] != proposal["proposal_reference"]
            or set(joint["reports"]) != {"M11", "M12"}
            or any(joint["reports"][g]["report_sha256"] != reports[g] for g in ("M11", "M12"))
        ):
            raise Rejected("delivery_joint_serving_mismatch")
    return dict(
        candidate=common | runtime,
        reports=reports,
        proposal_packet=proposal_pin,
        source_files=dict(demo=demo_pin, public_keys=keys_pin, source_trust=trust_pin),
        release_ready=False,
    )


if __name__ == "__main__":
    print(
        canonical(
            reconcile(
                Path(".runtime"),
                demo_pin=os.environ["M17_DEMO_SHA256"],
                proposal_pin=os.environ["M17_PROPOSAL_SHA256"],
                keys_pin=os.environ["M17_KEYS_SHA256"],
                trust_pin=os.environ["M19_TRUST_SHA256"],
                captures=dict(
                    canary=os.environ["T19_PRIMARY_SHA256"],
                    rollback=os.environ["T19_ROLLBACK_SHA256"],
                    recovery=os.environ["M17_PRIMARY_SHA256"],
                    inventory=os.environ["M19_PRIMARY_SHA256"],
                    fleet=os.environ["M19_FLEET_INPUTS_SHA256"],
                ),
                revision=os.environ["GITHUB_SHA"],
                serving_gate=os.environ.get("DELIVERY_SERVING_GATE", "M12"),
                joint_pin=os.environ.get("M11_M12_RECEIPT_SHA256"),
            )
        ).decode()
    )
