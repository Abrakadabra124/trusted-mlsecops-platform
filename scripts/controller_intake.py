"""Controller M21 producer start and read-only delivery verification."""

import argparse
import os
import re
from pathlib import Path

from mlsecops import controller_intake as intake
from mlsecops.contracts import Rejected, bounded_read, canonical, digest
from mlsecops.intake_gate import NATIVE_CASES, checked_cases
from mlsecops.intake_probe import CASE_IDS
from mlsecops.kube_intake_qualification import HOST_CASES
from scripts.intake_contracts import case_ids
from scripts.intake_denial_native import CHECK_IDS


def verify(state, *, start_pin, capture_pin, demo_pin, gate_pin, revision):
    """Offline read-only consumer. All four pins come from earlier producer steps."""
    gate = intake.pinned(state / "evidence/M21.json", gate_pin)
    primary = intake.pinned(
        state / "evidence/intake-gate.json", gate["artifact_hashes"]["intake_gate"]
    )
    capture = intake.pinned(state / intake.CAPTURE, capture_pin)
    start = intake.pinned(state / intake.START, start_pin)
    demo = intake.pinned(state / "storage-demo.json", demo_pin)
    owner = start["owner"]
    subject = capture["subject"]
    reference, evaluation = demo["candidate"]["candidate_reference"], demo["evaluation_reference"]
    metadata = demo["candidate"]["metadata"]
    expected = dict(
        candidate_reference=reference,
        evaluation_reference=evaluation,
        dataset_reference=demo["dataset"]["dataset_reference"],
        model=metadata["model_digest"],
        worker_image=metadata["image_id"],
        policy=metadata["policy_digest"],
        source_fingerprint=metadata["source_fingerprint"],
        kubernetes_candidate_reference=reference,
    )
    if (
        gate["status"] != "pass"
        or gate["gate"] != "M21"
        or type(gate["exit_code"]) is not int
        or gate["exit_code"] != 0
        or gate["profile"] != "local-cpu"
        or gate["source_dirty"] is not False
        or gate["policy_digest"] != metadata["policy_digest"]
        or owner["run"] != os.environ["GITHUB_RUN_ID"]
        or owner["attempt"] != os.environ["GITHUB_RUN_ATTEMPT"]
        or gate["source_revision"] != revision
        or owner["revision"] != revision
        or primary["source_revision"] != revision
        or metadata["source_revision"] != revision
        or primary["scope"] != "M21-intake-acceptance"
        or primary["status"] != "pass"
        or primary["release_ready"] is not False
        or primary["source_dirty"] is not False
        or primary["artifact_hashes"]
        != {k: v for k, v in gate["artifact_hashes"].items() if k != "intake_gate"}
        or primary["artifact_hashes"]["controller_capture"] != capture_pin
        or gate["input_digests"] != primary["input_digests"]
        or gate["cases"] != primary["cases"]
        or any(gate["input_digests"].get(k) != v for k, v in expected.items())
        or capture["start"] != start_pin
        or primary["started_at"] != start["started_at"]
        or subject["candidate_reference"] != reference
        or subject["evaluation_reference"] != evaluation
        or subject["dataset_reference"] != expected["dataset_reference"]
        or subject["metadata_sha256"] != digest(canonical(metadata))
        or subject["evaluation_sha256"] != digest(canonical(demo["evaluation"]))
        or capture["release_ready"] is not False
        or not re.fullmatch(r"[0-9a-f]{32}", primary["campaign_id"])
    ):
        raise Rejected("M21_delivery_subject")
    blobs = {
        k: intake.pinned(state / path, capture["artifacts"][k])
        for k, path in intake.PACKETS.items()
    }
    matrix = blobs["matrix"]
    intake.check_readback(matrix, blobs["readback"], evaluation, demo["evaluation"])
    campaign = state / "intake-gate" / primary["campaign_id"] / "evidence"
    cases = set()
    for name, expected_cases in (
        ("contracts", case_ids()),
        ("denials", CHECK_IDS),
        ("native", NATIVE_CASES),
        ("kubernetes", CASE_IDS | HOST_CASES),
    ):
        report = intake.pinned(
            campaign / ("M21-" + name + ".json"), primary["artifact_hashes"][name]
        )
        if name == "kubernetes" and (
            report != matrix or primary["artifact_hashes"][name] != capture["artifacts"]["matrix"]
        ):
            raise Rejected("M21_delivery_matrix")
        if name == "denials" and (
            report["input_digests"]["original_evaluation"] != evaluation
            or report["input_digests"]["original_candidate"] != reference
        ):
            raise Rejected("M21_delivery_sql_inputs")
        cases.update(name + ":" + item["id"] for item in checked_cases(report, expected_cases))
    checked_cases(
        primary,
        cases | {"signed-materials-reconciliation", "scoped-controller-native-intake-matrix"},
    )
    return dict(
        gate="M21",
        status="pass",
        release_ready=False,
        checks=primary["checks"],
        revision=revision,
        candidate_reference=reference,
        original_evaluation=evaluation,
        matrix_evaluation=matrix["positive"]["evaluation_reference"],
        model=expected["model"],
        gate_sha256=gate_pin,
        capture_sha256=capture_pin,
        original_readback=capture["artifacts"]["readback"],
        matrix_readback=matrix["persisted_readback_digest"],
        artifacts=primary["artifact_hashes"],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("begin", "verify", "check-substitution"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    state = root / ".runtime"
    if args.action == "begin":
        intake.begin(root, state)
        return
    pins = dict(
        start_pin=os.environ["M21_START_SHA256"],
        capture_pin=os.environ["M21_CAPTURE_SHA256"],
        demo_pin=os.environ["M17_DEMO_SHA256"],
        gate_pin=os.environ["M21_GATE_SHA256"],
        revision=os.environ["GITHUB_SHA"],
    )
    verified = verify(state, **pins)
    if args.action == "check-substitution":
        # Supply a different SHA-256 to the real consumer without modifying the original packet.
        wrong = digest(bounded_read(state / intake.CAPTURE) + b" ")
        try:
            verify(state, **(pins | {"capture_pin": wrong}))
        except Rejected as error:
            if str(error) != "M21_pin_mismatch:M21-controller-capture.json":
                raise
            verified = {
                "status": "rejected",
                "reason": str(error),
                "release_ready": False,
                "expected_digest": pins["capture_pin"],
                "substituted_digest": wrong,
            }
        else:
            raise Rejected("M21_delivery_digest_substitution_accepted")
    print(canonical(verified).decode())


if __name__ == "__main__":
    main()
