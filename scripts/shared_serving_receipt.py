"""Recheck two completed gate reports and emit their shared input and timing receipts."""

import os
from pathlib import Path

from mlsecops import trust_delivery
from mlsecops.contracts import bounded_read, canonical, decode, digest
from mlsecops.inference_gate import NATIVE_CASES
from scripts import shared_serving_native as shared


def receipt(state, env):
    proposal, _ = shared.pins(env)
    early_pin, full_pin = env["M11_M12_ACTUAL_SHA256"], env[shared.PIN]
    early = trust_delivery.pinned(state / shared.EARLY, early_pin)
    full = trust_delivery.pinned(state / shared.FULL, full_pin)
    shared.require(full["early_sha256"] == early_pin, "receipt_handoff")
    original = early["actual"]
    config = shared.retained(state, early)
    rows = {}
    for gate in ("M11", "M12"):
        raw = bounded_read(state / "evidence" / (gate + ".json"))
        r = decode(raw)
        fixed = dict(
            **original["source"],
            model=original["model_sha256"],
            release_subject=original["subject_sha256"],
            **{
                k: original[k]
                for k in ("candidate_reference", "proposal_reference", "evaluation_reference")
            },
        )
        hashes = dict(
            **original["artifact_hashes"],
            shared_native=full_pin,
            pinned_actual=early_pin,
            proposal_packet=proposal,
        )
        shared.require(
            r["gate"] == gate
            and r["status"] == "pass"
            and r["exit_code"] == 0
            and r["source_dirty"] is False
            and r["source_revision"] == original["source"]["source_revision"]
            and all(r["input_digests"][k] == v for k, v in fixed.items())
            and all(r["artifact_hashes"][k] == v for k, v in hashes.items())
            and r["metrics"]["qualification_permit_sha256"] == config["expected_permit"],
            "receipt_binding",
        )
        rows[gate] = dict(checks=r["metrics"]["checks"], report_sha256=digest(raw))
        if gate == "M12":
            shared.require(
                r["metrics"]["native_cases"]
                == len(NATIVE_CASES)
                == sum(row["id"] in NATIVE_CASES for row in r["cases"]),
                "receipt_m12",
            )
            rows[gate]["native_cases"] = len(NATIVE_CASES)
    return dict(
        reports=rows,
        actual_sha256=early_pin,
        native_sha256=full_pin,
        proposal_packet=proposal,
        proposal_reference=original["proposal_reference"],
        probe_sha256=original["artifact_hashes"]["probe.json"],
        permit=config["expected_permit"],
        proposal_issued=early["binding"]["proposal_issued_at"],
        proposal_expires=early["binding"]["proposal_expires_at"],
        actual_started=original["started_at"],
        actual_finished=original["finished_at"],
        release_ready=False,
    )


if __name__ == "__main__":
    print(canonical(receipt(Path(".runtime"), os.environ)).decode())
