"""Fresh M08 campaign bound to the existing synthetic candidate, without promotion."""

import copy
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import numpy as np

from mlsecops.candidate_subject import subject
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.prediction_protocol import PredictionBatch, validate_scores
from mlsecops.sandbox import resolve_image, run_worker
from scripts import poisoning, poisoning_contracts, poisoning_evidence, poisoning_native
from scripts.evaluation_contracts import case_ids


def contract_materials(root):
    names = ["evaluation_contracts.py", "poisoning_contracts.py"]
    names.extend(name.removeprefix("scripts.") + ".py" for name in poisoning_contracts.MODULES)
    return digest(
        canonical({name: digest(bounded_read(root / "scripts" / name)) for name in names})
    )


def run_contracts(root):
    import unittest

    process = subprocess.run(
        [sys.executable, "-m", "scripts.poisoning_contracts"],
        cwd=root,
        capture_output=True,
        check=False,
        timeout=300,
    )
    if process.returncode:
        raise Rejected("M08_controlled_contracts_failed")
    result = decode(process.stdout, 1024 * 1024)
    expected = case_ids(unittest.defaultTestLoader.loadTestsFromNames(poisoning_contracts.MODULES))
    if (
        result.get("status") != "pass"
        or result.get("scope") != poisoning_contracts.SCOPE
        or type(result.get("checks")) is not int
        or result["checks"] != len(expected)
        or len(expected) < 29
        or result.get("cases") != [{"id": name, "status": "pass"} for name in sorted(expected)]
    ):
        raise Rejected("M08_controlled_contracts_incomplete")
    return result


def bind_candidate(campaign, records, candidate, scores):
    """Recompute the candidate seed's comparisons using its own actual predictions."""
    poisoning_native.summarize(records)
    seed = candidate["policy"]["training_seed"]
    if seed not in poisoning.policy()["seeds"]:
        raise Rejected("M08_candidate_seed_unsupported")
    baseline = next(record for record in records if record["id"] == f"clean-{seed}")
    if baseline["input_digest"] != candidate["metadata"]["input_digest"]:
        raise Rejected("M08_candidate_training_mismatch")
    probes = read_json(safe_child(campaign, "probes.json"))
    count = len(probes)
    actual = validate_scores(scores, count * 2)

    def observed(record):
        content = bounded_read(safe_child(campaign, record["id"] + "/security-scores.json"))
        if digest(content) != record["artifacts"]["security-scores"]:
            raise Rejected("M08_candidate_scores_changed")
        return validate_scores(decode(content), count * 2)

    control = observed(baseline)
    error = float(np.max(np.abs(control - actual)))
    if error > candidate["policy"]["repeat_tolerance"] or not np.array_equal(
        control >= poisoning.policy()["threshold"], actual >= poisoning.policy()["threshold"]
    ):
        raise Rejected("M08_candidate_prediction_mismatch")
    bound = copy.deepcopy(records)
    for record in bound:
        if record["seed"] != seed:
            continue
        attacked = actual if record["family"] == "clean" else observed(record)
        offset = count if record["family"] == "backdoor" else 0
        record["metrics"] = poisoning.compare(
            probes,
            actual[:count].tolist(),
            attacked[:count].tolist(),
            actual[offset : offset + count].tolist(),
            attacked[offset : offset + count].tolist(),
        )
    return bound, error


def qualify(root, state, image="trusted-mlsecops:dev"):
    root, state = Path(root).resolve(), Path(state).resolve()
    output = safe_child(state, "evidence/poisoning-gate.json")
    started = now()
    write_json(output, {"status": "inconclusive", "release_ready": False, "started_at": started})
    try:
        contracts_digest = contract_materials(root)
        contracts = run_contracts(root)
        image = resolve_image(image)
        candidate = subject(root, state, image)
        report = poisoning_native.qualify(root, state, image)
        if datetime.fromisoformat(report["started_at"]) < datetime.fromisoformat(started):
            raise Rejected("M08_campaign_not_fresh")
        write_json(safe_child(state, "evidence/poisoning.json"), report)
        verified = poisoning_evidence.reconcile(root, state, report, image)
        if (
            verified["evidence_integrity"] != "pass"
            or verified["verified_cases"] != 35
            or verified["verified_files"] != 251
            or verified["status"] != report["status"]
        ):
            raise Rejected("M08_primary_reconciliation_incomplete")
        write_json(safe_child(state, "evidence/poisoning-reconciliation.json"), verified)
        campaign = safe_child(state, "poisoning/" + report["campaign_id"])
        views = [read_json(campaign / name) for name in ("probes.json", "triggered.json")]
        batch = PredictionBatch(
            candidate["model"], [row["features"] for view in views for row in view]
        )
        response, execution = run_worker(image, batch.request)
        scores, scan, protocol = batch.consume(response)
        poisoning_evidence.execution(execution, image)
        bound, error = bind_candidate(campaign, report["cases"], candidate, scores.tolist())
        summary = poisoning_native.summarize(bound)
        proof = {
            "request": batch.request,
            "response": response,
            "execution": execution,
            "scan": scan,
            "protocol": protocol,
            "cases": bound,
        }
        write_json(campaign / "candidate-binding.json", proof)
        if (
            subject(root, state, image) != candidate
            or contract_materials(root) != contracts_digest
            or poisoning_evidence.reconcile(root, state, report, image)["materials_digest"]
            != verified["materials_digest"]
        ):
            raise Rejected("M08_materials_changed")
        cases = (
            contracts["cases"]
            + [
                {"id": "native:" + record["id"], "status": record["metrics"]["status"]}
                for record in bound
            ]
            + [
                {"id": name, "status": "pass"}
                for name in (
                    "primary-material-reconciliation",
                    "candidate-lineage-readback",
                    "candidate-prediction-replay",
                    "candidate-source-unchanged",
                )
            ]
        )
        result = {
            "schema_version": 1,
            "scope": "M08-fresh-candidate-bound-synthetic-poisoning",
            "status": summary["status"],
            "release_ready": False,
            "started_at": started,
            "finished_at": now(),
            "campaign_id": report["campaign_id"],
            "source_revision": report["source_revision"],
            "source_dirty": report["source_dirty"],
            "cases": cases,
            "checks": len(cases),
            "input_digests": {
                **report["input_digests"],
                "candidate_reference": candidate["bindings"]["candidate_reference"],
                "evaluation_reference": candidate["bindings"]["evaluation_reference"],
                "model_digest": digest(candidate["model"]),
                "candidate_training_input": candidate["metadata"]["input_digest"],
            },
            "metrics": {
                **{key: value for key, value in summary.items() if key != "status"},
                "candidate_prediction_error": error,
                "primary_files_verified": verified["verified_files"],
            },
            "artifact_hashes": {
                "campaign": verified["report_digest"],
                "primary_materials": verified["materials_digest"],
                "contracts": contracts_digest,
                "candidate_binding": digest(bounded_read(campaign / "candidate-binding.json")),
            },
            "limitations": [
                "Frozen public synthetic families and budgets only; no universal poisoning detection",
                "Known probes are not independent M22 reviewer challenges; release remains separately gated",
                "Candidate seed uses actual model predictions; other seeds test the same fixed training procedure",
                "Trusted host/controller and scoped SQL readback; this is not production approval",
                "Per-scenario conditional intervals, no simultaneous matrix or population guarantee",
            ],
        }
        write_json(output, result)
        return result
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("M08_evidence_shape_invalid") from error
