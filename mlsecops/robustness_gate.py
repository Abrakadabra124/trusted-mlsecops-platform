"""M09: actual evaluated candidate parity, format and frozen evasion evidence."""

import subprocess
import sys
from datetime import datetime
from pathlib import Path

import numpy as np

from mlsecops import advisory
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
from scripts import robustness, robustness_contracts, robustness_native
from scripts.poisoning_evidence import execution as validate_execution


def contract_materials(root):
    names = [module.replace(".", "/") + ".py" for module in robustness_contracts.MODULES]
    names += [
        "scripts/robustness_contracts.py",
        "scripts/evaluation_contracts.py",
        "scripts/robustness.py",
        "scripts/robustness_native.py",
        "scripts/poisoning_evidence.py",
        "data.lock",
    ]
    return digest(canonical({name: digest(bounded_read(root / name)) for name in names}))


def run_contracts(root):
    process = subprocess.run(
        [sys.executable, "-m", "scripts.robustness_contracts"],
        cwd=root,
        capture_output=True,
        check=False,
        timeout=300,
    )
    if process.returncode:
        raise Rejected("M09_controlled_contracts_failed")
    result = decode(process.stdout, 1024**2)
    expected = robustness_contracts.case_ids(root)
    if (
        result.get("status") != "pass"
        or result.get("scope") != robustness_contracts.SCOPE
        or type(result.get("checks")) is not int
        or result["checks"] != len(expected)
        or not expected
        or result.get("cases") != [{"id": name, "status": "pass"} for name in sorted(expected)]
    ):
        raise Rejected("M09_controlled_contracts_incomplete")
    return result


def bind_candidate(campaign, candidate, scores):
    """Recompute golden parity and attack selection from actual candidate scores."""
    golden = read_json(campaign / "validation.json")
    probes = read_json(campaign / "probes.json")
    training = read_json(campaign / "request-0.json")
    reference = read_json(campaign / "response-0.json")
    tolerance = candidate["policy"]["parity_tolerance"]
    if (
        len(golden) < 1000
        or len(probes) != robustness.policy()["probe_rows"]
        or tolerance != 1e-5
        or digest(canonical(training)) != candidate["metadata"]["input_digest"]
        or reference["input_digest"] != candidate["metadata"]["input_digest"]
        or training["features"] != [row["features"] for row in golden]
    ):
        raise Rejected("M09_candidate_training_or_golden_mismatch")
    values = validate_scores(scores, len(golden) + 5 * len(probes))
    python = validate_scores(reference["python_scores"], len(golden))
    actual = values[: len(golden)]
    outside = abs(python - 0.5) > tolerance
    mismatch = int(np.count_nonzero((actual[outside] >= 0.5) != (python[outside] >= 0.5)))
    error = float(np.max(abs(actual - python)))
    if error > tolerance or mismatch:
        raise Rejected("M09_candidate_parity_failed")
    groups = np.split(values[len(golden) :], 5)
    clean, corners = groups[0].tolist(), [row.tolist() for row in groups[1:]]
    previous = [
        read_json(campaign / "clean.json"),
        *read_json(campaign / "attack.json")["corner_scores"],
    ]
    baseline = validate_scores([score for row in previous for score in row], 5 * len(probes))
    replay_error = float(np.max(abs(values[len(golden) :] - baseline)))
    if replay_error > candidate["policy"]["repeat_tolerance"] or not np.array_equal(
        values[len(golden) :] >= 0.5, baseline >= 0.5
    ):
        raise Rejected("M09_candidate_reference_replay_failed")
    selected = robustness.select([row["features"] for row in probes], clean, corners)
    return {
        "parity": {"rows": len(golden), "max_error": error, "label_mismatches": mismatch},
        "reference_replay_error": replay_error,
        "metrics": robustness.compare(probes, clean, selected["scores"]),
        "clean": clean,
        "selected": selected,
    }


def qualify(root, state, image="trusted-mlsecops:dev"):
    root, state = Path(root).resolve(), Path(state).resolve()
    output, started = safe_child(state, "evidence/robustness-gate.json"), now()
    write_json(output, {"status": "inconclusive", "release_ready": False, "started_at": started})
    try:
        contracts_digest = contract_materials(root)
        contracts = run_contracts(root)
        image = resolve_image(image)
        candidate = subject(root, state, image)
        report = robustness_native.qualify(root, state, image)
        if datetime.fromisoformat(report["started_at"]) < datetime.fromisoformat(started):
            raise Rejected("M09_campaign_not_fresh")
        campaign = safe_child(state, "robustness/" + report["campaign_id"])
        write_json(safe_child(state, "evidence/robustness.json"), report)
        hashes, model = report["artifact_hashes"], report["input_digests"]["model"]
        verified = robustness_native.reconcile(campaign, hashes, model)
        profile, train, golden, probes = robustness_native.materials(root)
        for name, expected in (
            ("train.json", train),
            ("validation.json", golden),
            ("probes.json", probes),
        ):
            if read_json(campaign / name) != expected:
                raise Rejected("M09_frozen_materials_mismatch")
        expected_training = {
            "action": "train",
            "train": train,
            "seed": profile["training_seed"],
            "features": [row["features"] for row in golden],
        }
        if read_json(campaign / "request-0.json") != expected_training:
            raise Rejected("M09_frozen_training_request_mismatch")
        if report["status"] != verified["status"] or report["protocol"] != robustness.policy():
            raise Rejected("M09_campaign_summary_mismatch")
        features = [row["features"] for row in probes]
        all_features = (
            [row["features"] for row in golden]
            + features
            + [row for corner in robustness.corners(features) for row in corner]
        )
        proofs = []

        def predict(rows):
            batch = PredictionBatch(candidate["model"], rows)
            response, execution = run_worker(image, batch.request)
            scores, scan, protocol = batch.consume(response)
            validate_execution(execution, image)
            proofs.append(
                {
                    "request": batch.request,
                    "response": response,
                    "execution": execution,
                    "scan": scan,
                    "protocol": protocol,
                }
            )
            return scores.tolist()

        bound = bind_candidate(campaign, candidate, predict(all_features))
        before = len(proofs)
        decisions = advisory.decide(robustness.outside_support(), predict)
        if len(proofs) != before or any(
            item["decision"] != "abstain" or item["score"] is not None for item in decisions
        ):
            raise Rejected("M09_outside_support_executed")
        mixed = advisory.decide(
            [robustness.outside_support()[0], features[0], robustness.outside_support()[-1]],
            predict,
        )
        if (
            mixed[0] != decisions[0]
            or mixed[2] != decisions[-1]
            or mixed[1]["decision"] != "score"
            or abs(mixed[1]["score"] - bound["clean"][0]) > profile["repeat_tolerance"]
            or len(proofs) != 2
        ):
            raise Rejected("M09_mixed_batch_binding")
        proof = {"predictions": proofs, "outcomes": bound, "abstain": decisions, "mixed": mixed}
        write_json(campaign / "candidate-binding.json", proof)
        if (
            subject(root, state, image) != candidate
            or contract_materials(root) != contracts_digest
            or robustness_native.reconcile(campaign, hashes, model) != verified
            or read_json(campaign / "candidate-binding.json") != proof
            or any(name in sys.modules for name in ("onnx", "onnxruntime"))
        ):
            raise Rejected("M09_materials_or_controller_boundary_changed")
        cases = (
            contracts["cases"]
            + [
                {"id": name, "status": "pass"}
                for name in (
                    "candidate-lineage-readback",
                    "frozen-primary-reconciliation",
                    "candidate-python-onnx-parity",
                    "candidate-full-probe-replay",
                    "candidate-domain-abstain",
                    "candidate-source-unchanged",
                )
            ]
            + [{"id": "candidate-evasion-threshold", "status": bound["metrics"]["status"]}]
        )
        result = {
            "schema_version": 1,
            "scope": "M09-fresh-candidate-bound-format-parity-evasion",
            "status": bound["metrics"]["status"],
            "release_ready": False,
            "started_at": started,
            "finished_at": now(),
            "campaign_id": report["campaign_id"],
            "source_revision": report["source_revision"],
            "source_dirty": report["source_dirty"],
            "cases": cases,
            "checks": len(cases),
            "input_digests": {
                **{key: value for key, value in report["input_digests"].items() if key != "model"},
                "reference_model_digest": report["input_digests"]["model"],
                "candidate_reference": candidate["bindings"]["candidate_reference"],
                "evaluation_reference": candidate["bindings"]["evaluation_reference"],
                "model_digest": digest(candidate["model"]),
                "candidate_training_input": candidate["metadata"]["input_digest"],
            },
            "metrics": {
                **{key: value for key, value in bound["metrics"].items() if key != "status"},
                "parity": bound["parity"],
                "reference_replay_error": bound["reference_replay_error"],
                "outside_support_abstentions": len(decisions),
                "primary_files_verified": len(hashes),
                "actual_candidate_predictions": len(all_features) + 1,
            },
            "artifact_hashes": {
                "campaign": digest(canonical(report)),
                "primary_materials": digest(canonical(hashes)),
                "contracts": contracts_digest,
                "candidate_binding": digest(bounded_read(campaign / "candidate-binding.json")),
            },
            "limitations": [
                "Fixed public synthetic probes and four corners only; not universal robustness or independent M22 challenges",
                "Format negatives use real parser fixtures with a mocked runtime constructor in a separate controlled process",
                "Actual candidate is parsed and predicted only in the isolated worker; host administrator remains trusted",
                "Python reference is freshly trained from the identical bound training request; parity covers frozen golden cases",
                "OOD guard covers individual support bounds, not all joint shifts; production serving is separate",
                "A failed robustness threshold blocks M09; this report never independently authorizes release",
            ],
        }
        write_json(output, result)
        return result
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("M09_evidence_shape_invalid") from error
