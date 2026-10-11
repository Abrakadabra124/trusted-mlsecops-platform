import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path

from mlsecops import evaluation_quality, holdout_budget, storage_dataset, storage_pipeline
from mlsecops.bootstrap import initialize
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
from mlsecops.evaluation_qualification import qualify as evaluate
from mlsecops.holdout_budget_qualification import qualify as budget_campaign
from mlsecops.inventory import command, source_fingerprint
from mlsecops.sandbox import resolve_image
from mlsecops.storage_bootstrap import bootstrap, docker, validate

QUALITY_CASES = {
    "native-signed-quality-report",
    "frozen-policy-bound",
    "paired-confidence-computed",
    "candidate-source-current",
    "promoter-readback-without-label-access",
    "verification-does-not-spend-budget",
    "publisher-holdout-read-denied",
    "publisher-self-evaluation-write-denied",
    "promoter-holdout-read-denied",
    "promoter-self-evaluation-write-denied",
    "curator-verifies-all-split-identities",
    "train-holdout-entity-leakage-rejected",
    "pre-access-policy:source",
    "pre-access-policy:label_horizon",
    "pre-access-policy:minimum_auprc",
    "invalid-policy-does-not-spend-budget",
    "valid-report-cannot-be-swapped-to-another-candidate",
    "missing-metric",
    "wrong-gain",
    "wrong-budget-policy",
    "wrong-model",
    "different-role-key-cannot-evaluate",
    "original-report-still-valid-after-negatives",
    "source-and-database-identity-unchanged",
}
BUDGET_CASES = {
    "actual-scorer-signed-first-reservation",
    "actual-model-quality-not-mock",
    "persisted-receipt-exact-bytes",
    "four-process-unique-atomic-claims",
    "concurrent-over-budget-denied",
    "read-only-ledger-exhausted",
    "publisher-cannot-reserve",
    "scorer-cannot-delete",
    "scorer-cannot-update",
    "new-run-and-candidate-no-reset",
    "denied-before-labels-worker-and-signature",
    "new-process-and-database-restart-no-reset",
    "all-ledger-rows-survive-restart",
}
CONTRACT_FILES = (
    "evaluation_contracts",
    "evaluation_quality_qualification",
    "evaluation_binding_qualification",
    "holdout_budget_qualification",
)


def contract_source(root):
    return digest(
        canonical(
            {name: digest(bounded_read(root / "scripts" / f"{name}.py")) for name in CONTRACT_FILES}
        )
    )


def checked_cases(evidence, expected=None):
    try:
        cases = evidence["cases"]
        names = [case["id"] for case in cases]
        if (
            evidence["status"] != "pass"
            or type(evidence["checks"]) is not int
            or evidence["checks"] != len(cases)
            or not cases
            or any(type(name) is not str or not name for name in names)
            or len(set(names)) != len(names)
            or any(case["status"] != "pass" for case in cases)
            or (expected is not None and set(names) != expected)
        ):
            raise Rejected("M07_component_cases_invalid")
        return cases
    except (KeyError, TypeError) as error:
        raise Rejected("M07_component_shape_invalid") from error


def run_contracts(root):
    from scripts.evaluation_contracts import SCOPE, case_ids

    completed = subprocess.run(
        [sys.executable, "-m", "scripts.evaluation_contracts"],
        cwd=root,
        capture_output=True,
        timeout=180,
        check=False,
    )
    if completed.returncode:
        raise Rejected("M07_controlled_contracts_failed")
    evidence = decode(completed.stdout, 1024 * 1024)
    if len(checked_cases(evidence)) < 48:
        raise Rejected("M07_controlled_contracts_incomplete")
    if evidence.get("scope") != SCOPE:
        raise Rejected("M07_controlled_contracts_scope_invalid")
    checked_cases(evidence, case_ids())
    return evidence


def check_budget(budget, image, holdout, fingerprint, started):
    try:
        cases = [{"id": name, "status": "pass"} for name in budget["cases"]]
        checked_cases({**budget, "cases": cases}, BUDGET_CASES)
        observed = datetime.fromisoformat(budget["observed_at"])
        if (
            budget["source_fingerprint"] != fingerprint
            or budget["image_id"] != image
            or budget["holdout_digest"] != holdout
            or budget["budget_policy"] != holdout_budget.policy()
            or budget["budget_policy_digest"] != digest(canonical(holdout_budget.policy()))
            or type(budget["consumed"]) is not int
            or budget["consumed"] != holdout_budget.LIMIT
            or budget["scope"] != "native-persistent-holdout-budget-component-not-full-M07"
            or observed.tzinfo is None
            or not datetime.fromisoformat(started) <= observed <= datetime.fromisoformat(now())
        ):
            raise Rejected("M07_budget_binding_invalid")
        return cases
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("M07_budget_shape_invalid") from error


def reconcile(root, state, evidence, image, started):
    try:
        checked_cases(evidence, QUALITY_CASES)
        policy = read_json(root / "policies/local-cpu.json")
        rules = evaluation_quality.freeze(policy)
        trust = read_json(state / "storage-trust.json")
        client = state / "storage-clients/promoter"
        candidate = evidence["candidate_reference"]
        bound = storage_pipeline.read_evaluation(
            client, evidence["evaluation_reference"], candidate, policy, trust
        )
        record, metadata, model = storage_pipeline.load_candidate(client, candidate, policy)
        splits, manifest, statement = storage_dataset.read_dataset(
            state / "storage-clients/curator",
            bound["dataset_reference"],
            policy,
            trust["curator"],
            trust["source_approval_digest"],
            ("train", "validation", "holdout"),
        )
        request = {
            "action": "train",
            "train": splits["train"],
            "seed": policy["training_seed"],
            "features": [row["features"] for row in splits["validation"]],
        }
        report = bound["report"]
        if (
            evidence["scope"] != "native-frozen-evaluation-component-not-full-M07"
            or evidence["source_fingerprint"] != source_fingerprint(root)
            or metadata["source_fingerprint"] != evidence["source_fingerprint"]
            or metadata["source_revision"] != command(["git", "-C", str(root), "rev-parse", "HEAD"])
            or metadata["input_digest"] != digest(canonical(request))
            or metadata["materials"] != manifest["objects"]
            or metadata["dataset_id"] != statement["dataset_id"]
            or metadata["lineage_id"] != statement["lineage_id"]
            or evidence["dataset_reference"] != bound["dataset_reference"]
            or evidence["image_id"] != image
            or metadata["image_id"] != image
            or evidence["evaluation_policy_digest"] != digest(canonical(rules))
            or evidence["metrics"] != {name: report[name] for name in evidence["metrics"]}
            or set(evidence["metrics"])
            != {
                "rows",
                "positives",
                "auprc",
                "dummy_auprc",
                "auprc_gain",
                "slices",
                "confidence_intervals",
            }
            or report["holdout_digest"] != manifest["objects"]["holdout.json"]["sha256"]
            or report["rows"] != len(splits["holdout"])
            or report["positives"] != sum(row["label"] for row in splits["holdout"])
            or sum(len(rows) for rows in splits.values()) != policy["rows"]
        ):
            raise Rejected("M07_material_binding_invalid")
        lower, upper = datetime.fromisoformat(started), datetime.fromisoformat(now())
        for value in (evidence["observed_at"], metadata["created_at"], report["created_at"]):
            observed = datetime.fromisoformat(value)
            if observed.tzinfo is None or not lower <= observed <= upper:
                raise Rejected("M07_stale_or_future_evidence")
        quality = report["quality_component"]
        if quality not in ("pass", "fail", "inconclusive"):
            raise Rejected("M07_quality_state_invalid")
        if report["confidence_intervals"]["status"] != "computed" and quality == "pass":
            quality = "inconclusive"
        return {
            "status": quality,
            "metrics": evidence["metrics"],
            "input_digests": {
                "candidate_reference": candidate,
                "evaluation_reference": evidence["evaluation_reference"],
                "dataset_reference": bound["dataset_reference"],
                "model": digest(model),
                "holdout": report["holdout_digest"],
                "training_request": metadata["input_digest"],
                "evaluation_policy": digest(canonical(rules)),
                "worker_image": image,
                "data_lock": digest(bounded_read(root / "data.lock")),
            },
            "artifact_hashes": {
                "candidate_record": digest(canonical(record)),
                "metadata": digest(canonical(metadata)),
                "manifest": digest(canonical(manifest)),
                "signed_evaluation": evidence["evaluation_reference"],
                "reservation": bound["holdout_access"]["reservation"],
            },
        }
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("M07_material_shape_invalid") from error


def qualify(root, state):
    root, state = Path(root).resolve(), Path(state).resolve()
    output = state / "evidence/evaluation-gate.json"
    started = now()
    write_json(output, {"status": "inconclusive", "release_ready": False, "started_at": started})
    image = resolve_image("trusted-mlsecops:dev")
    fingerprint, contracts_digest = source_fingerprint(root), contract_source(root)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    locked = digest(bounded_read(root / "data.lock"))
    evaluation_quality.freeze(read_json(root / "policies/local-cpu.json"))
    contracts = run_contracts(root)
    campaign_id = uuid.uuid4().hex
    campaign = safe_child(state, "evaluation-gate/" + campaign_id)
    campaign.mkdir(parents=True, exist_ok=False)
    quality_state = campaign / "quality"
    initialize(root, quality_state)
    bootstrap(quality_state, 15451)
    marker = validate(quality_state)
    try:
        native = evaluate(root, quality_state, image)
        result = reconcile(root, quality_state, native, image, started)
        budget = budget_campaign(root, campaign / "budget", image, 15452)
        budget_cases = check_budget(
            budget, image, result["input_digests"]["holdout"], fingerprint, started
        )
        if (
            fingerprint != source_fingerprint(root)
            or contracts_digest != contract_source(root)
            or locked != digest(bounded_read(root / "data.lock"))
            or revision != command(["git", "-C", str(root), "rev-parse", "HEAD"])
        ):
            raise Rejected("M07_source_changed_during_campaign")
        for name, evidence in (("contracts", contracts), ("native", native), ("budget", budget)):
            write_json(campaign / f"{name}.json", evidence)
            result["artifact_hashes"][name] = digest(bounded_read(campaign / f"{name}.json"))
        cases = [
            {
                "id": prefix + ":" + case["id"],
                "status": "pass",
                "expected": "pass",
                "actual": case["status"],
            }
            for prefix, component in (
                ("controlled", contracts["cases"]),
                ("native", native["cases"]),
                ("budget", budget_cases),
            )
            for case in component
        ]
        cases.append(
            {
                "id": "signed-materials-reconciliation",
                "status": result["status"],
                "expected": "pass",
                "actual": result["status"],
            }
        )
        result.update(
            schema_version=1,
            scope="M07-synthetic-local-cpu-independent-evaluation",
            release_ready=False,
            started_at=started,
            campaign_id=campaign_id,
            cases=cases,
            checks=len(cases),
            source_dirty=bool(command(["git", "-C", str(root), "status", "--porcelain"])),
            limitations=[
                "Synthetic lab only; real profiles rejected, no business utility or production promotion",
                "Preprocessing contract instruments actual host fit; worker isolation is a separate M20 gate",
                "Trusted host/scorer and local keys; not an independent attestation of a compromised signer",
                "Budget restart test uses a second fresh database; old snapshot rollback lacks an external witness",
                "Diagnostic IID intervals do not establish temporal/group or retraining uncertainty",
                "T08 lifecycle, other M-gates, image audit and full R1 acceptance remain mandatory",
            ],
        )
        result["input_digests"].update(
            source_fingerprint=fingerprint,
            host_contracts=contracts_digest,
            budget_policy=budget["budget_policy_digest"],
        )
    finally:
        current = validate(quality_state)
        if current["container_id"] != marker["container_id"]:
            raise Rejected("M07_cleanup_identity_changed")
        docker(["stop", marker["container_id"]], timeout=60)
    result["finished_at"] = now()
    write_json(output, result)
    return result
