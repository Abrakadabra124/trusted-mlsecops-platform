import argparse
import copy
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

from mlsecops import evaluation_quality, holdout_budget, storage, storage_dataset, storage_pipeline
from mlsecops.contracts import Rejected, canonical, now, read_json, write_json
from mlsecops.datasets import validate_rows
from mlsecops.inventory import source_fingerprint
from mlsecops.signing import sign
from mlsecops.storage_bootstrap import validate


def qualify(root, state, image):
    root, state = Path(root).resolve(), Path(state).resolve()
    marker = validate(state)
    fingerprint = source_fingerprint(root)
    cases = []

    def confirmed(name, condition):
        if not condition:
            raise Rejected(f"evaluation_qualification_failed:{name}")
        cases.append({"id": name, "status": "pass"})

    def rejected(name, operation, expected):
        try:
            operation()
        except Rejected as error:
            confirmed(name, str(error) == expected)
        else:
            raise Rejected(f"evaluation_qualification_bypass:{name}")

    result = storage_pipeline.demo(root, state, image)
    candidate = result["candidate"]["candidate_reference"]
    reference = result["evaluation_reference"]
    policy = read_json(root / "policies/local-cpu.json")
    trust = read_json(state / "storage-trust.json")
    scorer = state / "storage-clients/scorer"
    promoter = state / "storage-clients/promoter"
    publisher = state / "storage-clients/publisher"
    bound = storage_pipeline.read_evaluation(promoter, reference, candidate, policy, trust)
    report = bound["report"]
    if report["quality_component"] == "inconclusive":
        raise Rejected("evaluation_quality_inconclusive")
    confirmed(
        "native-signed-quality-report",
        bound == result["evaluation"] and report["quality_component"] == "pass",
    )
    confirmed(
        "frozen-policy-bound", report["evaluation_policy"] == evaluation_quality.freeze(policy)
    )
    confirmed(
        "paired-confidence-computed",
        report["confidence_intervals"]["status"] == "computed"
        and report["confidence_intervals"]["valid_resamples"] == 1000,
    )
    confirmed(
        "candidate-source-current",
        result["candidate"]["metadata"]["source_fingerprint"] == fingerprint,
    )
    before = holdout_budget.inspect(scorer, report["holdout_digest"])
    reads = []
    original_get = storage.get

    def tracked_get(client, table, identifier):
        reads.append((Path(client).name, table))
        return original_get(client, table, identifier)

    with patch.object(storage, "get", side_effect=tracked_get):
        storage_pipeline.read_evaluation(promoter, reference, candidate, policy, trust)
    confirmed(
        "promoter-readback-without-label-access",
        set(reads) == {("promoter", "candidates"), ("promoter", "evaluations")},
    )
    confirmed(
        "verification-does-not-spend-budget",
        holdout_budget.inspect(scorer, report["holdout_digest"]) == before,
    )
    for role, client in (("publisher", publisher), ("promoter", promoter)):
        rejected(
            f"{role}-holdout-read-denied",
            lambda client=client: storage.get(client, "holdout", report["holdout_digest"]),
            "storage_read_rejected:42501",
        )
        rejected(
            f"{role}-self-evaluation-write-denied",
            lambda client=client: storage.put(client, "evaluations", b"unauthorized-evaluation"),
            "storage_write_rejected:42501",
        )
    splits, _, _ = storage_dataset.read_dataset(
        state / "storage-clients/curator",
        bound["dataset_reference"],
        policy,
        trust["curator"],
        trust["source_approval_digest"],
        ("train", "validation", "holdout"),
    )
    confirmed(
        "curator-verifies-all-split-identities",
        len({row["entity_id"] for split in splits.values() for row in split}) == policy["rows"],
    )
    leaked = copy.deepcopy(splits["train"] + splits["validation"] + splits["holdout"])
    leaked[-1]["entity_id"] = leaked[0]["entity_id"]
    rejected(
        "train-holdout-entity-leakage-rejected",
        lambda: validate_rows(leaked, policy["rows"]),
        "invalid_or_duplicate_entity",
    )
    for field, value in (
        ("source", "unreviewed-business"),
        ("label_horizon", "immature-labels"),
        ("minimum_auprc", 0.1),
    ):
        invalid = {**policy, field: value}
        rejected(
            f"pre-access-policy:{field}",
            lambda invalid=invalid: storage_pipeline.evaluate(
                scorer, candidate, invalid, image, trust, state / "keys/evaluator.pem"
            ),
            "evaluation_profile_not_frozen_lab",
        )
    confirmed(
        "invalid-policy-does-not-spend-budget",
        holdout_budget.inspect(scorer, report["holdout_digest"]) == before,
    )
    record, metadata, _ = storage_pipeline.load_candidate(publisher, candidate, policy)
    alternate = {**metadata, "run_id": uuid.uuid4().hex}
    alternate_metadata = storage.put(publisher, "candidates", canonical(alternate))
    alternate_candidate = storage.put(
        publisher, "candidates", canonical({**record, "metadata_object": alternate_metadata})
    )
    rejected(
        "valid-report-cannot-be-swapped-to-another-candidate",
        lambda: storage_pipeline.read_evaluation(
            promoter, reference, alternate_candidate, policy, trust
        ),
        "stored_evaluation_subject_mismatch",
    )
    for name, mutate, expected in (
        ("missing-metric", lambda value: value["report"].pop("auprc"), "unexpected_fields"),
        (
            "wrong-gain",
            lambda value: value["report"].update(auprc_gain=1.0),
            "evaluation_metric_mismatch",
        ),
        (
            "wrong-budget-policy",
            lambda value: value["holdout_access"].update(policy_digest="0" * 64),
            "stored_evaluation_reservation_mismatch",
        ),
        (
            "wrong-model",
            lambda value: value["report"].update(model_digest="0" * 64),
            "stored_evaluation_subject_mismatch",
        ),
    ):
        altered = copy.deepcopy(bound)
        mutate(altered)
        fixture = storage.put(
            scorer,
            "evaluations",
            canonical(sign(altered, "stored-evaluation", state / "keys/evaluator.pem")),
        )
        rejected(
            name,
            lambda fixture=fixture: storage_pipeline.read_evaluation(
                promoter, fixture, candidate, policy, trust
            ),
            expected,
        )
    foreign = storage.put(
        scorer,
        "evaluations",
        canonical(sign(bound, "stored-evaluation", state / "keys/approver.pem")),
    )
    rejected(
        "different-role-key-cannot-evaluate",
        lambda: storage_pipeline.read_evaluation(promoter, foreign, candidate, policy, trust),
        "untrusted_key",
    )
    confirmed(
        "original-report-still-valid-after-negatives",
        storage_pipeline.read_evaluation(promoter, reference, candidate, policy, trust) == bound,
    )
    confirmed(
        "source-and-database-identity-unchanged",
        source_fingerprint(root) == fingerprint
        and validate(state)["container_id"] == marker["container_id"],
    )
    return {
        "schema_version": 1,
        "status": "pass",
        "scope": "native-frozen-evaluation-component-not-full-M07",
        "observed_at": now(),
        "source_fingerprint": fingerprint,
        "candidate_reference": candidate,
        "evaluation_reference": reference,
        "dataset_reference": bound["dataset_reference"],
        "image_id": report["image_id"],
        "evaluation_policy_digest": report["evaluation_policy_digest"],
        "checks": len(cases),
        "cases": cases,
        "metrics": {
            name: report[name]
            for name in (
                "rows",
                "positives",
                "auprc",
                "dummy_auprc",
                "auprc_gain",
                "slices",
                "confidence_intervals",
            )
        },
        "limitations": [
            "Synthetic utility and IID diagnostic intervals, not business utility or temporal/group inference",
            "SQL/host orchestration component; scoped Kubernetes checked separately by M20",
            "Corrupt signed fixtures intentionally retained as rejected append-only qualification artifacts",
            "M07 integration, train-only preprocessing evidence and full release acceptance still required",
            "Trusted scorer and control-plane admin; signature does not prove truth of a compromised signer",
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    destination = arguments.state / "evidence/evaluation-qualification.json"
    write_json(destination, {"status": "inconclusive", "observed_at": now()})
    try:
        result = qualify(Path(__file__).resolve().parents[1], arguments.state, arguments.image)
    except (Rejected, OSError) as error:
        write_json(destination, {"status": "fail", "observed_at": now(), "reason": str(error)})
        print(f"Evaluation qualification rejected: {error}", file=sys.stderr)
        return 1
    write_json(destination, result)
    print(canonical(result).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
