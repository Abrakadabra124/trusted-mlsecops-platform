import argparse
import sys
import uuid
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from unittest.mock import patch

import psycopg

from mlsecops import holdout_budget, storage, storage_pipeline
from mlsecops.bootstrap import initialize
from mlsecops.contracts import Rejected, canonical, digest, now, read_json, write_json
from mlsecops.holdout_diagnostics import CLAIM_CASES, ClaimFailure, check_claims
from mlsecops.inventory import source_fingerprint
from mlsecops.storage_bootstrap import bootstrap, docker, validate


def attempt(arguments):
    client, holdout_digest = arguments
    try:
        return holdout_budget.reserve(client, holdout_digest)
    except Rejected as error:
        return {"rejected": str(error)}


def qualify(root, state, image, port):
    state = Path(state).resolve()
    if state.exists():
        raise Rejected("holdout_qualification_requires_fresh_state")
    cases = []

    def confirmed(name, condition):
        if not condition:
            raise Rejected(f"holdout_qualification_failed:{name}")
        cases.append(name)

    initialize(root, state)
    bootstrap(state, port)
    marker = validate(state)
    try:
        result = storage_pipeline.demo(root, state, image)
        access = result["evaluation"]["holdout_access"]
        holdout_digest = access["holdout_digest"]
        scorer = state / "storage-clients/scorer"
        publisher = state / "storage-clients/publisher"
        confirmed("actual-scorer-signed-first-reservation", access["slot"] == 1)
        confirmed(
            "actual-model-quality-not-mock",
            result["evaluation"]["report"]["quality_component"] == "pass",
        )
        confirmed(
            "persisted-receipt-exact-bytes",
            storage.get(scorer, "evaluations", access["reservation"])
            == holdout_budget.reservation(holdout_digest, 1),
        )
        with ProcessPoolExecutor(max_workers=4) as pool:
            receipts = list(
                pool.map(attempt, [(str(scorer), holdout_digest)] * holdout_budget.LIMIT)
            )
        concurrent_claims = check_claims(receipts, holdout_digest)
        cases.extend(CLAIM_CASES)
        observed = holdout_budget.inspect(scorer, holdout_digest)
        confirmed("read-only-ledger-exhausted", observed["remaining_upper_bound"] == 0)
        content = holdout_budget.reservation("a" * 64, 1)
        try:
            storage.claim(publisher, "evaluations", content)
        except Rejected as error:
            confirmed("publisher-cannot-reserve", str(error) == "storage_claim_rejected:42501")
        else:
            raise Rejected("holdout_publisher_claim_bypass")
        for action in (
            "DELETE FROM ml.evaluations WHERE sha256 = %s",
            "UPDATE ml.evaluations SET payload = payload WHERE sha256 = %s",
        ):
            try:
                with storage.connect(scorer) as connection:
                    connection.execute(action, (access["reservation"],))
            except psycopg.Error as error:
                confirmed(f"scorer-cannot-{action.split()[0].lower()}", error.sqlstate == "42501")
            else:
                raise Rejected("holdout_refund_privilege_bypass")
        policy = read_json(root / "policies/local-cpu.json")
        trust = read_json(state / "storage-trust.json")
        candidate = result["candidate"]["candidate_reference"]
        record, metadata, _ = storage_pipeline.load_candidate(scorer, candidate, policy)
        metadata["run_id"] = uuid.uuid4().hex
        new_metadata = storage.put(publisher, "candidates", canonical(metadata))
        new_candidate = storage.put(
            publisher, "candidates", canonical({**record, "metadata_object": new_metadata})
        )
        reads = []
        original_get = storage.get

        def tracked_get(directory, table, identifier):
            reads.append(table)
            return original_get(directory, table, identifier)

        with (
            patch.object(storage, "get", side_effect=tracked_get),
            patch.object(
                storage_pipeline,
                "evaluate_verified_candidate",
                side_effect=AssertionError("exhausted budget reached worker"),
            ) as worker,
            patch.object(
                storage_pipeline,
                "sign",
                side_effect=AssertionError("exhausted budget reached signer"),
            ) as signer,
        ):
            try:
                storage_pipeline.evaluate(
                    scorer, new_candidate, policy, image, trust, state / "keys/evaluator.pem"
                )
            except Rejected as error:
                confirmed(
                    "new-run-and-candidate-no-reset", str(error) == "holdout_budget_exhausted"
                )
            else:
                raise Rejected("holdout_new_candidate_bypass")
            confirmed(
                "denied-before-labels-worker-and-signature",
                "holdout" not in reads and worker.call_count == signer.call_count == 0,
            )
        validate(state)
        docker(["restart", marker["container_id"]], timeout=60)
        bootstrap(state, port)
        with ProcessPoolExecutor(max_workers=1) as pool:
            after_restart = pool.submit(attempt, (str(scorer), holdout_digest)).result(timeout=30)
        confirmed(
            "new-process-and-database-restart-no-reset",
            after_restart == {"rejected": "holdout_budget_exhausted"},
        )
        confirmed(
            "all-ledger-rows-survive-restart",
            holdout_budget.inspect(scorer, holdout_digest) == observed,
        )
        return {
            "schema_version": 1,
            "observed_at": now(),
            "status": "pass",
            "scope": "native-persistent-holdout-budget-component-not-full-M07",
            "source_fingerprint": source_fingerprint(root),
            "image_id": result["evaluation"]["report"]["image_id"],
            "holdout_digest": holdout_digest,
            "budget_policy": holdout_budget.policy(),
            "budget_policy_digest": digest(canonical(holdout_budget.policy())),
            "checks": len(cases),
            "cases": cases,
            "consumed": holdout_budget.LIMIT,
            "concurrent_claims": concurrent_claims,
            "limitations": [
                "Trusted scorer/admin can bypass application policy; workers cannot",
                "One authoritative database; independent replicas can fork the budget",
                "Old snapshot rollback is not externally witnessed",
                "Synthetic lab cap is not a statistical adaptive-data-analysis guarantee",
            ],
        }
    finally:
        current = validate(state)
        if current["container_id"] != marker["container_id"]:
            raise Rejected("holdout_cleanup_identity_changed")
        docker(["stop", marker["container_id"]], timeout=60)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=Path(".runtime/holdout-budget-qualification"))
    parser.add_argument(
        "--output", type=Path, default=Path(".runtime/evidence/holdout-budget.json")
    )
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    parser.add_argument("--port", type=int, default=15446)
    arguments = parser.parse_args()
    write_json(arguments.output, {"status": "inconclusive", "observed_at": now()})
    try:
        result = qualify(
            Path(__file__).resolve().parents[1], arguments.state, arguments.image, arguments.port
        )
    except (Rejected, OSError) as error:
        result = {"status": "fail", "observed_at": now(), "reason": str(error)}
        if isinstance(error, ClaimFailure):
            result["diagnostics"] = {"holdout_concurrency": error.diagnostics}
        write_json(arguments.output, result)
        print(f"Holdout budget qualification rejected: {error}", file=sys.stderr)
        return 1
    write_json(arguments.output, result)
    print(canonical(result).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
