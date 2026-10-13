import argparse
import sys
import uuid
from pathlib import Path

import psycopg

from mlsecops import holdout_budget, intake_denial, storage, storage_pipeline
from mlsecops.contracts import (
    Rejected,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.sandbox import resolve_image, run_worker
from mlsecops.storage_bootstrap import validate

CHECK_IDS = {
    f"{scenario}:{check}"
    for scenario in ("unsafe-model", "malformed-response", "transport-fixture")
    for check in (
        "nonzero-decision",
        "bound-denial",
        "no-prediction",
        "idempotent-republication",
        "new-process-readback",
        "not-quality-evaluation",
    )
} | {
    "publisher-denial-write-forbidden",
    "scorer-update-forbidden",
    "scorer-delete-forbidden",
    "exact-spent-slots-without-refund",
    "only-reservations-and-denials-added",
    "original-quality-evaluation-unchanged",
    "source-and-database-identity-unchanged",
}
KNOWN_ERRORS = {
    "denial_native_identity",
    "denial_native_state_too_large",
    "denial_native_stale_candidate",
    "denial_native_budget_insufficient",
    "denial_native_prediction_attempted",
    "denial_native_unexpected_evaluation",
    "denial_native_type_confusion",
    "denial_native_publisher_write_allowed",
    "denial_native_transaction_required",
    "denial_native_mutation_allowed",
    "storage_connection_rejected",
    "storage_object_missing",
    "image_source_fingerprint_mismatch_rebuild_required",
    "intake_denial_persistence_failed",
} | {"denial_native_check_failed:" + name for name in CHECK_IDS}


def snapshot(client):
    with storage.connect(client) as connection:
        if connection.execute("SELECT current_user").fetchone() != ("ml_scorer",):
            raise Rejected("denial_native_identity")
        rows = connection.execute(
            "SELECT sha256 FROM ml.evaluations ORDER BY sha256 LIMIT 2001"
        ).fetchall()
        if len(rows) > 2000:
            raise Rejected("denial_native_state_too_large")
        return {row[0] for row in rows}


def qualify(root, state, image):
    marker = validate(state)
    policy = read_json(root / "policies/local-cpu.json")
    trust = read_json(safe_child(state, "storage-trust.json"))
    demo = read_json(safe_child(state, "storage-demo.json"))
    scorer, publisher, promoter = (
        safe_child(state, "storage-clients/" + role) for role in ("scorer", "publisher", "promoter")
    )
    key = safe_child(state, "keys/evaluator.pem")
    original = demo["candidate"]["candidate_reference"]
    record, metadata, _ = storage_pipeline.load_candidate(scorer, original, policy)
    image_id = resolve_image(image)
    fingerprint = source_fingerprint(root)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    if any(
        metadata[name] != value
        for name, value in (
            ("image_id", image_id),
            ("source_fingerprint", fingerprint),
            ("source_revision", revision),
        )
    ):
        raise Rejected("denial_native_stale_candidate")
    holdout = metadata["materials"]["holdout.json"]["sha256"]
    budget = holdout_budget.inspect(scorer, holdout)
    if budget["remaining_upper_bound"] < 3:
        raise Rejected("denial_native_budget_insufficient")
    before = snapshot(scorer)
    original_evaluation = storage_pipeline.read_evaluation(
        promoter, demo["evaluation_reference"], original, policy, trust
    )
    unsafe = b"\x80\x04N."
    unsafe_metadata = {**metadata, "model_digest": digest(unsafe), "run_id": uuid.uuid4().hex}
    unsafe_record = {
        **record,
        "model_object": storage.put(publisher, "candidates", unsafe),
        "metadata_object": storage.put(publisher, "candidates", canonical(unsafe_metadata)),
    }
    unsafe_candidate = storage.put(publisher, "candidates", canonical(unsafe_record))
    cases, denials, added, occupied = [], [], set(), []

    def confirmed(name, condition):
        if not condition:
            raise Rejected("denial_native_check_failed:" + name)
        cases.append({"id": name, "status": "pass"})

    for name, candidate, expected_status, expected_reason in (
        ("unsafe-model", unsafe_candidate, "fail", "model_parse_rejected"),
        ("malformed-response", original, "fail", "scanner_protocol_rejected"),
        ("transport-fixture", original, "inconclusive", "scanner_timeout"),
    ):
        actions = []

        def executor(reference, request):
            actions.append(request["action"])
            if request["action"] != "inspect":
                raise Rejected("denial_native_prediction_attempted")
            if name == "transport-fixture":
                raise Rejected("worker_deadline")
            output, execution = run_worker(reference, request)
            if name == "malformed-response":
                output["inspected"] = 0
            return output, execution

        try:
            storage_pipeline.evaluate(scorer, candidate, policy, image_id, trust, key, executor)
        except intake_denial.RecordedDenial as error:
            reference = error.reference
            confirmed(name + ":nonzero-decision", error.status == expected_status)
        else:
            raise Rejected("denial_native_unexpected_evaluation")
        payload = intake_denial.read(promoter, reference, candidate, policy, trust)
        confirmed(
            name + ":bound-denial",
            payload["intake"]["status"] == expected_status
            and payload["intake"]["reason"] == expected_reason
            and not payload["intake"]["approved_outputs"]
            and payload["decision"] == "deny-evaluation"
            and payload["release_ready"] is False,
        )
        confirmed(name + ":no-prediction", actions == ["inspect"])
        repeated = intake_denial.publish(
            scorer, candidate, policy, trust, key, payload["holdout_access"], payload["intake"]
        )
        confirmed(name + ":idempotent-republication", repeated == reference)
        fresh = decode(
            command(
                [
                    sys.executable,
                    "-m",
                    "mlsecops.intake_denial",
                    "--client",
                    str(promoter),
                    "--candidate",
                    candidate,
                    "--denial",
                    reference,
                    "--trust",
                    str(safe_child(state, "storage-trust.json")),
                ],
                timeout=60,
            ).encode()
        )
        confirmed(name + ":new-process-readback", fresh == payload)
        try:
            storage_pipeline.read_evaluation(promoter, reference, candidate, policy, trust)
        except Rejected as error:
            confirmed(name + ":not-quality-evaluation", str(error) == "wrong_payload_type")
        else:
            raise Rejected("denial_native_type_confusion")
        occupied.append(payload["holdout_access"]["slot"])
        added.update((reference, payload["holdout_access"]["reservation"]))
        denials.append(
            {"candidate_reference": candidate, "denial_reference": reference, "payload": payload}
        )

    envelope = storage.get(scorer, "evaluations", denials[0]["denial_reference"])
    try:
        storage.put(publisher, "evaluations", envelope)
    except Rejected as error:
        confirmed("publisher-denial-write-forbidden", str(error) == "storage_write_rejected:42501")
    else:
        raise Rejected("denial_native_publisher_write_allowed")
    for statement, name in (
        ("UPDATE ml.evaluations SET payload=payload WHERE sha256=%s", "update"),
        ("DELETE FROM ml.evaluations WHERE sha256=%s", "delete"),
    ):
        with storage.connect(scorer) as connection:
            if connection.autocommit:
                raise Rejected("denial_native_transaction_required")
            try:
                connection.execute(statement, (denials[0]["denial_reference"],))
            except psycopg.Error as error:
                confirmed("scorer-" + name + "-forbidden", error.sqlstate == "42501")
            else:
                raise Rejected("denial_native_mutation_allowed")
            finally:
                connection.rollback()
    after = holdout_budget.inspect(scorer, holdout)
    confirmed(
        "exact-spent-slots-without-refund",
        len(set(occupied)) == 3
        and set(after["occupied_slots"]) == set(budget["occupied_slots"]) | set(occupied),
    )
    confirmed(
        "only-reservations-and-denials-added",
        snapshot(scorer) == before | added and len(added) == 6,
    )
    confirmed(
        "original-quality-evaluation-unchanged",
        storage_pipeline.read_evaluation(
            promoter, demo["evaluation_reference"], original, policy, trust
        )
        == original_evaluation,
    )
    confirmed(
        "source-and-database-identity-unchanged",
        source_fingerprint(root) == fingerprint
        and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
        and resolve_image(image) == image_id
        and validate(state)["container_id"] == marker["container_id"],
    )
    if {case["id"] for case in cases} != CHECK_IDS or len(cases) != len(CHECK_IDS):
        raise Rejected("denial_native_case_set_incomplete")
    result = {
        "schema_version": 1,
        "scope": "durable-sql-intake-denial-not-full-M21",
        "status": "pass",
        "observed_at": now(),
        "source_revision": revision,
        "source_fingerprint": fingerprint,
        "source_dirty": bool(command(["git", "-C", str(root), "status", "--porcelain"])),
        "image_id": image_id,
        "input_digests": {
            "trust": digest(canonical(trust)),
            "policy": digest(canonical(policy)),
            "original_candidate": original,
            "original_evaluation": demo["evaluation_reference"],
        },
        "cases": cases,
        "checks": len(cases),
        "denials": denials,
        "release_ready": False,
        "limitations": [
            "Unsafe candidate is a benign pickle fixture published by the test operator, not a training attack",
            "Malformed response is injected after real inspection; transport timeout is an injected exception",
            "SQL durability verified by committed readback in another process, not a crash-recovery drill",
            "Scorer still reads holdout before intake and spends its existing budget; no labels in denial",
            "Full M21 aggregator and serving/release integration remain pending",
        ],
    }
    write_json(safe_child(state, "evidence/intake-denial-qualification.json"), result)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Mutating SQL denial qualification in a disposable lab"
    )
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    parser.add_argument("--confirm-disposable", action="store_true")
    arguments = parser.parse_args()
    if not arguments.confirm_disposable:
        print("Disposable lab confirmation required; no action taken", file=sys.stderr)
        return 2
    try:
        result = qualify(Path(__file__).resolve().parents[1], arguments.state, arguments.image)
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        reason = (
            str(error)
            if isinstance(error, Rejected) and str(error) in KNOWN_ERRORS
            else "denial_native_incomplete"
        )
        print(canonical({"status": "fail", "reason": reason, "release_ready": False}).decode())
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
