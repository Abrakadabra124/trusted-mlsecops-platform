import argparse
import shutil
import sys
import tempfile
import time
import uuid
from contextlib import suppress
from pathlib import Path
from unittest.mock import patch

import numpy as np
import psycopg

from mlsecops import (
    promotion_recovery,
    promotion_state,
    storage,
    storage_backup,
    storage_dataset,
    storage_pipeline,
    storage_restore,
)
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
from mlsecops.inventory import command, source_fingerprint
from mlsecops.kube_storage_probe import maintenance
from mlsecops.pipeline import validate_scores
from mlsecops.prediction_protocol import PredictionBatch
from mlsecops.sandbox import run_worker
from mlsecops.signing import verify
from mlsecops.storage_bootstrap import admin, docker, validate
from scripts.promotion_native import record


def qualify(root, state, image):
    state = Path(state).resolve()
    marker = validate(state)
    campaign = uuid.uuid4().hex
    started = now()
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    if command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("promotion_recovery_source_dirty")
    fingerprint = source_fingerprint(root)
    public = read_json(state / "trusted-keys.json")
    policy = read_json(root / "policies/local-cpu.json")
    trust = read_json(state / "storage-trust.json")
    demo = read_json(state / "storage-demo.json")
    promoter = state / "storage-clients/promoter"
    environment = "recovery-" + campaign
    promotion_state.configure(state, environment, "a" * 64)
    with storage.connect(promoter) as connection:
        issued = connection.execute(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint"
        ).fetchone()[0]
    material = storage.put(
        promoter, "releases", canonical({"controlled-recovery-material": campaign})
    )

    def selection(sequence):
        return storage.put(
            promoter,
            "releases",
            canonical(
                {
                    "schema_version": 1,
                    "kind": "promotion-selection",
                    "environment": environment,
                    "policy_sha256": "a" * 64,
                    "sequence": sequence,
                    "subject_sha256": "b" * 64,
                    "proposal_reference": material,
                    "authorization_reference": material,
                    "issued_at": issued,
                    "expires_at": issued + 1800,
                }
            ),
        )

    first, second = selection(1), selection(2)
    record(promoter, first)
    record(promoter, second)
    before_tables = storage_restore.ledger(marker["name"])
    before_promotion = promotion_recovery.read(marker["name"])
    original_dump = storage_backup.binary_command
    late = []

    def concurrent_promotion(arguments, *values, **keywords):
        if "pg_dump" not in arguments or late:
            raise Rejected("recovery_probe_unexpected_command")
        late.append(selection(3))
        record(promoter, late[0])
        return original_dump(arguments, *values, **keywords)

    cases = []

    def confirmed(name, condition):
        print(
            canonical(
                {
                    "scope": "promotion-recovery-check",
                    "case": name,
                    "status": "pass" if condition else "fail",
                }
            ).decode(),
            flush=True,
        )
        if not condition:
            raise Rejected("promotion_recovery_check_failed:" + name)
        cases.append(name)

    def rejected(name, expected, operation):
        try:
            operation()
        except Rejected as error:
            confirmed(name, str(error) == expected)
        else:
            raise Rejected("promotion_recovery_denial_bypassed:" + name)

    with patch.object(storage_backup, "binary_command", side_effect=concurrent_promotion):
        backup = storage_backup.create(root, state, include_promotion=True)
    directory = Path(backup["directory"])
    confirmed(
        "one-snapshot-cas-and-journal",
        backup["tables"] == before_tables and backup["promotion"] == before_promotion,
    )
    confirmed(
        "source-concurrent-promotion-committed",
        promotion_state.state(promoter, environment)["sequence"] == 3,
    )
    after_tables = storage_restore.ledger(marker["name"])
    after_promotion = promotion_recovery.read(marker["name"])
    target = safe_child(state, "evidence/recovery-" + campaign)
    interrupted = safe_child(state, "evidence/interrupted-" + campaign)

    def restore(destination, pin=backup["backup_id"], port=15442):
        return storage_restore.restore(
            root, directory, destination, public, port, expected_backup_id=pin
        )

    for pin in (None, "0" * 64):
        rejected(
            "missing-or-wrong-external-pin-" + str(pin is None),
            "restore_backup_pin_mismatch_or_missing",
            lambda pin=pin: restore(target, pin),
        )
    confirmed("pin-denial-before-target-creation", not target.exists())
    rejected(
        "withdrawn-backup-signer",
        "untrusted_key",
        lambda: storage_backup.read_backup(
            directory, {**public, "trust": public["curator"]}, policy
        ),
    )
    with tempfile.TemporaryDirectory(
        prefix="recovery-negative-", dir=state / "evidence"
    ) as temporary:
        fixture = Path(temporary)
        write_json(fixture / "manifest.json", read_json(directory / "manifest.json"))
        archive = bounded_read(directory / "data.dump", storage_backup.MAX_ARCHIVE)
        for name, content in (
            ("archive-byte-change", archive[:-1] + bytes([archive[-1] ^ 1])),
            ("archive-truncated", archive[:5]),
        ):
            (fixture / "data.dump").write_bytes(content)
            rejected(
                name,
                "backup_archive_integrity_failed",
                lambda: storage_restore.restore(
                    root, fixture, target, public, 15442, expected_backup_id=backup["backup_id"]
                ),
            )
        (fixture / "data.dump").unlink()
        rejected(
            "archive-missing",
            "artifact_unavailable",
            lambda: storage_restore.restore(
                root, fixture, target, public, 15442, expected_backup_id=backup["backup_id"]
            ),
        )
        confirmed("invalid-archives-do-not-create-target", not target.exists())

    def cleanup(destination):
        if not (destination / "storage.json").exists():
            return
        owned = validate(destination)
        if (
            destination.resolve().parent != (state / "evidence").resolve()
            or owned["workspace_id"] == marker["workspace_id"]
        ):
            raise Rejected("promotion_recovery_cleanup_ownership")
        docker(["rm", "--force", owned["container_id"]])
        docker(["network", "rm", owned["network"]])
        docker(["volume", "rm", owned["volume"]])
        shutil.rmtree(destination.resolve())

    recovery_started = time.monotonic()
    source_stopped = False
    try:
        docker(["stop", marker["name"]], timeout=60)
        source_stopped = True
        receipt = restore(target)
        target_marker = validate(target)
        confirmed(
            "independent-target-with-source-offline",
            target_marker["workspace_id"] != marker["workspace_id"]
            and target_marker["volume"] != marker["volume"]
            and target_marker["container_id"] != marker["container_id"],
        )
        confirmed(
            "restored-complete-snapshot-not-later-head",
            promotion_recovery.read(target_marker["name"]) == before_promotion
            and storage_restore.ledger(target_marker["name"]) == before_tables,
        )
        target_promoter = target / "storage-clients/promoter"
        confirmed(
            "restored-sequence-is-two-not-three",
            promotion_state.state(target / "storage-clients/serving", environment)["sequence"] == 2,
        )
        confirmed("current-request-remains-idempotent", record(target_promoter, second) == second)
        try:
            record(target_promoter, first)
        except psycopg.Error as error:
            confirmed("old-request-remains-rejected", error.sqlstate == "P1004")
        else:
            raise Rejected("promotion_recovery_old_sequence_accepted")
        rejected(
            "post-snapshot-object-absent",
            "storage_object_missing",
            lambda: storage.get(target_promoter, "releases", late[0]),
        )
        confirmed("completed-restore-retry-no-import", restore(target)["reused"])
        confirmed(
            "private-signing-keys-not-cloned",
            read_json(target / "trusted-keys.json") != public
            and read_json(target / "recovered-public-keys.json") == public,
        )
        confirmed("restore-never-grants-ready", receipt["release_ready"] is False)
        for role in ("promoter", "serving"):
            try:
                with storage.connect(target / f"storage-clients/{role}") as connection:
                    try:
                        connection.execute("DELETE FROM ml_promotion.heads WHERE false")
                    finally:
                        connection.rollback()
            except psycopg.Error as error:
                confirmed(role + "-direct-mutation-still-denied", error.sqlstate == "42501")
            else:
                raise Rejected("promotion_recovery_role_expanded")
        publisher = target / "storage-clients/publisher"
        candidate, metadata, model = storage_pipeline.load_candidate(
            publisher, demo["candidate"]["candidate_reference"], policy
        )
        splits, _, _ = storage_dataset.read_dataset(
            publisher,
            candidate["dataset_reference"],
            policy,
            trust["curator"],
            trust["source_approval_digest"],
            ("train", "validation"),
        )
        saved_scores = validate_scores(
            decode(storage.get(publisher, "candidates", candidate["scores_object"])), 3000
        )
        confirmed(
            "saved-predictions-bound-to-metadata",
            digest(canonical(saved_scores.tolist())) == metadata["validation_probability_digest"],
        )
        batch = PredictionBatch(model, [row["features"] for row in splits["validation"][:1000]])
        predicted, execution = run_worker(image, batch.request)
        scores, _, proof = batch.consume(predicted)
        maximum_error = float(np.max(np.abs(scores - saved_scores[:1000])))
        confirmed(
            "1000-golden-predictions-on-restored-model",
            maximum_error <= policy["repeat_tolerance"]
            and proof["model_digest"] == digest(model)
            and execution["image_id"] == metadata["image_id"],
        )
        evaluation = verify(
            decode(
                storage.get(
                    target / "storage-clients/scorer", "evaluations", demo["evaluation_reference"]
                )
            ),
            "stored-evaluation",
            public["evaluator"],
        )
        confirmed("evaluation-signature-and-binding-survive", evaluation == demo["evaluation"])
        golden_seconds = round(time.monotonic() - recovery_started, 6)
        confirmed("component-recovery-within-15-minutes", golden_seconds <= 900)
        late_target = storage.put(
            target_promoter, "releases", canonical({"late-target-row": campaign})
        )
        rejected(
            "retry-cannot-erase-later-cas-write",
            "restore_existing_target_changed",
            lambda: restore(target),
        )
        confirmed(
            "late-target-object-preserved",
            storage.get(target_promoter, "releases", late_target)
            == canonical({"late-target-row": campaign}),
        )
    finally:
        if source_stopped:
            docker(["start", marker["name"]], timeout=60)
        cleanup(target)

    deadline = time.monotonic() + 30
    while True:
        try:
            observed = promotion_recovery.read(marker["name"])
            break
        except Rejected:
            if time.monotonic() >= deadline:
                raise Rejected("promotion_recovery_source_restart_timeout") from None
            time.sleep(0.2)
    confirmed(
        "source-history-preserved",
        observed == after_promotion and storage_restore.ledger(marker["name"]) == after_tables,
    )
    original_restore = storage_restore.binary_command

    def response_lost(arguments, *values, **keywords):
        output = original_restore(arguments, *values, **keywords)
        if "--single-transaction" in arguments:
            raise Rejected("controlled-commit-observation-loss")
        return output

    try:
        with patch.object(storage_restore, "binary_command", side_effect=response_lost):
            rejected(
                "commit-observation-loss-is-not-success",
                "controlled-commit-observation-loss",
                lambda: restore(interrupted, port=15443),
            )
        interrupted_marker = validate(interrupted)
        confirmed(
            "interrupted-import-committed-but-no-receipt",
            not (interrupted / "recovery.json").exists()
            and promotion_recovery.read(interrupted_marker["name"]) == before_promotion,
        )
        confirmed(
            "interrupted-target-remains-in-maintenance",
            admin(
                interrupted_marker["name"],
                "SELECT datconnlimit FROM pg_database WHERE datname='mlsecops';",
            )
            == "0",
        )
        denied = maintenance(interrupted / "storage-clients/serving", "serving")
        confirmed(
            "actual-serving-connection-denied-after-interruption",
            denied
            == {"status": "pass", "role": "serving", "result": "database-maintenance-denied"},
        )
        rejected(
            "interrupted-target-not-overwritten-on-retry",
            "restore_requires_new_target",
            lambda: restore(interrupted, port=15443),
        )
        admin(
            interrupted_marker["name"],
            f"UPDATE ml_promotion.heads SET sequence=3 WHERE environment='{environment}';",
        )
        rejected(
            "broken-head-event-chain-detected",
            "backup_ledger_content_invalid",
            lambda: promotion_recovery.read(interrupted_marker["name"]),
        )
    finally:
        cleanup(interrupted)
    confirmed("qualification-targets-removed", not target.exists() and not interrupted.exists())
    confirmed(
        "source-and-revision-stable",
        validate(state)["container_id"] == marker["container_id"]
        and source_fingerprint(root) == fingerprint
        and command(["git", "-C", str(root), "rev-parse", "HEAD"]) == revision
        and not command(["git", "-C", str(root), "status", "--porcelain"]),
    )
    return {
        "schema_version": 1,
        "scope": "promotion-journal-and-cas-recovery-not-full-M17",
        "status": "pass",
        "release_ready": False,
        "full_M17": "inconclusive",
        "campaign_id": campaign,
        "started_at": started,
        "finished_at": now(),
        "source_revision": revision,
        "source_dirty": False,
        "source_fingerprint": fingerprint,
        "backup_id": backup["backup_id"],
        "archive_bytes": backup["bytes"],
        "promotion_migration": backup["promotion"]["migration"],
        "cases": cases,
        "storage_restore_seconds": receipt["elapsed_seconds"],
        "restore_to_golden_seconds": golden_seconds,
        "golden_rows": 1000,
        "golden_max_error": maximum_error,
        "limitations": [
            "Controlled SQL selections are not approved ML releases",
            "Backup pin chooses a recovery point, not proof of latest head",
            "Interrupted target remains fenced; automatic pre-receipt resume not implemented",
            "Fresh trust/revocation and serving activation still required",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Disposable full promotion-journal recovery qualification"
    )
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    parser.add_argument("--confirm-disposable", action="store_true", required=True)
    arguments = parser.parse_args()
    output = None
    try:
        validate(arguments.state)
        output = safe_child(arguments.state, "evidence/promotion-recovery.json")
        write_json(output, {"status": "inconclusive", "release_ready": False})
        result = qualify(Path(__file__).resolve().parents[1], arguments.state, arguments.image)
        write_json(output, result)
        print(canonical({**result, "cases": len(result["cases"])}).decode())
        return 0
    except (
        Rejected,
        psycopg.Error,
        OSError,
        KeyError,
        TypeError,
        ValueError,
        RuntimeError,
    ) as error:
        known = {
            "storage_connection_rejected",
            "storage_docker_failed:exec",
            "backup_snapshot_unavailable",
            "backup_process_failed_or_warned",
            "backup_ledger_content_invalid",
            "restore_ledger_mismatch",
            "restore_promotion_ledger_mismatch",
            "restore_target_busy",
            "promotion_backup_migration_mismatch",
            "promotion_recovery_source_dirty",
        }
        reason = str(error) if str(error) in known else "unclassified-sanitized"
        if output is not None:
            with suppress(Rejected, OSError):
                write_json(output, {"status": "fail", "reason": reason, "release_ready": False})
        print(
            canonical(
                {"scope": "promotion-recovery-failure", "status": "fail", "reason": reason}
            ).decode(),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
