import argparse
import copy
import shutil
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import numpy as np

from mlsecops import storage, storage_backup, storage_dataset, storage_pipeline, storage_restore
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    write_json,
)
from mlsecops.pipeline import validate_scores
from mlsecops.sandbox import run_worker
from mlsecops.signing import decode64, encode64, sign, verify
from mlsecops.storage_backup import read_backup
from mlsecops.storage_bootstrap import admin, docker, validate
from mlsecops.storage_qualification import qualify as qualify_storage
from mlsecops.storage_schema import TABLES
from mlsecops.storage_snapshot import binary_command


def backup_negatives(root, state, directory):
    root, state, directory = Path(root), Path(state), Path(directory)
    policy = read_json(root / "policies/local-cpu.json")
    public = read_json(state / "trusted-keys.json")
    statement, content = read_backup(directory, public, policy)
    original = read_json(directory / "manifest.json")
    cases = []

    def rejected(identifier, operation, reason):
        try:
            operation()
        except Rejected as error:
            if str(error) != reason:
                raise Rejected(f"recovery_wrong_rejection:{identifier}:{error}") from None
            cases.append(
                {"id": identifier, "status": "pass", "expected": reason, "actual": str(error)}
            )
        else:
            raise Rejected(f"recovery_qualification_bypass:{identifier}")

    with tempfile.TemporaryDirectory(
        prefix="backup-negatives-", dir=state / "evidence"
    ) as temporary:
        fixture = Path(temporary)
        atomic_write(fixture / "data.dump", content)
        now = datetime.now(UTC)
        changes = (
            ("boolean-schema", "schema_version", True, "backup_context_mismatch"),
            ("wrong-format", "format", "plain-sql", "backup_context_mismatch"),
            ("wrong-image", "image", "postgres:latest", "backup_context_mismatch"),
            ("wrong-policy", "policy_digest", "0" * 64, "backup_context_mismatch"),
            ("wrong-trust-bundle", "trusted_keys_digest", "0" * 64, "backup_context_mismatch"),
            ("invalid-source-identity", "source_workspace", "../source", "backup_context_mismatch"),
            (
                "boolean-migration",
                "migration",
                {**statement["migration"], "version": True},
                "backup_context_mismatch",
            ),
            (
                "wrong-migration",
                "migration",
                {**statement["migration"], "sha256": "0" * 64},
                "backup_context_mismatch",
            ),
            (
                "expired-snapshot",
                "started_at",
                (now - timedelta(hours=25)).isoformat(),
                "backup_time_window_invalid",
            ),
            (
                "future-snapshot",
                "completed_at",
                (now + timedelta(minutes=1)).isoformat(),
                "backup_time_window_invalid",
            ),
            (
                "inverted-snapshot",
                "completed_at",
                "2000-01-01T00:00:00+00:00",
                "backup_time_window_invalid",
            ),
            ("naive-timestamp", "started_at", "2026-10-07T00:00:00", "backup_time_window_invalid"),
            ("invalid-timestamp", "started_at", False, "backup_timestamp_invalid"),
            (
                "archive-traversal",
                "archive",
                {**statement["archive"], "name": "../data.dump"},
                "backup_archive_metadata_invalid",
            ),
            (
                "archive-boolean-size",
                "archive",
                {**statement["archive"], "bytes": True},
                "backup_archive_metadata_invalid",
            ),
            (
                "archive-oversized",
                "archive",
                {**statement["archive"], "bytes": 1024**3},
                "backup_archive_metadata_invalid",
            ),
            (
                "missing-table",
                "tables",
                {name: entry for name, entry in statement["tables"].items() if name != "train"},
                "backup_ledger_tables_invalid",
            ),
            (
                "invalid-row-digest",
                "tables",
                {**statement["tables"], "train": {**statement["tables"]["train"], "invalid": 1}},
                "backup_ledger_content_invalid",
            ),
            (
                "boolean-row-count",
                "tables",
                {**statement["tables"], "train": {**statement["tables"]["train"], "rows": True}},
                "backup_ledger_content_invalid",
            ),
        )
        for identifier, field, value, reason in changes:
            write_json(
                fixture / "manifest.json",
                sign({**statement, field: value}, "storage-backup", state / "keys/trust.pem"),
            )
            rejected(identifier, lambda: read_backup(fixture, public, policy), reason)
        signature = copy.deepcopy(original)
        signed = decode64(signature["signatures"][0]["sig"])
        signature["signatures"][0]["sig"] = encode64(signed[:-1] + bytes([signed[-1] ^ 1]))
        for identifier, envelope, reason in (
            ("signature-tamper", signature, "invalid_signature"),
            (
                "unsigned-payload",
                {**original, "payload": encode64(canonical({**statement, "format": "forged"}))},
                "invalid_signature",
            ),
            (
                "wrong-signer",
                sign(statement, "storage-backup", state / "keys/curator.pem"),
                "untrusted_key",
            ),
            (
                "wrong-envelope-type",
                sign(statement, "source", state / "keys/trust.pem"),
                "wrong_payload_type",
            ),
        ):
            write_json(fixture / "manifest.json", envelope)
            rejected(identifier, lambda: read_backup(fixture, public, policy), reason)
        write_json(fixture / "manifest.json", original)
        for identifier, invalid in (
            ("archive-single-byte", content[:-1] + bytes([content[-1] ^ 1])),
            ("archive-truncated", content[:-1]),
        ):
            atomic_write(fixture / "data.dump", invalid)
            rejected(
                identifier,
                lambda: read_backup(fixture, public, policy),
                "backup_archive_integrity_failed",
            )
        (fixture / "data.dump").unlink()
        rejected(
            "archive-missing", lambda: read_backup(fixture, public, policy), "artifact_unavailable"
        )
    if (
        read_backup(directory, public, policy)[1] != content
        or bounded_read(directory / "data.dump", len(content)) != content
    ):
        raise Rejected("backup_original_changed")
    cases.append(
        {
            "id": "backup-positive-after-negatives",
            "status": "pass",
            "expected": True,
            "actual": True,
        }
    )
    return cases


def qualify(root, state, image="trusted-mlsecops:dev", port=15441):
    root, state = Path(root).resolve(), Path(state).resolve()
    source_marker = validate(state)
    demo = storage_pipeline.demo(root, state, image)
    policy = read_json(root / "policies/local-cpu.json")
    public = read_json(state / "trusted-keys.json")
    trust = read_json(state / "storage-trust.json")
    before = storage_restore.ledger(source_marker["name"])
    late_content = canonical({"scope": "recovery-concurrent-write", "id": uuid.uuid4().hex})
    late_id = digest(late_content)
    original_command = storage_backup.binary_command
    inserted = False

    def concurrent_insert(arguments, *values, **keywords):
        nonlocal inserted
        if "pg_dump" not in arguments or inserted:
            raise Rejected("recovery_snapshot_probe_unexpected_command")
        storage.put(state / "storage-clients/ingestor", "quarantine", late_content)
        inserted = True
        return original_command(arguments, *values, **keywords)

    try:
        with patch("mlsecops.storage_backup.binary_command", concurrent_insert):
            backup = storage_backup.create(root, state)
        if (
            not inserted
            or storage.get(state / "storage-clients/ingestor", "quarantine", late_id)
            != late_content
        ):
            raise Rejected("recovery_concurrent_insert_not_observed")
    finally:
        if inserted:
            admin(
                source_marker["name"],
                f"DELETE FROM ml.quarantine WHERE sha256 = '{late_id}' AND payload = decode('{late_content.hex()}', 'hex');",
            )
    directory = Path(backup["directory"])
    cases = backup_negatives(root, state, directory)

    def confirmed(identifier, condition):
        if not condition:
            raise Rejected(f"recovery_qualification_failed:{identifier}")
        cases.append({"id": identifier, "status": "pass", "expected": True, "actual": True})

    def rejected(identifier, operation, reason):
        try:
            operation()
        except Rejected as error:
            if str(error) != reason:
                raise Rejected(f"recovery_wrong_rejection:{identifier}:{error}") from None
            cases.append(
                {"id": identifier, "status": "pass", "expected": reason, "actual": str(error)}
            )
        else:
            raise Rejected(f"recovery_qualification_bypass:{identifier}")

    confirmed("concurrent-insert-excluded-from-consistent-snapshot", backup["tables"] == before)
    rejected(
        "external-backup-signer-withdrawn",
        lambda: read_backup(directory, {**public, "trust": public["curator"]}, policy),
        "untrusted_key",
    )
    rejected(
        "external-artifact-trust-changed",
        lambda: read_backup(directory, {**public, "curator": public["evaluator"]}, policy),
        "backup_context_mismatch",
    )
    valid_toc = "\n".join(
        f"{index}; 0 {index} TABLE DATA ml {table} ml_owner"
        for index, table in enumerate(TABLES, 1)
    ).encode()
    storage_restore.validate_toc(valid_toc)
    confirmed("toc-exact-table-set", True)
    for identifier, invalid, reason in (
        ("toc-empty", b"", "restore_archive_table_scope_invalid"),
        ("toc-missing-table", valid_toc.split(b"\n", 1)[1], "restore_archive_table_scope_invalid"),
        (
            "toc-duplicate-table",
            valid_toc + b"\n" + valid_toc.split(b"\n", 1)[0],
            "restore_archive_table_scope_invalid",
        ),
        (
            "toc-unknown-table",
            valid_toc.replace(b"quarantine", b"untrusted"),
            "restore_archive_table_scope_invalid",
        ),
        (
            "toc-schema-command",
            valid_toc + b"\n42; 0 42 SCHEMA public postgres",
            "restore_archive_toc_invalid",
        ),
        ("toc-invalid-encoding", b"\xff", "restore_archive_toc_invalid"),
    ):
        rejected(identifier, lambda invalid=invalid: storage_restore.validate_toc(invalid), reason)
    rejected(
        "source-target-refused",
        lambda: storage_restore.restore(root, directory, state, public, port),
        "restore_requires_new_target",
    )
    with tempfile.TemporaryDirectory(
        prefix="restore-refusal-", dir=state / "evidence"
    ) as temporary:
        existing = Path(temporary)
        atomic_write(existing / "unrelated", b"preserve")
        rejected(
            "unowned-nonempty-target",
            lambda: storage_restore.restore(root, directory, existing, public, port),
            "restore_requires_new_target",
        )
        confirmed("unowned-target-unchanged", bounded_read(existing / "unrelated") == b"preserve")
        fixture = existing / "invalid-backup"
        fixture.mkdir()
        envelope = read_json(directory / "manifest.json")
        write_json(fixture / "manifest.json", {**envelope, "signatures": []})
        with patch(
            "mlsecops.storage_restore.initialize",
            side_effect=AssertionError("Invalid archive reached bootstrap"),
        ):
            rejected(
                "unsigned-backup-before-bootstrap",
                lambda: storage_restore.restore(root, fixture, existing / "new", public, port),
                "invalid_signature_count",
            )
        confirmed("unsigned-backup-creates-no-target", not (existing / "new").exists())
    for identifier, program, expected in (
        (
            "binary-output-limit",
            "import sys; sys.stdout.buffer.write(b'x'*4096)",
            "backup_process_limit_or_deadline",
        ),
        (
            "binary-warning-is-not-success",
            "import sys; sys.stderr.write('controlled warning')",
            "backup_process_failed_or_warned",
        ),
        ("binary-failed-command", "raise SystemExit(3)", "backup_process_failed_or_warned"),
    ):
        rejected(
            identifier,
            lambda program=program: binary_command(
                [sys.executable, "-c", program], output_limit=32
            ),
            expected,
        )
    rejected(
        "binary-deadline",
        lambda: binary_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.1),
        "backup_process_limit_or_deadline",
    )
    target = state / "evidence" / f"recovery-{uuid.uuid4().hex}"
    receipt = None
    started = time.monotonic()
    try:
        receipt = storage_restore.restore(root, directory, target, public, port)
        target_marker = validate(target)
        certificates = read_json(target / "storage-pki/identity.json")
        confirmed(
            "fresh-workspace-and-storage",
            target_marker["workspace_id"] != source_marker["workspace_id"]
            and target_marker["volume"] != source_marker["volume"]
            and target_marker["container_id"] != source_marker["container_id"],
        )
        confirmed("all-nine-table-ledgers-restored", receipt["tables"] == before)
        confirmed(
            "no-private-signing-key-clone",
            read_json(target / "trusted-keys.json") != public
            and read_json(target / "recovered-public-keys.json") == public,
        )
        confirmed("restore-is-not-release-ready", receipt["release_ready"] is False)
        repeated = storage_restore.restore(root, directory, target, public, port)
        confirmed(
            "repeat-preserves-container-and-certificates",
            repeated["reused"]
            and repeated["container_id"] == receipt["container_id"]
            and read_json(target / "storage-pki/identity.json") == certificates,
        )
        rejected(
            "late-row-not-in-restored-snapshot",
            lambda: storage.get(target / "storage-clients/ingestor", "quarantine", late_id),
            "storage_object_missing",
        )
        candidate = demo["candidate"]["candidate_reference"]
        record, metadata, model = storage_pipeline.load_candidate(
            target / "storage-clients/publisher", candidate, policy
        )
        original = storage_pipeline.load_candidate(
            state / "storage-clients/publisher", candidate, policy
        )
        confirmed("candidate-roundtrip", (record, metadata, model) == original)
        splits, _, _ = storage_dataset.read_dataset(
            target / "storage-clients/publisher",
            record["dataset_reference"],
            policy,
            trust["curator"],
            trust["source_approval_digest"],
            ("train", "validation"),
        )
        saved_scores = validate_scores(
            decode(
                storage.get(
                    target / "storage-clients/publisher", "candidates", record["scores_object"]
                )
            ),
            3000,
        )
        confirmed(
            "saved-score-digest",
            digest(canonical(saved_scores.tolist())) == metadata["validation_probability_digest"],
        )
        batch_id = uuid.uuid4().hex
        predicted, execution = run_worker(
            image,
            {
                "action": "predict",
                "model": encode64(model),
                "batch_id": batch_id,
                "features": [row["features"] for row in splits["validation"][:1000]],
            },
        )
        scores = validate_scores(predicted["scores"], 1000)
        confirmed(
            "golden-protocol-binding",
            predicted["batch_id"] == batch_id
            and predicted["model_digest"] == digest(model)
            and execution["image_id"] == metadata["image_id"],
        )
        maximum_error = float(np.max(np.abs(scores - saved_scores[:1000])))
        confirmed(
            "1000-golden-predictions-after-restore", maximum_error <= policy["repeat_tolerance"]
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
        confirmed("evaluation-signature-and-binding-restored", evaluation == demo["evaluation"])
        application_seconds = round(time.monotonic() - started, 6)
        confirmed("component-recovery-within-15-minutes", application_seconds <= 900)
        acl = qualify_storage(target)
        cases.extend({**case, "id": f"restored-storage:{case['id']}"} for case in acl["cases"])
        changed = canonical({"scope": "restore-must-not-erase-later-data", "id": uuid.uuid4().hex})
        changed_id = storage.put(target / "storage-clients/ingestor", "quarantine", changed)
        try:
            rejected(
                "repeat-does-not-overwrite-changed-target",
                lambda: storage_restore.restore(root, directory, target, public, port),
                "restore_existing_target_changed",
            )
            confirmed(
                "later-data-preserved",
                storage.get(target / "storage-clients/ingestor", "quarantine", changed_id)
                == changed,
            )
        finally:
            admin(
                target_marker["name"],
                f"DELETE FROM ml.quarantine WHERE sha256 = '{changed_id}' AND payload = decode('{changed.hex()}', 'hex');",
            )
        confirmed(
            "restored-ledger-after-negative-probes",
            storage_restore.ledger(target_marker["name"]) == before,
        )
        confirmed(
            "source-ledger-unchanged",
            storage_restore.ledger(source_marker["name"]) == before
            and validate(state)["container_id"] == source_marker["container_id"],
        )
    finally:
        if receipt is not None:
            marker = validate(target)
            if (
                marker["container_id"] != receipt["container_id"]
                or marker["workspace_id"] != receipt["target_workspace"]
                or marker["workspace_id"] == source_marker["workspace_id"]
                or target.resolve().parent != (state / "evidence").resolve()
            ):
                raise Rejected("recovery_cleanup_ownership_mismatch")
            docker(["rm", "--force", marker["container_id"]])
            docker(["network", "rm", marker["network"]])
            docker(["volume", "rm", marker["volume"]])
            shutil.rmtree(target.resolve())
    confirmed("qualification-target-removed", not target.exists())
    return {
        "schema_version": 1,
        "status": "pass",
        "scope": "storage-recovery-component-not-full-M17",
        "observed_at": now(),
        "cases": cases,
        "checks": len(cases),
        "backup_id": backup["backup_id"],
        "archive_bytes": backup["bytes"],
        "database_rows": sum(entry["rows"] for entry in before.values()),
        "database_bytes": sum(entry["bytes"] for entry in before.values()),
        "storage_restore_seconds": receipt["elapsed_seconds"],
        "restore_to_golden_seconds": application_seconds,
        "golden_rows": 1000,
        "golden_max_error": maximum_error,
        "limitations": [
            "Storage recovery component, not full M01/M17 or serving readiness",
            "Host administrator and backup signer trusted",
            "Current trust-service revocation and full release recovery pending",
            "No scheduler, offsite backup, encryption or production RPO claim",
            "Synthetic data only; component checks overlap other reports",
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    parser.add_argument("--port", type=int, default=15441)
    arguments = parser.parse_args()
    destination = arguments.state / "evidence/storage-recovery-qualification.json"
    try:
        result = qualify(
            Path(__file__).resolve().parents[1], arguments.state, arguments.image, arguments.port
        )
        write_json(destination, result)
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        write_json(destination, {"status": "fail", "observed_at": now(), "reason": str(error)})
        print(f"Storage recovery qualification rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
