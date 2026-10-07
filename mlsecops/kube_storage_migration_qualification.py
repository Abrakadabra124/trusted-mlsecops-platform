import argparse
import sys
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

import numpy as np

from mlsecops import (
    kube_artifact_reader,
    kube_storage,
    storage_backup,
    storage_pipeline,
    storage_restore,
)
from mlsecops import kube_storage_migration as migration
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    canonical,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.inventory import source_fingerprint
from mlsecops.kube_storage_qualification import probe
from mlsecops.kube_storage_qualification import qualify as qualify_storage
from mlsecops.kube_worker import load_image
from mlsecops.pipeline import validate_scores
from mlsecops.sandbox import resolve_image, run_worker
from mlsecops.signing import decode64, sign, verify
from mlsecops.storage_bootstrap import validate as validate_source
from mlsecops.storage_recovery_qualification import backup_negatives


def prepare(root, state, image):
    location = kube_storage.local_state(state)
    if (location / "migration-intent.json").exists() or any(
        entry["rows"] for entry in migration.ledger(state).values()
    ):
        raise Rejected("migration_qualification_requires_fresh_target")
    path = location / "migration-inputs.json"
    if path.exists():
        return read_json(path)
    demo = storage_pipeline.demo(root, state, image)
    backup = storage_backup.create(root, state)
    inputs = {
        "backup_id": backup["backup_id"],
        "candidate_reference": demo["candidate"]["candidate_reference"],
        "evaluation_reference": demo["evaluation_reference"],
        "dataset_reference": demo["dataset"]["dataset_reference"],
        "trust": read_json(state / "storage-trust.json"),
        "model_digest": demo["candidate"]["metadata"]["model_digest"],
        "evaluation_payload_digest": digest(canonical(demo["evaluation"])),
    }
    write_json(path, inputs)
    return inputs


def qualify(root, state, image):
    root, state = Path(root).resolve(), Path(state).resolve()
    image_id = resolve_image(image)
    source = validate_source(state)
    target = kube_storage.validate(state)
    certificates = read_json(kube_storage.local_state(state) / "storage-pki/identity.json")
    inputs = prepare(root, state, image)
    directory = safe_child(state, f"backups/{inputs['backup_id']}")
    public = read_json(state / "trusted-keys.json")
    policy = read_json(root / "policies/local-cpu.json")
    statement, archive = storage_backup.read_backup(directory, public, policy)
    original_source = storage_restore.ledger(source["name"])
    cases = [
        {**case, "id": f"backup:{case['id']}"} for case in backup_negatives(root, state, directory)
    ]

    def confirmed(name, condition):
        if not condition:
            raise Rejected(f"migration_qualification_failed:{name}")
        cases.append({"id": name, "status": "pass"})

    def rejected(name, action, reason):
        try:
            action()
        except Rejected as error:
            if str(error) != reason:
                raise Rejected(f"migration_qualification_wrong_rejection:{name}:{error}") from error
            confirmed(name, True)
        else:
            confirmed(name, False)

    with tempfile.TemporaryDirectory(
        prefix="migration-preflight-", dir=state / "evidence"
    ) as temporary:
        fixture = Path(temporary)
        original = read_json(directory / "manifest.json")
        write_json(fixture / "manifest.json", {**original, "signatures": []})
        with patch.object(
            kube_storage, "validate", side_effect=AssertionError("Invalid archive touched target")
        ):
            rejected(
                "unsigned-before-target-access",
                lambda: migration.migrate(root, state, fixture, public),
                "invalid_signature_count",
            )
            foreign = {**statement, "source_workspace": "0" * 32}
            write_json(
                fixture / "manifest.json", sign(foreign, "storage-backup", state / "keys/trust.pem")
            )
            atomic_write(fixture / "data.dump", archive)
            rejected(
                "foreign-workspace-before-target-access",
                lambda: migration.migrate(root, state, fixture, public),
                "migration_source_workspace_mismatch",
            )
    confirmed(
        "preflight-preserves-empty-target",
        all(entry["rows"] == 0 for entry in migration.ledger(state).values())
        and migration.connection_limit(state) == -1,
    )
    with migration.exclusive(state) as ensure:
        rejected(
            "concurrent-migration-refused",
            lambda: migration.migrate(root, state, directory, public),
            "migration_busy_or_lock_invalid",
        )
        ensure()
    with migration.exclusive(state) as ensure:
        ensure()
        confirmed("lock-released-on-session-close", True)
    write_record = migration.write_record
    restore_archive = migration.restore_archive
    native_calls = []

    def interrupted_record(*arguments):
        if arguments[2] == "cluster-storage-migration-receipt":
            raise Rejected("qualification_injected_receipt_interruption")
        return write_record(*arguments)

    def observed_restore(*arguments):
        result = restore_archive(*arguments)
        native_calls.append(True)
        return result

    with (
        patch.object(migration, "write_record", side_effect=interrupted_record),
        patch.object(migration, "restore_archive", side_effect=observed_restore),
    ):
        rejected(
            "interruption-after-native-import",
            lambda: migration.migrate(root, state, directory, public),
            "qualification_injected_receipt_interruption",
        )
    confirmed("native-import-executed-once", native_calls == [True])
    confirmed("interruption-leaves-maintenance", migration.connection_limit(state) == 0)
    confirmed("interrupted-bytes-match-snapshot", migration.ledger(state) == statement["tables"])
    location = kube_storage.local_state(state)
    confirmed("no-premature-completion-receipt", not (location / "migration-receipt.json").exists())
    tag, loaded = load_image(state, image)
    confirmed("loaded-current-reader-image", loaded == image_id)
    blocked = probe(state, tag, image_id, "ml-ingestor", "ingestor", "maintenance")
    confirmed(
        "real-client-denied-during-maintenance",
        blocked == {"status": "pass", "role": "ingestor", "result": "database-maintenance-denied"},
    )
    with patch.object(
        migration, "restore_archive", side_effect=AssertionError("Resume recopied committed data")
    ):
        resumed = migration.migrate(root, state, directory, public)
    confirmed(
        "resume-reopens-after-verification",
        migration.connection_limit(state) == -1 and resumed["release_ready"] is False,
    )
    receipt_before = read_json(location / "migration-receipt.json")
    with (
        patch.object(migration, "freeze", side_effect=AssertionError("Repeat interrupted clients")),
        patch.object(
            migration, "restore_archive", side_effect=AssertionError("Repeat reimported data")
        ),
    ):
        repeated = migration.migrate(root, state, directory, public)
    confirmed(
        "repeat-is-read-only",
        repeated["reused"] and read_json(location / "migration-receipt.json") == receipt_before,
    )
    verified = verify(receipt_before, "cluster-storage-migration-receipt", public["trust"])
    expected = {key: value for key, value in verified.items() if key != "recorded_at"}
    for field, value in (
        ("schema_version", True),
        ("volume_uid", "foreign"),
        ("namespace_uid", "foreign"),
        ("backup_id", "0" * 64),
        ("intent_digest", "0" * 64),
        ("release_ready", True),
    ):
        modified = {**verified, field: value}
        envelope = sign(modified, "cluster-storage-migration-receipt", state / "keys/trust.pem")
        rejected(
            f"receipt-binding:{field}",
            lambda envelope=envelope: migration.verify_record(
                envelope, "cluster-storage-migration-receipt", expected, public
            ),
            "migration_record_binding_mismatch",
        )
    unsigned = {**receipt_before, "signatures": []}
    rejected(
        "unsigned-receipt",
        lambda: migration.verify_record(
            unsigned, "cluster-storage-migration-receipt", expected, public
        ),
        "invalid_signature_count",
    )
    request = {
        "schema_version": 1,
        "role": "publisher",
        "candidate_reference": inputs["candidate_reference"],
        "evaluation_reference": inputs["evaluation_reference"],
        "trust": inputs["trust"],
        "policy_digest": digest(canonical(policy)),
    }
    published = kube_artifact_reader.read(state, tag, image_id, request)
    scored = kube_artifact_reader.read(state, tag, image_id, {**request, "role": "scorer"})
    confirmed(
        "publisher-reads-only-train-validation",
        published["rows"] == {"train": 14000, "validation": 3000},
    )
    confirmed(
        "scorer-holdout-without-label-output",
        scored["rows"] == {"holdout": 3000} and "golden" not in scored,
    )
    for role, observed in (("publisher", published), ("scorer", scored)):
        confirmed(
            f"{role}:migrated-artifact-binding",
            observed["role"] == role
            and observed["candidate_reference"] == inputs["candidate_reference"]
            and observed["dataset_reference"] == inputs["dataset_reference"]
            and observed["model_digest"] == inputs["model_digest"],
        )
    evaluation = verify(scored["evaluation"], "stored-evaluation", public["evaluator"])
    confirmed(
        "original-evaluation-signature-and-content",
        digest(canonical(evaluation)) == inputs["evaluation_payload_digest"],
    )
    golden = published["golden"]
    confirmed("golden-model-bytes", digest(decode64(golden["model"])) == inputs["model_digest"])
    expected_scores = validate_scores(golden["expected_scores"], 1000)
    batch_id = uuid.uuid4().hex
    predictions, execution = run_worker(
        image,
        {
            "action": "predict",
            "model": golden["model"],
            "features": golden["features"],
            "batch_id": batch_id,
        },
    )
    observed_scores = validate_scores(predictions["scores"], 1000)
    maximum_error = float(np.max(np.abs(expected_scores - observed_scores)))
    confirmed(
        "offline-golden-prediction-binding",
        predictions["batch_id"] == batch_id
        and predictions["model_digest"] == inputs["model_digest"]
        and execution["image_id"] == image_id,
    )
    confirmed("1000-migrated-golden-predictions", maximum_error <= policy["repeat_tolerance"])
    payload = canonical({"fixture": "post-migration-change", "nonce": uuid.uuid4().hex})
    identifier = digest(payload)
    kube_storage.admin(
        state,
        f"INSERT INTO ml.quarantine (sha256,payload) VALUES ('{identifier}',decode('{payload.hex()}','hex'));",
    )
    try:
        rejected(
            "repeat-does-not-overwrite-later-data",
            lambda: migration.migrate(root, state, directory, public),
            "migration_existing_target_changed",
        )
        confirmed(
            "later-data-remains-and-access-stays-open",
            migration.connection_limit(state) == -1
            and kube_storage.admin(
                state,
                f"SELECT encode(payload,'hex') FROM ml.quarantine WHERE sha256='{identifier}';",
            )
            == payload.hex(),
        )
    finally:
        kube_storage.admin(
            state,
            f"DELETE FROM ml.quarantine WHERE sha256='{identifier}' AND payload=decode('{payload.hex()}','hex');",
        )
    acl = qualify_storage(root, state, image)
    cases.extend({**case, "id": f"restored-storage:{case['id']}"} for case in acl["cases"])
    confirmed(
        "final-ledger-and-certificates",
        migration.ledger(state) == statement["tables"]
        and read_json(location / "storage-pki/identity.json") == certificates,
    )
    confirmed(
        "source-remains-unchanged",
        validate_source(state)["container_id"] == source["container_id"]
        and storage_restore.ledger(source["name"]) == original_source,
    )
    confirmed(
        "target-volume-preserved",
        kube_storage.validate(state)["volume_uid"] == target["volume_uid"],
    )
    return {
        "schema_version": 1,
        "status": "pass",
        "scope": "signed-cluster-migration-not-full-M04-M17-M20",
        "observed_at": now(),
        "source_fingerprint": source_fingerprint(root),
        "release_ready": False,
        "backup_id": inputs["backup_id"],
        "database_rows": resumed["database_rows"],
        "database_bytes": resumed["database_bytes"],
        "golden_rows": 1000,
        "golden_max_error": maximum_error,
        "training_image": published["image_id"],
        "prediction_image": image_id,
        "cases": cases,
        "checks": len(cases),
    }


def main():
    parser = argparse.ArgumentParser(
        description="One-time signed migration qualification on an empty private target"
    )
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    path = arguments.state / "evidence/kubernetes-migration-qualification.json"
    write_json(
        path,
        {
            "status": "inconclusive",
            "observed_at": now(),
            "reason": "qualification-running",
            "release_ready": False,
        },
    )
    try:
        result = qualify(Path(__file__).resolve().parents[1], arguments.state, arguments.image)
        write_json(path, result)
        print(canonical(result).decode())
        return 0
    except (Rejected, OSError) as error:
        write_json(
            path,
            {"status": "fail", "observed_at": now(), "reason": str(error), "release_ready": False},
        )
        print(f"Migration qualification rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
