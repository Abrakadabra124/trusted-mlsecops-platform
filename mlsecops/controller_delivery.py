"""Owned disposable R1 handoff. The only training invocation is inside M04's M20."""

import os

from mlsecops import (
    acceptance,
    kube_storage,
    kube_storage_migration,
    signing,
    storage_backup,
    storage_bootstrap,
    storage_dataset,
    storage_pipeline,
    storage_restore,
)
from mlsecops.contracts import Rejected, canonical, digest, read_json, safe_child, write_json
from mlsecops.storage_snapshot import MAX_ARCHIVE, binary_command

HISTORY = ("candidates", "evaluations")


def check_pair(controller, candidate, evaluation, dataset, metadata, signed):
    publisher = controller["publisher"]["result"]
    scorer = controller["scorer"]["result"]
    if (
        publisher["candidate_reference"] != candidate
        or canonical(publisher["metadata"]) != canonical(metadata)
        or scorer["evaluation_reference"] != evaluation
        or canonical(scorer["evaluation"]) != canonical(signed)
        or signed["candidate_reference"] != candidate
        or signed["dataset_reference"] != dataset
    ):
        raise Rejected("delivery_scoped_signed_pair_mismatch")


def restore_history(state, owner, migration, baseline, public, subject):
    """Move all reservations together with the signed evaluations, in one transaction."""
    if any(baseline[name]["rows"] for name in HISTORY):
        raise Rejected("delivery_history_requires_empty_destination")
    with kube_storage_migration.exclusive(state) as ensure:
        target = kube_storage.validate(state)
        if target["volume_uid"] != migration["volume_uid"]:
            raise Rejected("delivery_private_volume_changed")
        # This is an authority transfer. Keep the old SQL clients fenced until teardown.
        kube_storage_migration.freeze(state)
        tables = kube_storage_migration.ledger(state)
        if any(tables[k] != v for k, v in baseline.items() if k not in HISTORY):
            raise Rejected("delivery_private_dataset_changed")
        content = kube_storage.execute(
            state,
            [
                "pg_dump",
                "-h",
                "/tmp",
                "-U",
                "postgres",
                "-d",
                "mlsecops",
                "--format=custom",
                "--compress=0",
                "--data-only",
                "--no-large-objects",
                "--no-privileges",
                "--strict-names",
                *(f"--table=ml.{name}" for name in HISTORY),
            ],
            timeout=120,
            limit=MAX_ARCHIVE,
        )
        context = {
            "subject": subject,
            "workspace": owner["workspace_id"],
            "host_container": owner["container_id"],
            "volume_uid": target["volume_uid"],
            "dataset_migration": migration["receipt_digest"],
            "archive_sha256": digest(content),
            "before": baseline,
            "after": tables,
        }
        receipt = signing.sign(context, "controller-history-transfer", state / "keys/trust.pem")
        path = safe_child(state, "evidence/controller-history-transfer.json")
        write_json(path, receipt)
        if (
            signing.verify(read_json(path), "controller-history-transfer", public["trust"])
            != context
        ):
            raise Rejected("delivery_history_signature")
        if (
            storage_bootstrap.validate(state) != owner
            or storage_restore.ledger(owner["name"]) != baseline
        ):
            raise Rejected("delivery_history_host_changed")
        prefix = ["docker", "exec", "--user", "999:999", "-i", owner["container_id"], "pg_restore"]
        storage_restore.validate_toc(
            binary_command([*prefix, "--list"], content, output_limit=65536), data_tables=HISTORY
        )
        ensure()
        binary_command(
            [
                *prefix,
                "--host=/tmp",
                "--username=postgres",
                "--dbname=mlsecops",
                "--data-only",
                "--no-owner",
                "--no-privileges",
                "--single-transaction",
                "--exit-on-error",
            ],
            content,
            output_limit=65536,
        )
        if (
            storage_restore.ledger(owner["name"]) != tables
            or kube_storage_migration.ledger(state) != tables
            or kube_storage_migration.connection_limit(state) != 0
        ):
            raise Rejected("delivery_history_final_ledgers")
        ensure()


def train(root, state, dataset, image):
    from scripts.kube_trust_native import hosted

    hosted()
    owner = storage_bootstrap.validate(state)
    if owner["workspace_id"] != os.environ.get("M07_FRESH_WORKSPACE_ID"):
        raise Rejected("delivery_scoped_requires_joint_owner")
    public = read_json(state / "trusted-keys.json")
    policy = read_json(root / "policies/local-cpu.json")
    trust = {
        "curator": public["curator"],
        "evaluator": public["evaluator"],
        "source_approval_digest": dataset["source_approval_digest"],
    }
    backup = storage_backup.create(root, state)
    if any(backup["tables"][name]["rows"] for name in (*HISTORY, "releases")):
        raise Rejected("delivery_dataset_snapshot_contains_history")
    inputs = state / "kubernetes-storage/migration-inputs.json"
    if inputs.exists():
        raise Rejected("delivery_private_profile_already_used")
    migration = kube_storage_migration.migrate(root, state, backup["directory"], public)
    if migration["backup_id"] != backup["backup_id"] or migration["reused"]:
        raise Rejected("delivery_dataset_migration_binding")
    write_json(
        inputs,
        {
            "backup_id": backup["backup_id"],
            "trust": trust,
            "dataset_reference": dataset["dataset_reference"],
        },
    )
    path = state / "evidence/M04.json"
    write_json(path, {"status": "inconclusive", "exit_code": 2})
    gate = acceptance.report("M04", "local-cpu", root, state)
    write_json(path, gate)
    if gate["status"] != "pass" or gate["exit_code"] != 0:
        raise Rejected("delivery_scoped_M04_not_pass")
    controller = read_json(state / "evidence/controller-demo.json")
    bound = read_json(state / "evidence/M20-controller.json")
    candidate = bound["candidate_reference"]
    evaluation = bound["evaluation_reference"]
    if (
        bound["dataset_reference"] != dataset["dataset_reference"]
        or bound["image_id"] != image
        or bound["status"] != "pass"
    ):
        raise Rejected("delivery_scoped_controller_binding")
    subject = {
        "candidate_reference": candidate,
        "evaluation_reference": evaluation,
        "dataset_reference": dataset["dataset_reference"],
        "metadata_sha256": digest(canonical(controller["publisher"]["result"]["metadata"])),
        "evaluation_sha256": digest(canonical(controller["scorer"]["result"]["evaluation"])),
        "authority_report": gate["artifact_hashes"]["authority"],
    }
    if "M21_START_SHA256" in os.environ:
        from mlsecops.controller_intake import capture

        capture(root, state, subject, image)
    restore_history(state, owner, migration, backup["tables"], public, subject)
    # Real role reads of the transferred objects. Outer M03 instruments these accesses.
    publisher, scorer = (state / "storage-clients" / role for role in ("publisher", "scorer"))
    for client, selected in ((publisher, ("train", "validation")), (scorer, ("holdout",))):
        storage_dataset.read_dataset(
            client,
            dataset["dataset_reference"],
            policy,
            trust["curator"],
            trust["source_approval_digest"],
            selected,
        )
    _, metadata, _ = storage_pipeline.load_candidate(publisher, candidate, policy)
    signed = storage_pipeline.read_evaluation(scorer, evaluation, candidate, policy, trust)
    check_pair(controller, candidate, evaluation, dataset["dataset_reference"], metadata, signed)
    result = {
        "dataset": dataset,
        "candidate": {"candidate_reference": candidate, "metadata": metadata},
        "evaluation_reference": evaluation,
        "evaluation": signed,
        "status": "role-restricted-storage-preview-not-R1-accepted",
        "limitations": [
            "Disposable scoped controller run; original cluster storage fenced after transfer"
        ],
    }
    write_json(state / "storage-trust.json", trust)
    write_json(state / "storage-demo.json", result)
    return result
