"""Hosted synthetic controller handoff and read-only M21 original-subject verification."""

import argparse
import os
from pathlib import Path

from mlsecops import (
    artifact_intake,
    controller_delivery,
    controller_intake,
    controller_runtime,
    data_source,
    kube_artifact_reader,
    kube_storage_migration,
    signing,
    storage,
    storage_backup,
    storage_bootstrap,
    storage_dataset,
    storage_pipeline,
    storage_restore,
)
from mlsecops.contracts import Rejected, bounded_read, canonical, digest, read_json, write_json
from mlsecops.sandbox import resolve_image, run_worker

PACKET = "evidence/M21-original-subject.json"
TRANSFER = "evidence/controller-history-transfer.json"
DEMO = "evidence/controller-demo.json"
INSPECTION = "evidence/M21-independent-inspection.json"


def clean_receipt(receipt, content, image):
    artifact_intake.validate_receipt(receipt, content, image)
    if receipt["status"] != "pass" or receipt["approved_outputs"] != [digest(content)]:
        raise Rejected("M21_clean_intake_required")


def capture(root, state):
    controller_intake.start(root, state)
    if any((state / path).exists() for path in (DEMO, PACKET, TRANSFER)):
        raise Rejected("M21_original_already_present")
    policy = read_json(root / "policies/local-cpu.json")
    public = read_json(state / "trusted-keys.json")
    data_source.reproduce(root, state)
    versions = data_source.prepare_versioned(root, state)
    dataset = storage_dataset.publish(state, versions["dataset_id"], versions["lineage_id"], policy)
    trust = {
        "curator": public["curator"],
        "evaluator": public["evaluator"],
        "source_approval_digest": dataset["source_approval_digest"],
    }
    backup = storage_backup.create(root, state)
    if any(backup["tables"][name]["rows"] for name in ("candidates", "evaluations", "releases")):
        raise Rejected("M21_source_history_present")
    migration = kube_storage_migration.migrate(root, state, backup["directory"], public)
    if migration["reused"] or migration["backup_id"] != backup["backup_id"]:
        raise Rejected("M21_source_migration_mismatch")
    write_json(
        state / "kubernetes-storage/migration-inputs.json",
        {
            "backup_id": backup["backup_id"],
            "trust": trust,
            "dataset_reference": dataset["dataset_reference"],
        },
    )
    demo = controller_runtime.demo(root, state)
    published, scored = (demo[role]["result"] for role in ("publisher", "scorer"))
    subject = dict(
        candidate_reference=published["candidate_reference"],
        evaluation_reference=scored["evaluation_reference"],
        dataset_reference=dataset["dataset_reference"],
        metadata_sha256=digest(canonical(published["metadata"])),
        evaluation_sha256=digest(canonical(scored["evaluation"])),
    )
    profile = read_json(state / "controllers/resources.json")["profile"]
    image = resolve_image("trusted-mlsecops:dev")
    if image != profile["image_id"]:
        raise Rejected("M21_controller_image")
    request = dict(
        schema_version=1,
        candidate_reference=subject["candidate_reference"],
        evaluation_reference=subject["evaluation_reference"],
        policy_digest=digest(canonical(policy)),
        trust=trust,
    )
    model = kube_artifact_reader.read(
        state, profile["image"], image, request | {"role": "publisher"}
    )
    evidence = kube_artifact_reader.read(
        state, profile["image"], image, request | {"role": "scorer"}
    )
    envelope = evidence["evaluation"]
    signed = signing.verify(envelope, "stored-evaluation", public["evaluator"])
    content = signing.decode64(model["golden"]["model"])
    if (
        digest(canonical(envelope)) != subject["evaluation_reference"]
        or digest(content) != signed["report"]["model_digest"]
        or published["metadata"]["model_digest"] != digest(content)
        or published["metadata"]["image_id"] != image
        or demo["scorer"]["controller"]["pod_uid"] == demo["publisher"]["controller"]["pod_uid"]
    ):
        raise Rejected("M21_source_model_or_signature")
    controller_delivery.check_pair(
        demo,
        subject["candidate_reference"],
        subject["evaluation_reference"],
        subject["dataset_reference"],
        published["metadata"],
        signed,
    )
    original = signed["report"]["intake"]
    clean_receipt(original, content, image)
    independent = artifact_intake.inspect_candidate(
        content, signed["report"]["model_digest"], image, image, run_worker
    )
    clean_receipt(independent, content, image)
    if independent["inspection_id"] == original["inspection_id"]:
        raise Rejected("M21_intake_id_reused")
    write_json(state / INSPECTION, independent)
    packet = dict(
        start=os.environ["M21_START_SHA256"],
        subject=subject,
        trust=trust,
        image=image,
        demo=digest(bounded_read(state / DEMO)),
        inspection=digest(bounded_read(state / INSPECTION)),
        baseline=backup["tables"],
        migration=migration,
        release_ready=False,
    )
    write_json(state / PACKET, packet)
    controller_intake.output("capture", state / PACKET)


def checked_inputs(root, state):
    controller_intake.start(root, state)
    packet = controller_intake.pinned(state / PACKET, os.environ["M21_CAPTURE_SHA256"])
    if packet["start"] != os.environ["M21_START_SHA256"] or packet["release_ready"] is not False:
        raise Rejected("M21_source_start_mismatch")
    return packet


def transfer(root, state):
    packet = checked_inputs(root, state)
    controller_delivery.restore_history(
        state,
        storage_bootstrap.validate(state),
        packet["migration"],
        packet["baseline"],
        read_json(state / "trusted-keys.json"),
        packet["subject"],
    )
    controller_intake.output("transfer", state / TRANSFER)


def readback(root, state):
    packet = checked_inputs(root, state)
    owner = storage_bootstrap.validate(state)
    public = read_json(state / "trusted-keys.json")
    transfer_pin = os.environ["M21_TRANSFER_SHA256"]
    moved = signing.verify(
        controller_intake.pinned(state / TRANSFER, transfer_pin),
        "controller-history-transfer",
        public["trust"],
    )
    subject, image = packet["subject"], packet["image"]
    candidate, evaluation = subject["candidate_reference"], subject["evaluation_reference"]
    before = storage_restore.ledger(owner["name"])
    if (
        moved["subject"] != subject
        or moved["workspace"] != owner["workspace_id"]
        or moved["host_container"] != owner["container_id"]
        or moved["before"] != packet["baseline"]
        or moved["volume_uid"] != packet["migration"]["volume_uid"]
        or moved["dataset_migration"] != packet["migration"]["receipt_digest"]
        or moved["after"] != before
        or kube_storage_migration.connection_limit(state) != 0
    ):
        raise Rejected("M21_transfer_mismatch")
    reader = state / "storage-clients/promoter"
    with storage.connect(reader) as conn:
        role = conn.execute("SELECT current_user").fetchone()[0]
    if role != "ml_promoter":
        raise Rejected("M21_readback_identity")
    policy = read_json(root / "policies/local-cpu.json")
    _, metadata, content = storage_pipeline.load_candidate(reader, candidate, policy)
    signed = storage_pipeline.read_evaluation(
        reader, evaluation, candidate, policy, packet["trust"]
    )
    demo = controller_intake.pinned(state / DEMO, packet["demo"])
    controller_delivery.check_pair(
        demo, candidate, evaluation, subject["dataset_reference"], metadata, signed
    )
    if (
        digest(canonical(signed)) != subject["evaluation_sha256"]
        or digest(canonical(metadata)) != subject["metadata_sha256"]
        or metadata["source_revision"] != os.environ["GITHUB_SHA"]
        or metadata["image_id"] != image
    ):
        raise Rejected("M21_readback_source")
    independent = controller_intake.pinned(state / INSPECTION, packet["inspection"])
    original = signed["report"]["intake"]
    for receipt in (original, independent):
        clean_receipt(receipt, content, image)
    if independent["inspection_id"] == original["inspection_id"]:
        raise Rejected("M21_readback_history_or_inspection_changed")
    after = storage_restore.ledger(owner["name"])
    if after != before:
        raise Rejected("M21_readback_history_changed")

    def unexpected_worker(*args):
        raise Rejected("M21_wrong_digest_reached_worker")

    wrong_model = digest(content + b" ")
    try:
        artifact_intake.inspect_candidate(content, wrong_model, image, image, unexpected_worker)
    except Rejected as error:
        if str(error) != "intake_subject_mismatch":
            raise
        model_rejection = str(error)
    else:
        raise Rejected("M21_foreign_model_digest_accepted")
    # Change only the supplied digest. The retained file and the database remain intact.
    wrong = digest(bounded_read(state / PACKET) + b" ")
    try:
        controller_intake.pinned(state / PACKET, wrong)
    except Rejected as error:
        if str(error) != "M21_pin_mismatch:" + Path(PACKET).name:
            raise
        reason = str(error)
    else:
        raise Rejected("M21_foreign_capture_accepted")
    return dict(
        scope="controller-original-readonly-synthetic",
        status="pass",
        release_ready=False,
        revision=os.environ["GITHUB_SHA"],
        run=os.environ["GITHUB_RUN_ID"],
        attempt=os.environ["GITHUB_RUN_ATTEMPT"],
        **subject,
        start=packet["start"],
        capture=os.environ["M21_CAPTURE_SHA256"],
        transfer=transfer_pin,
        controller_demo=packet["demo"],
        inspection=packet["inspection"],
        original_inspection=original["inspection_id"],
        independent_inspection=independent["inspection_id"],
        inspected=independent["inspected"],
        skipped=independent["skipped"],
        unsupported=independent["unsupported"],
        errors=independent["errors"],
        approved_outputs=independent["approved_outputs"],
        dataset_rows=signed["report"]["rows"],
        model_bytes=len(content),
        model_sha256=digest(content),
        image=image,
        reader=role,
        slot=signed["holdout_access"]["slot"],
        ledger_before=digest(canonical(before)),
        ledger_after=digest(canonical(after)),
        candidate_rows=before["candidates"]["rows"],
        evaluation_rows=before["evaluations"]["rows"],
        releases=before["releases"]["rows"],
        rejected_model_digest=wrong_model,
        model_rejection=model_rejection,
        rejected_digest=wrong,
        rejection=reason,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("capture", "transfer", "readback"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    state = root / ".runtime"
    if args.phase == "capture":
        capture(root, state)
    elif args.phase == "transfer":
        transfer(root, state)
    else:
        result = readback(root, state)
        write_json(state / "evidence/M21-original-result.json", result)
        print(canonical(result).decode())


if __name__ == "__main__":
    main()
