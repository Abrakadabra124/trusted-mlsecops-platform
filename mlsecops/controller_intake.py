"""Pass the original controller subject and its independent readback to ordinary M21."""

import os
from pathlib import Path

from mlsecops import artifact_intake, intake_denial, kube_artifact_reader, signing, storage_pipeline
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.storage_bootstrap import validate

START = "evidence/M21-controller-start.json"
CAPTURE = "evidence/M21-controller-capture.json"
MATRIX = "evidence/kube-intake-qualification.json"
PACKETS = {
    "matrix": MATRIX,
    "readback": "evidence/M21-original-readback.json",
    "controller": "evidence/controller-demo.json",
    "authority": "evidence/authority-qualification.json",
}


def pinned(path, pin):
    raw = bounded_read(path)
    if digest(raw) != pin:
        raise Rejected("M21_pin_mismatch:" + path.name)
    return decode(raw)


def output(name, path):
    pin = digest(bounded_read(path))
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as sink:
        print(f"{name}={pin}", file=sink)
    return pin


def owner(root, state):
    from scripts.kube_trust_native import hosted

    hosted()
    marker = validate(state)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    if (
        root != Path(os.environ["GITHUB_WORKSPACE"]).resolve()
        or state != root / ".runtime"
        or revision != os.environ["GITHUB_SHA"]
        or command(["git", "-C", str(root), "status", "--porcelain"])
    ):
        raise Rejected("M21_controller_checkout")
    return dict(
        workspace=marker["workspace_id"],
        container=marker["container_id"],
        revision=revision,
        fingerprint=source_fingerprint(root),
        run=os.environ["GITHUB_RUN_ID"],
        attempt=os.environ["GITHUB_RUN_ATTEMPT"],
        keys=digest(bounded_read(state / "trusted-keys.json")),
    )


def begin(root, state):
    identity = owner(root, state)
    if any(
        (state / name).exists()
        for name in (START, CAPTURE, MATRIX, "storage-demo.json", "evidence/controller-demo.json")
    ):
        raise Rejected("M21_controller_campaign_already_started")
    write_json(state / START, {"owner": identity, "started_at": now()})
    return output("start", state / START)


def start(root, state):
    receipt = pinned(state / START, os.environ.get("M21_START_SHA256"))
    if receipt["owner"] != owner(root, state):
        raise Rejected("M21_controller_start_owner")
    return receipt["started_at"]


def check_readback(matrix, reader, original_reference, original):
    positive = matrix["positive"]
    if (
        reader["positive"] != original
        or reader["release_ready"] is not False
        or reader["model_digest"] != matrix["model_digest"]
        or reader["candidate_reference"] != original["candidate_reference"]
        or matrix["candidate_reference"] != original["candidate_reference"]
        or reader["denials"] != [item["payload"] for item in matrix["denials"]]
        or reader["controller"]["pod_uid"] == matrix["controller"]["pod_uid"]
        or positive["evaluation_reference"] == original_reference
        or positive["evaluation"]["candidate_reference"] != original["candidate_reference"]
        or positive["evaluation"]["holdout_access"]["slot"] == original["holdout_access"]["slot"]
    ):
        raise Rejected("M21_controller_original_readback")


def capture(root, state, subject, image):
    """Called inside the producer, after M04, while the training database is still active."""
    from mlsecops import kube_intake_qualification as kube
    from mlsecops.controller_bootstrap import verify_saved
    from mlsecops.intake_gate import fresh

    root, state = Path(root).resolve(), Path(state).resolve()
    began = start(root, state)
    if (state / CAPTURE).exists():
        raise Rejected("M21_controller_capture_exists")
    controller = read_json(state / PACKETS["controller"])
    candidate = controller["publisher"]["result"]
    scorer = controller["scorer"]["result"]
    metadata, original = candidate["metadata"], scorer["evaluation"]
    reference = subject["candidate_reference"]
    evaluation = subject["evaluation_reference"]
    profile = verify_saved(state, read_json(state / "controllers/resources.json"))["profile"]
    trust = read_json(state / "kubernetes-storage/migration-inputs.json")["trust"]
    if (
        candidate["candidate_reference"] != reference
        or scorer["evaluation_reference"] != evaluation
        or original["candidate_reference"] != reference
        or original["dataset_reference"] != subject["dataset_reference"]
        or digest(canonical(metadata)) != subject["metadata_sha256"]
        or digest(canonical(original)) != subject["evaluation_sha256"]
        or digest(bounded_read(state / PACKETS["authority"])) != subject["authority_report"]
        or metadata["image_id"] != image
        or profile["image_id"] != image
    ):
        raise Rejected("M21_controller_subject")
    fresh(metadata["created_at"], began)
    fresh(original["report"]["created_at"], began)
    model = kube_artifact_reader.read(
        state,
        profile["image"],
        image,
        {
            "schema_version": 1,
            "role": "publisher",
            "candidate_reference": reference,
            "evaluation_reference": evaluation,
            "policy_digest": metadata["policy_digest"],
            "trust": trust,
        },
    )
    content = signing.decode64(model["golden"]["model"])
    if digest(content) != metadata["model_digest"]:
        raise Rejected("M21_controller_model_digest")
    artifact_intake.validate_receipt(original["report"]["intake"], content, image)
    matrix = kube.qualify(root, state, content, image, metadata["materials"])
    reader = kube.invoke(
        state,
        profile,
        "promoter",
        {
            "context": {
                "schema_version": 1,
                "profile": profile,
                "candidate_reference": reference,
                "trust": trust,
            },
            "evaluation_reference": evaluation,
            "denial_references": [item["reference"] for item in matrix["denials"]],
        },
    )
    check_readback(matrix, reader, evaluation, original)
    write_json(state / PACKETS["readback"], reader)
    write_json(
        state / CAPTURE,
        {
            "subject": subject,
            "start": os.environ["M21_START_SHA256"],
            "artifacts": {k: digest(bounded_read(state / path)) for k, path in PACKETS.items()},
            "release_ready": False,
        },
    )
    return output("capture", state / CAPTURE)


def resume(root, state, image):
    """Check producer pins and signed records on the authoritative destination before further work."""
    from mlsecops.intake_gate import checked_cases, fresh
    from mlsecops.intake_probe import CASE_IDS
    from mlsecops.kube_intake_qualification import HOST_CASES

    began = start(root, state)
    packet = pinned(state / CAPTURE, os.environ.get("M21_CAPTURE_SHA256"))
    demo = pinned(state / "storage-demo.json", os.environ.get("M17_DEMO_SHA256"))
    artifacts = {k: pinned(state / path, packet["artifacts"][k]) for k, path in PACKETS.items()}
    public = read_json(state / "trusted-keys.json")
    transfer = signing.verify(
        read_json(state / "evidence/controller-history-transfer.json"),
        "controller-history-transfer",
        public["trust"],
    )
    identity = pinned(state / START, os.environ["M21_START_SHA256"])["owner"]
    subject = packet["subject"]
    ref, evaluation = subject["candidate_reference"], subject["evaluation_reference"]
    trust = read_json(state / "storage-trust.json")
    if (
        packet["start"] != os.environ["M21_START_SHA256"]
        or packet["release_ready"] is not False
        or transfer["subject"] != subject
        or transfer["workspace"] != identity["workspace"]
        or transfer["host_container"] != identity["container"]
        or trust["curator"] != public["curator"]
        or trust["evaluator"] != public["evaluator"]
        or demo["candidate"]["candidate_reference"] != ref
        or demo["evaluation_reference"] != evaluation
        or demo["dataset"]["dataset_reference"] != subject["dataset_reference"]
        or subject["authority_report"] != packet["artifacts"]["authority"]
    ):
        raise Rejected("M21_controller_transfer_subject")
    reader = state / "storage-clients/promoter"
    policy = read_json(root / "policies/local-cpu.json")
    _, metadata, content = storage_pipeline.load_candidate(reader, ref, policy)
    original = storage_pipeline.read_evaluation(reader, evaluation, ref, policy, trust)
    matrix = artifacts["matrix"]
    check_readback(matrix, artifacts["readback"], evaluation, original)
    checked_cases(matrix, CASE_IDS | HOST_CASES)
    fresh(matrix["started_at"], began)
    fresh(matrix["finished_at"], matrix["started_at"])
    positive = matrix["positive"]
    if (
        original != demo["evaluation"]
        or digest(canonical(original)) != subject["evaluation_sha256"]
        or original["dataset_reference"] != subject["dataset_reference"]
        or metadata != demo["candidate"]["metadata"]
        or digest(canonical(metadata)) != subject["metadata_sha256"]
        or metadata["model_digest"] != digest(content)
        or matrix["model_digest"] != digest(content)
        or matrix["materials"] != metadata["materials"]
        or matrix["source_revision"] != identity["revision"]
        or matrix["source_fingerprint"] != identity["fingerprint"]
        or matrix["image_id"] != image
        or metadata["image_id"] != image
        or storage_pipeline.read_evaluation(
            reader, positive["evaluation_reference"], ref, policy, trust
        )
        != positive["evaluation"]
        or any(
            intake_denial.read(reader, entry["reference"], ref, policy, trust) != entry["payload"]
            for entry in matrix["denials"]
        )
    ):
        raise Rejected("M21_controller_transferred_records")
    artifact_intake.validate_receipt(original["report"]["intake"], content, image)
    return began, demo, matrix
