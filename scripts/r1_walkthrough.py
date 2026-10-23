import argparse
import platform
import time
from pathlib import Path

import numpy as np

from mlsecops import (
    bootstrap,
    data_source,
    inventory,
    sandbox,
    storage_backup,
    storage_bootstrap,
    storage_dataset,
    storage_pipeline,
    storage_restore,
)
from mlsecops.acceptance import GATES
from mlsecops.contracts import Rejected, canonical, digest, now, read_json, write_json
from mlsecops.prediction_protocol import PredictionBatch
from scripts import release_native, serving_output_native


def destination(root, state):
    root = Path(root).resolve()
    state = Path(state)
    state = state if state.is_absolute() else root / state
    runtime = root / ".runtime"
    if runtime.is_symlink() or state.is_symlink() or state.parent.is_symlink():
        raise Rejected("walkthrough_state_symlink")
    state = state.resolve()
    if state.parent != runtime or state == runtime:
        raise Rejected("walkthrough_state_outside_runtime")
    if state.exists():
        raise Rejected("walkthrough_requires_fresh_state")
    return state


def verify_subject(demo, proposal, serving):
    required = {
        "actual-candidate-revocation-http-503",
        "actual-candidate-revocation-readiness-503",
    }
    if (
        proposal.get("status") != "pass"
        or proposal.get("release_ready") is not False
        or "actual-promotion-admission-without-assurance-denied" not in proposal.get("cases", [])
        or serving.get("status") != "pass"
        or serving.get("release_ready") is not False
        or serving.get("scope") != "actual-candidate-serving-qualification-not-release-approval"
        or serving.get("candidate_reference") != demo["candidate"]["candidate_reference"]
        or serving.get("evaluation_reference") != demo["evaluation_reference"]
        or any(
            serving.get(name) != proposal[name]
            for name in ("model_sha256", "subject_sha256", "proposal_reference")
        )
        or not required.issubset(serving.get("cases", []))
    ):
        raise Rejected("walkthrough_subject_chain_mismatch")


def stop_owned(state):
    marker = storage_bootstrap.validate(state)
    storage_bootstrap.docker(["stop", marker["container_id"]])
    if storage_bootstrap.inspect("container", marker["container_id"])["State"]["Running"]:
        raise Rejected("walkthrough_stop_unconfirmed")
    return "stopped-volumes-retained"


def recover(root, source, target, image, demo, proposal):
    policy = read_json(root / "policies/local-cpu.json")
    trust = read_json(source / "storage-trust.json")
    public = read_json(source / "trusted-keys.json")
    reference = demo["candidate"]["candidate_reference"]
    original = storage_pipeline.load_candidate(
        source / "storage-clients/publisher", reference, policy
    )
    splits, _, _ = storage_dataset.read_dataset(
        source / "storage-clients/publisher",
        original[0]["dataset_reference"],
        policy,
        trust["curator"],
        trust["source_approval_digest"],
        ("validation",),
    )
    features = [row["features"] for row in splits["validation"][:1000]]
    batch = PredictionBatch(original[2], features)
    before, _ = sandbox.run_worker(image, batch.request)
    expected, _, _ = batch.consume(before)
    backup = storage_backup.create(root, source)
    write_json(source / "evidence/walkthrough-backup.json", backup)
    source_marker = storage_bootstrap.validate(source)
    stop_owned(source)
    started = time.monotonic()
    receipt = storage_restore.restore(
        root,
        Path(backup["directory"]),
        target,
        public,
        15440,
        expected_backup_id=backup["backup_id"],
    )
    marker = storage_bootstrap.validate(target)
    restored = storage_pipeline.load_candidate(
        target / "storage-clients/publisher", reference, policy
    )
    if (
        restored != original
        or digest(restored[2]) != proposal["model_sha256"]
        or receipt["tables"] != backup["tables"]
        or receipt["release_ready"] is not False
        or marker["workspace_id"] == source_marker["workspace_id"]
        or marker["volume"] == source_marker["volume"]
        or marker["container_id"] == source_marker["container_id"]
        or read_json(target / "trusted-keys.json") == public
        or read_json(target / "recovered-public-keys.json") != public
    ):
        raise Rejected("walkthrough_restore_identity_mismatch")
    restored_batch = PredictionBatch(restored[2], features)
    output, execution = sandbox.run_worker(image, restored_batch.request)
    actual, _, proof = restored_batch.consume(output)
    error = float(np.max(np.abs(np.asarray(expected) - np.asarray(actual))))
    if (
        proof["rows"] != 1000
        or proof["model_digest"] != proposal["model_sha256"]
        or execution["image_id"] != image
        or error > policy["parity_tolerance"]
        or storage_bootstrap.inspect("container", source_marker["container_id"])["State"]["Running"]
    ):
        raise Rejected("walkthrough_restore_readback_failed")
    repeated = storage_restore.restore(
        root,
        Path(backup["directory"]),
        target,
        public,
        15440,
        expected_backup_id=backup["backup_id"],
    )
    if not repeated["reused"] or repeated["container_id"] != marker["container_id"]:
        raise Rejected("walkthrough_restore_not_idempotent")
    return {
        "status": "pass",
        "scope": "same-candidate-storage-recovery-not-full-M17",
        "backup_id": backup["backup_id"],
        "candidate_reference": reference,
        "model_sha256": proposal["model_sha256"],
        "golden_rows": proof["rows"],
        "max_error": error,
        "restore_to_readback_seconds": time.monotonic() - started,
        "source_offline": True,
        "fresh_volume": True,
        "repeat_preserved_container": True,
        "release_ready": False,
    }


def run(root, state):
    root = Path(root).resolve()
    state = destination(root, state)
    if platform.system() != "Linux":
        raise Rejected("walkthrough_requires_disposable_linux")
    if inventory.command(["git", "-C", str(root), "status", "--porcelain"]):
        raise Rejected("walkthrough_requires_clean_checkout")
    data_source.validate_lock(root)
    state.mkdir(parents=True)
    source, target = state / "source", state / "recovered"
    report = {
        "schema_version": 1,
        "scope": "end-to-end-refusal-qualification-not-R1-acceptance",
        "status": "inconclusive",
        "r1_status": "incomplete",
        "release_ready": False,
        "release_decision": "not-evaluated",
        "started_at": now(),
        "source_revision": inventory.command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "source_fingerprint": inventory.source_fingerprint(root),
        "required_gates": list(GATES),
        "stages": [],
        "cleanup": {},
    }

    def stage(name, action):
        report["active_stage"] = name
        write_json(state / "report.json", report)
        print(canonical({"stage": name, "status": "running"}).decode(), flush=True)
        result = action()
        write_json(state / f"{name}.json", result)
        report["stages"].append(
            {"id": name, "status": "pass", "evidence_sha256": digest(canonical(result))}
        )
        write_json(state / "report.json", report)
        return result

    try:

        def prepare():
            first = bootstrap.initialize(root, source)
            second = bootstrap.initialize(root, source)
            if first != second:
                raise Rejected("walkthrough_bootstrap_not_idempotent")
            inventory.build_image(root, "trusted-mlsecops:dev")
            image = sandbox.resolve_image("trusted-mlsecops:dev")
            storage_bootstrap.bootstrap(source, 15439)
            return {"status": "pass", "image_id": image, "bootstrap_repeated": True}

        prepared = stage("preparation", prepare)
        image = prepared["image_id"]
        demo = stage("data-training-evaluation", lambda: storage_pipeline.demo(root, source, image))
        proposal = stage("release-decision", lambda: release_native.qualify(root, source, image))
        write_json(source / "evidence/release-native.json", proposal)
        inference = stage(
            "inference-observation", lambda: serving_output_native.run(root, source, image, 15446)
        )
        verify_subject(demo, proposal, inference)
        report.update(
            release_decision="refused",
            refusal_reason="release_assurance_required",
            candidate_reference=demo["candidate"]["candidate_reference"],
            evaluation_reference=demo["evaluation_reference"],
            model_sha256=proposal["model_sha256"],
            subject_sha256=proposal["subject_sha256"],
            inference_mode="qualification-only-not-production",
        )
        recovery = stage("recovery", lambda: recover(root, source, target, image, demo, proposal))
        report["inference_checks"] = len(inference["cases"])
        report["recovery"] = recovery
        report["status"] = "pass"
    except (Rejected, OSError, ValueError, KeyError, TypeError):
        report["status"] = "fail"
        report["failed_stage"] = report.get("active_stage", "preparation")
    finally:
        for name, owned_state in (("source", source), ("recovered", target)):
            if not (owned_state / "storage.json").is_file():
                report["cleanup"][name] = "no-storage-receipt"
                continue
            try:
                report["cleanup"][name] = stop_owned(owned_state)
            except (Rejected, OSError, ValueError, KeyError, TypeError):
                report["cleanup"][name] = "ownership-or-stop-unconfirmed"
                report["status"] = "fail"
        report["finished_at"] = now()
        write_json(state / "report.json", report)
    return report


def main(arguments=None):
    parser = argparse.ArgumentParser(
        description="Disposable end-to-end refusal path, not full R1 acceptance"
    )
    parser.add_argument("--confirm-disposable", action="store_true", required=True)
    parser.add_argument("--state", type=Path, default=Path(".runtime/r1-walkthrough"))
    arguments = parser.parse_args(arguments)
    try:
        report = run(Path(__file__).resolve().parents[1], arguments.state)
    except (Rejected, OSError, ValueError, KeyError, TypeError):
        print(
            canonical(
                {
                    "status": "fail",
                    "reason": "walkthrough_preflight_rejected",
                    "release_ready": False,
                }
            ).decode()
        )
        return 1
    print(canonical(report).decode())
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
