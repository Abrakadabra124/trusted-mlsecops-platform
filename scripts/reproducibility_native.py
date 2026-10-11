import argparse
import re
import uuid
from pathlib import Path

from sklearn.metrics import average_precision_score

from mlsecops.bootstrap import initialize
from mlsecops.contracts import Rejected, canonical, decode, digest, now, read_json, write_json
from mlsecops.datasets import generate, prepare, publish_records, verify_dataset
from mlsecops.inventory import command, source_fingerprint
from mlsecops.pipeline import load_candidate, train_candidate
from mlsecops.prediction_protocol import PredictionBatch
from mlsecops.sandbox import resolve_image, run_worker
from mlsecops.storage_bootstrap import docker, inspect
from scripts.reproducibility import compare, validate_record
from scripts.tracking_client import Client, configure_access, publish, read_back
from scripts.tracking_service import up

IMAGE_LABEL = "org.trusted-mlsecops.reproducibility"


def environment(image):
    result = docker(
        [
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "65532:65532",
            "--pids-limit",
            "16",
            "--memory",
            "128m",
            "--memory-swap",
            "128m",
            "--cpus",
            "1",
            image,
            "python",
            "-c",
            "import json,os; print(json.dumps({'OMP_NUM_THREADS':os.environ.get('OMP_NUM_THREADS')}))",
        ]
    )
    return decode(result.stdout)


def derive_environment(base, identity):
    base_tag = "trusted-mlsecops:repro-base-" + identity
    tag = "trusted-mlsecops:repro-env-" + identity
    if inspect("image", base_tag, required=False) or inspect("image", tag, required=False):
        raise Rejected("reproducibility_image_name_already_exists")
    docker(["image", "tag", base, base_tag])
    try:
        docker(
            [
                "build",
                "--platform",
                "linux/amd64",
                "--network",
                "none",
                "--tag",
                tag,
                "-",
            ],
            f"FROM {base_tag}\nENV OMP_NUM_THREADS=2\nLABEL {IMAGE_LABEL}={identity}\n".encode(),
            timeout=180,
        )
        observed = inspect("image", tag)
        if (
            observed["Config"].get("Labels", {}).get(IMAGE_LABEL) != identity
            or observed["Id"] == base
        ):
            raise Rejected("reproducibility_environment_image_invalid")
        return tag, observed["Id"]
    finally:
        if inspect("image", base_tag)["Id"] != base:
            raise Rejected("reproducibility_base_tag_changed")
        docker(["image", "rm", base_tag])


def remove_environment(tag, image, identity):
    observed = inspect("image", tag)
    if observed["Id"] != image or observed["Config"].get("Labels", {}).get(IMAGE_LABEL) != identity:
        raise Rejected("reproducibility_cleanup_foreign_image")
    docker(["image", "rm", tag])
    if inspect("image", tag, required=False):
        raise Rejected("reproducibility_cleanup_incomplete")


def record_from(metadata, golden, vector, observed_environment):
    record = {
        "run_id": metadata["run_id"],
        "inputs": {
            "request": metadata["input_digest"],
            "dataset": metadata["dataset_id"],
            "policy": metadata["policy_digest"],
            "source": digest(
                canonical({key: metadata[key] for key in ("source_fingerprint", "source_revision")})
            ),
            "environment": digest(
                canonical(
                    {
                        "image_id": metadata["image_id"],
                        "versions": metadata["versions"],
                        **observed_environment,
                    }
                )
            ),
            "golden": digest(canonical(golden)),
        },
        "model_digest": metadata["model_digest"],
        "vector_digest": digest(canonical(vector)),
        "auprc": float(average_precision_score([row["label"] for row in golden], vector)),
    }
    validate_record(record, vector)
    return record


def projection(record, metadata, name):
    return {
        "source_run_id": record["run_id"],
        "params": {
            **record["inputs"],
            "input_bundle_digest": digest(canonical(record["inputs"])),
            "model_digest": record["model_digest"],
            "vector_digest": record["vector_digest"],
            "worker_image": metadata["image_id"],
            "case": name,
            "status": "unapproved-candidate",
        },
        "metrics": {"auprc": record["auprc"]},
    }


def run_one(state, dataset, policy, image, golden, observed_environment):
    metadata = train_candidate(state, dataset, policy, image)
    _, model = load_candidate(state, metadata["run_id"], policy)
    batch = PredictionBatch(model, [row["features"] for row in golden])
    output, execution = run_worker(image, batch.request)
    if execution["image_id"] != metadata["image_id"]:
        raise Rejected("reproducibility_prediction_image_changed")
    vector, _, _ = batch.consume(output)
    vector = vector.tolist()
    record = record_from(metadata, golden, vector, observed_environment)
    write_json(state / "candidates" / record["run_id"] / "golden-scores.json", vector)
    return record, vector, metadata


def qualify(root, worker_image, *, runtime_state=None, campaign_id=None):
    runtime_state = Path(runtime_state) if runtime_state is not None else root / ".runtime"
    output_path = runtime_state / "evidence/reproducibility.json"
    write_json(output_path, {"status": "inconclusive", "release_ready": False, "started_at": now()})
    image = resolve_image(worker_image)
    baseline_environment = environment(image)
    if baseline_environment != {"OMP_NUM_THREADS": "1"}:
        raise Rejected("reproducibility_baseline_profile_changed")
    identity = campaign_id if campaign_id is not None else uuid.uuid4().hex
    if not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{32}", identity):
        raise Rejected("reproducibility_campaign_id_invalid")
    state = runtime_state / "reproducibility" / identity
    if state.exists():
        raise Rejected("reproducibility_campaign_reused")
    tracker_state = runtime_state / "tracking-service"
    service = up(root, tracker_state, 15445)
    initialize(root, state)
    policy = read_json(root / "policies/local-cpu.json")
    dataset = prepare(state, policy)
    splits, manifest = verify_dataset(state, dataset, policy)
    golden = splits["holdout"]
    if len(golden) != 3000:
        raise Rejected("reproducibility_golden_profile_changed")
    runs = [run_one(state, dataset, policy, image, golden, baseline_environment) for _ in range(3)]
    baseline = compare([item[0] for item in runs], [item[1] for item in runs])
    seed_policy = {**policy, "training_seed": policy["training_seed"] + 1}
    seed_dataset = publish_records(
        state, seed_policy, generate(policy["data_seed"], policy["rows"])
    )
    seed_splits, seed_manifest = verify_dataset(state, seed_dataset, seed_policy)
    if seed_manifest["objects"] != manifest["objects"] or seed_splits != splits:
        raise Rejected("reproducibility_seed_mutation_altered_data")
    runs.append(run_one(state, seed_dataset, seed_policy, image, golden, baseline_environment))
    rows = generate(policy["data_seed"], policy["rows"])
    rows[0]["features"][0] = 1.0 - rows[0]["features"][0]
    data_dataset = publish_records(state, policy, rows)
    data_splits, data_manifest = verify_dataset(state, data_dataset, policy)
    if (
        data_splits["holdout"] != golden
        or data_splits["validation"] != splits["validation"]
        or data_manifest["objects"]["train.json"] == manifest["objects"]["train.json"]
    ):
        raise Rejected("reproducibility_data_mutation_not_train_only")
    runs.append(run_one(state, data_dataset, policy, image, golden, baseline_environment))
    tag, derived = derive_environment(image, identity)
    try:
        mutated_environment = environment(derived)
        if mutated_environment != {"OMP_NUM_THREADS": "2"} or resolve_image(derived) != derived:
            raise Rejected("reproducibility_environment_not_changed")
        runs.append(run_one(state, dataset, policy, derived, golden, mutated_environment))
    finally:
        remove_environment(tag, derived, identity)
    mutations = []
    for name, entry, required in zip(
        ("seed", "data", "environment"),
        runs[3:],
        ("request", "dataset", "environment"),
        strict=True,
    ):
        changed = sorted(
            key
            for key in runs[0][0]["inputs"]
            if runs[0][0]["inputs"][key] != entry[0]["inputs"][key]
        )
        if required not in changed:
            raise Rejected("reproducibility_mutation_binding_missing:" + name)
        try:
            compare([runs[0][0], runs[1][0], entry[0]], [runs[0][1], runs[1][1], entry[1]])
        except Rejected as error:
            if str(error) != "reproducibility_inputs_changed":
                raise
        else:
            raise Rejected("reproducibility_native_mutation_accepted:" + name)
        mutations.append(
            {
                "kind": name,
                "status": "pass",
                "comparison": "rejected-input-change",
                "changed_inputs": changed,
                "max_probability_difference": max(
                    abs(left - right) for left, right in zip(runs[0][1], entry[1], strict=True)
                ),
            }
        )
    if len({entry[0]["run_id"] for entry in runs}) != 6:
        raise Rejected("reproducibility_training_run_reused")
    credentials = read_json(tracker_state / "credentials.json")
    clients = {
        role: Client(service["endpoint"], tracker_state / "ca.crt", role, credentials[role])
        for role in ("admin", "publisher", "reader")
    }
    experiment = configure_access(clients["admin"], credentials, "reproducibility-" + identity)
    receipts = []
    for name, (record, vector, metadata) in zip(
        ("repeat-1", "repeat-2", "repeat-3", "seed", "data", "environment"), runs, strict=True
    ):
        exported = projection(record, metadata, name)
        receipt = publish(clients["publisher"], experiment, exported)
        read_back(clients["reader"], receipt, exported)
        receipts.append(receipt)
    if len({receipt["run_id"] for receipt in receipts}) != 6:
        raise Rejected("reproducibility_tracking_run_reused")
    result = {
        "status": "pass",
        "scope": "native-input-mutations-and-tracking-not-full-M06",
        "release_ready": False,
        "campaign_id": identity,
        "completed_at": now(),
        "baseline": baseline,
        "mutations": mutations,
        "training_runs": 6,
        "prediction_runs": 6,
        "golden_rows": len(golden),
        "image_id": image,
        "environment_image_id": derived,
        "baseline_environment": baseline_environment,
        "mutated_environment": mutated_environment,
        "source_fingerprint": source_fingerprint(root),
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "source_dirty": bool(command(["git", "-C", str(root), "status", "--porcelain"])),
        "records": [record for record, _, _ in runs],
        "tracking_receipts": receipts,
    }
    write_json(state / "evidence/reproducibility.json", result)
    write_json(output_path, result)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Native seed/data/environment reproducibility checks"
    )
    parser.add_argument("--worker-image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        print(canonical(qualify(root, arguments.worker_image)).decode())
        return 0
    except (Rejected, OSError) as error:
        reason = str(error) if isinstance(error, Rejected) else type(error).__name__
        result = {
            "status": "fail"
            if isinstance(error, Rejected) and reason.startswith("reproducibility_")
            else "inconclusive",
            "release_ready": False,
            "reason": reason,
            "completed_at": now(),
        }
        write_json(root / ".runtime/evidence/reproducibility.json", result)
        print(canonical(result).decode())
        return 1 if result["status"] == "fail" else 2


if __name__ == "__main__":
    raise SystemExit(main())
