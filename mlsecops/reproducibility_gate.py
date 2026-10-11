import copy
import re
import uuid
from pathlib import Path

from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.datasets import verify_dataset
from mlsecops.inventory import command, source_fingerprint
from mlsecops.pipeline import load_candidate

NAMES = ("repeat-1", "repeat-2", "repeat-3", "seed", "data", "environment")


def host_source(root):
    return digest(
        canonical(
            {path.name: digest(bounded_read(path)) for path in (root / "scripts").glob("*.py")}
        )
    )


def reconcile(root, state, evidence, reader):
    from scripts.reproducibility import compare, validate_record
    from scripts.reproducibility_native import projection, record_from
    from scripts.tracking_client import read_back

    try:
        if (
            evidence["status"] != "pass"
            or evidence["scope"] != "native-input-mutations-and-tracking-not-full-M06"
            or evidence["release_ready"] is not False
            or type(evidence["source_dirty"]) is not bool
            or evidence["source_fingerprint"] != source_fingerprint(root)
            or evidence["source_revision"] != command(["git", "-C", str(root), "rev-parse", "HEAD"])
            or any(
                type(evidence[key]) is not int or evidence[key] != value
                for key, value in (
                    ("training_runs", 6),
                    ("prediction_runs", 6),
                    ("golden_rows", 3000),
                )
            )
            or any(
                type(evidence[key]) is not list or len(evidence[key]) != size
                for key, size in (("records", 6), ("tracking_receipts", 6), ("mutations", 3))
            )
            or not re.fullmatch(r"[0-9a-f]{32}", evidence["campaign_id"])
            or any(
                not re.fullmatch(r"sha256:[0-9a-f]{64}", evidence[key])
                for key in ("image_id", "environment_image_id")
            )
            or evidence["image_id"] == evidence["environment_image_id"]
            or evidence["baseline_environment"] != {"OMP_NUM_THREADS": "1"}
            or evidence["mutated_environment"] != {"OMP_NUM_THREADS": "2"}
        ):
            raise Rejected("M06_campaign_header_invalid")
        campaign = safe_child(state, "reproducibility/" + evidence["campaign_id"])
        policy = read_json(root / "policies/local-cpu.json")
        vectors, metadata_runs, cases, hashes = [], [], [], {}
        reference = None
        for index, record in enumerate(evidence["records"]):
            if not re.fullmatch(r"[0-9a-f]{32}", record["run_id"]):
                raise Rejected("M06_run_identity_invalid")
            location = safe_child(campaign, "candidates/" + record["run_id"])
            vector = read_json(location / "golden-scores.json")
            validate_record(record, vector)
            current_policy = (
                {**policy, "training_seed": policy["training_seed"] + 1} if index == 3 else policy
            )
            metadata, model = load_candidate(campaign, record["run_id"], current_policy)
            splits, manifest = verify_dataset(campaign, metadata["dataset_id"], current_policy)
            if reference is None:
                reference = splits
            expected_splits = copy.deepcopy(reference)
            if index == 4:
                expected_splits["train"][0]["features"][0] = (
                    1 - expected_splits["train"][0]["features"][0]
                )
            request = {
                "action": "train",
                "train": splits["train"],
                "seed": current_policy["training_seed"],
                "features": [row["features"] for row in splits["validation"]],
            }
            image = evidence["environment_image_id"] if index == 5 else evidence["image_id"]
            if (
                splits != expected_splits
                or len(reference["holdout"]) != 3000
                or len(vector) != 3000
                or metadata["input_digest"] != digest(canonical(request))
                or metadata["materials"] != manifest["objects"]
                or metadata["image_id"] != image
                or metadata["status"] != "unapproved-candidate"
                or metadata["source_fingerprint"] != evidence["source_fingerprint"]
                or metadata["source_revision"] != evidence["source_revision"]
            ):
                raise Rejected("M06_candidate_binding_invalid")
            expected = record_from(
                metadata,
                reference["holdout"],
                vector,
                {"OMP_NUM_THREADS": "2" if index == 5 else "1"},
            )
            if record != expected:
                raise Rejected("M06_record_not_bound_to_materials")
            vectors.append(vector)
            metadata_runs.append(metadata)
            hashes.update(
                {
                    f"model:{NAMES[index]}": digest(model),
                    f"vector:{NAMES[index]}": record["vector_digest"],
                    f"metadata:{NAMES[index]}": digest(bounded_read(location / "run.json")),
                }
            )
            cases.append(
                {
                    "id": "materials:" + NAMES[index],
                    "status": "pass",
                    "expected": digest(canonical(expected)),
                    "actual": digest(canonical(record)),
                }
            )
        baseline = compare(evidence["records"][:3], vectors[:3])
        if (
            baseline != evidence["baseline"]
            or len({record["run_id"] for record in evidence["records"]}) != 6
        ):
            raise Rejected("M06_baseline_or_fresh_runs_invalid")
        cases.extend(
            [
                {"id": "fresh-process-runs", "status": "pass", "expected": 6, "actual": 6},
                {
                    "id": "common-golden-rows",
                    "status": "pass",
                    "expected": 3000,
                    "actual": len(reference["holdout"]),
                },
                {
                    "id": "three-run-numeric-repeat",
                    "status": "pass",
                    "expected": {"probability_max": 1e-6, "auprc_max": 1e-4},
                    "actual": {
                        "probability": baseline["max_probability_difference"],
                        "auprc": baseline["auprc_difference"],
                    },
                },
            ]
        )
        for index, required in zip(range(3, 6), ("request", "dataset", "environment"), strict=True):
            record = evidence["records"][index]
            changed = sorted(
                key
                for key in record["inputs"]
                if record["inputs"][key] != evidence["records"][0]["inputs"][key]
            )
            expected = {
                "kind": NAMES[index],
                "status": "pass",
                "comparison": "rejected-input-change",
                "changed_inputs": changed,
                "max_probability_difference": max(
                    abs(left - right)
                    for left, right in zip(vectors[0], vectors[index], strict=True)
                ),
            }
            if required not in changed or evidence["mutations"][index - 3] != expected:
                raise Rejected("M06_mutation_not_bound_to_materials")
            try:
                compare([*evidence["records"][:2], record], [*vectors[:2], vectors[index]])
            except Rejected as error:
                if str(error) != "reproducibility_inputs_changed":
                    raise
            else:
                raise Rejected("M06_mutation_accepted_as_repeat")
            cases.append(
                {
                    "id": "mutation:" + NAMES[index],
                    "status": "pass",
                    "expected": "reproducibility_inputs_changed",
                    "actual": "reproducibility_inputs_changed",
                }
            )
        receipts = evidence["tracking_receipts"]
        if len({receipt["run_id"] for receipt in receipts}) != 6:
            raise Rejected("M06_tracking_run_reused")
        for name, record, metadata, receipt in zip(
            NAMES, evidence["records"], metadata_runs, receipts, strict=True
        ):
            exported = projection(record, metadata, name)
            expected = digest(canonical(exported))
            if (
                not re.fullmatch(r"[0-9a-f]{32}", receipt["run_id"])
                or receipt["record_digest"] != expected
                or set(receipt) != {"run_id", "record_digest", "artifact_path"}
                or not isinstance(receipt["artifact_path"], str)
                or not receipt["artifact_path"].startswith("/api/2.0/mlflow-artifacts/artifacts/")
            ):
                raise Rejected("M06_tracking_receipt_invalid")
            read_back(reader, receipt, exported)
            cases.append(
                {
                    "id": "tracking-read-back:" + name,
                    "status": "pass",
                    "expected": expected,
                    "actual": receipt["record_digest"],
                }
            )
        return {
            "status": "pass",
            "scope": "M06-synthetic-local-cpu-reproducibility",
            "release_ready": False,
            "cases": cases,
            "checks": len(cases),
            "metrics": {
                "training_runs": 6,
                "prediction_runs": 6,
                "tracking_runs": 6,
                "golden_rows": 3000,
                "max_probability_difference": baseline["max_probability_difference"],
                "auprc_difference": baseline["auprc_difference"],
            },
            "input_digests": {
                **evidence["records"][0]["inputs"],
                "worker_image": evidence["image_id"],
                "mutated_worker_image": evidence["environment_image_id"],
            },
            "artifact_hashes": {**hashes, "native_campaign": digest(canonical(evidence))},
            "campaign_id": evidence["campaign_id"],
            "source_dirty": evidence["source_dirty"],
            "limitations": [
                "Local synthetic CPU profile only; no cross-platform or production claim",
                "Trusted host executes and reconciles fresh runs; not independent build attestation",
                "Tracking recovery, Kubernetes publisher, full T08 and other M-gates remain mandatory",
                "M06 pass does not authorize release or waive image findings",
            ],
        }
    except (KeyError, TypeError, ValueError, IndexError) as error:
        raise Rejected("M06_evidence_shape_invalid") from error


def qualify(root, state):
    from scripts.reproducibility_native import qualify as execute
    from scripts.tracking_client import Client

    root, state = Path(root).resolve(), Path(state).resolve()
    output = state / "evidence/reproducibility-qualification.json"
    write_json(output, {"status": "inconclusive", "release_ready": False, "started_at": now()})
    campaign_id = uuid.uuid4().hex
    fingerprint = source_fingerprint(root)
    host_fingerprint = host_source(root)
    evidence = execute(root, "trusted-mlsecops:dev", runtime_state=state, campaign_id=campaign_id)
    if (
        evidence["campaign_id"] != campaign_id
        or fingerprint != source_fingerprint(root)
        or host_fingerprint != host_source(root)
    ):
        raise Rejected("M06_campaign_or_source_changed")
    if (
        read_json(
            safe_child(state, "reproducibility/" + campaign_id + "/evidence/reproducibility.json")
        )
        != evidence
    ):
        raise Rejected("M06_campaign_persistence_mismatch")
    tracker = state / "tracking-service"
    configuration = read_json(tracker / "configuration.json")
    credentials = read_json(tracker / "credentials.json")
    reader = Client(
        f"https://127.0.0.1:{configuration['port']}",
        tracker / "ca.crt",
        "reader",
        credentials["reader"],
    )
    result = reconcile(root, state, evidence, reader)
    result["input_digests"]["host_scripts"] = host_fingerprint
    result["finished_at"] = now()
    write_json(output, result)
    return result
