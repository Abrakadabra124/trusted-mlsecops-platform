import argparse
import importlib.metadata
import re
import sys
from datetime import datetime
from pathlib import Path

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
from mlsecops.prediction_protocol import response, validate_request, validate_scan, validate_scores
from mlsecops.sandbox import resolve_image
from mlsecops.signing import encode64
from scripts.poisoning import compare, matrix, poison, policy
from scripts.poisoning_native import host_source, materials, summarize


def equal(actual, expected, reason):
    if canonical(actual) != canonical(expected):
        raise Rejected("poisoning_evidence_" + reason)


def timestamp(value, earliest, latest):
    observed = datetime.fromisoformat(value)
    if observed.tzinfo is None or not datetime.fromisoformat(
        earliest
    ) <= observed <= datetime.fromisoformat(latest):
        raise Rejected("poisoning_evidence_timestamp")


def execution(value, image):
    equal(
        {
            name: value[name]
            for name in (
                "image_id",
                "network",
                "memory_limit_bytes",
                "cpu_limit",
                "deadline_seconds",
            )
        },
        {
            "image_id": image,
            "network": "none",
            "memory_limit_bytes": 4 * 1024**3,
            "cpu_limit": 2,
            "deadline_seconds": 600,
        },
        "execution_boundary",
    )
    elapsed = value["elapsed_seconds"]
    if type(elapsed) not in (int, float) or not 0 <= elapsed <= 600:
        raise Rejected("poisoning_evidence_execution_time")


def case_materials(
    directory,
    case,
    profile,
    train,
    validation,
    probes,
    triggered,
    inputs,
    revision,
    started,
    finished,
):
    try:
        return _case_materials(
            directory,
            case,
            profile,
            train,
            validation,
            probes,
            triggered,
            inputs,
            revision,
            started,
            finished,
        )
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("poisoning_evidence_case_shape") from error


def _case_materials(
    directory,
    case,
    profile,
    train,
    validation,
    probes,
    triggered,
    inputs,
    revision,
    started,
    finished,
):
    record = decode(bounded_read(safe_child(directory, "result.json")))
    equal({name: record[name] for name in case}, case, "case_identity")
    files = {
        "model": "model.onnx",
        "metadata": "metadata.json",
        "mutation": "mutation.json",
        "validation-scores": "validation-scores.json",
        "security-scores": "security-scores.json",
        "prediction": "prediction.json",
    }
    contents = {
        name: bounded_read(safe_child(directory, filename)) for name, filename in files.items()
    }
    equal(
        record["artifacts"],
        {name: digest(content) for name, content in contents.items()},
        "artifact_digest",
    )
    stored = {name: decode(content) for name, content in contents.items() if name != "model"}
    model = contents["model"]
    if len(model) > profile["model_limit_bytes"]:
        raise Rejected("poisoning_evidence_model_limit")
    if case["family"] == "clean":
        mutated = train
        receipt = {
            "family": "clean",
            "changed_rows": 0,
            "before_digest": digest(canonical(train)),
            "after_digest": digest(canonical(train)),
        }
    else:
        mutated, receipt = poison(train, case["family"], case["count"], case["seed"])
    equal(stored["mutation"], receipt, "mutation")
    equal(record["mutation_count"], case["count"], "mutation_count")
    split_objects = {
        f"{name}.json": {
            "sha256": digest(canonical(rows)),
            "rows": len(rows),
            "bytes": len(canonical(rows)),
        }
        for name, rows in (("train", mutated), ("validation", validation))
    }
    dataset = digest(canonical(split_objects))
    lineage = digest(canonical({"protocol": policy(), "case": case, "mutation": receipt}))
    training = {
        "action": "train",
        "train": mutated,
        "seed": case["seed"],
        "features": [row["features"] for row in validation],
    }
    metadata = stored["metadata"]
    expected = {
        "schema_version": 1,
        "run_id": record["run_id"],
        "model_digest": digest(model),
        "dataset_id": dataset,
        "lineage_id": lineage,
        "materials": split_objects,
        "policy_digest": digest(canonical({**profile, "training_seed": case["seed"]})),
        "input_digest": digest(canonical(training)),
        "image_id": inputs["image"],
        "source_fingerprint": inputs["source"],
        "source_revision": revision,
        "validation_probability_digest": digest(canonical(stored["validation-scores"])),
        "status": "unapproved-candidate",
        "versions": {
            name: importlib.metadata.version(name)
            for name in ("numpy", "onnx", "onnxruntime", "scikit-learn", "skl2onnx")
        },
    }
    equal({name: metadata[name] for name in expected}, expected, "training_materials")
    timestamp(metadata["created_at"], started, finished)
    if type(record["run_id"]) is not str or re.fullmatch(r"[0-9a-f]{32}", record["run_id"]) is None:
        raise Rejected("poisoning_evidence_run_identity")
    parity = metadata["validation_parity_max_error"]
    if type(parity) not in (int, float) or not 0 <= parity <= profile["parity_tolerance"]:
        raise Rejected("poisoning_evidence_parity")
    expected_record = {
        "dataset_digest": dataset,
        "lineage_digest": lineage,
        "model_digest": digest(model),
        "input_digest": digest(canonical(training)),
        "validation_parity_max_error": parity,
        "training_seconds": metadata["execution"]["elapsed_seconds"],
        "prediction_seconds": stored["prediction"]["execution"]["elapsed_seconds"],
    }
    equal({name: record[name] for name in expected_record}, expected_record, "record_binding")
    execution(metadata["execution"], inputs["image"])
    prediction = stored["prediction"]
    execution(prediction["execution"], inputs["image"])
    validate_scan(prediction["scan"])
    validate_scores(stored["validation-scores"], len(validation))
    scores = stored["security-scores"]
    validate_scores(scores, len(probes) + len(triggered))
    protocol = prediction["protocol"]
    batch_id = protocol["batch_id"]
    request = {
        "schema_version": 2,
        "action": "predict",
        "batch_id": batch_id,
        "model": encode64(model),
        "features": [row["features"] for rows in (probes, triggered) for row in rows],
        "row_ids": [f"{batch_id}:{index}" for index in range(len(scores))],
    }
    validate_request(request)
    equal(
        protocol,
        {
            "schema_version": 2,
            "batch_id": batch_id,
            "model_digest": digest(model),
            "request_digest": digest(canonical(request)),
            "response_digest": digest(canonical(response(request, scores, prediction["scan"]))),
            "rows": len(scores),
        },
        "prediction_binding",
    )
    return record, scores


def reconcile(root, state, report, image):
    try:
        return _reconcile(Path(root), Path(state), report, image)
    except (KeyError, TypeError, ValueError, AttributeError, OSError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("poisoning_evidence_campaign_shape") from error


def _reconcile(root, state, report, image):
    identity = report["campaign_id"]
    if type(identity) is not str or re.fullmatch(r"[0-9a-f]{32}", identity) is None:
        raise Rejected("poisoning_evidence_campaign_identity")
    campaign = safe_child(state, "poisoning/" + identity)
    expected = {
        "schema_version": 1,
        "scope": "native-poisoning-matrix-component-not-full-M08",
        "execution_status": "complete",
        "release_ready": False,
        "full_M08": "inconclusive",
        "source_revision": command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "protocol": policy(),
        **summarize(report["cases"]),
    }
    equal({name: report[name] for name in expected}, expected, "header")
    if type(report["source_dirty"]) is not bool:
        raise Rejected("poisoning_evidence_source_dirty_type")
    started, finished = report["started_at"], report["finished_at"]
    timestamp(started, "2026-01-01T00:00:00+00:00", now())
    timestamp(finished, started, now())
    profile, train, validation, probes, triggered = materials(root)
    inputs = {
        "source": source_fingerprint(root),
        "host_scripts": host_source(root),
        "protocol": digest(canonical(policy())),
        "data_lock": digest(bounded_read(root / "data.lock")),
        "image": image,
        "train": digest(canonical(train)),
        "validation": digest(canonical(validation)),
        "security_probes": digest(canonical(probes)),
        "trigger_probes": digest(canonical(triggered)),
    }
    equal(report["input_digests"], inputs, "inputs")
    snapshot = {}

    def capture(name):
        content = bounded_read(safe_child(campaign, name))
        snapshot[name] = digest(content)
        return decode(content)

    equal(capture("report.json"), report, "report_changed")
    equal(
        capture("campaign.json"),
        {
            "campaign_id": identity,
            "started_at": started,
            "source_revision": expected["source_revision"],
            "protocol": policy(),
            "inputs": inputs,
            "status": "inconclusive",
            "release_ready": False,
        },
        "campaign_manifest",
    )
    for name, rows in (
        ("train", train),
        ("validation", validation),
        ("probes", probes),
        ("triggered", triggered),
    ):
        equal(capture(name + ".json"), rows, "material_" + name)
    verifier = digest(bounded_read(root / "scripts/poisoning_evidence.py"))
    controls, checked = {}, []
    count = len(probes)
    for case, claimed in zip(matrix(), report["cases"], strict=True):
        directory = safe_child(campaign, case["id"])
        for filename in (
            "model.onnx",
            "metadata.json",
            "mutation.json",
            "validation-scores.json",
            "security-scores.json",
            "prediction.json",
            "result.json",
        ):
            name = case["id"] + "/" + filename
            snapshot[name] = digest(bounded_read(safe_child(campaign, name)))
        record, scores = case_materials(
            directory,
            case,
            profile,
            train,
            validation,
            probes,
            triggered,
            inputs,
            expected["source_revision"],
            started,
            finished,
        )
        equal(record, claimed, "case_report_binding")
        if case["family"] == "clean":
            controls[case["seed"]] = scores
        reference = controls[case["seed"]]
        position = count if case["family"] == "backdoor" else 0
        metrics = compare(
            probes,
            reference[:count],
            scores[:count],
            reference[position : position + count],
            scores[position : position + count],
        )
        equal(record["metrics"], metrics, "metrics")
        checked.append(record)
    equal({name: report[name] for name in summarize(checked)}, summarize(checked), "aggregate")
    equal(
        {name: digest(bounded_read(safe_child(campaign, name))) for name in snapshot},
        snapshot,
        "changed_during_read",
    )
    equal(source_fingerprint(root), inputs["source"], "source_changed")
    equal(host_source(root), inputs["host_scripts"], "host_changed")
    equal(digest(bounded_read(root / "data.lock")), inputs["data_lock"], "lock_changed")
    equal(
        command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        expected["source_revision"],
        "revision_changed",
    )
    equal(
        digest(bounded_read(root / "scripts/poisoning_evidence.py")), verifier, "verifier_changed"
    )
    return {
        "schema_version": 1,
        "scope": "poisoning-primary-material-reconciliation-not-full-M08",
        "status": report["status"],
        "evidence_integrity": "pass",
        "release_ready": False,
        "full_M08": "inconclusive",
        "campaign_id": identity,
        "verified_cases": len(checked),
        "verified_files": len(snapshot),
        "violating_scenarios": report["violating_scenarios"],
        "inconclusive_scenarios": report["inconclusive_scenarios"],
        "source_revision": expected["source_revision"],
        "input_digests": inputs,
        "report_digest": snapshot["report.json"],
        "materials_digest": digest(canonical(snapshot)),
        "verifier_digest": verifier,
        "observed_at": now(),
        "limitations": [
            "Local trusted-controller reconciliation, not a signed release approval",
            "No retraining or inference rerun; complete consistent forgery by a compromised host is outside this boundary",
            "Parity and execution receipts are checked, not independently remeasured",
            "Known probes and self-review do not satisfy independent M22 challenges",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Reconcile all frozen poisoning materials without executing models"
    )
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--report", type=Path, default=Path(".runtime/evidence/poisoning.json"))
    parser.add_argument(
        "--output", type=Path, default=Path(".runtime/evidence/poisoning-reconciliation.json")
    )
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    try:
        evidence = arguments.state.absolute() / "evidence"
        relative = arguments.output.absolute().relative_to(evidence).as_posix()
        output = safe_child(evidence, relative)
        if output.resolve() == arguments.report.resolve():
            raise Rejected("poisoning_evidence_output_is_input")
    except (Rejected, ValueError, OSError):
        print(
            canonical(
                {
                    "status": "fail",
                    "reason": "poisoning_evidence_unsafe_output",
                    "release_ready": False,
                }
            ).decode()
        )
        return 1
    result = {
        "status": "inconclusive",
        "evidence_integrity": "inconclusive",
        "release_ready": False,
    }
    write_json(output, result)
    try:
        result = reconcile(
            Path(__file__).resolve().parents[1],
            arguments.state,
            read_json(arguments.report),
            resolve_image(arguments.image),
        )
    except (Rejected, OSError) as error:
        result = {
            "status": "fail",
            "evidence_integrity": "fail",
            "reason": str(error),
            "release_ready": False,
        }
    write_json(output, result)
    print(canonical(result).decode(), file=sys.stdout)
    return {"pass": 0, "fail": 1, "inconclusive": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
