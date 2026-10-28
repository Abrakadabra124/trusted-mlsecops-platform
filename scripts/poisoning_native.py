import argparse
import re
import sys
import uuid
from pathlib import Path

from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    safe_child,
    write_json,
)
from mlsecops.data_source import generated, validate_lock
from mlsecops.datasets import generate, validate_rows
from mlsecops.evaluation_quality import freeze
from mlsecops.inventory import command, source_fingerprint
from mlsecops.pipeline import train_verified_dataset
from mlsecops.prediction_protocol import PredictionBatch
from mlsecops.sandbox import resolve_image, run_worker
from scripts.poisoning import compare, matrix, poison, policy, trigger


def host_source(root):
    return digest(
        canonical(
            {
                name: digest(bounded_read(root / "scripts" / name))
                for name in ("poisoning.py", "poisoning_native.py")
            }
        )
    )


def materials(root):
    profile = read_json(root / "policies/local-cpu.json")
    freeze(profile)
    lock = validate_lock(root)
    content = generated(root)
    if {"sha256": digest(content), "bytes": len(content)} != lock["output"]:
        raise Rejected("poisoning_source_lock_mismatch")
    records = decode(content)
    train, validation = records[:14000], records[14000:17000]
    rules = policy()
    probes = generate(rules["probe_seed"], rules["probe_rows"])
    for row in probes:
        row["entity_id"] += rules["probe_entity_offset"]
    if (
        profile["split_counts"] != [14000, 3000, 3000]
        or len(train) != rules["train_rows"]
        or len(validation) != 3000
        or validate_rows(records).intersection(validate_rows(probes))
        or {tuple(row["features"]) for row in records}.intersection(
            tuple(row["features"]) for row in probes
        )
    ):
        raise Rejected("poisoning_materials_not_disjoint")
    return profile, train, validation, probes, trigger(probes)


def execute(
    root, directory, case, train, validation, views, profile, image, *, experiment_policy=None
):
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
    split_objects = {
        f"{name}.json": {
            "sha256": digest(canonical(rows)),
            "rows": len(rows),
            "bytes": len(canonical(rows)),
        }
        for name, rows in (("train", mutated), ("validation", validation))
    }
    dataset = digest(canonical(split_objects))
    rules = policy() if experiment_policy is None else experiment_policy
    lineage = digest(canonical({"protocol": rules, "case": case, "mutation": receipt}))
    current_profile = {**profile, "training_seed": case["seed"]}
    metadata, model, validation_scores = train_verified_dataset(
        dataset,
        lineage,
        {"train": mutated, "validation": validation},
        {"objects": split_objects},
        current_profile,
        image,
        run_worker,
    )
    batch = PredictionBatch(model, [row["features"] for rows in views for row in rows])
    output, execution = run_worker(image, batch.request)
    scores, scan, protocol = batch.consume(output)
    if execution["image_id"] != image or metadata["image_id"] != image:
        raise Rejected("poisoning_worker_image_changed")
    directory.mkdir()
    atomic_write(directory / "model.onnx", model)
    stored = {
        "metadata": metadata,
        "mutation": receipt,
        "validation-scores": validation_scores,
        "security-scores": scores.tolist(),
        "prediction": {"scan": scan, "protocol": protocol, "execution": execution},
    }
    artifacts = {"model": digest(model)}
    for name, value in stored.items():
        write_json(directory / f"{name}.json", value)
        artifacts[name] = digest(bounded_read(directory / f"{name}.json"))
    return {
        **case,
        "run_id": metadata["run_id"],
        "model_digest": digest(model),
        "input_digest": metadata["input_digest"],
        "dataset_digest": dataset,
        "lineage_digest": lineage,
        "artifacts": artifacts,
        "training_seconds": metadata["execution"]["elapsed_seconds"],
        "prediction_seconds": execution["elapsed_seconds"],
        "validation_parity_max_error": metadata["validation_parity_max_error"],
        "mutation_count": receipt["changed_rows"],
    }, scores.tolist()


def summarize(records, *, expected_cases=None):
    required = {"id", "family", "seed", "count", "run_id", "mutation_count", "metrics"}
    if type(records) is not list or any(
        type(record) is not dict
        or not required.issubset(record)
        or type(record["run_id"]) is not str
        or re.fullmatch(r"[0-9a-f]{32}", record["run_id"]) is None
        or type(record["metrics"]) is not dict
        or "status" not in record["metrics"]
        or type(record["mutation_count"]) is not int
        for record in records
    ):
        raise Rejected("poisoning_matrix_shape_invalid")
    expected = matrix() if expected_cases is None else expected_cases
    if (
        len(records) != len(expected)
        or len({record["run_id"] for record in records}) != len(expected)
        or any(
            canonical({name: record[name] for name in case}) != canonical(case)
            for record, case in zip(records, expected, strict=True)
        )
        or any(record["mutation_count"] != record["count"] for record in records)
        or any(
            record["metrics"]["status"] not in ("pass", "fail", "inconclusive")
            for record in records
        )
    ):
        raise Rejected("poisoning_incomplete_or_changed_matrix")
    statuses = [record["metrics"]["status"] for record in records]
    return {
        "status": "fail"
        if "fail" in statuses
        else "inconclusive"
        if "inconclusive" in statuses
        else "pass",
        "training_runs": len(records),
        "prediction_runs": len(records),
        "poisoned_runs": sum(record["family"] != "clean" for record in records),
        "clean_controls": sum(record["family"] == "clean" for record in records),
        "nonviolating_scenarios": statuses.count("pass"),
        "violating_scenarios": statuses.count("fail"),
        "inconclusive_scenarios": statuses.count("inconclusive"),
        "clean_self_control_rejections": sum(
            record["family"] == "clean" and record["metrics"]["status"] != "pass"
            for record in records
        ),
    }


def qualify(root, state, image):
    root, state = Path(root).resolve(), Path(state).resolve()
    image = resolve_image(image)
    fingerprint, scripts = source_fingerprint(root), host_source(root)
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    profile, train, validation, probes, triggered = materials(root)
    identity = uuid.uuid4().hex
    campaign = safe_child(state, "poisoning/" + identity)
    campaign.mkdir(parents=True, exist_ok=False)
    rules = policy()
    started = now()
    inputs = {
        "source": fingerprint,
        "host_scripts": scripts,
        "protocol": digest(canonical(rules)),
        "data_lock": digest(bounded_read(root / "data.lock")),
        "image": image,
        "train": digest(canonical(train)),
        "validation": digest(canonical(validation)),
        "security_probes": digest(canonical(probes)),
        "trigger_probes": digest(canonical(triggered)),
    }
    write_json(
        campaign / "campaign.json",
        {
            "campaign_id": identity,
            "started_at": started,
            "source_revision": revision,
            "protocol": rules,
            "inputs": inputs,
            "status": "inconclusive",
            "release_ready": False,
        },
    )
    for name, rows in (
        ("train", train),
        ("validation", validation),
        ("probes", probes),
        ("triggered", triggered),
    ):
        write_json(campaign / f"{name}.json", rows)
    records, controls = [], {}
    count = len(probes)
    for case in matrix():
        record, scores = execute(
            root,
            campaign / case["id"],
            case,
            train,
            validation,
            (probes, triggered),
            profile,
            image,
        )
        if case["family"] == "clean":
            controls[case["seed"]] = scores
        reference = controls[case["seed"]]
        position = count if case["family"] == "backdoor" else 0
        record["metrics"] = compare(
            probes,
            reference[:count],
            scores[:count],
            reference[position : position + count],
            scores[position : position + count],
        )
        write_json(campaign / case["id"] / "result.json", record)
        records.append(record)
        print(
            canonical(
                {
                    "case": case["id"],
                    "completed": len(records),
                    "total": 35,
                    "status": record["metrics"]["status"],
                }
            ).decode(),
            file=sys.stderr,
            flush=True,
        )
    if (
        source_fingerprint(root) != fingerprint
        or host_source(root) != scripts
        or command(["git", "-C", str(root), "rev-parse", "HEAD"]) != revision
        or digest(bounded_read(root / "data.lock")) != inputs["data_lock"]
    ):
        raise Rejected("poisoning_sources_changed_during_campaign")
    summary = summarize(records)
    result = {
        "schema_version": 1,
        "scope": "native-poisoning-matrix-component-not-full-M08",
        **summary,
        "execution_status": "complete",
        "release_ready": False,
        "full_M08": "inconclusive",
        "campaign_id": identity,
        "started_at": started,
        "finished_at": now(),
        "source_revision": revision,
        "source_dirty": bool(command(["git", "-C", str(root), "status", "--porcelain"])),
        "protocol": rules,
        "input_digests": inputs,
        "cases": records,
        "limitations": [
            "Only the frozen synthetic families and budgets, not universal poisoning detection",
            "Per-scenario conditional entity intervals; no independent seeds or simultaneous matrix confidence",
            "Research controller knows synthetic labels; offline workers lack evaluation labels and authority",
            "Dedicated research probes, not production holdout approval or a reset of its SQL budget",
            "No independent reviewer challenges, M22 matrix or complete M08 acceptance binding yet",
            "Passing scenarios can mean ineffective attacks, not proof that a detector blocked them",
        ],
    }
    write_json(campaign / "report.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Frozen 30+5 synthetic train-only poisoning research"
    )
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    parser.add_argument("--output", type=Path, default=Path(".runtime/evidence/poisoning.json"))
    parser.add_argument("--image", default="trusted-mlsecops:dev")
    arguments = parser.parse_args()
    write_json(
        arguments.output, {"status": "inconclusive", "started_at": now(), "release_ready": False}
    )
    try:
        result = qualify(Path(__file__).resolve().parents[1], arguments.state, arguments.image)
    except (Rejected, OSError) as error:
        write_json(
            arguments.output, {"status": "fail", "reason": str(error), "release_ready": False}
        )
        print(f"Poisoning campaign rejected: {error}", file=sys.stderr)
        return 1
    write_json(arguments.output, result)
    print(
        canonical(
            {
                name: result[name]
                for name in (
                    "status",
                    "scope",
                    "training_runs",
                    "poisoned_runs",
                    "clean_controls",
                    "violating_scenarios",
                    "inconclusive_scenarios",
                    "release_ready",
                )
            }
        ).decode()
    )
    return {"pass": 0, "fail": 1, "inconclusive": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
