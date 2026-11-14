"""Recompute a pinned native M06 packet from retained bytes after service teardown."""

from mlsecops import reproducibility_gate
from mlsecops.contracts import canonical, decode, digest
from mlsecops.datasets import verify_manifest
from mlsecops.final_evidence import need, same, timestamp
from mlsecops.prediction_protocol import response, validate_scan
from mlsecops.signing import encode64
from scripts.poisoning_evidence import execution
from scripts.reproducibility_native import record_from

NAMES = reproducibility_gate.NAMES
SIGNED_CASE = "signed-candidate-three-fresh-repeats"
CASE_IDS = sorted(
    [
        *("materials:" + name for name in NAMES),
        *("tracking-read-back:" + name for name in NAMES),
        *("mutation:" + name for name in NAMES[3:]),
        "fresh-process-runs",
        "common-golden-rows",
        "three-run-numeric-repeat",
        SIGNED_CASE,
    ]
)


def prediction(proof, model, holdout, scores, scan):
    batch_id = proof["batch_id"]
    request = dict(
        schema_version=2,
        action="predict",
        model=encode64(model),
        features=[r["features"] for r in holdout],
        batch_id=batch_id,
        row_ids=[f"{batch_id}:{i}" for i in range(len(holdout))],
    )
    validate_scan(scan)
    output = response(request, scores, scan)
    same(
        proof,
        dict(
            schema_version=2,
            batch_id=batch_id,
            model_digest=digest(model),
            request_digest=output["request_digest"],
            response_digest=digest(canonical(output)),
            rows=len(holdout),
        ),
        "repeat-prediction",
    )


def verify(report, packet, obj, values):
    refs = report["artifact_hashes"]
    native = decode(obj(refs["native_campaign"]))
    policy = decode(obj(values["policy"]))
    same(native["image_id"], values["image_id"], "repeat-image")
    same(native["source_dirty"], False, "repeat-source")
    same(native["campaign_id"], packet["campaign_id"], "repeat-campaign")
    completed = timestamp(native["completed_at"])
    need(
        timestamp(report["started_at"])
        <= completed
        <= timestamp(packet["finished_at"])
        <= timestamp(report["finished_at"]),
        "repeat-time",
    )
    records = native["records"]
    for field in ("predictions", "tracking_readbacks", "records"):
        need(isinstance(native[field], list) and len(native[field]) == 6, "repeat-inventory")
    datasets = {r["inputs"]["dataset"] for r in records}
    need(len(datasets) == 3 and datasets == native["local_manifests"].keys(), "repeat-datasets")
    for record, allowed in zip(
        records[3:],
        ({"request", "dataset", "policy"}, {"request", "dataset"}, {"environment"}),
        strict=True,
    ):
        changed = {k for k, v in record["inputs"].items() if v != records[0]["inputs"][k]}
        need(changed == allowed, "repeat-mutation-inputs")
    batches = [p["protocol"]["batch_id"] for p in native["predictions"]]
    need(len(set([*batches, values["prediction_protocol"]["batch_id"]])) == 7, "repeat-batches")
    splits_by_id = {}
    vectors = []

    def load(index, record, current_policy):
        name = NAMES[index]
        raw_metadata = obj(refs["metadata:" + name])
        meta = decode(raw_metadata)
        model = obj(refs["model:" + name])
        vector = decode(obj(refs["vector:" + name]))
        dataset = record["inputs"]["dataset"]
        manifest = verify_manifest(
            native["local_manifests"][dataset],
            dataset,
            current_policy,
            native["source_approval"],
            native["curator"],
            moment=completed,
        )
        same(
            [meta["model_digest"], meta["dataset_id"], meta["policy_digest"], meta["run_id"]],
            [digest(model), dataset, digest(canonical(current_policy)), record["run_id"]],
            "repeat-run",
        )
        need(0 < len(model) <= current_policy["model_limit_bytes"], "repeat-model-size")
        if index != 4:
            same(manifest["objects"], values["split_materials"], "repeat-signed-splits")
        if dataset not in splits_by_id:
            splits = {}
            for file, item in manifest["objects"].items():
                raw = obj(item["sha256"])
                rows = decode(raw)
                same([len(raw), len(rows)], [item["bytes"], item["rows"]], "repeat-split-size")
                splits[file.removesuffix(".json")] = rows
            splits_by_id[dataset] = splits
        splits = splits_by_id[dataset]
        observed = native["predictions"][index]
        execution(meta["execution"], meta["image_id"])
        execution(observed["execution"], meta["image_id"])
        prediction(observed["protocol"], model, splits["holdout"], vector, observed["scan"])
        vectors.append(vector)
        return meta, model, splits, manifest, vector, digest(raw_metadata)

    def tracking(index, receipt, exported):
        same(
            native["tracking_readbacks"][index],
            dict(
                run_id=receipt["run_id"],
                source_run_id=exported["source_run_id"],
                params=exported["params"],
                metrics=exported["metrics"],
                artifact=exported,
            ),
            "repeat-tracking-readback",
        )

    result = reproducibility_gate.reconcile_materials(
        native, policy, values["source_revision"], values["source_fingerprint"], load, tracking
    )
    replay = decode(obj(refs["candidate_replay"]))
    holdout = splits_by_id[records[0]["inputs"]["dataset"]]["holdout"]
    scores = replay["scores"]
    execution(replay["execution"], values["image_id"])
    same(replay["protocol"], values["prediction_protocol"], "repeat-signed-protocol")
    prediction(replay["protocol"], obj(values["model"]), holdout, scores, values["evaluation_scan"])
    meta = decode(obj(values["evaluation_artifacts"]["metadata"]))
    actual = record_from(meta, holdout, scores, native["baseline_environment"])
    same(
        [actual["model_digest"], actual["inputs"]["dataset"]],
        [values["model"], values["dataset"]],
        "repeat-signed-identity",
    )
    same(replay["candidate"], actual, "repeat-signed-record")
    same(actual["auprc"], values["evaluation_auprc"], "repeat-signed-auprc")
    same(replay["split_materials"], values["split_materials"], "repeat-signed-splits")
    run_ids = [r["run_id"] for r in records]
    same(replay["reference_runs"], run_ids[:3], "repeat-references")
    need(actual["run_id"] not in run_ids, "repeat-candidate-reused")
    expected_inputs = {**actual["inputs"], "dataset": records[0]["inputs"]["dataset"]}
    same(records[0]["inputs"], expected_inputs, "repeat-signed-inputs")
    probability = max(abs(a - b) for v in vectors[:3] for a, b in zip(scores, v, strict=True))
    auprc = max(abs(actual["auprc"] - r["auprc"]) for r in records[:3])
    need(probability <= 1e-6 and auprc <= 1e-4, "repeat-candidate-tolerance")
    metrics = {
        **result["metrics"],
        "candidate_probability_difference": probability,
        "candidate_auprc_difference": auprc,
    }
    cases = [
        *result["cases"],
        dict(
            id=SIGNED_CASE,
            status="pass",
            expected=dict(probability_max=1e-6, auprc_max=1e-4),
            actual=dict(probability=probability, auprc=auprc),
        ),
    ]
    same(sorted(c["id"] for c in cases), CASE_IDS, "repeat-case-inventory")
    same(packet["cases"], cases, "repeat-cases")
    same(packet["checks"], len(cases), "repeat-checks")
    same(packet["metrics"], metrics, "repeat-primary-metrics")
    same(report["metrics"], dict(checks=len(cases), **metrics), "repeat-report-metrics")
    inputs = {
        **result["input_digests"],
        **{
            k: values[k]
            for k in (
                "candidate_reference",
                "evaluation_reference",
                "dataset_reference",
                "model_digest",
                "candidate_training_input",
                "frozen_demo",
            )
        },
        "host_scripts": values["reproducibility_host_scripts"],
    }
    same(packet["input_digests"], inputs, "repeat-primary-inputs")
    same(
        report["input_digests"],
        dict(source_fingerprint=values["source_fingerprint"], **inputs),
        "repeat-report-inputs",
    )
    artifacts = {**result["artifact_hashes"], "candidate_replay": refs["candidate_replay"]}
    same(packet["artifact_hashes"], artifacts, "repeat-primary-artifacts")
    same(
        refs,
        dict(reproducibility_qualification=refs["reproducibility_qualification"], **artifacts),
        "repeat-report-artifacts",
    )
    for key in ("scope", "release_ready", "source_dirty"):
        same(packet[key], result[key], "repeat-primary-scope")
