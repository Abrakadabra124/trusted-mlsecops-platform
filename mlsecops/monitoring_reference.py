"""Freeze a monitoring reference from verified release materials and validation.

The caller owns the isolated prediction worker and separately authorizes access
to the validation split. This builder never reads holdout or authorizes release.
"""

import time

from mlsecops import (
    audit_lineage,
    datasets,
    monitoring,
    monitoring_stream,
    release_bundle,
    release_policy,
    signing,
)
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.prediction_protocol import PredictionBatch


def build(
    package,
    *,
    context,
    publisher_public,
    expected_serving_image,
    validation_content,
    run_worker,
    signing_key,
    clock=lambda: time.time_ns() // 1000000,
):
    started = monitoring.integer(clock(), 1, 2**53 - 1)
    verified = release_bundle.verify(
        package,
        context=context,
        publisher_public=publisher_public,
        expected_serving_image=expected_serving_image,
        clock=started // 1000,
    )
    public = signing.encode64(signing.load_key(signing_key).public_key().public_bytes_raw())
    if public in (publisher_public, context["trust"]["curator"], context["trust"]["evaluator"]):
        raise Rejected("monitor_reference_roles")
    lineage = audit_lineage.from_verified_package(
        package, verified["manifest"], context["trust"]["curator"]
    )
    descriptor = decode(package["documents"]["split_manifest"])["objects"]["validation.json"]
    if (
        type(validation_content) is not bytes
        or len(validation_content) > 16 * 1024 * 1024
        or len(validation_content) != descriptor["bytes"]
        or digest(validation_content) != descriptor["sha256"]
    ):
        raise Rejected("monitor_validation_binding")
    rows = decode(validation_content)
    datasets.validate_rows(rows, descriptor["rows"])
    if canonical(rows) != validation_content:
        raise Rejected("monitor_validation_noncanonical")
    observations = monitoring.integer(len(rows), monitoring.MIN_OBSERVATIONS)
    positives = monitoring.integer(
        sum(row["label"] for row in rows), monitoring.MIN_POSITIVES, observations
    )
    reference = {
        "schema_version": 1,
        "profile": monitoring.PROFILE,
        "model_sha256": digest(verified["model"]),
        "bundle_sha256": verified["subject_sha256"],
        "dataset_sha256": lineage.dataset_sha256,
        "evaluation_sha256": lineage.evaluation_sha256,
        "source_fingerprint": lineage.source_fingerprint,
        "observations": observations,
        "abstentions": 0,
        "positive_labels": positives,
    }
    # Copy pins before invoking a separately owned worker; it cannot alter the verified package snapshot.
    manifest = decode(canonical(verified["manifest"]))
    batch = PredictionBatch(verified["model"], [row["features"] for row in rows])
    scores, _scan, receipt = batch.consume(run_worker(batch.request))
    histograms = {key: [0] * monitoring.BINS for key in monitoring.SERIES}
    true_positives = 0
    for row, score in zip(rows, scores.tolist(), strict=True):
        for name, value in zip(datasets.FEATURES, row["features"], strict=True):
            histograms[name][monitoring_stream.bucket(value)] += 1
        histograms["prediction"][monitoring_stream.bucket(score)] += 1
        true_positives += int(row["label"] == 1 and score >= 0.5)
    finished = monitoring.integer(clock(), started, 2**53 - 1)
    release_policy.window(manifest, finished // 1000)
    reference.update(frozen_at_ms=finished, histograms=histograms, true_positives=true_positives)
    monitoring.validate_reference(reference)
    return {
        "envelope": signing.sign(reference, "monitor-reference", signing_key),
        "evidence": {
            "schema_version": 1,
            "reference_sha256": digest(canonical(reference)),
            "validation_sha256": descriptor["sha256"],
            "validation_bytes": len(validation_content),
            "split": "validation",
            "prediction_receipt": receipt,
            "release_ready": False,
        },
    }
