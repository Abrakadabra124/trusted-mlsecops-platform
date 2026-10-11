import math
import re

from mlsecops.contracts import Rejected, canonical, digest

INPUTS = {"request", "dataset", "policy", "source", "environment", "golden"}


def probability(value):
    return type(value) in (int, float) and 0 <= value <= 1 and math.isfinite(value)


def validate_record(record, vector):
    if (
        type(record) is not dict
        or set(record) != {"run_id", "inputs", "model_digest", "vector_digest", "auprc"}
        or not isinstance(record["run_id"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", record["run_id"])
        or type(record["inputs"]) is not dict
        or set(record["inputs"]) != INPUTS
        or any(
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
            for value in [
                *record["inputs"].values(),
                record["model_digest"],
                record["vector_digest"],
            ]
        )
        or type(vector) is not list
        or not vector
        or not all(probability(value) for value in vector)
        or not probability(record["auprc"])
        or record["vector_digest"] != digest(canonical(vector))
    ):
        raise Rejected("reproducibility_record_invalid")


def compare(records, vectors):
    if (
        type(records) is not list
        or type(vectors) is not list
        or len(records) != 3
        or len(vectors) != 3
    ):
        raise Rejected("reproducibility_requires_three_runs")
    for record, vector in zip(records, vectors, strict=True):
        validate_record(record, vector)
    if len({record["run_id"] for record in records}) != 3:
        raise Rejected("reproducibility_run_reused")
    if len({digest(canonical(record["inputs"])) for record in records}) != 1:
        raise Rejected("reproducibility_inputs_changed")
    if len({len(vector) for vector in vectors}) != 1:
        raise Rejected("reproducibility_golden_length_changed")
    difference = max(max(column) - min(column) for column in zip(*vectors, strict=True))
    auprc_difference = max(record["auprc"] for record in records) - min(
        record["auprc"] for record in records
    )
    if difference > 1e-6 or auprc_difference > 1e-4:
        raise Rejected("reproducibility_numeric_tolerance_failed")
    return {
        "status": "pass",
        "fresh_runs": 3,
        "golden_rows": len(vectors[0]),
        "input_digest": digest(canonical(records[0]["inputs"])),
        "max_probability_difference": difference,
        "auprc_difference": auprc_difference,
        "artifact_hashes": [record["model_digest"] for record in records],
        "vector_hashes": [record["vector_digest"] for record in records],
    }
