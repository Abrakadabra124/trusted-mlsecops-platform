"""Deterministic lab statistics, not an authenticated collector or alert sender.

Inputs must be authenticated by the operator boundary before evaluation. One
serialized evaluator belongs to one immutable reference and ordered stream.
"""

import math
import re

from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.datasets import FEATURES

PROFILE = "synthetic-local-cpu-v1"
SERIES = (*FEATURES, "prediction")
MAX_OBSERVATIONS = 20000
MIN_OBSERVATIONS = 1000
MIN_POSITIVES = 200
PSI_THRESHOLD = 0.2
BINS = 12  # underflow, ten fixed intervals over [0, 1], overflow
PSEUDOCOUNT = 0.5
REFERENCES = (
    "model_sha256",
    "bundle_sha256",
    "dataset_sha256",
    "evaluation_sha256",
    "source_fingerprint",
)
COUNTS = ("observations", "abstentions", "histograms")


def integer(value, minimum=0, maximum=MAX_OBSERVATIONS):
    if type(value) is not int or not minimum <= value <= maximum:
        raise Rejected("monitor_integer_invalid")
    return value


def sha256(value):
    if type(value) is not str or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise Rejected("monitor_digest_invalid")
    return value


def schema(document, fields):
    require_fields(document, ("schema_version", *fields))
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise Rejected("monitor_schema_invalid")


def histogram(values):
    if type(values) is not list or len(values) != BINS:
        raise Rejected("monitor_histogram_shape")
    return integer(sum(integer(value) for value in values))


def counts(document, *, minimum=0):
    total = integer(document["observations"], minimum)
    abstentions = integer(document["abstentions"], maximum=total)
    require_fields(document["histograms"], SERIES)
    for key, values in document["histograms"].items():
        expected = total - abstentions if key == "prediction" else total
        if histogram(values) != expected:
            raise Rejected("monitor_count_mismatch")
        if key == "prediction" and (values[0] or values[-1]):
            raise Rejected("monitor_prediction_outside_support")
    return total, abstentions


def validate_reference(document):
    schema(
        document,
        ("profile", *REFERENCES, "frozen_at_ms", *COUNTS, "positive_labels", "true_positives"),
    )
    if document["profile"] != PROFILE:
        raise Rejected("monitor_profile_invalid")
    for field in REFERENCES:
        sha256(document[field])
    integer(document["frozen_at_ms"], 1, 2**53 - 1)
    total, abstentions = counts(document, minimum=MIN_OBSERVATIONS)
    if abstentions:
        raise Rejected("monitor_reference_abstentions")
    positives = integer(document["positive_labels"], MIN_POSITIVES, total)
    integer(document["true_positives"], maximum=positives)


def psi(expected, observed):
    totals = [histogram(values) for values in (expected, observed)]
    if not all(totals):
        raise Rejected("monitor_empty_histogram")
    distributions = [
        [(count + PSEUDOCOUNT) / (total + BINS * PSEUDOCOUNT) for count in values]
        for values, total in zip((expected, observed), totals, strict=True)
    ]
    return math.fsum((b - a) * math.log(b / a) for a, b in zip(*distributions, strict=True))


def quality(reference_true, reference_positive, current_true, current_positive):
    """None means insufficient labels; True means a strictly >0.05 recall drop.

    Counts are trusted aggregates of matched labels, not user-supplied proof.
    Integer cross-products avoid accepting an exact 0.05 drop due to rounding.
    """
    integer(reference_positive, MIN_POSITIVES)
    integer(reference_true, maximum=reference_positive)
    integer(current_positive)
    integer(current_true, maximum=current_positive)
    if current_positive < MIN_POSITIVES:
        return None
    difference = reference_true * current_positive - current_true * reference_positive
    return 20 * difference > reference_positive * current_positive


class Evaluator:
    def __init__(self, reference, expected_sha256):
        validate_reference(reference)
        content = canonical(reference)
        if digest(content) != sha256(expected_sha256):
            raise Rejected("monitor_reference_binding")
        self._reference = decode(content)
        self._reference_sha256 = expected_sha256
        self._sequence = 0
        self._ended = reference["frozen_at_ms"]
        self._streak = dict.fromkeys(SERIES, 0)
        self._last = None

    def evaluate(self, document):
        schema(document, ("reference_sha256", "sequence", "started_at_ms", "ended_at_ms", *COUNTS))
        if sha256(document["reference_sha256"]) != self._reference_sha256:
            raise Rejected("monitor_window_binding")
        sequence = integer(document["sequence"], 1, 2**53 - 1)
        started = integer(document["started_at_ms"], 1, 2**53 - 1)
        ended = integer(document["ended_at_ms"], 1, 2**53 - 1)
        if not 0 < ended - started <= 60000:
            raise Rejected("monitor_window_duration")
        if started < self._reference["frozen_at_ms"]:
            raise Rejected("monitor_window_before_reference")
        total, abstentions = counts(document)
        reference = digest(canonical(document))
        if sequence < self._sequence:
            raise Rejected("monitor_window_replay")
        if sequence == self._sequence:
            if reference != self._last["window_sha256"]:
                raise Rejected("monitor_window_conflict")
            return decode(canonical(self._last))
        if started < self._ended:
            raise Rejected("monitor_window_overlap")
        gap = sequence != self._sequence + 1 or (self._sequence > 0 and started != self._ended)
        streak, values = {}, {}
        for key in SERIES:
            sufficient = (total - abstentions if key == "prediction" else total) >= MIN_OBSERVATIONS
            value = (
                psi(self._reference["histograms"][key], document["histograms"][key])
                if sufficient
                else None
            )
            values[key] = value
            previous = 0 if gap else self._streak[key]
            streak[key] = (
                min(2, previous + 1) if value is not None and value >= PSI_THRESHOLD else 0
            )
        drifting = [key for key in FEATURES if streak[key] >= 2]
        alerts = ["telemetry_gap"] if gap else []
        if drifting:
            alerts.append("data_drift")
        if streak["prediction"] >= 2:
            alerts.append("prediction_drift")
        result = {
            "schema_version": 1,
            "reference_sha256": self._reference_sha256,
            "window_sha256": reference,
            "sequence": sequence,
            "status": "observed" if total >= MIN_OBSERVATIONS else "insufficient",
            "prediction_status": "observed"
            if total - abstentions >= MIN_OBSERVATIONS
            else "insufficient",
            "observations": total,
            "abstentions": abstentions,
            "psi": values,
            "alerts": alerts,
            "drift_features": drifting,
            "release_ready": False,
        }
        self._sequence, self._ended, self._streak, self._last = sequence, ended, streak, result
        return decode(canonical(result))
