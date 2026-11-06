"""Bounded in-process aggregation from verified immutable serving context.

The HTTP owner must call add only after an actual successful response. This
module does not authenticate network observations or persist raw features.
"""

import math
import re
import threading
from bisect import bisect_right
from dataclasses import dataclass

from mlsecops import advisory, monitoring, serving_context
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.datasets import FEATURES

CUTS = tuple(index / 10 for index in range(11))


def observation_id(request_id, row):
    if type(request_id) is not str or re.fullmatch(r"[a-f0-9]{32}", request_id) is None:
        raise Rejected("monitor_request_id")
    monitoring.integer(row, 0, 99)
    return digest(canonical([request_id, row]))


def bucket(value):
    return 10 if value == 1 else bisect_right(CUTS, value)


def prediction(row, value):
    require_fields(value, ("decision", "reason", "score"))
    supported = all(0 <= item <= 1 for item in row)
    if not supported:
        if value != {"decision": "abstain", "reason": "outside-support", "score": None}:
            raise Rejected("monitor_abstention_invalid")
        return None
    score = value["score"]
    if (
        value["decision"] != "score"
        or value["reason"] is not None
        or type(score) not in (int, float)
        or not 0 <= score <= 1
        or not math.isfinite(score)
    ):
        raise Rejected("monitor_score_invalid")
    return score


@dataclass(frozen=True, slots=True, repr=False)
class ClosedWindow:
    content: bytes
    predictions: tuple[tuple[str, bool], ...]

    def document(self):
        return decode(self.content)

    @property
    def sha256(self):
        return digest(self.content)


class Accumulator:
    def __init__(self, reference, expected_sha256, *, started_at_ms):
        monitoring.validate_reference(reference)
        content = canonical(reference)
        if digest(content) != monitoring.sha256(expected_sha256):
            raise Rejected("monitor_reference_binding")
        monitoring.integer(started_at_ms, reference["frozen_at_ms"], 2**53 - 1)
        self._reference, self._reference_sha256 = decode(content), expected_sha256
        self._started = started_at_ms
        self._lock = threading.Lock()
        self._histograms = {key: [0] * monitoring.BINS for key in monitoring.SERIES}
        self._abstentions = 0
        self._requests, self._predictions = set(), []
        self._closed = None

    def add(self, context, features, predictions, request_id):
        if type(context) not in (serving_context.ReleaseTrace, serving_context.QualificationTrace):
            raise Rejected("monitor_context_type")
        actual = {
            "model_sha256": context.model_sha256,
            "bundle_sha256": context.bundle_sha256,
            "dataset_sha256": context.lineage.dataset_sha256,
            "evaluation_sha256": context.lineage.evaluation_sha256,
            "source_fingerprint": context.lineage.source_fingerprint,
        }
        if any(actual[key] != self._reference[key] for key in monitoring.REFERENCES):
            raise Rejected("monitor_context_binding")
        advisory.validate(features)
        if type(predictions) is not list or len(predictions) != len(features):
            raise Rejected("monitor_predictions_shape")
        prepared = []
        for index, (row, decision) in enumerate(zip(features, predictions, strict=True)):
            identifier = observation_id(request_id, index)
            score = prediction(row, decision)
            prepared.append((identifier, tuple(bucket(value) for value in row), score))
        with self._lock:
            if self._closed is not None:
                raise Rejected("monitor_window_closed")
            if request_id in self._requests:
                raise Rejected("monitor_request_duplicate")
            if len(self._predictions) + len(prepared) > monitoring.MAX_OBSERVATIONS:
                raise Rejected("monitor_capacity")
            for identifier, bins, score in prepared:
                for key, index in zip(FEATURES, bins, strict=True):
                    self._histograms[key][index] += 1
                if score is None:
                    self._abstentions += 1
                else:
                    self._histograms["prediction"][bucket(score)] += 1
                self._predictions.append((identifier, score is not None and score >= 0.5))
            self._requests.add(request_id)

    def close(self, *, sequence, ended_at_ms):
        monitoring.integer(sequence, 1, 2**53 - 1)
        monitoring.integer(ended_at_ms, 1, 2**53 - 1)
        if not 0 < ended_at_ms - self._started <= 60000:
            raise Rejected("monitor_window_duration")
        with self._lock:
            if self._closed is not None:
                old = self._closed.document()
                if (sequence, ended_at_ms) != (old["sequence"], old["ended_at_ms"]):
                    raise Rejected("monitor_close_conflict")
                return self._closed
            document = {
                "schema_version": 1,
                "reference_sha256": self._reference_sha256,
                "prediction_ledger_sha256": digest(canonical(self._predictions)),
                "sequence": sequence,
                "started_at_ms": self._started,
                "ended_at_ms": ended_at_ms,
                "observations": len(self._predictions),
                "abstentions": self._abstentions,
                "histograms": self._histograms,
            }
            self._closed = ClosedWindow(canonical(document), tuple(self._predictions))
            return self._closed
