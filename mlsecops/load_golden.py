"""Pinned one-row request and strict response binding for synthetic M14 runs."""

import math
import re
from dataclasses import dataclass

from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.datasets import FEATURES


@dataclass(frozen=True)
class Golden:
    body: bytes
    model: str
    bundle: str
    score: float

    def __post_init__(self):
        if (
            type(self.body) is not bytes
            or not 0 < len(self.body) <= 65536
            or any(
                type(value) is not str or re.fullmatch("[a-f0-9]{64}", value) is None
                for value in (self.model, self.bundle)
            )
            or type(self.score) not in (int, float)
            or not math.isfinite(self.score)
            or not 0 <= self.score <= 1
        ):
            raise Rejected("load_golden_contract")
        payload = decode(self.body, 65536)
        require_fields(payload, ("schema_version", "instances"))
        if (
            type(payload["schema_version"]) is not int
            or payload["schema_version"] != 1
            or type(payload["instances"]) is not list
            or len(payload["instances"]) != 1
        ):
            raise Rejected("load_golden_body")
        row = payload["instances"][0]
        require_fields(row, FEATURES)
        if any(
            type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1
            for value in row.values()
        ):
            raise Rejected("load_golden_body")

    @classmethod
    def from_expected(cls, expected):
        # Pick the first independently obtained reference row, never an arbitrary
        # caller-provided URL, body, model alias or a score from the load run itself.
        if (
            type(expected) is not dict
            or not {"features", "scores", "model", "bundle"} <= expected.keys()
        ):
            raise Rejected("load_golden_reference")
        features, scores = expected["features"], expected["scores"]
        if (
            type(features) is not list
            or not features
            or type(scores) is not list
            or len(features) != len(scores)
            or type(features[0]) is not list
            or len(features[0]) != len(FEATURES)
            or any(
                type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1
                for value in features[0]
            )
        ):
            raise Rejected("load_golden_reference")
        body = canonical(
            {"schema_version": 1, "instances": [dict(zip(FEATURES, features[0], strict=True))]}
        )
        return cls(body, expected["model"], expected["bundle"], scores[0])

    def valid(self, response):
        try:
            require_fields(
                response,
                ("schema_version", "model_sha256", "bundle_sha256", "predictions", "request_id"),
            )
            predictions = response["predictions"]
            if (
                type(response["schema_version"]) is not int
                or response["schema_version"] != 1
                or response["model_sha256"] != self.model
                or response["bundle_sha256"] != self.bundle
                or type(response["request_id"]) is not str
                or re.fullmatch("[a-f0-9]{32}", response["request_id"]) is None
                or type(predictions) is not list
                or len(predictions) != 1
            ):
                return False
            prediction = predictions[0]
            require_fields(prediction, ("score", "decision", "reason"))
            score = prediction["score"]
            return (
                prediction["decision"] == "score"
                and prediction["reason"] is None
                and type(score) in (int, float)
                and math.isfinite(score)
                and 0 <= score <= 1
                and abs(score - self.score) <= 1e-6
            )
        except (Rejected, TypeError, OverflowError):
            return False

    def binding(self):
        return {
            "payload_sha256": digest(self.body),
            "model_sha256": self.model,
            "bundle_sha256": self.bundle,
            "rows_per_request": 1,
            "absolute_score_tolerance": 1e-6,
        }
