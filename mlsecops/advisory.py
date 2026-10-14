import math

from mlsecops.contracts import Rejected
from mlsecops.datasets import FEATURES
from mlsecops.prediction_protocol import validate_scores


def validate(features):
    if not isinstance(features, list) or not 1 <= len(features) <= 100:
        raise Rejected("advisory_batch_limit")
    for row in features:
        if not isinstance(row, list) or len(row) != len(FEATURES):
            raise Rejected("advisory_feature_shape")
        try:
            finite = all(type(value) in (int, float) and math.isfinite(value) for value in row)
        except OverflowError:
            finite = False
        if not finite:
            raise Rejected("advisory_feature_type")


def decide(features, predictor):
    validate(features)
    supported, positions, decisions = [], [], []
    for index, row in enumerate(features):
        decisions.append({"decision": "abstain", "reason": "outside-support", "score": None})
        if all(0 <= value <= 1 for value in row):
            supported.append(list(row))
            positions.append(index)
    if supported:
        scores = validate_scores(predictor(supported), len(supported))
        for index, score in zip(positions, scores.tolist(), strict=True):
            decisions[index] = {"decision": "score", "reason": None, "score": score}
    return decisions
