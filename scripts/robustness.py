import copy
import itertools

import numpy as np

from mlsecops.contracts import Rejected
from mlsecops.datasets import FEATURES, validate_features, validate_rows
from mlsecops.prediction_protocol import validate_scores


def policy():
    return {
        "schema_version": 1,
        "profile": "synthetic-evasion-lab-v1",
        "training_seed": 17,
        "probe_seed": 73041,
        "probe_rows": 3000,
        "probe_entity_offset": 2000000,
        "mutable_features": ["change_size", "change_entropy"],
        "linf_budget": 0.05,
        "l1_budget": 0.10,
        "additional_queries_per_row": 4,
        "attack": "four-box-corners-retain-clean-if-better",
        "target_label": 0,
        "threshold": 0.5,
        "maximum_recall_drop": 0.05,
        "minimum_positives": 200,
        "authority": "research-only-no-release-no-final-holdout-query",
        "abstain": "outside-synthetic-support-no-statistical-novelty-claim",
    }


def verify_changes(original, changed):
    validate_features(original)
    validate_features(changed)
    if len(original) != len(changed):
        raise Rejected("evasion_row_count")
    rules = policy()
    mutable = {FEATURES.index(name) for name in rules["mutable_features"]}
    for before, after in zip(original, changed, strict=True):
        distances = [abs(new - old) for old, new in zip(before, after, strict=True)]
        if (
            any(distances[index] != 0 for index in range(len(FEATURES)) if index not in mutable)
            or max(distances) > rules["linf_budget"] + 1e-12
            or sum(distances) > rules["l1_budget"] + 1e-12
        ):
            raise Rejected("evasion_budget_or_immutable_feature")


def corners(features):
    validate_features(features)
    rules = policy()
    positions = [FEATURES.index(name) for name in rules["mutable_features"]]
    variants = []
    for directions in itertools.product((-1, 1), repeat=len(positions)):
        changed = copy.deepcopy(features)
        for row in changed:
            for index, direction in zip(positions, directions, strict=True):
                row[index] = min(1.0, max(0.0, row[index] + direction * rules["linf_budget"]))
        verify_changes(features, changed)
        variants.append(changed)
    return variants


def select(features, clean_scores, corner_scores):
    best = validate_scores(clean_scores, len(features)).tolist()
    if not isinstance(corner_scores, list) or len(corner_scores) != 4:
        raise Rejected("evasion_incomplete_queries")
    chosen = copy.deepcopy(features)
    for changed, scores in zip(corners(features), corner_scores, strict=True):
        checked = validate_scores(scores, len(features))
        for index, score in enumerate(checked):
            if score < best[index]:
                best[index], chosen[index] = float(score), changed[index]
    verify_changes(features, chosen)
    return {"features": chosen, "scores": best, "corner_scores": copy.deepcopy(corner_scores)}


def attack(features, clean_scores, predictor):
    validate_scores(clean_scores, len(features))
    outputs = []
    for changed in corners(features):
        outputs.append(validate_scores(predictor(changed), len(features)).tolist())
    return select(features, clean_scores, outputs)


def compare(records, clean_scores, attacked_scores):
    validate_rows(records)
    clean = validate_scores(clean_scores, len(records))
    attacked = validate_scores(attacked_scores, len(records))
    if (attacked > clean).any():
        raise Rejected("evasion_target_direction")
    rules = policy()
    positive = np.asarray([record["label"] == 1 for record in records])
    positives = int(positive.sum())
    clean_true = int(np.sum(positive & (clean >= rules["threshold"])))
    attacked_true = int(np.sum(positive & (attacked >= rules["threshold"])))
    lost = clean_true - attacked_true
    sufficient = len(records) == rules["probe_rows"] and positives >= rules["minimum_positives"]
    return {
        "status": "inconclusive"
        if not sufficient
        else "pass"
        if lost * 20 <= positives
        else "fail",
        "rows": len(records),
        "positives": positives,
        "clean_true_positives": clean_true,
        "attacked_true_positives": attacked_true,
        "lost_true_positives": lost,
        "clean_recall": clean_true / positives if positives else None,
        "attacked_recall": attacked_true / positives if positives else None,
        "recall_drop": lost / positives if positives else None,
        "conditional_attack_success": lost / clean_true if clean_true else None,
        "maximum_recall_drop": rules["maximum_recall_drop"],
    }


def outside_support():
    rows = []
    for index in range(len(FEATURES)):
        for value in (-0.01, 1.01):
            row = [0.5] * len(FEATURES)
            row[index] = value
            rows.append(row)
    return rows
