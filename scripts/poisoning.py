import copy
from statistics import NormalDist

import numpy as np
from sklearn.metrics import average_precision_score

from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.datasets import validate_rows
from mlsecops.prediction_protocol import validate_scores


def policy():
    return {
        "schema_version": 1,
        "profile": "synthetic-poisoning-lab-v1",
        "families": ["label-flip", "backdoor"],
        "seeds": [17, 29, 43, 71, 101],
        "train_rows": 14000,
        "budgets": [70, 140, 700],
        "fractions": [0.005, 0.01, 0.05],
        "probe_seed": 73031,
        "probe_rows": 3000,
        "probe_entity_offset": 1000000,
        "target_label": 0,
        "source_label": 1,
        "selection": "uniform-positive-train-without-replacement",
        "trigger": {"feature": "change_entropy", "index": 4, "value": 1.0},
        "threshold": 0.5,
        "maximum_auprc_drop": 0.03,
        "maximum_asr_increase_upper": 0.10,
        "minimum_eligible": 500,
        "bootstrap": {
            "method": "paired-iid-percentile",
            "resamples": 2000,
            "seed": 73037,
            "level": 0.95,
        },
        "decision_upper": "max-paired-bootstrap-and-wilson-on-clean-correct-eligible-probes",
        "independent_unit": "synthetic-entity-conditional-on-one-trained-pair",
        "multiple_testing": "per-scenario-no-simultaneous-matrix-guarantee-no-seed-pooling",
        "authority": "research-only-no-release-no-final-holdout-query",
    }


def matrix():
    rules = policy()
    cases = []
    for seed in rules["seeds"]:
        cases.append({"id": f"clean-{seed}", "family": "clean", "seed": seed, "count": 0})
        for family in rules["families"]:
            for count in rules["budgets"]:
                cases.append(
                    {
                        "id": f"{family}-{count}-{seed}",
                        "family": family,
                        "seed": seed,
                        "count": count,
                    }
                )
    return cases


def trigger(records):
    validate_rows(records)
    altered = copy.deepcopy(records)
    definition = policy()["trigger"]
    for row in altered:
        row["features"][definition["index"]] = definition["value"]
    return altered


def poison(records, family, count, seed):
    validate_rows(records)
    if (
        family not in policy()["families"]
        or type(count) is not int
        or not 1 <= count <= len(records)
        or type(seed) is not int
        or not 0 <= seed < 2**32
    ):
        raise Rejected("poisoning_capability_invalid")
    eligible = [index for index, row in enumerate(records) if row["label"] == 1]
    if len(eligible) < count:
        raise Rejected("poisoning_insufficient_train_selection")
    selected = sorted(np.random.default_rng(seed).choice(eligible, count, replace=False).tolist())
    altered = copy.deepcopy(records)
    for index in selected:
        altered[index]["label"] = 0
        if family == "backdoor":
            definition = policy()["trigger"]
            altered[index]["features"][definition["index"]] = definition["value"]
    validate_rows(altered)
    return altered, {
        "family": family,
        "seed": seed,
        "changed_rows": count,
        "fraction": count / len(records),
        "train_rows": len(records),
        "changed_entity_ids": [records[index]["entity_id"] for index in selected],
        "before_digest": digest(canonical(records)),
        "after_digest": digest(canonical(altered)),
        "capability": "labels-only" if family == "label-flip" else "labels-and-change_entropy",
    }


def wilson(successes, count):
    value = successes / count
    quantile = NormalDist().inv_cdf(0.975)
    denominator = 1 + quantile**2 / count
    center = (value + quantile**2 / (2 * count)) / denominator
    radius = (
        quantile * ((value * (1 - value) + quantile**2 / (4 * count)) / count) ** 0.5 / denominator
    )
    return [max(0.0, center - radius), min(1.0, center + radius)]


def compare(records, clean_scores, attacked_scores, clean_probes, attacked_probes):
    validate_rows(records)
    vectors = [
        validate_scores(values, len(records))
        for values in (clean_scores, attacked_scores, clean_probes, attacked_probes)
    ]
    clean_scores, attacked_scores, clean_probes, attacked_probes = vectors
    rules = policy()
    labels = np.array([row["label"] for row in records], dtype=np.int64)
    if len(set(labels.tolist())) != 2:
        return {"status": "inconclusive", "reason": "single-class-security-evaluation"}
    baseline = float(average_precision_score(labels, clean_scores))
    attacked = float(average_precision_score(labels, attacked_scores))
    eligible = (labels == rules["source_label"]) & (clean_probes >= rules["threshold"])
    count = int(eligible.sum())
    result = {
        "status": "inconclusive",
        "clean_auprc": baseline,
        "attacked_auprc": attacked,
        "auprc_drop": baseline - attacked,
        "eligible_rows": count,
        "eligible_ids_digest": digest(
            canonical(
                [
                    row["entity_id"]
                    for row, selected in zip(records, eligible, strict=True)
                    if selected
                ]
            )
        ),
        "clean_asr": 0.0 if count else None,
        "attacked_asr": None,
        "asr_delta": None,
        "asr_delta_ci": None,
        "asr_wilson_ci": None,
        "decision_upper": None,
        "bootstrap_degenerate": None,
        "minimum_eligible": rules["minimum_eligible"],
        "bootstrap": rules["bootstrap"],
        "reason": "insufficient-eligible-probes",
    }
    if count >= rules["minimum_eligible"]:
        control_errors = (clean_probes[eligible] < rules["threshold"]).astype(float)
        errors = (attacked_probes[eligible] < rules["threshold"]).astype(float)
        paired = errors - control_errors
        generator = np.random.default_rng(rules["bootstrap"]["seed"])
        sampled = [
            float(paired[generator.integers(0, count, count)].mean())
            for _ in range(rules["bootstrap"]["resamples"])
        ]
        interval = np.quantile(sampled, [0.025, 0.975], method="linear").tolist()
        wilson_interval = wilson(int(errors.sum()), count)
        upper = max(interval[1], wilson_interval[1])
        result.update(
            status="pass",
            reason=None,
            attacked_asr=float(errors.mean()),
            asr_delta=float(paired.mean()),
            asr_delta_ci=interval,
            asr_wilson_ci=wilson_interval,
            decision_upper=upper,
            bootstrap_degenerate=min(sampled) == max(sampled),
        )
        if upper > rules["maximum_asr_increase_upper"]:
            result.update(status="fail", reason="targeted-asr-upper-bound")
    if result["auprc_drop"] > rules["maximum_auprc_drop"]:
        result.update(status="fail", reason="clean-auprc-drop")
    return result
