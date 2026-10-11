import numpy as np
from sklearn.metrics import average_precision_score

from mlsecops.contracts import Rejected, canonical, digest, require_fields
from mlsecops.datasets import FEATURES, validate_features
from mlsecops.prediction_protocol import validate_scores

SUMMARY_FIELDS = (
    "rows",
    "positives",
    "auprc",
    "dummy_auprc",
    "auprc_gain",
    "slices",
    "quality_component",
    "quality_reasons",
    "confidence_intervals",
    "evaluation_policy",
    "evaluation_policy_digest",
)


def definition():
    return {
        "schema_version": 1,
        "profile": "synthetic-release-lab-v1",
        "metric": "sklearn-average-precision-not-trapezoidal-pr-area",
        "baseline": "constant-score-equivalent-to-DummyClassifier-prior-for-AP",
        "minimum_auprc": 0.8,
        "minimum_auprc_gain": 0.1,
        "minimum_positives": 200,
        "minimum_slice_rows": 100,
        "threshold": 0.5,
        "slice_feature": "change_size",
        "slice_boundary": 0.5,
        "slices": ["low-change", "high-change"],
        "label_maturity": "synthetic-immediate-only-no-business-horizon",
        "method": "paired-iid-percentile",
        "confidence_level": 0.95,
        "resamples": 1000,
        "seed": 73021,
        "interval_use": "diagnostic-only-not-pilot-utility-approval",
    }


def freeze(profile):
    required = {
        "environment": "local-cpu",
        "source": "synthetic-release-lab-v1",
        "label_horizon": "synthetic-only-no-business-horizon",
        "features": list(FEATURES),
        **{
            name: definition()[name]
            for name in (
                "minimum_auprc",
                "minimum_auprc_gain",
                "minimum_positives",
                "minimum_slice_rows",
            )
        },
    }
    if not isinstance(profile, dict) or canonical(
        {name: profile.get(name) for name in required}
    ) != canonical(required):
        raise Rejected("evaluation_profile_not_frozen_lab")
    return definition()


def validate_rules(rules):
    if canonical(rules) != canonical(definition()):
        raise Rejected("evaluation_rules_changed")


def unavailable_intervals(reason):
    return {
        "status": "inconclusive",
        "reason": reason,
        "valid_resamples": 0,
        "undefined_resamples": 0,
        "auprc": None,
        "auprc_gain": None,
    }


def intervals(labels, scores, rules):
    validate_rules(rules)
    random = np.random.default_rng(rules["seed"])
    values = []
    undefined = 0
    for _ in range(rules["resamples"]):
        selected = random.integers(0, len(labels), size=len(labels))
        sampled = labels[selected]
        if not 0 < sampled.sum() < len(sampled):
            undefined += 1
            continue
        precision = float(average_precision_score(sampled, scores[selected]))
        values.append((precision, precision - float(sampled.mean())))
    result = {
        "method": rules["method"],
        "confidence_level": rules["confidence_level"],
        "seed": rules["seed"],
        "requested_resamples": rules["resamples"],
        **unavailable_intervals("undefined_bootstrap_replicates"),
        "valid_resamples": len(values),
        "undefined_resamples": undefined,
    }
    if not undefined:
        bounds = np.quantile(values, [0.025, 0.975], axis=0, method="linear")
        result.update(
            status="computed",
            reason=None,
            auprc=bounds[:, 0].tolist(),
            auprc_gain=bounds[:, 1].tolist(),
        )
    return result


def decide(rows, positives, slices, auprc, gain, rules):
    reasons = []
    if positives < rules["minimum_positives"]:
        reasons.append("insufficient_positive_labels")
    if not 0 < positives < rows:
        reasons.append("single_class_holdout")
    for name in rules["slices"]:
        if slices[name]["rows"] < rules["minimum_slice_rows"]:
            reasons.append(f"insufficient_slice_rows:{name}")
        if not slices[name]["positives"]:
            reasons.append(f"undefined_slice_recall:{name}")
    if reasons:
        return "inconclusive", reasons
    if auprc < rules["minimum_auprc"]:
        reasons.append("auprc_below_minimum")
    if gain < rules["minimum_auprc_gain"]:
        reasons.append("baseline_gain_below_minimum")
    return ("fail" if reasons else "pass"), reasons


def summarize(holdout, scores, rules):
    validate_rules(rules)
    if not isinstance(holdout, list) or any(
        not isinstance(row, dict) or "features" not in row or "label" not in row for row in holdout
    ):
        raise Rejected("evaluation_rows_invalid")
    validate_features([row["features"] for row in holdout])
    if any(type(row["label"]) is not int or row["label"] not in (0, 1) for row in holdout):
        raise Rejected("evaluation_label_invalid")
    probabilities = validate_scores(scores, len(holdout))
    labels = np.array([row["label"] for row in holdout], dtype=np.int64)
    positives = int(labels.sum())
    both_classes = 0 < positives < len(labels)
    slices = {}
    feature_index = FEATURES.index(rules["slice_feature"])
    low = np.array([row["features"][feature_index] for row in holdout]) < rules["slice_boundary"]
    for name, selected in zip(rules["slices"], (low, ~low), strict=True):
        count = int(selected.sum())
        actual = int(labels[selected].sum())
        predicted = probabilities[selected] >= rules["threshold"]
        true_positives = int(np.logical_and(labels[selected] == 1, predicted).sum())
        slices[name] = {
            "rows": count,
            "positives": actual,
            "predicted_positives": int(predicted.sum()),
            "true_positives": true_positives,
            "recall": true_positives / actual if actual else None,
            "precision": true_positives / int(predicted.sum()) if predicted.any() else None,
        }
    auprc = float(average_precision_score(labels, probabilities)) if both_classes else None
    baseline = float(labels.mean())
    gain = auprc - baseline if auprc is not None else None
    status, reasons = decide(len(holdout), positives, slices, auprc, gain, rules)
    confidence = (
        unavailable_intervals("insufficient_holdout_evidence")
        if status == "inconclusive"
        else intervals(labels, probabilities, rules)
    )
    return {
        "rows": len(holdout),
        "positives": positives,
        "auprc": auprc,
        "dummy_auprc": baseline,
        "auprc_gain": gain,
        "slices": slices,
        "quality_component": status,
        "quality_reasons": reasons,
        "confidence_intervals": confidence,
        "evaluation_policy": definition(),
        "evaluation_policy_digest": digest(canonical(rules)),
    }


def number(value, lower=0, upper=1):
    return type(value) in (float, int) and lower <= value <= upper


def validate_summary(summary):
    require_fields(summary, SUMMARY_FIELDS)
    rules = summary["evaluation_policy"]
    validate_rules(rules)
    if summary["evaluation_policy_digest"] != digest(canonical(rules)):
        raise Rejected("evaluation_policy_digest_mismatch")
    rows, positives = summary["rows"], summary["positives"]
    if (
        type(rows) is not int
        or not 1 <= rows <= 20000
        or type(positives) is not int
        or not 0 <= positives <= rows
    ):
        raise Rejected("evaluation_counts_invalid")
    baseline = summary["dummy_auprc"]
    auprc, gain = summary["auprc"], summary["auprc_gain"]
    if not number(baseline) or abs(baseline - positives / rows) > 1e-12:
        raise Rejected("evaluation_baseline_mismatch")
    if 0 < positives < rows:
        if not number(auprc) or not number(gain, -1) or abs(auprc - baseline - gain) > 1e-12:
            raise Rejected("evaluation_metric_mismatch")
    elif auprc is not None or gain is not None:
        raise Rejected("evaluation_undefined_metric")
    slices = summary["slices"]
    require_fields(slices, rules["slices"])
    for values in slices.values():
        require_fields(
            values,
            ("rows", "positives", "predicted_positives", "true_positives", "recall", "precision"),
        )
        if (
            any(
                type(values[name]) is not int or not 0 <= values[name] <= rows
                for name in ("rows", "positives", "predicted_positives", "true_positives")
            )
            or max(values["positives"], values["predicted_positives"]) > values["rows"]
            or values["true_positives"] > min(values["positives"], values["predicted_positives"])
        ):
            raise Rejected("evaluation_slice_counts_invalid")
        for metric, denominator in (("recall", "positives"), ("precision", "predicted_positives")):
            if (values[denominator] == 0 and values[metric] is not None) or (
                values[denominator] > 0 and not number(values[metric])
            ):
                raise Rejected("evaluation_slice_metric_invalid")
            if (
                values[denominator]
                and abs(values[metric] - values["true_positives"] / values[denominator]) > 1e-12
            ):
                raise Rejected("evaluation_slice_ratio_mismatch")
    if (
        sum(value["rows"] for value in slices.values()) != rows
        or sum(value["positives"] for value in slices.values()) != positives
    ):
        raise Rejected("evaluation_slice_totals_mismatch")
    status, reasons = decide(rows, positives, slices, auprc, gain, rules)
    if summary["quality_component"] != status or summary["quality_reasons"] != reasons:
        raise Rejected("evaluation_decision_mismatch")
    confidence = summary["confidence_intervals"]
    if status == "inconclusive":
        if canonical(confidence) != canonical(
            unavailable_intervals("insufficient_holdout_evidence")
        ):
            raise Rejected("evaluation_insufficient_confidence")
        return
    require_fields(
        confidence,
        (
            "method",
            "confidence_level",
            "seed",
            "requested_resamples",
            "status",
            "reason",
            "valid_resamples",
            "undefined_resamples",
            "auprc",
            "auprc_gain",
        ),
    )
    if (
        canonical({name: confidence[name] for name in ("method", "confidence_level", "seed")})
        != canonical({name: rules[name] for name in ("method", "confidence_level", "seed")})
        or type(confidence["requested_resamples"]) is not int
        or confidence["requested_resamples"] != rules["resamples"]
    ):
        raise Rejected("evaluation_confidence_policy_mismatch")
    if (
        any(
            type(confidence[name]) is not int or not 0 <= confidence[name] <= rules["resamples"]
            for name in ("valid_resamples", "undefined_resamples")
        )
        or confidence["valid_resamples"] + confidence["undefined_resamples"] != rules["resamples"]
    ):
        raise Rejected("evaluation_confidence_counts_invalid")
    if confidence["undefined_resamples"]:
        if (
            confidence["status"] != "inconclusive"
            or confidence["reason"] != "undefined_bootstrap_replicates"
            or confidence["auprc"] is not None
            or confidence["auprc_gain"] is not None
        ):
            raise Rejected("evaluation_undefined_confidence")
    else:
        if confidence["status"] != "computed" or confidence["reason"] is not None:
            raise Rejected("evaluation_confidence_status_invalid")
        for name, lower in (("auprc", 0), ("auprc_gain", -1)):
            bounds = confidence[name]
            if (
                not isinstance(bounds, list)
                or len(bounds) != 2
                or not all(number(value, lower) for value in bounds)
                or bounds[0] > bounds[1]
            ):
                raise Rejected("evaluation_confidence_bounds_invalid")
