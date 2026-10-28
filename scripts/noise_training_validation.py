"""Fixed train/validation experiment. No frozen probes, model loading or services."""

import argparse
import copy
import importlib.metadata
import json
import platform
import uuid
from decimal import Decimal
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from mlsecops import noise_training
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, now, write_json
from mlsecops.data_source import generated, validate_lock
from mlsecops.datasets import arrays
from scripts import poisoning, robustness

SEEDS = (619, 631)
MATERIALS = (
    "mlsecops/noise_training.py",
    "scripts/noise_training_validation.py",
    "scripts/poisoning.py",
    "scripts/robustness.py",
    "mlsecops/robust_training.py",
    "data.lock",
)


def decide(baseline, clean, evasion, poisoned):
    if len(poisoned) != 4 or any(
        r["status"] not in ("pass", "fail", "inconclusive") for r in [evasion, *poisoned]
    ):
        raise Rejected("noise_validation_incomplete_result")
    statuses = [r["status"] for r in [evasion, *poisoned]]
    if (
        clean["auprc"] < 0.80
        or clean["auprc_gain"] < 0.10
        or Decimal(str(baseline["auprc"])) - Decimal(str(clean["auprc"])) > Decimal("0.03")
    ):
        statuses.append("fail")
    if clean["positives"] < 200:
        statuses.append("inconclusive")
    return (
        "fail" if "fail" in statuses else "inconclusive" if "inconclusive" in statuses else "pass"
    )


def quality(labels, scores):
    ap = float(average_precision_score(labels, scores))
    positive = labels == 1
    negative = labels == 0
    return {
        "rows": len(labels),
        "positives": int(positive.sum()),
        "auprc": ap,
        "auprc_gain": ap - float(labels.mean()),
        "recall": float((scores[positive] >= 0.5).mean()),
        "false_positive_rate": float((scores[negative] >= 0.5).mean()),
        "brier_score": float(np.mean((scores - labels) ** 2)),
    }


def run(root, *, balanced=False):
    root = Path(root).resolve()
    training = noise_training.definition(balanced)
    lock = validate_lock(root)
    content = generated(root)
    if {"sha256": digest(content), "bytes": len(content)} != lock["output"]:
        raise Rejected("noise_validation_source_binding")
    rows = decode(content)
    train, validation = rows[:14000], rows[14000:17000]
    del rows, content
    if len(train) != 14000 or len(validation) != 3000:
        raise Rejected("noise_validation_split")
    source = {name: digest(bounded_read(root / name)) for name in MATERIALS}
    campaign = root / ".runtime/noise-validation" / uuid.uuid4().hex
    campaign.mkdir(parents=True, exist_ok=False)
    report = {
        "scope": "train-validation-development-not-acceptance",
        "started_at": now(),
        "status": "inconclusive",
        "release_ready": False,
        "training": training,
        "development_seeds": list(SEEDS),
        "inputs": {
            "source": source,
            "train": digest(canonical(train)),
            "validation": digest(canonical(validation)),
            "data_output": lock["output"],
        },
        "environment": {
            "system": platform.system(),
            "python": platform.python_version(),
            **{
                name: importlib.metadata.version(name)
                for name in ("numpy", "scipy", "scikit-learn")
            },
        },
        "arms": {},
    }
    write_json(campaign / "report.json", report)
    validation_features, labels = arrays(validation)
    features = [row["features"] for row in validation]
    triggers = [row["features"] for row in poisoning.trigger(validation)]
    cases = [("clean", train)]
    for seed in SEEDS:
        for family in ("label-flip", "backdoor"):
            altered, receipt = poisoning.poison(train, family, 700, seed)
            name = f"{family}-{seed}"
            cases.append((name, altered))
            write_json(campaign / f"{name}-mutation.json", receipt)
    for arm in ("baseline", "candidate"):
        results, controls = {}, None
        for name, records in cases:
            x, y = arrays(records)
            model = make_pipeline(
                StandardScaler(), LogisticRegression(random_state=17, max_iter=300)
            )
            model.fit(x, y)
            optimization = (
                noise_training.refit(model, x, y, balanced=balanced) if arm == "candidate" else None
            )
            scores = model.predict_proba(validation_features)[:, 1]
            trigger_scores = model.predict_proba(np.asarray(triggers, dtype=np.float32))[:, 1]
            result = {"quality": quality(labels, scores), "optimization": optimization}
            private = {
                "scores": scores.tolist(),
                "trigger_scores": trigger_scores.tolist(),
                "training_digest": digest(canonical(records)),
                "scaler_mean": model.steps[0][1].mean_.tolist(),
                "scaler_scale": model.steps[0][1].scale_.tolist(),
                "coefficients": model.steps[-1][1].coef_.tolist(),
                "intercept": model.steps[-1][1].intercept_.tolist(),
            }
            if name == "clean":
                controls = (scores, trigger_scores)
                corners = [
                    model.predict_proba(np.asarray(v, dtype=np.float32))[:, 1].tolist()
                    for v in robustness.corners(features)
                ]
                selected = robustness.select(features, scores.tolist(), corners)
                result["evasion"] = robustness.compare(
                    validation, scores.tolist(), selected["scores"]
                )
                private["corner_scores"] = corners
            else:
                matched = 1 if name.startswith("backdoor") else 0
                result["poisoning"] = poisoning.compare(
                    validation,
                    controls[0].tolist(),
                    scores.tolist(),
                    controls[matched].tolist(),
                    (trigger_scores if matched else scores).tolist(),
                )
            write_json(campaign / f"{arm}-{name}.json", private)
            result["primary_digest"] = digest(bounded_read(campaign / f"{arm}-{name}.json"))
            results[name] = result
        report["arms"][arm] = results
    if source != {name: digest(bounded_read(root / name)) for name in MATERIALS} or canonical(
        validate_lock(root)
    ) != canonical(lock):
        raise Rejected("noise_validation_materials_changed")
    baseline, candidate = report["arms"]["baseline"], report["arms"]["candidate"]
    report.update(
        status=decide(
            baseline["clean"]["quality"],
            candidate["clean"]["quality"],
            candidate["clean"]["evasion"],
            [r["poisoning"] for n, r in candidate.items() if n != "clean"],
        ),
        finished_at=now(),
        fits=10,
        adoption="not-adopted",
    )
    write_json(campaign / "report.json", report)
    name = "noise-validation-balanced.json" if balanced else "noise-validation.json"
    write_json(root / ".runtime/evidence" / name, report)
    return copy.deepcopy(report)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--balanced", action="store_true")
    result = run(Path(__file__).resolve().parents[1], balanced=parser.parse_args().balanced)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit({"pass": 0, "fail": 1, "inconclusive": 2}[result["status"]])
