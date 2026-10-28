"""Frozen M22 absolute-count protocol; independent challenges remain mandatory."""

from scripts import poisoning, poisoning_native


def policy():
    return {
        **{k: v for k, v in poisoning.policy().items() if k not in ("train_rows", "fractions")},
        "profile": "synthetic-absolute-poisoning-lab-v1",
        "train_sizes": [2000, 14000],
        "budgets": [1, 5, 25],
        "seeds": [17, 29, 43],
        "subset": "first-N-rows-of-locked-train",
        "authority": "M22-component-no-independent-challenges-no-release",
    }


def matrix():
    rules = policy()
    cases = []
    for size in rules["train_sizes"]:
        for seed in rules["seeds"]:
            for family, count in [
                ("clean", 0),
                *[(f, n) for f in rules["families"] for n in rules["budgets"]],
            ]:
                cases.append(
                    {
                        "id": f"{size}-{family}-{count}-{seed}",
                        "train_rows": size,
                        "family": family,
                        "count": count,
                        "seed": seed,
                    }
                )
    return cases


def summarize(records):
    return poisoning_native.summarize(records, expected_cases=matrix())


def full_status(summary):
    return "fail" if summary["status"] == "fail" else "inconclusive"
