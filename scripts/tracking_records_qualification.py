import copy

from mlsecops.contracts import Rejected, canonical, digest
from scripts.tracking_records import export_records


def qualify():
    policy = {"training_seed": 17, "data_seed": 24017, "repeat_tolerance": 1e-6}
    run = {
        "run_id": "a" * 32,
        "dataset_id": "b" * 64,
        "input_digest": "c" * 64,
        "policy_digest": digest(canonical(policy)),
        "source_fingerprint": "d" * 64,
        "source_revision": "e" * 40,
        "image_id": "sha256:" + "f" * 64,
        "model_digest": "1" * 64,
        "validation_probability_digest": "2" * 64,
        "validation_parity_max_error": 0.0,
        "materials": {"train.json": {"sha256": "3" * 64}},
        "versions": {"numpy": "2.5.3"},
        "status": "unapproved-candidate",
        "private": "must-not-leave-host",
    }
    report = {
        "status": "pass",
        "source_fingerprint": run["source_fingerprint"],
        "dataset_id": run["dataset_id"],
        "policy_digest": run["policy_digest"],
        "metrics": {"fresh_runs": 3, "max_probability_difference": 0.0, "auprc": [0.9] * 3},
        "runs": [{**copy.deepcopy(run), "run_id": digit * 32} for digit in "abc"],
    }
    cases = []
    exported = export_records(report, policy)
    if len(exported) != 3 or b"must-not-leave-host" in canonical(exported):
        raise Rejected("tracking_projection_leaks_or_loses_runs")
    cases.append({"id": "three-independent-redacted-records", "status": "pass"})
    scenarios = {
        "failed-source": lambda value: value.update(status="fail"),
        "missing-run": lambda value: value["runs"].pop(),
        "reused-run": lambda value: value["runs"][1].update(run_id="a" * 32),
        "seed-or-data-input-changed": lambda value: value["runs"][1].update(input_digest="4" * 64),
        "image-environment-changed": lambda value: value["runs"][1].update(
            image_id="sha256:" + "4" * 64
        ),
        "versions-changed": lambda value: value["runs"][1].update(versions={"numpy": "different"}),
        "materials-changed": lambda value: value["runs"][1].update(materials={}),
        "foreign-dataset": lambda value: value["runs"][1].update(dataset_id="4" * 64),
        "foreign-source": lambda value: value["runs"][1].update(source_fingerprint="4" * 64),
        "foreign-policy": lambda value: value["runs"][1].update(policy_digest="4" * 64),
        "mutable-image": lambda value: value["runs"][1].update(image_id="latest"),
        "bad-run-id": lambda value: value["runs"][1].update(run_id="../bad"),
        "bad-digest": lambda value: value["runs"][1].update(model_digest=True),
        "release-claim": lambda value: value["runs"][1].update(status="approved"),
        "missing-field": lambda value: value["runs"][1].pop("model_digest"),
        "invalid-runs": lambda value: value.update(runs=None),
        "invalid-report": lambda value: value.clear(),
        "boolean-run-count": lambda value: value["metrics"].update(fresh_runs=True),
        "probability-drift": lambda value: value["metrics"].update(max_probability_difference=0.01),
        "nan-drift": lambda value: value["metrics"].update(max_probability_difference=float("nan")),
        "negative-drift": lambda value: value["metrics"].update(max_probability_difference=-1),
        "metric-missing": lambda value: value["metrics"].update(auprc=[]),
        "metric-boolean": lambda value: value["metrics"].update(auprc=[True, 0.9, 0.9]),
        "metric-outside-range": lambda value: value["metrics"].update(auprc=[1.1] * 3),
        "quality-drift": lambda value: value["metrics"].update(auprc=[0.8, 0.9, 0.9]),
        "parity-nan": lambda value: value["runs"][1].update(
            validation_parity_max_error=float("nan")
        ),
    }
    for name, mutate in scenarios.items():
        invalid = copy.deepcopy(report)
        mutate(invalid)
        try:
            export_records(invalid, policy)
        except Rejected:
            cases.append({"id": name, "status": "pass"})
        else:
            raise Rejected("tracking_projection_bypass:" + name)
    return {
        "status": "pass",
        "scope": "tracking-projection-contracts",
        "checks": len(cases),
        "cases": cases,
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
