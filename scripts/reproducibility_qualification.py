import copy

from mlsecops.contracts import Rejected, canonical, digest
from scripts.reproducibility import compare


def fixture():
    vectors = [[0.1, 0.3, 0.8] for _ in range(3)]
    records = [
        {
            "run_id": str(index + 1) * 32,
            "inputs": {
                "request": "a" * 64,
                "dataset": "b" * 64,
                "policy": "c" * 64,
                "source": "d" * 64,
                "environment": "e" * 64,
                "golden": "f" * 64,
            },
            "model_digest": str(index + 1) * 64,
            "vector_digest": digest(canonical(vectors[index])),
            "auprc": 0.9,
        }
        for index in range(3)
    ]
    return records, vectors


def qualify():
    cases = []
    records, vectors = fixture()
    result = compare(records, vectors)
    if result["status"] != "pass" or result["max_probability_difference"] != 0:
        raise Rejected("reproducibility_positive_failed")
    cases.append("same-inputs-distinct-runs-and-artifact-hashes")
    for name, mutate in (
        ("missing-run", lambda runs, scores: runs.pop()),
        ("reused-run", lambda runs, scores: runs[2].update(run_id=runs[0]["run_id"])),
        ("bad-run-id", lambda runs, scores: runs[2].update(run_id="invalid")),
        ("missing-input", lambda runs, scores: runs[2]["inputs"].pop("request")),
        ("inputs-not-object", lambda runs, scores: runs[2].update(inputs=list(runs[2]["inputs"]))),
        ("unknown-input", lambda runs, scores: runs[2]["inputs"].update(unknown="a" * 64)),
        ("bad-digest", lambda runs, scores: runs[2]["inputs"].update(request="invalid")),
        ("changed-seed-request", lambda runs, scores: runs[2]["inputs"].update(request="b" * 64)),
        ("changed-data", lambda runs, scores: runs[2]["inputs"].update(dataset="a" * 64)),
        (
            "changed-environment",
            lambda runs, scores: runs[2]["inputs"].update(environment="a" * 64),
        ),
        ("changed-policy", lambda runs, scores: runs[2]["inputs"].update(policy="a" * 64)),
        ("changed-golden", lambda runs, scores: runs[2]["inputs"].update(golden="a" * 64)),
        ("bad-model-hash", lambda runs, scores: runs[2].update(model_digest="bad")),
        ("bad-vector-hash", lambda runs, scores: runs[2].update(vector_digest="a" * 64)),
        ("missing-vector", lambda runs, scores: scores.pop()),
        ("empty-vector", lambda runs, scores: scores[2].clear()),
        ("short-vector", lambda runs, scores: scores[2].pop()),
        ("nan-score", lambda runs, scores: scores[2].__setitem__(0, float("nan"))),
        ("boolean-score", lambda runs, scores: scores[2].__setitem__(0, True)),
        ("negative-score", lambda runs, scores: scores[2].__setitem__(0, -0.1)),
        ("score-over-one", lambda runs, scores: scores[2].__setitem__(0, 1.1)),
        ("huge-integer-score", lambda runs, scores: scores[2].__setitem__(0, 10**400)),
        ("nan-auprc", lambda runs, scores: runs[2].update(auprc=float("nan"))),
        ("boolean-auprc", lambda runs, scores: runs[2].update(auprc=True)),
        ("auprc-difference", lambda runs, scores: runs[2].update(auprc=0.89)),
        ("missing-field", lambda runs, scores: runs[2].pop("auprc")),
    ):
        invalid, scores = copy.deepcopy(records), copy.deepcopy(vectors)
        mutate(invalid, scores)
        try:
            compare(invalid, scores)
        except Rejected:
            cases.append(name)
        else:
            raise Rejected("reproducibility_bypass:" + name)
    invalid, scores = fixture()
    scores[2].pop()
    invalid[2]["vector_digest"] = digest(canonical(scores[2]))
    try:
        compare(invalid, scores)
    except Rejected:
        cases.append("valid-hash-but-short-vector")
    else:
        raise Rejected("reproducibility_short_vector_accepted")
    try:
        compare([None, None, None], vectors)
    except Rejected:
        cases.append("malformed-record-type")
    else:
        raise Rejected("reproducibility_invalid_record_accepted")
    invalid, scores = fixture()
    invalid[2]["inputs"] = None
    try:
        compare(invalid, scores)
    except Rejected:
        cases.append("null-inputs-rejected")
    else:
        raise Rejected("reproducibility_null_inputs_accepted")
    invalid, scores = fixture()
    scores[2][0] += 0.001
    invalid[2]["vector_digest"] = digest(canonical(scores[2]))
    try:
        compare(invalid, scores)
    except Rejected:
        cases.append("matching-hash-but-numerical-drift")
    else:
        raise Rejected("reproducibility_numerical_drift_accepted")
    for shift, rejected in ((9e-7, True), (2e-7, False)):
        invalid, scores = fixture()
        scores[1][0] += shift
        scores[2][0] -= shift
        for record, vector in zip(invalid, scores, strict=True):
            record["vector_digest"] = digest(canonical(vector))
        try:
            result = compare(invalid, scores)
        except Rejected as error:
            if not rejected or str(error) != "reproducibility_numeric_tolerance_failed":
                raise
        else:
            if rejected:
                raise Rejected("reproducibility_pairwise_drift_accepted")
            if result["max_probability_difference"] != scores[1][0] - scores[2][0]:
                raise Rejected("reproducibility_pairwise_difference_incorrect")
        cases.append("pairwise-drift-rejected" if rejected else "pairwise-within-tolerance")
    return {
        "status": "pass",
        "scope": "reproducibility-comparison-contracts",
        "checks": len(cases),
        "cases": cases,
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
