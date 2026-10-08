import copy

from mlsecops.contracts import Rejected, canonical
from scripts.image_comparison import compare


def qualify():
    baseline = {
        "name": "worker",
        "scan_executed": True,
        "status": "fail",
        "packages": 100,
        "database": {"built": "current", "schema_version": "v6.1.10"},
        "findings": [
            {"id": "first", "package": "a", "installed": "1"},
            {"id": "second", "package": "b", "installed": "1"},
        ],
    }
    candidate = {
        **copy.deepcopy(baseline),
        "name": "worker-candidate",
        "packages": 90,
        "findings": [
            {"id": "second", "package": "b", "installed": "2"},
            {"id": "new", "package": "c", "installed": "1"},
        ],
    }
    storage = {**copy.deepcopy(baseline), "name": "storage"}
    storage_candidate = {**copy.deepcopy(storage), "name": "storage-candidate"}
    inputs = [baseline, candidate, storage, storage_candidate]
    result = compare(inputs)
    if (
        result["status"] != "pass"
        or result["release_ready"] is not False
        or result["worker"]["removed"] != [{"id": "first", "package": "a"}]
        or result["worker"]["introduced"] != [{"id": "new", "package": "c"}]
        or result["worker"]["remaining_pairs"] != 1
        or result["worker"]["candidate_status"] != "fail"
    ):
        raise Rejected("comparison_valid_delta_failed")
    cases = [{"id": "version-change-not-fake-remediation", "status": "pass"}]
    for name, mutate in (
        ("missing-candidate", lambda value: value.pop()),
        ("duplicate-component", lambda value: value.append(value[0])),
        ("unverified-scan", lambda value: value[1].update(scan_executed=False)),
        ("wrong-database", lambda value: value[1].update(database={"built": "other"})),
        ("missing-findings", lambda value: value[1].pop("findings")),
    ):
        invalid = copy.deepcopy(inputs)
        mutate(invalid)
        if compare(invalid)["status"] != "inconclusive":
            raise Rejected(f"comparison_invalid_accepted:{name}")
        cases.append({"id": name, "status": "pass"})
    return {
        "status": "pass",
        "scope": "image-comparison-contracts",
        "checks": len(cases),
        "cases": cases,
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
