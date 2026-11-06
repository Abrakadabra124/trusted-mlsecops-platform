"""Current controlled M11 contracts; skipped and expected-failing tests are not passes."""

import unittest

from mlsecops.contracts import canonical
from scripts.evaluation_contracts import Result
from scripts.evaluation_contracts import case_ids as loaded_ids

MODULES = (
    "scripts.trust_qualification",
    "scripts.trust_authority_qualification",
    "scripts.release_reader_qualification",
    "scripts.release_authorization_qualification",
    "scripts.rollback_authorization_qualification",
    "scripts.rollback_admission_qualification",
    "scripts.release_key_rotation_qualification",
    "scripts.release_key_store_qualification",
    "scripts.trust_rotation_qualification",
    "scripts.trust_root_store_qualification",
    "scripts.serving_core_qualification",
)
SCOPE = "controlled-M11-contracts"


def case_ids():
    return loaded_ids(unittest.defaultTestLoader.loadTestsFromNames(MODULES))


def qualify():
    suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
    expected = loaded_ids(suite)
    result = Result()
    suite.run(result)
    complete = (
        bool(expected)
        and result.wasSuccessful()
        and not result.skipped
        and not result.expectedFailures
        and result.testsRun == len(expected) == len(result.passed)
        and set(result.passed) == expected
    )
    return {
        "status": "pass" if complete else "fail",
        "scope": SCOPE,
        "checks": len(result.passed),
        "cases": [
            {"id": name, "status": "pass", "expected": True, "actual": True}
            for name in sorted(result.passed)
        ],
    }


if __name__ == "__main__":
    report = qualify()
    print(canonical(report).decode())
    raise SystemExit(0 if report["status"] == "pass" else 1)
