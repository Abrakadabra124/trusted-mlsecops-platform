"""Machine-readable execution of the existing controlled poisoning contracts."""

import unittest

from mlsecops.contracts import canonical
from scripts.evaluation_contracts import Result, case_ids

MODULES = (
    "scripts.poisoning_qualification",
    "scripts.poisoning_native_qualification",
    "scripts.poisoning_evidence_qualification",
)
SCOPE = "controlled-poisoning-contracts-not-native-isolation"


def qualify():
    suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
    expected = case_ids(suite)
    result = Result()
    suite.run(result)
    complete = (
        len(expected) >= 29
        and result.wasSuccessful()
        and not result.skipped
        and not result.expectedFailures
        and result.testsRun == len(expected)
        and set(result.passed) == expected
    )
    return {
        "status": "pass" if complete else "fail",
        "scope": SCOPE,
        "checks": result.testsRun,
        "cases": [{"id": name, "status": "pass"} for name in sorted(result.passed)],
    }


if __name__ == "__main__":
    report = qualify()
    print(canonical(report).decode())
    raise SystemExit(0 if report["status"] == "pass" else 1)
