import unittest

from mlsecops.contracts import canonical
from scripts.evaluation_contracts import Result
from scripts.evaluation_contracts import case_ids as suite_ids

MODULES = (
    "scripts.artifact_intake_qualification",
    "scripts.intake_denial_qualification",
    "scripts.model_contract_qualification",
    "scripts.kube_intake_contracts",
)
SCOPE = "controlled-intake-contracts-real-parser-and-paths-not-native-isolation"


def case_ids():
    return suite_ids(unittest.defaultTestLoader.loadTestsFromNames(MODULES))


def qualify():
    suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
    expected = case_ids()
    result = Result()
    suite.run(result)
    complete = (
        result.wasSuccessful()
        and not result.skipped
        and not result.expectedFailures
        and len(expected) >= 66
        and result.testsRun == len(expected) == len(result.passed)
        and set(result.passed) == expected
    )
    return {
        "status": "pass" if complete else "fail",
        "scope": SCOPE,
        "checks": len(result.passed),
        "cases": [{"id": name, "status": "pass"} for name in sorted(result.passed)],
    }


if __name__ == "__main__":
    report = qualify()
    print(canonical(report).decode())
    raise SystemExit(0 if report["status"] == "pass" else 1)
