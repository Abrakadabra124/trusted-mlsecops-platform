import unittest

from mlsecops.contracts import canonical

MODULES = (
    "scripts.evaluation_quality_qualification",
    "scripts.evaluation_binding_qualification",
    "scripts.holdout_budget_qualification",
)
SCOPE = "controlled-evaluation-contracts-including-real-host-fit-not-native-isolation"


def case_ids(suite=None):
    if suite is None:
        suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
    names = set()
    for test in suite:
        names.update(case_ids(test) if isinstance(test, unittest.TestSuite) else {test.id()})
    return names


class Result(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.passed = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed.append(test.id())


def qualify():
    suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
    expected = suite.countTestCases()
    result = Result()
    suite.run(result)
    complete = (
        result.wasSuccessful()
        and not result.skipped
        and not result.expectedFailures
        and expected >= 48
        and expected == result.testsRun == len(set(result.passed))
    )
    return {
        "status": "pass" if complete else "fail",
        "scope": SCOPE,
        "checks": expected,
        "cases": [{"id": name, "status": "pass"} for name in result.passed],
    }


if __name__ == "__main__":
    report = qualify()
    print(canonical(report).decode())
    raise SystemExit(0 if report["status"] == "pass" else 1)
