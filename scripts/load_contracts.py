"""Fresh controlled M14 contracts; skips and missing methods never count as passes."""

import contextlib
import io
import unittest

from mlsecops.contracts import canonical
from scripts.evaluation_contracts import Result
from scripts.evaluation_contracts import case_ids as loaded_ids

MODULES = (
    "scripts.load_golden_qualification",
    "scripts.load_measurement_qualification",
    "scripts.load_clock_qualification",
    "scripts.load_exchange_qualification",
    "scripts.load_probe_qualification",
    "scripts.load_diagnostics_qualification",
    "scripts.load_resources_qualification",
    "scripts.kube_load_operator_qualification",
    "scripts.kube_load_native_qualification",
    "scripts.trust_session_qualification",
    "scripts.serving_http_qualification",
    "scripts.serving_http_audit_qualification",
)
SCOPE = "controlled-M14-load-contracts"


def case_ids():
    return loaded_ids(unittest.defaultTestLoader.loadTestsFromNames(MODULES))


def qualify():
    suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
    expected = loaded_ids(suite)
    result = Result()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
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
        "scope": SCOPE,
        "status": "pass" if complete else "fail",
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
