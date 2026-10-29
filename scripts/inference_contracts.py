"""Complete controlled M12 suite, with no skipped tests accepted as evidence."""

import ast
import unittest
from pathlib import Path

from mlsecops.contracts import canonical
from scripts.evaluation_contracts import Result

MODULES = (
    "scripts.serving_startup_qualification",
    "scripts.candidate_serving_reader_qualification",
    "scripts.serving_core_qualification",
    "scripts.serving_runtime_qualification",
    "scripts.serving_http_qualification",
    "scripts.kube_attach_qualification",
    "scripts.kube_serving_runtime_qualification",
    "scripts.kube_candidate_qualification",
)
SCOPE = "controlled-M12-reader-loader-http-contracts"


def case_ids(root=None):
    root = Path(root or Path(__file__).resolve().parents[1])
    return {
        f"{module}.{cls.name}.{method.name}"
        for module in MODULES
        for cls in ast.parse(
            (root / (module.replace(".", "/") + ".py")).read_text(encoding="utf-8")
        ).body
        if isinstance(cls, ast.ClassDef)
        for method in cls.body
        if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
        and method.name.startswith("test_")
    }


def qualify():
    expected = case_ids()
    result = Result()
    unittest.defaultTestLoader.loadTestsFromNames(MODULES).run(result)
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
