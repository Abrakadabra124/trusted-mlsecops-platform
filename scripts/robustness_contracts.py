"""Run real format/parser fixtures outside the gate controller process."""

import ast
import unittest
from pathlib import Path

from mlsecops.contracts import canonical
from scripts.evaluation_contracts import Result

MODULES = (
    "scripts.model_contract_qualification",
    "scripts.robustness_qualification",
    "scripts.robustness_native_qualification",
)
SCOPE = "controlled-M09-format-and-evasion-contracts"


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
    suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
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
        "cases": [{"id": name, "status": "pass"} for name in sorted(result.passed)],
    }


if __name__ == "__main__":
    result = qualify()
    print(canonical(result).decode())
    raise SystemExit(0 if result["status"] == "pass" else 1)
