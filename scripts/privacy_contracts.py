"""Fixed current M13 contracts; a skipped method never supplies acceptance evidence."""

import ast
import contextlib
import io
import unittest
from pathlib import Path

from mlsecops.contracts import canonical
from scripts.evaluation_contracts import Result

MODULES = (
    "scripts.serving_http_qualification",
    "scripts.serving_http_audit_qualification",
    "scripts.serving_audit_qualification",
    "scripts.serving_context_qualification",
    "scripts.serving_privacy_qualification",
    "scripts.serving_metrics_qualification",
    "scripts.serving_metrics_probe_qualification",
    "scripts.serving_output_qualification",
    "scripts.serving_output_native_qualification",
    "scripts.audit_event_qualification",
    "scripts.audit_retention_qualification",
    "scripts.audit_admission_qualification",
    "scripts.audit_snapshot_qualification",
    "scripts.audit_packet_io_qualification",
    "scripts.audit_http_observation_qualification",
    "scripts.audit_export_qualification",
    "scripts.audit_export_probe_qualification",
    "scripts.audit_correlation_qualification",
    "scripts.audit_correlation_probe_qualification",
    "scripts.audit_evidence_qualification",
    "scripts.audit_evidence_parent_qualification",
    "scripts.privacy_evidence_qualification",
    "scripts.process_privacy_qualification",
    "scripts.worker_privacy_qualification",
    "scripts.controller_privacy_qualification",
    "scripts.worker_transport_privacy_qualification",
    "scripts.kube_privacy_logs_qualification",
    "scripts.kube_privacy_worker_qualification",
    "scripts.kube_privacy_services_qualification",
    "scripts.kube_privacy_exchange_qualification",
    "scripts.kube_privacy_operator_qualification",
    "scripts.kube_privacy_probe_qualification",
    "scripts.kube_cli_privacy_qualification",
    "scripts.kube_cli_privacy_exchange_qualification",
)
SCOPE = "controlled-M13-privacy-contracts"


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
    # Intentional negative-case diagnostics are private, not CLI evidence.
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
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
    value = qualify()
    print(canonical(value).decode())
    raise SystemExit(0 if value["status"] == "pass" else 1)
