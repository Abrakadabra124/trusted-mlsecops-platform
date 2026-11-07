"""Fresh controlled M15 contracts; skips and missing methods never count as passes."""

import contextlib
import io
import sys
import unittest

from mlsecops.contracts import canonical
from scripts.evaluation_contracts import Result
from scripts.evaluation_contracts import case_ids as loaded_ids

MODULES = (
    "scripts.monitoring_qualification",
    "scripts.monitoring_stream_qualification",
    "scripts.monitoring_labels_qualification",
    "scripts.monitoring_alerts_qualification",
    "scripts.monitoring_delivery_qualification",
    "scripts.monitoring_runtime_qualification",
    "scripts.monitoring_http_qualification",
    "scripts.monitoring_config_qualification",
    "scripts.monitoring_cli_qualification",
    "scripts.monitoring_reference_qualification",
    "scripts.monitoring_packet_qualification",
    "scripts.monitoring_probe_qualification",
    "scripts.kube_monitoring_native_qualification",
    "scripts.feedback_qualification",
    "scripts.feedback_native_qualification",
    "scripts.monitoring_state_qualification",
    "scripts.monitoring_restart_qualification",
    "scripts.monitoring_privacy_qualification",
    "scripts.load_monitoring_qualification",
)
SCOPE = "controlled-M15-monitoring-contracts"


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
    if sys.platform == "linux":
        from mlsecops.runtime_bootstrap import initialize

        initialize()
    report = qualify()
    print(canonical(report).decode())
    raise SystemExit(0 if report["status"] == "pass" else 1)
