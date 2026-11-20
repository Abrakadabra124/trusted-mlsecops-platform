"""Closed public M07 diagnostics, never acceptance or raw exception publication."""

import sys
from pathlib import Path

from mlsecops.contracts import bounded_read, canonical, decode
from mlsecops.holdout_diagnostics import CLAIM_CASES, REJECTION_CODES
from mlsecops.storage_connection_diagnostics import checked

REASONS = {
    "M07_component_cases_invalid",
    "M07_component_shape_invalid",
    "M07_controlled_contracts_failed",
    "M07_controlled_contracts_incomplete",
    "M07_controlled_contracts_scope_invalid",
    "M07_budget_binding_invalid",
    "M07_budget_shape_invalid",
    "M07_material_binding_invalid",
    "M07_stale_or_future_evidence",
    "M07_quality_state_invalid",
    "M07_material_shape_invalid",
    "M07_integrity_gate_not_accepted",
    "M07_integrity_candidate_mismatch",
    "M07_requires_fresh_owned_storage",
    "M07_source_changed_during_campaign",
    "M07_cleanup_identity_changed",
    "storage_connection_rejected",
    *("holdout_qualification_failed:" + case for case in CLAIM_CASES),
}
FIELDS = set(
    "schema_version diagnostic_only complete attempts claimed_slots "
    "rejection_codes invalid_receipts".split()
)
DEFAULT = Path(".runtime/evidence/M07.json")
LIMIT = 1024 * 1024


def count(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def concurrency(value):
    return (
        type(value) is dict
        and len(value) in (7, 8)
        and FIELDS <= value.keys() <= FIELDS | {"connection_failures"}
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["diagnostic_only"] is True
        and type(value["complete"]) is bool
        and count(value["attempts"], 33)
        and type(value["claimed_slots"]) is list
        and len(value["claimed_slots"]) <= 32
        and all(count(slot, 32) and slot >= 1 for slot in value["claimed_slots"])
        and type(value["rejection_codes"]) is dict
        and value["rejection_codes"].keys() <= REJECTION_CODES | {"unclassified_rejection"}
        and all(count(number, 32) for number in value["rejection_codes"].values())
        and count(value["invalid_receipts"], 32)
        and (
            "connection_failures" not in value
            or (
                type(value["connection_failures"]) is list
                and len(value["connection_failures"]) <= 32
                and all(checked(failure, 32) for failure in value["connection_failures"])
            )
        )
    )


def project(report):
    result = dict(
        gate="M07",
        status="unavailable",
        exit_code=None,
        reason="unavailable",
        diagnostic_only=True,
        release_ready=False,
    )
    if type(report) is not dict or report.get("gate") != "M07":
        return result
    status, code = report.get("status"), report.get("exit_code")
    if type(status) is not str or status not in ("pass", "fail", "inconclusive"):
        return result
    if type(code) is not int or code != {"pass": 0, "fail": 1, "inconclusive": 2}[status]:
        return result
    risks = report.get("residual_risks")
    reason = risks[0] if type(risks) is list and len(risks) == 1 else None
    if type(reason) is not str or len(reason) > 128 or reason not in REASONS:
        reason = "unclassified"
    result.update(status=status, exit_code=code, reason=reason)
    if "diagnostics" in report:
        diagnostics = report["diagnostics"]
        if (
            type(diagnostics) is dict
            and diagnostics.keys() == {"holdout_concurrency"}
            and concurrency(diagnostics["holdout_concurrency"])
        ):
            result["holdout_concurrency"] = decode(canonical(diagnostics["holdout_concurrency"]))
        else:
            result["diagnostic_invalid"] = True
    return result


def main(argv=None):
    """Emit one bounded JSON line; caller must preserve the original M07 exit status."""
    arguments = sys.argv[1:] if argv is None else argv
    report = None
    try:
        if len(arguments) <= 1:
            report = decode(
                bounded_read(Path(arguments[0]) if arguments else DEFAULT, LIMIT), LIMIT
            )
    except (OSError, ValueError, TypeError):
        pass
    print(canonical(project(report)).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
