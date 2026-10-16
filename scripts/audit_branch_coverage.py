import argparse
import json
from pathlib import Path

from coverage import Coverage
from coverage.exceptions import CoverageException

from mlsecops.contracts import Rejected

ROOT = Path(__file__).resolve().parents[1]
FILES = ("mlsecops/serving_audit.py", "mlsecops/audit_retention.py")
MINIMUM = 95


def check(data_file):
    measurement = Coverage(data_file=data_file, config_file=False)
    measurement.clear_exclude("exclude")
    measurement.clear_exclude("partial")
    measurement.load()
    data = measurement.get_data()
    measured = {Path(name).resolve() for name in data.measured_files()}
    if not data.has_arcs() or any(ROOT / name not in measured for name in FILES):
        raise Rejected("audit_branch_measurement_missing")
    modules = []
    for name in FILES:
        stats = measurement.branch_stats(str(ROOT / name))
        if not stats or any(
            type(total) is not int
            or type(taken) is not int
            or not 0 <= taken <= total
            or total <= 0
            for total, taken in stats.values()
        ):
            raise Rejected("audit_branch_measurement_invalid")
        total = sum(total for total, _taken in stats.values())
        taken = sum(taken for _total, taken in stats.values())
        modules.append(
            {
                "module": name,
                "total_branches": total,
                "covered_branches": taken,
                "branch_percent": round(100 * taken / total, 4),
                "status": "pass" if 100 * taken >= MINIMUM * total else "fail",
            }
        )
    return {
        "schema_version": 1,
        "scope": "audit-branch-coverage-component-not-full-M18",
        "minimum_branch_percent": MINIMUM,
        "status": "pass" if all(module["status"] == "pass" for module in modules) else "fail",
        "modules": modules,
        "release_ready": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("data_file")
    arguments = parser.parse_args(argv)
    try:
        report = check(arguments.data_file)
    except (CoverageException, OSError, ValueError):
        report = {
            "status": "inconclusive",
            "reason": "audit_branch_measurement_invalid",
            "release_ready": False,
        }
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
