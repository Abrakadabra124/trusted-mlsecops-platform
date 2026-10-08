from mlsecops.contracts import canonical
from scripts.image_archive_qualification import qualify as archive_contracts
from scripts.image_audit_flow_qualification import qualify as flow_contracts
from scripts.image_audit_qualification import qualify as report_contracts
from scripts.image_audit_runner_qualification import qualify as runner_contracts
from scripts.image_candidates_qualification import qualify as candidate_contracts
from scripts.image_comparison_qualification import qualify as comparison_contracts


def qualify():
    reports = [
        operation()
        for operation in (
            archive_contracts,
            flow_contracts,
            report_contracts,
            runner_contracts,
            candidate_contracts,
            comparison_contracts,
        )
    ]
    return {
        "status": "pass",
        "scope": "controlled-image-contracts-only",
        "checks": sum(report["checks"] for report in reports),
        "reports": reports,
    }


if __name__ == "__main__":
    print(canonical(qualify()).decode())
