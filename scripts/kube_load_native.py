"""Hosted baseline measurement with the actual signed candidate and owned cleanup."""

from pathlib import Path

from mlsecops.contracts import Rejected, canonical, write_json
from scripts.kube_candidate_native import qualify
from scripts.kube_trust_native import hosted

CODES = frozenset(
    {
        "load_resource_missing",
        "load_resource_pod",
        "load_resource_sample",
        "load_resource_node",
        "load_resource_container",
        "load_resource_timestamp",
        "load_resource_window",
        "load_resource_window_uncovered",
        "load_resource_tail_missing",
        "load_resource_sampling_gap",
        "load_resource_reset_or_change",
        "load_resource_samples_limit",
        "load_probe_report_changed",
        "load_exchange_read_failed",
        "load_exchange_binding",
        "load_exchange_order",
        "load_exchange_changed",
        "load_worker_binding",
        "load_worker_job",
        "load_worker_job_changed",
        "load_worker_pod_changed",
        "load_probe_changed",
        "load_probe_not_running",
        "load_resource_node_changed",
        "load_golden_changed",
        "load_summary_changed",
        "load_retained_write",
        "load_retained_changed",
        "load_retained_incomplete",
        "load_operator_worker_cleanup_unconfirmed",
        "load_clock_anchor",
        "load_clock_elapsed",
        "load_clock_drift",
        "load_overload_accounting",
    }
)


def run(root, state):
    hosted()
    write_json(
        state / "evidence/kubernetes-load-public.json",
        {"status": "inconclusive", "release_ready": False},
    )
    # The existing controller bootstrap resolves and verifies this locally built
    # tag against the current source/image descriptor before issuing the permit.
    result = qualify(root, state, "trusted-mlsecops:dev", load=True)
    write_json(state / "evidence/kubernetes-load-private.json", result)
    public = {
        key: result[key]
        for key in (
            "source",
            "source_dirty",
            "started_at",
            "finished_at",
            "candidate_reference",
            "proposal_reference",
            "model_sha256",
            "subject_sha256",
            "qualification_permit_sha256",
            "full_M14",
            "release_ready",
            "native",
        )
    }
    public.update(
        schema_version=1,
        scope="actual-candidate-load-baseline",
        status="pass" if result["native"]["profile_met"] else "fail",
    )
    write_json(state / "evidence/kubernetes-load-public.json", public)
    return public


def main():
    root, state = Path.cwd(), Path(".runtime").resolve()
    try:
        result = run(root, state)
        print(canonical(result).decode(), flush=True)
        return 0 if result["status"] == "pass" else 1
    except Exception as failure:
        code = str(failure)
        result = {
            "status": "fail",
            "scope": "actual-candidate-load-baseline",
            "release_ready": False,
            "full_M14": "inconclusive",
            "code": code
            if isinstance(failure, Rejected) and code in CODES
            else "load_native_rejected",
        }
        print(canonical(result).decode(), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
