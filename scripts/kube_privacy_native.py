"""Fresh hosted privacy integration, not the complete M13 acceptance gate."""

import re
import sys
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, digest, safe_child, write_json
from mlsecops.inventory import command
from mlsecops.private_cli import Arguments
from mlsecops.trust_acceptance import materials
from scripts import kube_candidate_native, kube_serving_native
from scripts.kube_privacy_diagnostic import location
from scripts.kube_trust_native import hosted

CASES = {
    "actual-golden-response",
    "actual-candidate-context",
    "missing-auth-401",
    "single-privacy-input-observation",
    "actual-pressure-429",
    "fenced-predict-503",
    "fenced-ready-503",
    "one-observed-worker",
    "final-worker-absence",
    "all-client-input-canaries-available",
    "retained-primary-correlation",
    "operator-reverified-primary-packet",
    "context-candidate-not-release-selection",
    "context-ready-generation-bound",
    "context-prediction-generation-bound",
    "context-private-references-not-public",
    "context-public-shape-unchanged",
    "audit-http-pair-accepted",
    "audit-http-pair-durable",
    "privacy-http-input-and-output-matrix",
    "privacy-owned-audit-input-absent",
    "privacy-native-telemetry-disabled",
    "privacy-approved-metrics-cardinality",
    "independent-client-burst-boundary",
    "client-quota-refill-recovers",
    "client-admission-accounting",
}


def projection(report):
    native = report["native"]
    if (
        report["status"] != "pass"
        or report["release_ready"] is not False
        or report["source_dirty"] is not False
        or report["full_M13"] != "inconclusive"
        or native["status"] != "pass"
        or native["release_ready"] is not False
        or native["scope"] != "actual-candidate-kubernetes-privacy-not-full-M13"
        or native["model_sha256"] != report["model_sha256"]
        or native["subject_sha256"] != report["subject_sha256"]
        or report["actual_refusal"]["parent_refusal"] != "release_assurance_required"
        or native["output_observation"]["fd_lifecycle_complete"] is not True
        or native["output_observation"]["native_stderr_bytes"] != 0
        or native["output_observation"]["canary_count"] != 9
        or native["operator_observation"]["service_windows"] != 2
        or native["operator_observation"]["worker_terminal"] is not True
        or native["privacy"]["approved_metric_series"] != 69
        or native["privacy"]["request_cases"] != 12
        or native["privacy"]["audit_events_confirmed"] != 36
        or {v["id"] for v in native["cases"]} != CASES
        or len({v["id"] for v in native["cases"]}) != len(native["cases"])
        or any(
            canonical(v)
            != canonical({"id": v["id"], "status": "pass", "expected": True, "actual": True})
            for v in native["cases"]
        )
    ):
        raise Rejected("privacy_native_incomplete")
    # Finite public counters only. Raw logs, packet hashes, Pod/request/principal
    # identifiers and private source-to-request references stay in private state.
    result = {
        "schema_version": 1,
        "status": "pass",
        "scope": "hosted-kubernetes-privacy-component-not-full-M13",
        "release_ready": False,
        "full_M13": "inconclusive",
        "source_revision": report["source"]["source_revision"],
        "checks": len(native["cases"]),
        "input_canaries": 9,
        "privacy_requests": 12,
        "privacy_durable_events": 36,
        "metric_series": 69,
        "observed_http_responses": native["audit"]["observed_responses"],
        "correlated_requests": native["audit"]["correlation"]["correlated_requests"],
        "audit_events": native["audit"]["correlation"]["events"],
        "worker_terminal_stream": True,
        "service_log_windows": 2,
        "native_stderr_bytes": 0,
        "worker_cleanup": True,
    }
    if (
        type(result["source_revision"]) is not str
        or re.fullmatch("[a-f0-9]{40}", result["source_revision"]) is None
        or any(
            type(result[k]) is not int or not 1 <= result[k] <= 65536
            for k in ("observed_http_responses", "correlated_requests", "audit_events")
        )
    ):
        raise Rejected("privacy_public_projection")
    return result


def qualify(root, state, image):
    hosted()
    before = materials(root)
    prepared = kube_serving_native.prepare(root, state, image)
    report = kube_candidate_native.qualify(
        root,
        state,
        image,
        prepared=(prepared["profile"], prepared["actual"]),
        privacy=True,
    )
    if (
        materials(root) != before
        or command(["git", "-C", str(root), "status", "--porcelain"])
        or report["actual_refusal"] != prepared["actual"]
        or report["source"]
        != {
            "source_revision": prepared["source_revision"],
            "source_fingerprint": prepared["source_fingerprint"],
            "image_id": prepared["profile"]["image_id"],
        }
    ):
        raise Rejected("privacy_native_source_changed")
    report["method_materials"] = digest(canonical(before))
    public = projection(report)
    write_json(safe_child(state, "evidence/kubernetes-privacy-private.json"), report)
    return public


def main(arguments=None):
    path = None
    try:
        hosted()
        parser = Arguments(prog="kubernetes-privacy")
        parser.add_argument("--state", type=Path, required=True)
        parser.add_argument("--image", default="trusted-mlsecops:dev")
        options = parser.parse_args(arguments)
        path = safe_child(options.state, "evidence/kubernetes-privacy-public.json")
        write_json(path, {"status": "inconclusive", "release_ready": False})
        result = qualify(
            Path(__file__).resolve().parents[1], options.state.resolve(), options.image
        )
        write_json(path, result)
        print(canonical(result).decode())
        return 0
    except Exception as error:
        if path is not None:
            write_json(path, {"status": "fail", "release_ready": False})
        print(
            canonical(
                {"scope": "privacy-native-failure", "status": "fail", **location(error)}
            ).decode(),
            file=sys.stderr,
        )
        print("kubernetes_privacy_rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
