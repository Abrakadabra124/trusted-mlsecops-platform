"""Fresh synthetic M13 composition. Privacy acceptance cannot authorize a release."""

import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from mlsecops import audit_snapshot
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    read_json,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.storage import object_id
from mlsecops.trust_acceptance import materials
from scripts import (
    feedback_privacy_native,
    kube_privacy_native,
    monitoring_privacy_probe,
    privacy_contracts,
)
from scripts.kube_cli_privacy_probe import verify_snapshot
from scripts.kube_trust_native import hosted
from scripts.serving_output_native import source, verify_packet

SCOPE = "M13-fresh-serving-privacy-and-controlled-release-contracts"
ARTIFACTS = (
    "reference.json",
    "config.json",
    "request.json",
    "probe.json",
    "monitor-worker.json",
    "monitor-reference.json",
)


def require(condition):
    if condition is not True:
        raise Rejected("M13_evidence_binding")


def contracts(root):
    process = subprocess.run(
        [sys.executable, "-m", "scripts.privacy_contracts"],
        cwd=root,
        capture_output=True,
        timeout=300,
        check=False,
    )
    names = privacy_contracts.case_ids(root)
    if process.returncode or process.stderr:
        contract_diagnostic(process, names)
        raise Rejected("M13_controlled_contracts_failed")
    value = decode(process.stdout, 2 * 1024**2)
    expected = [
        {"id": name, "status": "pass", "expected": True, "actual": True} for name in sorted(names)
    ]
    require_fields(value, ("scope", "status", "checks", "cases"))
    require(
        bool(expected)
        and value["scope"] == privacy_contracts.SCOPE
        and value["status"] == "pass"
        and type(value["checks"]) is int
        and value["checks"] == len(expected)
        and canonical(value["cases"]) == canonical(expected)
    )
    return value


def contract_diagnostic(process, expected, *, scope="M13-contract-diagnostic"):
    # Only identifiers from the current source's fixed inventory may be public.
    # Never publish child exception text, values or a caller-provided identifier.
    try:
        value = decode(process.stdout, 2 * 1024**2)
        passed = {c["id"] for c in value["cases"] if c["status"] == "pass"}
    except (Rejected, KeyError, TypeError, ValueError):
        passed = set()
    missing = sorted(expected - passed)
    markers = {
        "onnx-gpu-discovery": b"GPU device discovery failed",
        "onnx-runtime": b"onnxruntime",
        "python-traceback": b"Traceback (most recent call last)",
        "logging-handler": b"Logging error",
        "resource-warning": b"ResourceWarning",
        "runtime-warning": b"RuntimeWarning",
        "thread-exception": b"Exception in thread",
        "ignored-finalizer": b"Exception ignored",
    }
    print(
        canonical(
            {
                "scope": scope,
                "status": "fail",
                "release_ready": False,
                "missing_methods": missing[:16],
                "missing_count": len(missing),
                "nonzero_exit": process.returncode != 0,
                "stderr_present": bool(process.stderr),
                "stderr_bytes": len(process.stderr),
                "stderr_markers": sorted(
                    name for name, marker in markers.items() if marker in process.stderr
                ),
            }
        ).decode(),
        flush=True,
    )


def campaign(value):
    require(type(value) is str and re.fullmatch("[a-f0-9]{32}", value) is not None)
    return value


def reconcile(value, expected_source, *, started, finished, methods):
    try:
        require_fields(expected_source, ("source_revision", "source_fingerprint", "image_id"))
        for key, pattern in (
            ("source_revision", "[a-f0-9]{40}"),
            ("source_fingerprint", "[a-f0-9]{64}"),
            ("image_id", "sha256:[a-f0-9]{64}"),
        ):
            require(
                type(expected_source[key]) is str
                and re.fullmatch(pattern, expected_source[key]) is not None
            )
        require(value["source"] == expected_source)
        require(value["schema_version"] == 1 and type(value["schema_version"]) is int)
        require(value["scope"] == "actual-candidate-kubernetes-inference")
        require(value["method_materials"] == object_id(methods))
        for key in (
            "candidate_reference",
            "evaluation_reference",
            "proposal_reference",
            "model_sha256",
            "subject_sha256",
            "qualification_permit_sha256",
        ):
            object_id(value[key])
        require(
            campaign(value["privacy_campaign_id"])
            != campaign(value["controlled_cli"]["privacy_campaign_id"])
        )
        require(value["controlled_cli"]["runtime_source"] == expected_source)
        times = [
            datetime.fromisoformat(t)
            for t in (started, value["started_at"], value["finished_at"], finished)
        ]
        require(all(t.utcoffset() is not None for t in times) and times == sorted(times))
        require(
            type(value["proposal_issued_at"]) is int
            and 0 <= value["proposal_issued_at"] <= times[1].timestamp()
        )
        public = kube_privacy_native.projection(value)
        # Projection itself verifies exact required scenarios, counters, closed
        # snapshots, service controls and the deliberate distinct-subject boundary.
        return {
            k: v
            for k, v in public.items()
            if k
            not in {
                "schema_version",
                "status",
                "scope",
                "release_ready",
                "full_M13",
                "source_revision",
                "checks",
            }
        }
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("M13_evidence_shape") from None


def retained(root, state, value):
    current = value["source"]
    actual_campaign = campaign(value["privacy_campaign_id"])
    cli_campaign = campaign(value["controlled_cli"]["privacy_campaign_id"])
    audit = value["native"]["audit"]
    result = {
        **{
            k: value[k]
            for k in (
                "qualification_permit_sha256",
                "proposal_reference",
                "subject_sha256",
                "model_sha256",
                "candidate_reference",
                "evaluation_reference",
            )
        },
        "campaign_id": actual_campaign,
        "runtime": {
            "audit_evidence": audit,
            "http_correlation": audit["correlation"],
            "public_audit_window": audit["public"],
        },
    }
    checked = verify_packet(
        root,
        state,
        current,
        actual_campaign,
        result,
        evidence_directory="evidence/privacy/" + actual_campaign,
        proposal_report="release-proposals/"
        + campaign(value["actual_refusal"]["campaign_id"])
        + "/report.json",
    )
    require(canonical(checked) == canonical(audit))
    artifact_names = ARTIFACTS
    require_fields(value["artifact_hashes"], artifact_names)
    for name in artifact_names:
        require(
            digest(
                bounded_read(
                    safe_child(state, "candidate-inference/" + actual_campaign + "/" + name)
                )
            )
            == value["artifact_hashes"][name]
        )
    monitoring_privacy_probe.reverify(
        value["native"],
        read_json(safe_child(state, "candidate-inference/" + actual_campaign + "/request.json")),
        actual_campaign,
    )
    feedback_privacy_native.reverify(state, value)
    cli_path = safe_child(state, "evidence/cli-privacy/" + cli_campaign)
    context = read_json(cli_path / "context.json")
    cli = value["controlled_cli"]
    require(
        context["model_sha256"] == cli["model_sha256"]
        and context["bundle_sha256"] == cli["subject_sha256"]
    )
    raw = audit_snapshot.load_packet(cli_path / "closed-window")
    require(raw == canonical(cli["native"]["privacy"]))
    snapshot = decode(raw, 2 * 1024**2)
    require(
        canonical(verify_snapshot(snapshot["snapshot"], context, snapshot["http"]))
        == canonical(snapshot["audit"])
    )
    hashes = {
        "actual_audit": object_id(audit["packet_sha256"]),
        "controlled_cli_packet": digest(raw),
        "monitoring": object_id(value["native"]["monitoring_observation"]["proof_sha256"]),
        "feedback_privacy": object_id(value["feedback_privacy"]["proof_sha256"]),
    }
    for name, path, receipts in (
        (
            "actual",
            safe_child(state, "evidence/privacy/" + actual_campaign),
            value["native"]["operator_observation"]["service_observations"],
        ),
        ("controlled_cli", cli_path, cli["service_windows"]),
    ):
        kube_privacy_native.checked_services(receipts)
        for namespace, receipt in receipts.items():
            content = audit_snapshot.load_packet(path / "services" / namespace)
            require(digest(content) == receipt["sha256"])
            hashes[name + "_" + namespace] = digest(content)
    return hashes


def ingress_retained(state):
    """Offline replay of the newly added ingress evidence, not a live CAS reread."""
    state = Path(state).resolve()
    raw = bounded_read(state / "evidence/kubernetes-privacy-private.json", 4 * 1024**2)
    admission = read_json(state / "evidence/privacy-gate-private.json")
    require(read_json(state / "evidence/M13.json")["status"] == "pass")
    require(digest(raw) == admission["private_observation"])
    value = decode(raw, 4 * 1024**2)
    where = safe_child(state, "candidate-inference/" + campaign(value["privacy_campaign_id"]))
    require_fields(value["artifact_hashes"], ARTIFACTS)
    for name in ARTIFACTS:
        require(digest(bounded_read(where / name)) == value["artifact_hashes"][name])
    observed = monitoring_privacy_probe.reverify(
        value["native"], read_json(where / "request.json"), value["privacy_campaign_id"]
    )
    feedback_privacy_native.reverify(state, value)
    return {
        "scope": "M13-monitoring-feedback-post-cleanup",
        "status": "pass",
        "release_ready": False,
        "private_observation": digest(raw),
        "monitoring_observations": observed["observations"],
        "feedback_commands": 11,
    }


def qualify(root, state, image="trusted-mlsecops:dev"):
    hosted()
    root, state = Path(root).resolve(), Path(state).resolve()
    started = now()
    output = safe_child(state, "evidence/privacy-gate.json")
    private = safe_child(state, "evidence/kubernetes-privacy-private.json")
    for path in (output, private):
        write_json(path, {"status": "inconclusive", "release_ready": False})
    before = materials(root)
    expected_source = source(root, image)
    controlled = contracts(root)
    observed = kube_privacy_native.qualify(root, state, image)
    content = bounded_read(private, 4 * 1024**2)
    value = decode(content, 4 * 1024**2)
    require(canonical(observed) == canonical(kube_privacy_native.projection(value)))
    metrics = reconcile(
        value, expected_source, started=started, finished=now(), methods=digest(canonical(before))
    )
    packets = retained(root, state, value)
    require(source(root, image) == expected_source and materials(root) == before)
    require(bounded_read(private, 4 * 1024**2) == content)
    names = (
        "fresh-source-image-and-methods",
        "actual-signed-primary-and-retained-audit",
        "distinct-controlled-release-primary-and-cli",
        "closed-service-windows-and-leak-controls",
        "http-auth-quota-fenced-privacy",
        "finite-approved-metrics-and-public-export",
        "terminal-native-worker-output",
        "post-cleanup-retained-packet-recheck",
    )
    cases = controlled["cases"] + [
        {"id": "M13-" + name, "status": "pass", "expected": True, "actual": True} for name in names
    ]
    result = {
        "schema_version": 1,
        "scope": SCOPE,
        "status": "pass",
        "release_ready": False,
        "source_dirty": False,
        "started_at": started,
        "finished_at": now(),
        "source_revision": expected_source["source_revision"],
        "cases": cases,
        "checks": len(cases),
        "metrics": metrics,
        "input_digests": {
            **expected_source,
            **{
                k: value[k]
                for k in (
                    "candidate_reference",
                    "proposal_reference",
                    "evaluation_reference",
                    "model_sha256",
                    "subject_sha256",
                )
            },
        },
        "artifact_hashes": {
            "method_materials": digest(canonical(before)),
            "controlled_contracts": digest(canonical(controlled)),
        },
        "limitations": [
            "Synthetic serving privacy mechanism acceptance, not release approval or membership-inference protection",
            "Actual candidate uses a qualification permit; distinct controlled CLI release proves approval/context wiring, not actual assurance",
            "CLI admission is not independently observed; independent admission/HTTP linkage is checked on the actual shared audit path",
            "Closed service windows and private campaign retention, not continuous service history or external forensic archive",
            "No protection against privileged host owner or injected exporters; real pilot requires purpose/retention/privacy specification",
            "Training inputs are governed stored datasets, not serving telemetry; independent M22, image findings and all remaining gates stay mandatory",
        ],
    }
    write_json(
        safe_child(state, "evidence/privacy-gate-private.json"),
        {"private_observation": digest(content), "retained_packets": packets},
    )
    write_json(safe_child(state, "evidence/privacy-contracts.json"), controlled)
    write_json(safe_child(state, "evidence/kubernetes-privacy-public.json"), observed)
    write_json(output, result)
    return result
