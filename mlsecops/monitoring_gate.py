"""Fresh M15 acceptance. Monitoring evidence never authorizes release."""

import dataclasses
import math
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from mlsecops import audit_lineage, load_monitoring, performance_delivery, release_policy
from mlsecops.candidate_serving_reader import KIND
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
from mlsecops.privacy_gate import ARTIFACTS, contract_diagnostic
from mlsecops.storage import object_id
from mlsecops.trust_acceptance import materials
from scripts import kube_monitoring_native, monitoring_contracts
from scripts.kube_trust_native import hosted
from scripts.serving_output_native import source, verified_materials

SCOPE = "M15-fresh-actual-candidate-monitoring-acceptance"


def require(condition):
    if condition is not True:
        raise Rejected("M15_evidence_binding")


def contracts(root):
    process = subprocess.run(
        [sys.executable, "-m", "scripts.monitoring_contracts"],
        cwd=root,
        capture_output=True,
        timeout=300,
        check=False,
    )
    names = monitoring_contracts.case_ids()
    if process.returncode or process.stderr:
        contract_diagnostic(process, names, scope="M15-contract-diagnostic")
        raise Rejected("M15_controlled_contracts_failed")
    value = decode(process.stdout, 2 * 1024**2)
    expected = [
        {"id": n, "status": "pass", "expected": True, "actual": True} for n in sorted(names)
    ]
    require_fields(value, ("scope", "status", "checks", "cases"))
    require(
        bool(expected)
        and value["scope"] == monitoring_contracts.SCOPE
        and value["status"] == "pass"
    )
    require(type(value["checks"]) is int and value["checks"] == len(expected))
    require(canonical(value["cases"]) == canonical(expected))
    return value


def reconcile(value, expected, *, started, finished):
    require_fields(expected, ("source_revision", "source_fingerprint", "image_id"))
    for key, pattern in (
        ("source_revision", "[a-f0-9]{40}"),
        ("source_fingerprint", "[a-f0-9]{64}"),
        ("image_id", "sha256:[a-f0-9]{64}"),
    ):
        require(type(expected[key]) is str and re.fullmatch(pattern, expected[key]) is not None)
    require(value["source"] == expected and value["source_dirty"] is False)
    require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    require(value["scope"] == "actual-candidate-kubernetes-inference" and value["status"] == "pass")
    require(value["release_ready"] is False and value["full_M15"] == "inconclusive")
    campaign(value["monitoring_campaign_id"])
    for key in (
        "candidate_reference",
        "proposal_reference",
        "model_sha256",
        "subject_sha256",
        "qualification_permit_sha256",
    ):
        object_id(value[key])
    times = [
        datetime.fromisoformat(t)
        for t in (started, value["started_at"], value["finished_at"], finished)
    ]
    require(all(t.utcoffset() is not None for t in times) and times == sorted(times))
    native = value["native"]
    require(
        native["scope"] == "actual-candidate-monitoring-observation" and native["status"] == "pass"
    )
    require(native["release_ready"] is False and native["full_M15"] == "inconclusive")
    require(native["worker_cleanup_verified"] is True)
    require(
        native["model_sha256"] == value["model_sha256"]
        and native["subject_sha256"] == value["subject_sha256"]
    )


def campaign(value):
    require(type(value) is str and re.fullmatch("[a-f0-9]{32}", value) is not None)
    return value


def artifacts(state, value):
    directory = safe_child(
        state, "candidate-inference/" + campaign(value["monitoring_campaign_id"])
    )
    require_fields(value["artifact_hashes"], ARTIFACTS)
    result = {}
    for name in ARTIFACTS:
        content = bounded_read(directory / name, 16 * 1024**2)
        require(digest(content) == object_id(value["artifact_hashes"][name]))
        result[name] = decode(content, 16 * 1024**2)
    require(canonical(result["probe.json"]) == canonical(value["native"]))
    return result


def live_binding(root, state, value, files):
    """Re-read signed source proposal while SQL is live; never fake this offline."""
    proposal = campaign(value["actual_refusal"]["campaign_id"])
    context, verified, package, publisher = verified_materials(
        root, state, value["source"], report_path="release-proposals/" + proposal + "/report.json"
    )
    config, expected = files["config.json"], files["request.json"]
    require(
        canonical(config["context"]) == canonical(context)
        and config["publisher_public"] == publisher
    )
    require(value["candidate_reference"] == context["candidate_reference"])
    require(value["proposal_reference"] == digest(canonical(package["envelope"])))
    require(
        value["model_sha256"] == digest(verified["model"])
        and value["subject_sha256"] == verified["subject_sha256"]
    )
    permit = release_policy.checked(config["permit_envelope"], KIND, config["permit_public"])
    fixed = {
        "schema_version": 1,
        "purpose": KIND,
        "campaign_id": value["monitoring_campaign_id"],
        "environment": context["policy"]["environment"],
        "proposal_sha256": value["proposal_reference"],
        "subject_sha256": value["subject_sha256"],
        "model_sha256": value["model_sha256"],
        **value["source"],
    }
    require_fields(permit, (*fixed, "issued_at", "expires_at"))
    require(canonical({k: permit[k] for k in fixed}) == canonical(fixed))
    require(
        digest(canonical(permit))
        == value["qualification_permit_sha256"]
        == config["expected_permit"]
    )
    release_policy.window(permit, math.ceil(time.time()), maximum=600)
    lineage = dataclasses.asdict(
        audit_lineage.from_verified_package(
            package, verified["manifest"], context["trust"]["curator"]
        )
    )
    reference = load_monitoring.reference(expected)
    for key in ("dataset_sha256", "evaluation_sha256", "source_fingerprint"):
        require(reference[key] == lineage[key])
    descriptor = decode(package["documents"]["split_manifest"])["objects"]["validation.json"]
    validation = canonical(expected["monitoring"]["rows"])
    evidence = files["monitor-reference.json"]["evidence"]
    require(digest(validation) == descriptor["sha256"] == evidence["validation_sha256"])
    require(
        len(validation) == descriptor["bytes"] == evidence["validation_bytes"]
        and evidence["split"] == "validation"
    )
    require(reference["observations"] == descriptor["rows"])
    return lineage


def retained(state, value, files):
    public = read_json(state / "evidence/kubernetes-monitoring-public.json")
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
        "native",
        "feedback_quarantine",
    ):
        require(canonical(public[key]) == canonical(value[key]))
    epoch = campaign(value["monitoring_campaign_id"])
    require(
        public["campaign"] == epoch
        and public["status"] == "pass"
        and public["release_ready"] is False
    )
    expected, config = files["request.json"], files["config.json"]
    require(
        expected["model"] == value["model_sha256"] and expected["bundle"] == value["subject_sha256"]
    )
    require(config["expected_campaign"] == epoch)
    reference = load_monitoring.reference(expected)
    require(
        canonical(expected["monitoring"]["reference"])
        == canonical(files["monitor-reference.json"]["envelope"])
    )
    directory = safe_child(state, "evidence/monitoring/" + epoch)
    binding = read_json(directory / "binding.json")
    require(canonical(binding["reference"]) == canonical(reference))
    trace = binding["context"]
    for key, field in (
        ("permit_sha256", "qualification_permit_sha256"),
        ("proposal_sha256", "proposal_reference"),
        ("bundle_sha256", "subject_sha256"),
        ("model_sha256", "model_sha256"),
    ):
        require(trace[key] == value[field])
    proof = kube_monitoring_native.reverify(state)
    # reverify reconstructs windows/labels/receipts and quarantine from primary bytes.
    require(proof["status"] == "pass" and proof["post_cleanup_reverified"] is True)
    require(proof["reference_sha256"] == digest(canonical(reference)))
    summary = {
        k: proof[k]
        for k in (
            "observations",
            "clean_windows",
            "shift_windows",
            "delivered_alerts",
            "max_delivery_seconds",
        )
    }
    feedback = proof["feedback_quarantine"]
    summary["feedback"] = {
        k: feedback[k]
        for k in (
            "submitted_records",
            "quarantine_rows_added",
            "direct_database_denials",
            "retry_unchanged",
            "protected_tables_unchanged",
            "promotion_unchanged",
            "training_eligible",
            "verified_labels",
        )
    }
    hashes = {"candidate-" + k: v for k, v in value["artifact_hashes"].items()}
    for name, limit in (
        ("binding.json", 2 * 1024**2),
        ("packet.json", 32 * 1024**2),
        ("feedback/proof.json", 1024**2),
    ):
        hashes[name] = digest(bounded_read(directory / name, limit))
    hashes["public"] = digest(bounded_read(state / "evidence/kubernetes-monitoring-public.json"))
    return summary, hashes, trace["lineage"]


@performance_delivery.diagnostic
def qualify(root, state, *, pins=None):
    hosted()
    root, state = Path(root).resolve(), Path(state).resolve()
    started = now()
    output = safe_child(state, "evidence/monitoring-gate.json")
    private = safe_child(state, "evidence/kubernetes-monitoring-private.json")
    for path in (output, private):
        write_json(path, {"status": "inconclusive", "release_ready": False})
    before, expected = materials(root), source(root, "trusted-mlsecops:dev")
    index = performance_delivery.start(
        root, state, expected, performance_delivery.owner("M15", pins)
    )
    controlled = contracts(root)
    observed = kube_monitoring_native.run(root, state, **performance_delivery.prepare_args(index))
    content = bounded_read(private, 4 * 1024**2)
    value = decode(content, 4 * 1024**2)
    require(
        canonical(observed)
        == canonical(read_json(state / "evidence/kubernetes-monitoring-public.json"))
    )
    reconcile(value, expected, started=started, finished=now())
    files = artifacts(state, value)
    lineage = live_binding(root, state, value, files)
    metrics, packets, retained_lineage = retained(state, value, files)
    require(canonical(lineage) == canonical(retained_lineage))
    require(source(root, "trusted-mlsecops:dev") == expected and materials(root) == before)
    require(bounded_read(private, 4 * 1024**2) == content)
    names = (
        "fresh-source-image-methods",
        "signed-candidate-validation-reference",
        "ten-clean-and-two-shift-windows",
        "delayed-signed-label-quality",
        "scheduled-signed-delivery-within-120s",
        "feedback-quarantine-and-no-auto-promotion",
        "terminal-worker-and-retained-primary",
    )
    cases = controlled["cases"] + [
        {"id": "M15-" + n, "status": "pass", "expected": True, "actual": True} for n in names
    ]
    result = {
        "schema_version": 1,
        "scope": SCOPE,
        "status": "pass",
        "full_M15": "pass",
        "release_ready": False,
        "source_dirty": False,
        "source_revision": expected["source_revision"],
        "started_at": started,
        "finished_at": now(),
        "checks": len(cases),
        "cases": cases,
        "metrics": metrics,
        "input_digests": {
            **expected,
            **{
                k: value[k]
                for k in (
                    "candidate_reference",
                    "proposal_reference",
                    "model_sha256",
                    "subject_sha256",
                    "qualification_permit_sha256",
                )
            },
        },
        "artifact_hashes": {
            "method_materials": digest(canonical(before)),
            "controlled_contracts": digest(canonical(controlled)),
        },
        "limitations": [
            "Synthetic CPU monitoring acceptance, not production utility or release approval",
            "Ten clean windows do not estimate production false-positive rate; thresholds need real-data calibration",
            "Restart contracts prove explicit cold recovery and history loss, not durable restoration of observations",
            "M13/M14 have separate accepted campaigns; M18 still requires all mandatory gates on one candidate",
            "Single owned hosted runner and qualification identities; independent M22 and all remaining release gates remain mandatory",
        ],
    }
    write_json(
        state / "evidence/monitoring-gate-private.json",
        {"private_observation": digest(content), "retained_packets": packets},
    )
    write_json(state / "evidence/monitoring-contracts.json", controlled)
    performance_delivery.seal(root, state, "M15", index, value, digest(content), packets, result)
    write_json(output, result)
    return result


def post_cleanup(state):
    state = Path(state).resolve()
    require(read_json(state / "evidence/M15.json")["status"] == "pass")
    admission = read_json(state / "evidence/monitoring-gate-private.json")
    content = bounded_read(state / "evidence/kubernetes-monitoring-private.json", 4 * 1024**2)
    require(digest(content) == admission["private_observation"])
    value = decode(content, 4 * 1024**2)
    metrics, packets, _lineage = retained(state, value, artifacts(state, value))
    require(packets == admission["retained_packets"])
    require(
        canonical(metrics)
        == canonical(read_json(state / "evidence/monitoring-gate.json")["metrics"])
    )
    return {
        "status": "pass",
        "scope": "M15-retained-primary-after-infrastructure-cleanup",
        "release_ready": False,
        "post_cleanup_reverified": True,
        **metrics,
    }
