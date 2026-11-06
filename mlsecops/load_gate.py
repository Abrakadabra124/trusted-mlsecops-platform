"""Fresh M14 composition, bound to retained observations and immutable source."""

import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from mlsecops import load_clock, load_diagnostics, load_measurement
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.load_exchange import MAX_PACKET
from mlsecops.privacy_gate import contract_diagnostic
from mlsecops.storage import object_id
from mlsecops.trust_acceptance import materials
from scripts import kube_load_native, load_contracts, load_resources
from scripts.kube_load_operator import overload
from scripts.kube_trust_native import hosted
from scripts.serving_output_native import source

SCOPE = "M14-fresh-actual-candidate-load-acceptance"
PACKETS = ("start-request.json", "finish-request.json", "resources.json")


def require(condition):
    if condition is not True:
        raise Rejected("M14_evidence_binding")


def contracts(root):
    process = subprocess.run(
        [sys.executable, "-m", "scripts.load_contracts"],
        cwd=root,
        capture_output=True,
        timeout=300,
        check=False,
    )
    names = load_contracts.case_ids()
    if process.returncode or process.stderr:
        contract_diagnostic(process, names, scope="M14-contract-diagnostic")
        raise Rejected("M14_controlled_contracts_failed")
    value = decode(process.stdout, 2 * 1024**2)
    expected = [
        {"id": name, "status": "pass", "expected": True, "actual": True} for name in sorted(names)
    ]
    require_fields(value, ("scope", "status", "checks", "cases"))
    require(bool(expected) and value["scope"] == load_contracts.SCOPE and value["status"] == "pass")
    require(type(value["checks"]) is int and value["checks"] == len(expected))
    require(canonical(value["cases"]) == canonical(expected))
    return value


def reconcile(value, expected_source, *, started, finished):
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
    require(value["source"] == expected_source and value["source_dirty"] is False)
    require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    require(value["scope"] == "actual-candidate-kubernetes-inference" and value["status"] == "pass")
    require(value["release_ready"] is False and value["full_M14"] == "inconclusive")
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
    require(
        type(value["proposal_issued_at"]) is int
        and 0 <= value["proposal_issued_at"] <= times[1].timestamp()
    )
    native = value["native"]
    require(native["scope"] == "actual-candidate-load-observation" and native["status"] == "pass")
    require(native["release_ready"] is False and native["full_M14"] == "inconclusive")
    for key in ("profile_met", "worker_cleanup_verified", "operator_retained_reverified"):
        require(native[key] is True)
    require(native["model_sha256"] == value["model_sha256"] == native["golden"]["model_sha256"])
    require(
        native["subject_sha256"] == value["subject_sha256"] == native["golden"]["bundle_sha256"]
    )
    require(
        native["golden"]["rows_per_request"] == 1
        and type(native["golden"]["rows_per_request"]) is int
    )
    require(native["golden"]["absolute_score_tolerance"] == 1e-6)
    object_id(native["golden"]["payload_sha256"])
    require(
        native["measurement"]["profile_met"] is True and native["overload"]["profile_met"] is True
    )
    return native


def retained(state, value):
    campaign = value["load_campaign_id"]
    require(type(campaign) is str and re.fullmatch("[a-f0-9]{32}", campaign) is not None)
    native = value["native"]
    receipt = native["operator"]
    require_fields(receipt["retained_sha256"], PACKETS)
    packets, hashes = {}, {}
    directory = safe_child(state, "evidence/load/" + campaign)
    for name in PACKETS:
        content = bounded_read(safe_child(directory, name), MAX_PACKET)
        hashes[name] = digest(content)
        require(hashes[name] == object_id(receipt["retained_sha256"][name]))
        packets[name] = decode(content, MAX_PACKET)
    for phase in ("start", "finish"):
        packet = packets[phase + "-request.json"]
        require_fields(packet, ("phase", "campaign", "payload"))
        require(packet["phase"] == phase and packet["campaign"] == campaign)
        require(canonical(packet["payload"]["golden"]) == canonical(native["golden"]))
    payload = packets["finish-request.json"]["payload"]
    require_fields(payload, ("observation", "summary", "overload", "golden", "diagnostics"))
    observation = payload["observation"]
    require_fields(observation, ("records", "exhausted", "elapsed_ns", "clock"))
    summary = load_measurement.summarize(
        **{k: observation[k] for k in ("records", "exhausted", "elapsed_ns")}
    )
    require(summary["profile_met"] is True)
    require(canonical(summary) == canonical(payload["summary"]) == canonical(native["measurement"]))
    require(digest(canonical(summary)) == receipt["summary_sha256"])
    require(overload(payload["overload"])["profile_met"] is True)
    require(canonical(payload["overload"]) == canonical(native["overload"]))
    load_diagnostics.checked(payload["diagnostics"], summary, payload["overload"])
    require(canonical(payload["diagnostics"]) == canonical(native["diagnostics"]))
    require(digest(canonical(native["diagnostics"])) == receipt["diagnostics_sha256"])
    resource = packets["resources.json"]
    require_fields(resource, ("samples", "window", "compute"))
    require_fields(resource["samples"], ("controller", "worker"))
    window = load_clock.window(observation["clock"], observation["elapsed_ns"])
    start_ns = int(datetime.fromisoformat(value["started_at"]).timestamp() * 1_000_000_000)
    finish_ns = int(datetime.fromisoformat(value["finished_at"]).timestamp() * 1_000_000_000)
    require(start_ns <= window["start_ns"] - window["uncertainty_ns"])
    require(window["end_ns"] + window["uncertainty_ns"] <= finish_ns)
    require(canonical(window) == canonical(resource["window"]))
    measured = {
        name: load_resources.summarize(rows, **window) for name, rows in resource["samples"].items()
    }
    require(canonical(measured) == canonical(receipt["resources"]))
    require(canonical(resource["compute"]) == canonical(receipt["compute"]))
    artifact_names = ("reference.json", "config.json", "request.json", "probe.json")
    require_fields(value["artifact_hashes"], artifact_names)
    for name in artifact_names:
        content = bounded_read(safe_child(state, "candidate-inference/" + campaign + "/" + name))
        require(digest(content) == object_id(value["artifact_hashes"][name]))
        hashes["candidate-" + name] = digest(content)
        if name == "probe.json":
            require(canonical(decode(content)) == canonical(native))
    return hashes


def qualify(root, state):
    hosted()
    root, state = Path(root).resolve(), Path(state).resolve()
    started = now()
    output = safe_child(state, "evidence/load-gate.json")
    private = safe_child(state, "evidence/kubernetes-load-private.json")
    for path in (output, private):
        write_json(path, {"status": "inconclusive", "release_ready": False})
    before = materials(root)
    expected_source = source(root, "trusted-mlsecops:dev")
    controlled = contracts(root)
    observed = kube_load_native.run(root, state)
    content = bounded_read(private, 4 * 1024**2)
    value = decode(content, 4 * 1024**2)
    require(observed["status"] == "pass" and observed["source"] == expected_source)
    require(canonical(observed["native"]) == canonical(value["native"]))
    native = reconcile(value, expected_source, started=started, finished=now())
    packets = retained(state, value)
    require(source(root, "trusted-mlsecops:dev") == expected_source and materials(root) == before)
    require(bounded_read(private, 4 * 1024**2) == content)
    names = (
        "fresh-source-image-methods",
        "signed-candidate-golden-binding",
        "full-client-window-and-latency",
        "independent-resource-window",
        "bounded-overload-and-recovery",
        "retained-packets-after-owned-cleanup",
    )
    cases = controlled["cases"] + [
        {"id": "M14-" + name, "status": "pass", "expected": True, "actual": True} for name in names
    ]
    result = {
        "schema_version": 1,
        "scope": SCOPE,
        "status": "pass",
        "full_M14": "pass",
        "release_ready": False,
        "source_dirty": False,
        "source_revision": expected_source["source_revision"],
        "started_at": started,
        "finished_at": now(),
        "checks": len(cases),
        "cases": cases,
        "artifact_hashes": {
            "method_materials": digest(canonical(before)),
            "private_observation": digest(content),
            "controlled_contracts": digest(canonical(controlled)),
            **{"retained_" + k.replace("-", "_").replace(".", "_"): v for k, v in packets.items()},
        },
        "input_digests": {
            **expected_source,
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
        "metrics": {
            "measurement": native["measurement"],
            "overload": native["overload"],
            "operator": native["operator"],
            "post_cleanup_primary_reverified": True,
        },
        "limitations": [
            "synthetic CPU reference profile",
            "sampled memory, not true peak",
            "closed-loop client model",
            "qualified candidate, not release authorization",
            "M18 and R1 remain unaccepted",
        ],
    }
    write_json(safe_child(state, "evidence/load-contracts.json"), controlled)
    write_json(output, result)
    return result
