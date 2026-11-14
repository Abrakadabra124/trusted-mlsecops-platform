"""Frozen M14/M15 capture and private evidence replay on the owner's original proposal."""

import math
import os
import re
from datetime import datetime
from functools import wraps

from mlsecops import final_evidence, load_monitoring, release_policy, trust_delivery
from mlsecops.candidate_serving_reader import KIND
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    require_fields,
    safe_child,
    write_json,
)
from mlsecops.storage import object_id
from scripts.candidate_lineage_native import KNOWN_OWNERS, OWNERS
from scripts.serving_output_native import verified_materials

PROPOSAL = "evidence/release-native.json"
DEMO = "storage-demo.json"
FILES = {
    PROPOSAL: "PROPOSAL",
    DEMO: "DEMO",
    "trusted-keys.json": "KEYS",
    "storage-trust.json": "TRUST",
}
MODES = {"M14": "load", "M15": "monitoring"}
SOURCE = ("image_id", "source_revision", "source_fingerprint")
IDENTITY = (
    "candidate_reference",
    "evaluation_reference",
    "proposal_reference",
    "subject_sha256",
    "model_sha256",
)


def require(value):
    if value is not True:
        raise Rejected("performance_delivery_binding")


def diagnostic(qualify):
    from scripts.kube_load_native import failure_site

    @wraps(qualify)
    def run(*args, **kwargs):
        try:
            return qualify(*args, **kwargs)
        except Exception as error:
            print(
                canonical(
                    {"scope": "performance-gate-failure", "site": failure_site(error)}
                ).decode(),
                flush=True,
            )
            raise

    return run


def owner(gate, pins):
    if pins is None:
        pins = {name: os.environ.get(f"{gate}_{label}_SHA256") for name, label in FILES.items()}
        if all(v is None for v in pins.values()):
            return None
    require_fields(pins, FILES)
    return {name: object_id(pin) for name, pin in pins.items()}


def pinned(path, key, limit=16 * 1024**2):
    raw = bounded_read(path, limit)
    require(digest(raw) == object_id(key))
    return decode(raw, limit)


def capture(root, state, source, pins):
    for name, pin in pins.items():
        pinned(safe_child(state, name), pin)
    report = read_json(state / PROPOSAL)
    campaign = report["campaign_id"]
    require(isinstance(campaign, str) and re.fullmatch("[0-9a-f]{32}", campaign) is not None)
    policy = read_json(safe_child(state, f"release-proposals/{campaign}/policy-envelope.json"))
    _, _, package, _ = verified_materials(root, state, source)
    final_evidence.retain_package(state, package)
    index = {
        "freeze": pins,
        **source,
        "policy_reference": final_evidence.retain(state, canonical(policy)),
    }
    frozen(root, state, index)
    return index


def frozen(root, state, index):
    return final_evidence.frozen(
        root, state, index, index["source_revision"], index["source_fingerprint"]
    )


def start(root, state, source, pins):
    if pins is None:
        return None
    trust_delivery.clean_campaign(state)
    return capture(root, state, source, pins)


def prepare_args(index):
    return {} if index is None else {"proposal_pin": index["freeze"][PROPOSAL]}


def signed_inputs(root, state, gate, index, value):
    values, keys, _ = frozen(root, state, index)
    require(value["source"] == {k: values[k] for k in SOURCE})
    require(all(value[k] == values[k] for k in IDENTITY))
    mode = MODES[gate]
    epoch = value[mode + "_campaign_id"]
    require(
        type(epoch) is str
        and re.fullmatch("[a-f0-9]{32}", epoch) is not None
        and epoch == value["qualification_campaign_id"]
    )
    directory = safe_child(state, "candidate-inference/" + epoch)

    def artifact(name):
        return pinned(directory / name, value["artifact_hashes"][name])

    config = artifact("config.json")
    context = dict(
        candidate_reference=values["candidate_reference"],
        evaluation_reference=values["evaluation_reference"],
        policy=read_json(root / "policies/local-cpu.json"),
        trust=read_json(state / "storage-trust.json"),
        expected=value["source"],
        owners=OWNERS,
        known_owners=KNOWN_OWNERS,
    )
    require(
        canonical(config["context"]) == canonical(context)
        and config["publisher_public"] == keys["approver"]
    )
    require(
        config["expected_campaign"] == epoch
        and config["proposal_reference"] == values["proposal_reference"]
    )
    permit = release_policy.checked(config["permit_envelope"], KIND, config["permit_public"])
    fixed = dict(
        schema_version=1,
        purpose=KIND,
        campaign_id=epoch,
        environment=context["policy"]["environment"],
        proposal_sha256=values["proposal_reference"],
        subject_sha256=values["subject_sha256"],
        model_sha256=values["model_sha256"],
        **value["source"],
    )
    require_fields(permit, (*fixed, "issued_at", "expires_at"))
    require(canonical({k: permit[k] for k in fixed}) == canonical(fixed))
    require(
        digest(canonical(permit))
        == config["expected_permit"]
        == value["qualification_permit_sha256"]
    )
    start, end = (datetime.fromisoformat(value[k]) for k in ("started_at", "finished_at"))
    require(start.utcoffset() is not None and end.utcoffset() is not None and start <= end)
    require(
        values["proposal_issued_at"]
        == value["proposal_issued_at"]
        <= int(start.timestamp())
        <= permit["issued_at"]
    )
    require(permit["expires_at"] <= values["proposal_expires_at"])
    release_policy.window(permit, math.ceil(end.timestamp()), maximum=600)
    request = artifact("request.json")
    ref = load_monitoring.reference(request)
    validation = canonical(request["monitoring"]["rows"])
    require(
        ref["evaluation_sha256"] == values["evaluation_reference"]
        and ref["dataset_sha256"] == values["dataset_reference"]
        and ref["source_fingerprint"] == values["source_fingerprint"]
        and ref["model_sha256"] == values["model_sha256"]
        and ref["bundle_sha256"] == values["subject_sha256"]
    )
    require(
        digest(validation) == values["validation"]
        and ref["observations"] == len(request["monitoring"]["rows"])
    )
    require(
        len(
            {
                config["permit_public"],
                request["monitoring"]["reference_public"],
                keys["approver"],
                keys["curator"],
                keys["evaluator"],
                keys["trust"],
            }
        )
        == 6
    )
    refusal = value["actual_refusal"]
    require(
        refusal["campaign_id"] == read_json(state / PROPOSAL)["campaign_id"]
        and (refusal["candidate"], refusal["proposal"], refusal["model"])
        == (values["candidate_reference"], values["proposal_reference"], values["model"])
        and refusal["parent_refusal"] == "release_assurance_required"
        and refusal["job_outcome"] == "rejected"
    )
    return {
        k: values[k]
        for k in (
            "evaluation_reference",
            "dataset_reference",
            "release_subject",
            "model",
            "qualified_candidate_subject",
            "qualified_candidate_model",
        )
    }


def seal(root, state, gate, index, value, private_pin, packets, result):
    if index is None:
        return
    inputs = signed_inputs(root, state, gate, index, value)
    result["input_digests"].update(inputs)
    result["artifact_hashes"].update(
        proposal_packet=index["freeze"][PROPOSAL],
        storage_demo=index["freeze"][DEMO],
        signed_evaluation=inputs["evaluation_reference"],
    )
    write_json(
        state / f"evidence/{gate}-frozen-private.json",
        dict(
            gate=gate,
            index=index,
            private_observation=private_pin,
            retained_packets=packets,
            component_sha256=digest(canonical(result) + b"\n"),
        ),
    )


def replay(root, state, gate, *, pins, report_pin, admission_pin):
    """Caller supplies hashes taken at capture; no SQL, container or cluster calls."""
    from mlsecops import load_gate, monitoring_gate

    mode = MODES[gate]
    report = pinned(state / f"evidence/{gate}.json", report_pin)
    admission = pinned(state / f"evidence/{gate}-frozen-private.json", admission_pin)
    require(admission["gate"] == gate and admission["index"]["freeze"] == owner(gate, pins))
    component = pinned(state / f"evidence/{mode}-gate.json", admission["component_sha256"])
    require(
        component["status"] == "pass"
        and component["release_ready"] is False
        and report["gate"] == gate
        and report["status"] == "pass"
        and type(report["exit_code"]) is int
        and report["exit_code"] == 0
        and report.get("release_ready", False) is False
        and report["source_dirty"] is False
    )
    require(
        canonical(report["cases"]) == canonical(component["cases"])
        and canonical(report["artifact_hashes"]) == canonical(component["artifact_hashes"])
        and canonical(report["metrics"])
        == canonical({"checks": component["checks"], **component["metrics"]})
    )
    require(
        report["source_revision"]
        == component["source_revision"]
        == admission["index"]["source_revision"]
        and canonical(report["input_digests"]) == canonical(component["input_digests"])
    )
    value = pinned(
        state / f"evidence/kubernetes-{mode}-private.json",
        admission["private_observation"],
        4 * 1024**2,
    )
    bindings = signed_inputs(root, state, gate, admission["index"], value)
    require(
        all(
            report["input_digests"][k] == v
            for k, v in {
                **bindings,
                **value["source"],
                **{k: value[k] for k in (*IDENTITY, "qualification_permit_sha256")},
            }.items()
        )
    )
    require(
        report["artifact_hashes"]["proposal_packet"] == pins[PROPOSAL]
        and report["artifact_hashes"]["storage_demo"] == pins[DEMO]
        and report["artifact_hashes"]["signed_evaluation"] == bindings["evaluation_reference"]
    )
    times = {"started": report["started_at"], "finished": report["finished_at"]}
    if gate == "M14":
        native = load_gate.reconcile(value, value["source"], **times)
        packets = load_gate.retained(state, value)
        for name in ("measurement", "overload", "operator", "monitoring"):
            require(canonical(component["metrics"][name]) == canonical(native[name]))
    else:
        monitoring_gate.reconcile(value, value["source"], **times)
        metrics, packets, _ = monitoring_gate.retained(
            state, value, monitoring_gate.artifacts(state, value)
        )
        require(canonical(metrics) == canonical(component["metrics"]))
    require(packets == admission["retained_packets"])
    return dict(
        gate=gate, status="pass", release_ready=False, report_sha256=report_pin, report=report
    )
