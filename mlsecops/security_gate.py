"""M23 capture on an owned hosted runner and acceptance after verified teardown."""

import math
import os
import sys
from datetime import datetime
from pathlib import Path

from mlsecops import cluster, security_events
from mlsecops.canary_native_evidence import read_pinned
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    safe_child,
    write_json,
)
from mlsecops.inventory import command, source_fingerprint
from mlsecops.private_cli import Arguments
from mlsecops.storage_bootstrap import inspect, validate
from mlsecops.trust_acceptance import materials
from scripts.kube_trust_native import hosted

CANDIDATE_KINDS = {"promotion.denied", "inventory.mismatch"}
STAGES = ("sources", "inventory", "outage")
LIMITATIONS = [
    "Synthetic local-cpu evidence on one owned hosted runner.",
    "Intake uses a controlled worker response. Trust and HTTP identity stimuli use controlled subjects.",
    "Inventory reads the trained candidate and controlled graph faults. The audit-specific denial uses controlled authorization and real promotion storage.",
    "Inference uses a qualification permit. Release approval and M18 require separate evidence.",
]


def require(value):
    if not value:
        raise Rejected("M23_evidence_binding")


def reconcile(sources, candidate, source):
    names = []
    measurements, hashes = {}, {}
    for label, value, kinds in (
        ("sources", sources, security_events.RULES.keys() - CANDIDATE_KINDS),
        ("candidate", candidate, CANDIDATE_KINDS),
    ):
        require(value["cases"] and isinstance(value["cases"], list))
        names.extend(value["cases"])
        require(value["routes"].keys() == kinds)
        for kind, milliseconds in value["routes"].items():
            require(security_events.integer(milliseconds, 0) <= security_events.DELIVERY_MS)
            measurements[kind] = {
                "route": security_events.RULES[kind][3],
                "max_delivery_ms": milliseconds,
            }
        require(value["artifact_hashes"])
        for key, pin in value["artifact_hashes"].items():
            hashes[label + "-" + key] = security_events.hexadecimal(pin)
    require(len(set(names)) == len(names))
    subject = candidate["candidate"]
    security_events.shape(
        subject,
        (
            "candidate_reference",
            "evaluation_reference",
            "model_sha256",
            "image_id",
            "source_revision",
            "source_fingerprint",
        ),
    )
    require(all(subject[name] == value for name, value in source.items()))
    for name in ("candidate_reference", "evaluation_reference", "model_sha256"):
        security_events.hexadecimal(subject[name])
    require(subject["image_id"].startswith("sha256:"))
    security_events.hexadecimal(subject["image_id"][7:])
    sequence = sources["sequence_notice_seconds"]
    require(sequence.keys() == {"ingest-hole", "heartbeat-head-only"})
    heartbeat = sources["heartbeat_notice_seconds"]
    for seconds in (*sequence.values(), heartbeat):
        require(type(seconds) in (float, int) and math.isfinite(seconds) and 0 <= seconds <= 120)
    cases = [dict(id=name, status="pass", expected=True, actual=True) for name in sorted(names)]
    return dict(
        cases=cases,
        checks=len(cases),
        input_digests={
            **subject,
            "model": subject["model_sha256"],
            "release_subject": security_events.hexadecimal(candidate["release_subject"]),
        },
        artifact_hashes=hashes,
        metrics=dict(
            routes=measurements,
            sequence_notice_seconds=sequence,
            heartbeat_notice_seconds=heartbeat,
            outage=candidate["metrics"],
        ),
    )


def confirm_cleanup(state):
    marker = validate(state)
    require(inspect("container", marker["container_id"])["State"]["Running"] is False)
    require(cluster.NAME not in command(["kind", "get", "clusters"]).splitlines())


def source_state(root):
    require(not command(["git", "-C", str(root), "status", "--porcelain"]))
    return dict(
        source_revision=command(["git", "-C", str(root), "rev-parse", "HEAD"]),
        source_fingerprint=source_fingerprint(root),
    )


def stage_path(state, name):
    require(name in STAGES)
    return safe_child(state, "evidence/M23-" + name + ".json")


def runner():
    # A rerun of a hosted workflow must capture a new set of packets.
    return {
        name: str(security_events.integer(int(os.environ[name])))
        for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
    }


def delivery_inputs(state):
    if "M23_DEMO_SHA256" not in os.environ:
        return None
    demo_pin = security_events.hexadecimal(os.environ["M23_DEMO_SHA256"])
    proposal_pin = security_events.hexadecimal(os.environ.get("M23_PROPOSAL_SHA256"))
    demo = decode(read_pinned(safe_child(state, "storage-demo.json"), demo_pin))
    proposal = decode(read_pinned(safe_child(state, "evidence/release-native.json"), proposal_pin))
    security_events.shape(proposal["source"], ("image_id", "source_revision", "source_fingerprint"))
    require(demo["candidate"]["metadata"]["model_digest"] == proposal["model_sha256"])
    return dict(
        frozen_demo=demo_pin,
        proposal_packet=proposal_pin,
        proposal_reference=proposal["proposal_reference"],
        candidate_reference=demo["candidate"]["candidate_reference"],
        evaluation_reference=demo["evaluation_reference"],
        model_sha256=proposal["model_sha256"],
        release_subject=proposal["subject_sha256"],
        **proposal["source"],
    )


def capture(root, state, name, operation):
    hosted()
    path = stage_path(state, name)
    source, method = source_state(root), digest(canonical(materials(root)))
    delivery = delivery_inputs(state)
    if delivery is not None:
        require(all(delivery[k] == v for k, v in source.items()))
    started = now()
    binding = operation(root, state)
    require(source_state(root) == source and digest(canonical(materials(root))) == method)
    require(delivery_inputs(state) == delivery)
    record = dict(
        schema_version=1,
        stage=name,
        owner=runner(),
        started_at=started,
        finished_at=now(),
        source=source,
        methods=method,
        binding=binding,
        **({"delivery": delivery} if delivery is not None else {}),
    )
    write_json(path, record)
    content = bounded_read(path)
    require(content == canonical(record) + b"\n")
    return digest(content)


def read_stage(state, name, pin, source, method, owner, delivery=None):
    raw = bounded_read(stage_path(state, name))
    require(digest(raw) == security_events.hexadecimal(pin))
    record = decode(raw)
    security_events.shape(
        record,
        (
            "schema_version",
            "stage",
            "owner",
            "started_at",
            "finished_at",
            "source",
            "methods",
            "binding",
            *(("delivery",) if delivery is not None else ()),
        ),
    )
    security_events.version(record["schema_version"])
    require(
        record["stage"] == name
        and record["owner"] == owner
        and record["source"] == source
        and record["methods"] == method
        and record.get("delivery") == delivery
    )
    return record


def qualify(root, state):
    hosted()
    from mlsecops import security_gate_candidate, security_gate_sources

    root, state = Path(root).resolve(), Path(state).resolve()
    source, method, owner = source_state(root), digest(canonical(materials(root))), runner()
    pins = {name: os.environ["M23_" + name.upper() + "_SHA256"] for name in STAGES}
    delivery = delivery_inputs(state)
    packets = {
        name: read_stage(state, name, pins[name], source, method, owner, delivery)
        for name in STAGES
    }
    times = [
        datetime.fromisoformat(packets[name][field])
        for name in STAGES
        for field in ("started_at", "finished_at")
    ]
    require(
        all(t.utcoffset() is not None for t in times)
        and times == sorted(times)
        and times[-1] <= datetime.fromisoformat(now())
    )
    confirm_cleanup(state)
    sources = security_gate_sources.replay(root, state, packets["sources"]["binding"])
    candidate = security_gate_candidate.replay(
        root,
        state,
        inventory_pin=packets["inventory"]["binding"],
        outage_pin=packets["outage"]["binding"],
    )
    sealed = datetime.fromisoformat(candidate["proposal_finished_at"])
    require(sealed.utcoffset() is not None and sealed <= times[0])
    evidence = reconcile(sources, candidate, source)
    if delivery is not None:
        inputs = evidence["input_digests"]
        require(
            evidence["artifact_hashes"]["candidate-outage-proposal_sha256"]
            == delivery["proposal_packet"]
            and all(inputs[k] == delivery[k] for k in (*candidate["candidate"], "release_subject"))
        )
        inputs["proposal_reference"] = delivery["proposal_reference"]
        evidence["artifact_hashes"]["frozen_demo"] = delivery["frozen_demo"]
    evidence["artifact_hashes"].update(
        {"method_materials": method, **{"stage-" + k: v for k, v in pins.items()}}
    )
    return dict(
        **evidence,
        status="pass",
        source_dirty=False,
        started_at=packets["sources"]["started_at"],
        finished_at=now(),
        release_ready=False,
        limitations=LIMITATIONS.copy(),
    )


def main():
    name = "unknown"
    try:
        parser = Arguments()
        parser.add_argument("stage", choices=STAGES)
        name = parser.parse_args().stage
        hosted()
        from mlsecops import security_gate_candidate, security_gate_sources

        functions = dict(
            sources=security_gate_sources.capture,
            inventory=security_gate_candidate.capture_inventory,
            outage=security_gate_candidate.capture_outage,
        )
        root = Path(__file__).resolve().parents[1]
        pin = capture(root, root / ".runtime", name, functions[name])
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            print("sha256=" + pin, file=output)
        print(canonical(dict(stage=name, primary_manifest_sha256=pin)).decode())
        return 0
    except Exception as error:
        from scripts.kube_load_native import failure_site

        diagnostic = dict(stage=name, status="fail", site=failure_site(error))
        if name == "outage":
            from scripts.kube_security_outage_native import failure_report

            detail = failure_report(error)
            diagnostic.update(request=detail["request"], callers=detail["callers"])
        print(canonical(diagnostic).decode(), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
