"""Bind existing defensive M23 captures to the joint delivery's original candidate.

Order: freeze -> sources -> inventory -> outage (source SQL online) -> fresh
serving cluster -> M11/M12 actual -> recovery -> SQL stop/witness -> controlled
rotations -> cluster teardown -> ordinary M23 gate -> delivery receipt. Outage
prepare reads the original signed proposal from SQL; it cannot run after stop.
Never renew the proposal or reuse mutable M23 authorities for M11/M12.
"""

import os
import sys
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from mlsecops import security_events as schema
from mlsecops import security_gate
from mlsecops.canary_native_evidence import read_pinned
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    safe_child,
    write_json,
)
from scripts import controller_delivery, serving_campaign, shared_serving_receipt
from scripts.kube_trust_native import hosted

STAGES = security_gate.STAGES
FILES = {
    "M23_DEMO_SHA256": "storage-demo.json",
    "M23_PROPOSAL_SHA256": "evidence/release-native.json",
    "M23_KEYS_FILE_SHA256": "trusted-keys.json",
    "M23_TRUST_SHA256": "storage-trust.json",
    "M23_SQL_SHA256": "storage.json",
}
# Public owner inputs used by the existing outage verifier. Never copy keys/tokens.
OWNER_FILES = ("resources.json", "materials/identity.json", "materials/registry.json")
REPORT_FIELDS = (
    "schema_version",
    "gate",
    "status",
    "profile",
    "started_at",
    "finished_at",
    "policy_digest",
    "source_revision",
    "input_digests",
    "cases",
    "metrics",
    "artifact_hashes",
    "exit_code",
    "redaction_version",
    "residual_risks",
    "source_dirty",
)


def require(value):
    if not value:
        raise Rejected("M23_delivery_binding")


def same(actual, expected):
    # Canonical comparison distinguishes bool from int throughout nested schemas.
    require(canonical(actual) == canonical(expected))


def pinned(path, pin):
    raw = read_pinned(path, schema.hexadecimal(pin))
    value = decode(raw)
    require(raw == canonical(value) + b"\n")
    return value


def inputs(state, env):
    files = {name: schema.hexadecimal(env[key]) for key, name in FILES.items()}
    values = {
        name: decode(read_pinned(safe_child(state, name), pin)) for name, pin in files.items()
    }
    demo, proposal = values["storage-demo.json"], values["evidence/release-native.json"]
    meta, source = demo["candidate"]["metadata"], proposal["source"]
    schema.shape(source, ("source_revision", "source_fingerprint", "image_id"))
    schema.hexadecimal(source["source_revision"], 40)
    schema.hexadecimal(source["source_fingerprint"])
    require(type(source["image_id"]) is str and source["image_id"].startswith("sha256:"))
    schema.hexadecimal(source["image_id"][7:])
    same({k: meta[k] for k in source}, source)
    require(source["source_revision"] == env["GITHUB_SHA"])
    require(
        proposal["status"] == "pass"
        and proposal["source_dirty"] is False
        and proposal["release_ready"] is False
    )
    require(meta["model_digest"] == proposal["model_sha256"])
    subject = dict(
        **source,
        candidate_reference=demo["candidate"]["candidate_reference"],
        evaluation_reference=demo["evaluation_reference"],
        model_sha256=proposal["model_sha256"],
        release_subject=proposal["subject_sha256"],
        proposal_reference=proposal["proposal_reference"],
        policy_digest=meta["policy_digest"],
    )
    for key in subject.keys() - source.keys():
        schema.hexadecimal(subject[key])
    return dict(**subject, files=files)


def path(state, stage):
    require(stage in STAGES)
    return safe_child(state, "evidence/M23-delivery-" + stage + ".json")


def chain(root, state, env, count=3):
    current = inputs(state, env)
    source = security_gate.source_state(root)
    same(source, {k: current[k] for k in ("source_revision", "source_fingerprint")})
    methods, owner = digest(canonical(security_gate.materials(root))), security_gate.runner()
    previous, records, times = None, {}, []
    for stage in STAGES[:count]:
        pin = schema.hexadecimal(env["M23_" + stage.upper() + "_DELIVERY_SHA256"])
        record = pinned(path(state, stage), pin)
        schema.shape(
            record, ("schema_version", "stage", "owner", "inputs", "stage_sha256", "previous")
        )
        schema.version(record["schema_version"])
        stage_pin = schema.hexadecimal(env["M23_" + stage.upper() + "_SHA256"])
        same(
            record,
            dict(
                schema_version=1,
                stage=stage,
                owner=owner,
                inputs=current,
                stage_sha256=stage_pin,
                previous=previous,
            ),
        )
        packet = security_gate.read_stage(state, stage, stage_pin, source, methods, owner)
        times.extend(datetime.fromisoformat(packet[k]) for k in ("started_at", "finished_at"))
        records[stage], previous = record, pin
    require(all(t.utcoffset() is not None for t in times) and times == sorted(times))
    return records


def operations():
    from mlsecops import security_gate_candidate, security_gate_sources

    return dict(
        sources=security_gate_sources.capture,
        inventory=security_gate_candidate.capture_inventory,
        outage=security_gate_candidate.capture_outage,
    )


def capture(root, state, stage, env):
    require(stage in STAGES)
    index = STAGES.index(stage)
    chain(root, state, env, index)
    original = inputs(state, env)
    # A stage cannot silently replace an earlier capture on the same run/attempt.
    destination = path(state, stage)
    require(not destination.exists() and not security_gate.stage_path(state, stage).exists())
    pin = security_gate.capture(root, state, stage, operations()[stage])
    same(inputs(state, env), original)
    record = dict(
        schema_version=1,
        stage=stage,
        owner=security_gate.runner(),
        inputs=original,
        stage_sha256=pin,
        previous=None
        if index == 0
        else env["M23_" + STAGES[index - 1].upper() + "_DELIVERY_SHA256"],
    )
    write_json(destination, record)
    return dict(sha256=pin, delivery=digest(canonical(record) + b"\n"))


def transition(root, state, env):
    chain(root, state, env)
    original = inputs(state, env)
    retired = safe_child(state, "M23-retired-serving")
    destination = safe_child(state, "evidence/M23-delivery-transition.json")
    require(not retired.exists() and not destination.exists())
    owner_files = {
        name: digest(bounded_read(safe_child(state, "kubernetes-security/" + name)))
        for name in OWNER_FILES
    }
    packet = serving_campaign.transition(state, retired, env["M23_SQL_SHA256"])
    for name, pin in owner_files.items():
        read_pinned(safe_child(retired, "kubernetes-security/" + name), pin)
    same(inputs(state, env), original)
    record = dict(
        schema_version=1,
        inputs=original,
        transition=packet,
        outage_delivery=env["M23_OUTAGE_DELIVERY_SHA256"],
        owner_files=owner_files,
    )
    validate_transition(record, original, env)
    write_json(destination, record)
    return dict(sha256=digest(canonical(record) + b"\n"))


def validate_transition(record, original, env):
    schema.shape(
        record, ("schema_version", "inputs", "transition", "outage_delivery", "owner_files")
    )
    schema.version(record["schema_version"])
    same(record["inputs"], original)
    same(record["outage_delivery"], env["M23_OUTAGE_DELIVERY_SHA256"])
    schema.shape(record["owner_files"], OWNER_FILES)
    for pin in record["owner_files"].values():
        schema.hexadecimal(pin)
    packet = record["transition"]
    schema.shape(packet, ("before", "after", "source_sql"))
    same(packet["source_sql"], env["M23_SQL_SHA256"])
    for side in ("before", "after"):
        schema.shape(packet[side], ("namespace", "volume"))
        for value in packet[side].values():
            schema.hexadecimal(value)
    require(all(packet["before"][k] != packet["after"][k] for k in ("namespace", "volume")))


@contextmanager
def authority(root, state, env):
    """Read the original public owner after teardown, then restore the late owner.

    The legacy verifier resolves three public files at a fixed runtime path.
    Preserve their exact late-campaign bytes even on replay failure. SQL and the
    cluster must be offline before any swap; neither credentials nor keys move.
    """
    chain(root, state, env)
    record = pinned(state / "evidence/M23-delivery-transition.json", env["M23_TRANSITION_SHA256"])
    validate_transition(record, inputs(state, env), env)
    offline = schema.hexadecimal(env["SOURCE_OFFLINE_SHA256"])
    same(shared_serving_receipt.offline_pin(state), offline)
    security_gate.confirm_cleanup(state)
    originals = {
        name: read_pinned(safe_child(state, "M23-retired-serving/kubernetes-security/" + name), pin)
        for name, pin in record["owner_files"].items()
    }
    current = {
        name: bounded_read(safe_child(state, "kubernetes-security/" + name)) for name in OWNER_FILES
    }
    try:
        for name, raw in originals.items():
            atomic_write(safe_child(state, "kubernetes-security/" + name), raw)
        yield
    finally:
        for name, raw in current.items():
            atomic_write(safe_child(state, "kubernetes-security/" + name), raw)
        for name, raw in current.items():
            same(
                digest(bounded_read(safe_child(state, "kubernetes-security/" + name))), digest(raw)
            )
        same(shared_serving_receipt.offline_pin(state), offline)


def gates(serving_gate):
    original = controller_delivery.intake_gates(serving_gate)
    return tuple(sorted((*original, "M23"))) if serving_gate == "M11-M12" else original


def receipt(root, state, parent, env):
    chain(root, state, env)
    original = inputs(state, env)
    expected = {
        k: original[k]
        for k in (
            "source_revision",
            "source_fingerprint",
            "image_id",
            "candidate_reference",
            "evaluation_reference",
            "proposal_reference",
        )
    } | dict(
        qualified_candidate_model=original["model_sha256"],
        qualified_candidate_subject=original["release_subject"],
    )
    same(parent["candidate"], expected)
    require(parent["release_ready"] is False)
    same(sorted(parent["reports"]), sorted(controller_delivery.intake_gates("M11-M12")))
    same(parent["proposal_packet"], env["M23_PROPOSAL_SHA256"])
    for gate, pin in parent["reports"].items():
        read_pinned(state / "evidence" / (gate + ".json"), schema.hexadecimal(pin))
    transition_pin = schema.hexadecimal(env["M23_TRANSITION_SHA256"])
    moved = pinned(state / "evidence/M23-delivery-transition.json", transition_pin)
    validate_transition(moved, original, env)
    offline = schema.hexadecimal(env["SOURCE_OFFLINE_SHA256"])
    same(shared_serving_receipt.offline_pin(state), offline)
    report_pin = schema.hexadecimal(env["M23_REPORT_SHA256"])
    report = pinned(state / "evidence/M23.json", report_pin)
    schema.shape(report, REPORT_FIELDS)
    schema.version(report["schema_version"])
    schema.version(report["redaction_version"])
    # Replay the existing signatures, all seven routes, deadlines, outage and
    # cleanup checks. A resealed summary or a different candidate is insufficient.
    with authority(root, state, env):
        replayed = security_gate.qualify(root, state)
    bound = {
        k: original[k]
        for k in (
            "source_revision",
            "source_fingerprint",
            "image_id",
            "candidate_reference",
            "evaluation_reference",
            "model_sha256",
            "release_subject",
        )
    } | dict(model=original["model_sha256"])
    same(replayed["input_digests"], bound)
    same(
        replayed["artifact_hashes"]["candidate-outage-proposal_sha256"], env["M23_PROPOSAL_SHA256"]
    )
    same(
        {
            k: report[k]
            for k in (
                "gate",
                "status",
                "exit_code",
                "profile",
                "source_dirty",
                "source_revision",
                "policy_digest",
            )
        },
        dict(
            gate="M23",
            status="pass",
            exit_code=0,
            profile="local-cpu",
            source_dirty=False,
            source_revision=original["source_revision"],
            policy_digest=original["policy_digest"],
        ),
    )
    same(
        {k: report[k] for k in ("input_digests", "artifact_hashes", "cases", "started_at")},
        {k: replayed[k] for k in ("input_digests", "artifact_hashes", "cases", "started_at")},
    )
    same(report["metrics"], dict(checks=replayed["checks"], **replayed["metrics"]))
    same(report["residual_risks"], replayed["limitations"])
    times = [
        datetime.fromisoformat(t)
        for t in (report["started_at"], report["finished_at"], replayed["finished_at"])
    ]
    require(all(t.utcoffset() is not None for t in times) and times == sorted(times))
    same(inputs(state, env), original)
    same(shared_serving_receipt.offline_pin(state), offline)
    return parent | dict(
        reports=parent["reports"] | {"M23": report_pin},
        security_capture={
            stage: env["M23_" + stage.upper() + "_DELIVERY_SHA256"] for stage in STAGES
        },
        security_transition=transition_pin,
        source_offline=offline,
    )


def main():
    hosted()
    root = Path(__file__).resolve().parents[1]
    state, env = root / ".runtime", os.environ
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "capture":
        output = capture(root, state, args[1], env)
    elif args == ["transition"]:
        output = transition(root, state, env)
    elif args == ["offline"]:
        output = dict(sha256=shared_serving_receipt.offline_pin(state))
    elif args == ["gate"]:
        from mlsecops import acceptance

        with authority(root, state, env):
            report = acceptance.report("M23", "local-cpu", root, state)
        write_json(state / "evidence/M23.json", report)
        require(
            report["status"] == "pass"
            and type(report["exit_code"]) is int
            and report["exit_code"] == 0
        )
        output = dict(sha256=digest(canonical(report) + b"\n"))
    elif args == ["receipt"]:
        pins = dict(
            demo_pin=env["M17_DEMO_SHA256"],
            proposal_pin=env["M17_PROPOSAL_SHA256"],
            revision=env["GITHUB_SHA"],
        )
        scoped = controller_delivery.reconcile(state, keys_pin=env["M17_KEYS_SHA256"], **pins)
        serving = env["DELIVERY_SERVING_GATE"]
        parent = controller_delivery.intake_delivery(state, pins, scoped, serving)
        result = receipt(root, state, parent, env) if serving == "M11-M12" else parent
        print(canonical(result).decode())
        return
    else:
        raise Rejected("M23_delivery_arguments")
    with Path(env["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as out:
        for key, value in output.items():
            print(key + "=" + value, file=out)


if __name__ == "__main__":
    try:
        main()
    except (Rejected, OSError, KeyError, TypeError, ValueError):
        sys.exit("M23 delivery verification failed")
