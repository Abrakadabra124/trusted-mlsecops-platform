"""Retain one original proposal and join the frozen trio to storage recovery.

Retention authenticates historical material, never extends a native permit. Native
commands stay behind the hosted guard; offline load/replay do not contact SQL.
"""

import math
import os
import sys
import time
from pathlib import Path

from mlsecops import final_evidence, storage_bootstrap
from mlsecops import performance_delivery as delivery
from mlsecops.contracts import bounded_read, canonical, decode, digest, safe_child, write_json
from mlsecops.storage import object_id
from scripts import serving_campaign as campaign
from scripts.controller_delivery import intake_gates

FREEZE = "evidence/M18-frozen-inputs.json"
RECEIPT = "evidence/serving-retention-private.json"
PHASES = ("M23", "M13", "M14", "M15", "M11-M12")
# Exact output of m23_delivery.gates("M11-M12"). The sidecar must be integrated
# before using this workflow; a legacy 17-gate receipt is deliberately rejected.
PARENT_GATES = tuple(sorted((*intake_gates("M11-M12"), "M23")))
CANDIDATE = (
    *delivery.SOURCE,
    "candidate_reference",
    "evaluation_reference",
    "proposal_reference",
    "qualified_candidate_subject",
    "qualified_candidate_model",
)


def window(values, clock, minimum=600):
    """Reserve the existing maximum qualification window, without changing expiry."""
    current = math.ceil(time.time()) if clock is None else clock
    issued, expires = values["proposal_issued_at"], values["proposal_expires_at"]
    delivery.require(type(current) is int and issued <= current < expires)
    delivery.require(current >= values["captured_at"] and expires - current >= minimum)
    return current


def original(root, state, freeze_pin, pins, revision):
    index = delivery.pinned(safe_child(state, FREEZE), freeze_pin)
    delivery.require(index["source_revision"] == revision)
    delivery.require(index["freeze"] == delivery.owner("M14", pins))
    final_evidence.clean(root, revision, index["source_fingerprint"])
    values, _, _ = delivery.frozen(root, state, index)
    return values


def live_source(state, pin):
    owner = delivery.pinned(safe_child(state, "storage.json"), pin)
    delivery.require(storage_bootstrap.validate(state) == owner)
    observed = storage_bootstrap.inspect("container", owner["container_id"])["State"]
    delivery.require(observed["Running"] is True and observed["Status"] == "running")


def retain(root, state, *, freeze_pin, source_pin, pins, revision, clock=None):
    values = original(root, state, freeze_pin, pins, revision)
    live_source(state, source_pin)
    current = window(values, clock)
    receipt = dict(
        schema_version=1,
        freeze_sha256=object_id(freeze_pin),
        source_sql=object_id(source_pin),
        pins=pins,
        captured_at=current,
    )
    path = safe_child(state, RECEIPT)
    if path.exists():
        pin = digest(bounded_read(path))
        previous, _ = load(root, state, pin, revision)
        delivery.require(previous == dict(receipt, captured_at=previous["captured_at"]))
        return pin
    write_json(path, receipt)
    pin = digest(canonical(receipt) + b"\n")
    load(root, state, pin, revision)
    return pin


def load(root, state, pin, revision):
    receipt = delivery.pinned(safe_child(state, RECEIPT), pin)
    delivery.require(type(receipt["schema_version"]) is int and receipt["schema_version"] == 1)
    values = original(root, state, receipt["freeze_sha256"], receipt["pins"], revision)
    delivery.pinned(safe_child(state, "storage.json"), receipt["source_sql"])
    window(values, receipt["captured_at"])
    return receipt, values


def preflight(root, state, pin, revision, phase, *, clock=None):
    delivery.require(phase in PHASES)
    receipt, values = load(root, state, pin, revision)
    live_source(state, receipt["source_sql"])
    current = window(values, clock)
    return dict(
        phase=phase,
        proposal_reference=values["proposal_reference"],
        expires_at=values["proposal_expires_at"],
        remaining_seconds=values["proposal_expires_at"] - current,
        release_ready=False,
    )


def join(parent, summary, values, pins):
    """Keep the original delivery receipt fields used by the unchanged M18 gap map."""
    delivery.require(parent["release_ready"] is False and summary["release_ready"] is False)
    delivery.require(set(parent["reports"]) == set(PARENT_GATES))
    delivery.require(set(summary["reports"]) == set(campaign.GATES))
    delivery.require(parent["proposal_packet"] == pins[delivery.PROPOSAL])
    object_id(parent["security_transition"])
    object_id(parent["source_offline"])
    delivery.require(set(parent["security_capture"]) == {"sources", "inventory", "outage"})
    for pin in parent["security_capture"].values():
        object_id(pin)
    final_evidence.subset(parent["candidate"], {k: values[k] for k in CANDIDATE}, "trio-parent")
    final_evidence.subset(
        summary, {k: values[k] for k in (*delivery.SOURCE, *delivery.IDENTITY)}, "trio-subject"
    )
    delivery.require(
        all(parent["reports"][g] == summary["reports"][g] for g in ("M02", "M03", "M07"))
    )
    return parent | dict(
        reports=parent["reports"] | summary["reports"],
        serving_campaign=summary,
        release_ready=False,
    )


def replay(root, state, *, retention_pin, parent_pin, reports, admissions, transitions, revision):
    """Pure file replay; the hosted caller must first verify both native cleanups."""
    retained, values = load(root, state, retention_pin, revision)
    delivery.require(len(transitions) == 3)
    nodes = campaign.chain(transitions[:2], retained["source_sql"])
    last = transitions[2]
    delivery.require(last["source_sql"] == retained["source_sql"] and last["before"] == nodes[-1])
    for key in ("namespace", "volume"):
        delivery.require(object_id(last["after"][key]) not in {n[key] for n in nodes})
    # Every native gate must have retained the very same original input files.
    for gate in ("M14", "M15"):
        index = delivery.pinned(state / f"evidence/{gate}-frozen-private.json", admissions[gate])[
            "index"
        ]
        delivery.require(index["freeze"] == retained["pins"])
        delivery.require(index["policy_reference"] == values["policy_reference"])
    summary, _ = campaign.replay(
        root,
        state,
        pins=retained["pins"],
        reports=reports,
        admissions=admissions,
        transitions=transitions[:2],
        source_pin=retained["source_sql"],
        revision=revision,
    )
    parent = delivery.pinned(state / "evidence/delivery-candidate.json", parent_pin)
    result = join(parent, summary, values, retained["pins"])
    security = delivery.pinned(
        state / "evidence/M23-delivery-transition.json", parent["security_transition"]
    )
    previous = security["transition"]
    delivery.require(previous["source_sql"] == retained["source_sql"])
    delivery.require(previous["after"] == nodes[0])
    delivery.require(
        security["inputs"]["files"] == retained["pins"] | {"storage.json": retained["source_sql"]}
    )
    for key in ("namespace", "volume"):
        delivery.require(
            object_id(previous["before"][key]) not in {n[key] for n in [*nodes, last["after"]]}
        )
    # The parent verifier already replays its native packets. Recheck its exact
    # public bytes, and bind the controller/intake/serving reports to this freeze.
    for gate, pin in parent["reports"].items():
        report = final_evidence.published_report(state, gate, pin)
        if gate in {"M04", "M05", "M11", "M12", "M21", "M23"}:
            campaign.bind_report(gate, report, values)
        if gate == "M05":
            final_evidence.subset(
                report["input_digests"],
                {
                    k: values[k]
                    for k in (
                        "candidate_reference",
                        "evaluation_reference",
                        "model_sha256",
                        "subject_sha256",
                        "proposal_reference",
                    )
                }
                | {"proposal_packet": retained["pins"][delivery.PROPOSAL]},
                "trio-isolation-proposal",
            )
    result["serving_retention"] = retention_pin
    result["serving_to_joint"] = last
    return result


def main(arguments=None):
    from mlsecops.security_gate import confirm_cleanup
    from scripts.kube_trust_native import hosted
    from scripts.shared_serving_receipt import offline_pin

    args = sys.argv[1:] if arguments is None else arguments
    hosted()
    delivery.require(args in (["retain"], ["replay"], *(["check", p] for p in PHASES)))
    root = Path(__file__).resolve().parents[1]
    state = root / ".runtime"
    env = os.environ
    revision = env["GITHUB_SHA"]
    if args == ["retain"]:
        pin = retain(
            root,
            state,
            freeze_pin=env["M18_FREEZE_SHA256"],
            source_pin=env["SOURCE_SQL"],
            pins={p: env[label] for p, label in delivery.FILES.items()},
            revision=revision,
        )
        print("::add-mask::" + pin)
        with Path(env["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as out:
            print("sha256=" + pin, file=out)
    elif args[0] == "check":
        print(
            canonical(preflight(root, state, env["SERVING_RETENTION"], revision, args[1])).decode()
        )
    else:
        confirm_cleanup(state)
        delivery.require(offline_pin(state) == object_id(env["SOURCE_OFFLINE_SHA256"]))
        result = replay(
            root,
            state,
            retention_pin=env["SERVING_RETENTION"],
            parent_pin=env["PARENT_RECEIPT"],
            reports={g: env[g + "_REPORT"] for g in campaign.GATES},
            admissions={g: env[g + "_ADMISSION"] for g in ("M13", "M14", "M15")},
            transitions=[
                decode(env[k].encode())
                for k in ("PRIVACY_TO_LOAD", "LOAD_TO_MONITORING", "MONITORING_TO_JOINT")
            ],
            revision=revision,
        )
        confirm_cleanup(state)
        delivery.require(offline_pin(state) == env["SOURCE_OFFLINE_SHA256"])
        delivery.require(result["source_offline"] == env["SOURCE_OFFLINE_SHA256"])
        write_json(state / "evidence/delivery-candidate.json", result)
        pin = digest(canonical(result) + b"\n")
        delivery.pinned(state / "evidence/delivery-candidate.json", pin)
        with Path(env["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as out:
            print("receipt=" + pin, file=out)
        print(
            canonical(
                dict(
                    scope="storage-recovery-frozen-trio",
                    release_ready=False,
                    reports=result["reports"],
                    receipt=pin,
                )
            ).decode()
        )


if __name__ == "__main__":
    main()
