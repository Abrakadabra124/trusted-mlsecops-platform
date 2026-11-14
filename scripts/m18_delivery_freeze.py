"""Keep the original signed proposal available for independent M18 replay after SQL stops."""

import os
import sys
from pathlib import Path

from mlsecops import final_evidence, release_bundle
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
from mlsecops.security_events import hexadecimal
from scripts.kube_trust_native import hosted
from scripts.serving_output_native import source

RECEIPT = "evidence/M18-frozen-inputs.json"
PRIMARY = {"M01": "foundation-qualification.json", "M02": "data-qualification.json"}


def capture(root, state, freeze, revision):
    live = source(root, "trusted-mlsecops:dev")
    if live["source_revision"] != revision:
        raise Rejected("M18_freeze_source_changed")
    proposal = decode(
        final_evidence.pinned(
            safe_child(state, "evidence/release-native.json"),
            freeze["evidence/release-native.json"],
        )
    )
    keys = decode(
        final_evidence.pinned(safe_child(state, "trusted-keys.json"), freeze["trusted-keys.json"])
    )
    campaign = hexadecimal(proposal["campaign_id"], 32)
    policy = decode(
        bounded_read(safe_child(state, "release-proposals/" + campaign + "/policy-envelope.json"))
    )
    package = release_bundle.load(
        safe_child(state, "storage-clients/serving"),
        proposal["proposal_reference"],
        publisher_public=keys["approver"],
    )
    if release_bundle.index(package["envelope"], keys["approver"])["release_id"] != campaign:
        raise Rejected("M18_freeze_campaign_changed")
    final_evidence.retain_package(state, package)
    receipt = dict(
        schema_version=1,
        **live,
        freeze=freeze,
        policy_reference=final_evidence.retain(state, canonical(policy)),
    )
    final_evidence.frozen(root, state, receipt, revision, live["source_fingerprint"])
    path = safe_child(state, RECEIPT)
    write_json(path, receipt)
    pin = digest(canonical(receipt) + b"\n")
    final_evidence.pinned(path, pin)
    return pin


def replay(root, state, pin, *, early_reports=None, evaluation_pin=None):
    receipt = decode(final_evidence.pinned(safe_child(state, RECEIPT), pin))
    revision, fingerprint = receipt["source_revision"], receipt["source_fingerprint"]
    final_evidence.clean(root, revision, fingerprint)
    values, _, _ = final_evidence.frozen(root, state, receipt, revision, fingerprint)
    summary = {
        "scope": "offline-original-proposal-materials",
        "release_ready": False,
        "frozen_inputs_sha256": pin,
        **{
            key: values[key]
            for key in (
                "source_revision",
                "candidate_reference",
                "evaluation_reference",
                "model",
                "release_subject",
                "proposal_reference",
            )
        },
    }
    if early_reports is not None:
        summary["verified_source_reports"] = verify_early(root, state, values, early_reports)
    if evaluation_pin is not None:
        verify_evaluation(root, state, values, evaluation_pin)
        summary.setdefault("verified_source_reports", {})["M07"] = evaluation_pin
    return summary


def verify_evaluation(root, state, values, pin):
    from mlsecops.evaluation_gate import contract_source

    report = final_evidence.published_report(state, "M07", pin)
    names = {
        section + ":" + name
        for section, cases in final_evidence.evaluation_cases().items()
        for name in cases
    }
    names.add("signed-materials-reconciliation")
    refs = final_evidence.check_gate(
        "M07", report, values, final_evidence.timestamp(now()), digest(canonical(sorted(names)))
    )
    final_evidence.same(
        report["input_digests"]["host_contracts"],
        contract_source(root),
        "evaluation-contract-source",
    )
    raw = final_evidence.pinned(
        safe_child(state, "evidence/evaluation-gate.json"), refs["evaluation_gate"]
    )
    packet = decode(raw)
    campaign = hexadecimal(packet["campaign_id"], 32)
    final_evidence.retain(state, raw)
    for name in ("contracts", "native", "budget"):
        path = safe_child(state, f"evaluation-gate/{campaign}/{name}.json")
        final_evidence.retain(state, final_evidence.pinned(path, refs[name]))
    for ref in refs.values():
        final_evidence.blob(state, ref)
    final_evidence.primary("M07", report, lambda ref: final_evidence.blob(state, ref), values)


def verify_early(root, state, values, pins):
    # The expected outcomes belong to the checked-out policy and precede the run.
    expected = decode(bounded_read(root / "policies/m18-foundation-intake.json"))
    final_evidence.same(sorted(pins), sorted(PRIMARY), "early-gates")
    for gate, filename in PRIMARY.items():
        report = final_evidence.published_report(state, gate, pins[gate])
        inventory = expected[gate]
        artifacts = final_evidence.check_gate(
            gate,
            report,
            values,
            final_evidence.timestamp(now()),
            digest(canonical(sorted(inventory))),
        )
        final_evidence.need(artifacts.keys() == {final_evidence.PRIMARY[gate]}, "early-artifacts")
        for case in report["cases"]:
            outcome = inventory[case["id"]]
            final_evidence.same(
                case["expected"], True if outcome is True else "reject", "early-expected"
            )
            final_evidence.same(case["actual"], outcome, "early-observation")
        packet_pin = artifacts[final_evidence.PRIMARY[gate]]
        packet = final_evidence.pinned(safe_child(state, "evidence/" + filename), packet_pin)
        final_evidence.retain(state, packet)
        final_evidence.primary(gate, report, lambda ref: final_evidence.blob(state, ref), values)
    return pins


def main():
    hosted()
    root = Path(__file__).resolve().parents[1]
    state = root / ".runtime"
    if sys.argv[1:] == ["capture"]:
        freeze = {
            name: os.environ[var]
            for name, var in (
                ("storage-demo.json", "M18_DEMO_SHA256"),
                ("storage-trust.json", "M18_TRUST_SHA256"),
                ("trusted-keys.json", "M18_KEYS_FILE_SHA256"),
                ("evidence/release-native.json", "M18_PROPOSAL_SHA256"),
            )
        }
        pin = capture(root, state, freeze, os.environ["GITHUB_SHA"])
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as out:
            print("sha256=" + pin, file=out)
    elif sys.argv[1:] == ["replay"]:
        pins = {gate: os.environ[gate + "_REPORT_SHA256"] for gate in PRIMARY}
        print(
            canonical(
                replay(
                    root,
                    state,
                    os.environ["M18_FREEZE_SHA256"],
                    early_reports=pins,
                    evaluation_pin=os.environ["M07_REPORT_SHA256"],
                )
            ).decode()
        )
    else:
        raise Rejected("M18_freeze_arguments")


if __name__ == "__main__":
    try:
        main()
    except (Rejected, OSError, KeyError, TypeError, ValueError):
        sys.exit("M18 frozen input verification failed")
