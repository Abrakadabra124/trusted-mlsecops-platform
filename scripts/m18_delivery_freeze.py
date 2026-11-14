"""Keep the original signed proposal available for independent M18 replay after SQL stops."""

import os
import sys
from pathlib import Path

from mlsecops import final_evidence, release_bundle, reproducibility_offline
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


def replay(
    root,
    state,
    pin,
    *,
    early_reports=None,
    evaluation_pin=None,
    integrity_pin=None,
    reproducibility_pin=None,
):
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
    if integrity_pin is not None:
        verify_integrity(root, state, values, integrity_pin)
        summary.setdefault("verified_source_reports", {})["M03"] = integrity_pin
    if reproducibility_pin is not None:
        summary["reproducibility_metrics"] = verify_reproducibility(
            state, values, reproducibility_pin
        )
        summary.setdefault("verified_source_reports", {})["M06"] = reproducibility_pin
    return summary


def verify_reproducibility(state, values, pin):
    report = final_evidence.published_report(state, "M06", pin)
    refs = final_evidence.check_gate(
        "M06",
        report,
        values,
        final_evidence.timestamp(now()),
        digest(canonical(reproducibility_offline.CASE_IDS)),
    )

    def retain(path, ref, *, json_line=False):
        raw = bounded_read(safe_child(state, path))
        if json_line:
            # Native campaign and vectors are pinned as canonical JSON before the file LF.
            final_evidence.need(raw.endswith(b"\n"), "repeat-json-line")
            raw = raw[:-1]
        final_evidence.same(digest(raw), ref, "repeat-material-digest")
        final_evidence.retain(state, raw)
        return raw

    packet = decode(
        retain("evidence/reproducibility-qualification.json", refs["reproducibility_qualification"])
    )
    campaign = "reproducibility/" + hexadecimal(packet["campaign_id"], 32)
    native = decode(
        retain(campaign + "/evidence/reproducibility.json", refs["native_campaign"], json_line=True)
    )
    retain(campaign + "/candidate-replay.json", refs["candidate_replay"])
    retained_datasets = set()
    for name, record in zip(reproducibility_offline.NAMES, native["records"], strict=True):
        path = campaign + "/candidates/" + hexadecimal(record["run_id"], 32)
        retain(path + "/model.onnx", refs["model:" + name])
        retain(path + "/golden-scores.json", refs["vector:" + name], json_line=True)
        metadata = decode(retain(path + "/run.json", refs["metadata:" + name]))
        dataset = hexadecimal(metadata["dataset_id"], 64)
        if dataset not in retained_datasets:
            for filename in ("train.json", "validation.json", "holdout.json"):
                retain(
                    campaign + "/approved/" + dataset + "/" + filename,
                    metadata["materials"][filename]["sha256"],
                )
            retained_datasets.add(dataset)
    final_evidence.primary("M06", report, lambda ref: final_evidence.blob(state, ref), values)
    return report["metrics"]


def verify_integrity(root, state, values, pin):
    contract = decode(bounded_read(root / "policies/m18-integrity.json"))
    report = final_evidence.published_report(state, "M03", pin)
    refs = final_evidence.check_gate(
        "M03", report, values, final_evidence.timestamp(now()), contract["case_inventory"]
    )
    components = ("filesystem", "storage", "pipeline")
    final_evidence.same(
        sorted(refs), sorted([*components, "integrity_qualification"]), "integrity-artifacts"
    )

    def retain_file(filename, ref):
        raw = final_evidence.pinned(safe_child(state, "evidence/" + filename), ref)
        final_evidence.retain(state, raw)
        return decode(raw)

    packet = retain_file("integrity-qualification.json", refs["integrity_qualification"])
    expected_cases = {}
    counts = {"integration": 2}
    for name in components:
        content = retain_file("M03-" + name + ".json", refs[name])
        final_evidence.same(content["status"], "pass", "integrity-component")
        final_evidence.check_cases("M03", content["cases"])
        pairs = {c["id"]: [c["expected"], c["actual"]] for c in content["cases"]}
        final_evidence.same(digest(canonical(pairs)), contract[name], "integrity-outcomes")
        expected_cases.update({name + ":" + k: v for k, v in pairs.items()})
        counts[name] = len(pairs)
    snapshot = values["integrity_snapshot"]
    for field in ("approved_sql_hashes_before", "approved_sql_hashes_after"):
        final_evidence.same(packet[field], snapshot, "integrity-snapshot")
    expected_cases["integration:approved-sql-hashes-unchanged"] = [snapshot, snapshot]
    expected_cases["integration:idempotent-sql-publication"] = [values["dataset_reference"]] * 2
    final_evidence.same(
        {c["id"]: [c["expected"], c["actual"]] for c in report["cases"]},
        expected_cases,
        "integrity-cases",
    )
    final_evidence.same(packet["component_checks"], counts, "integrity-count")
    final_evidence.same(
        report["metrics"], {"checks": sum(counts.values()), **counts}, "integrity-count"
    )
    final_evidence.primary("M03", report, lambda ref: final_evidence.blob(state, ref), values)


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
    elif sys.argv[1:] == ["replay-m06"]:
        print(
            canonical(
                replay(
                    root,
                    state,
                    os.environ["M18_FREEZE_SHA256"],
                    reproducibility_pin=os.environ["M06_REPORT_SHA256"],
                )
            ).decode()
        )
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
                    integrity_pin=os.environ["M03_REPORT_SHA256"],
                )
            ).decode()
        )
    else:
        raise Rejected("M18_freeze_arguments")


if __name__ == "__main__":
    try:
        main()
    except (final_evidence.Invalid, final_evidence.Missing) as error:
        sys.exit(f"M18 frozen input verification failed ({error})")
    except (Rejected, OSError, KeyError, TypeError, ValueError):
        sys.exit("M18 frozen input verification failed")
