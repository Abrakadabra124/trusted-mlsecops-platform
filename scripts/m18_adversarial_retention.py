"""Retain original M08/M09 preimages; no training, runtime, new verdict or release."""

import unittest

from mlsecops import final_evidence as final
from mlsecops.contracts import bounded_read, canonical, decode, digest, now, safe_child
from mlsecops.security_events import hexadecimal
from scripts import poisoning, poisoning_contracts, robustness_contracts, robustness_native
from scripts.evaluation_contracts import case_ids

NAMES = {"M08": "poisoning", "M09": "robustness"}


def contract_manifest(root, gate):
    final.need(gate in NAMES, "adversarial-gate")
    if gate == "M08":
        names = ["evaluation_contracts.py", "poisoning_contracts.py"]
        names.extend(m.removeprefix("scripts.") + ".py" for m in poisoning_contracts.MODULES)
        base = root / "scripts"
    else:
        names = [m.replace(".", "/") + ".py" for m in robustness_contracts.MODULES]
        names += [
            "scripts/robustness_contracts.py",
            "scripts/evaluation_contracts.py",
            "scripts/robustness.py",
            "scripts/robustness_native.py",
            "scripts/poisoning_evidence.py",
            "data.lock",
        ]
        base = root
    return {name: digest(bounded_read(safe_child(base, name))) for name in names}


def material_names(gate):
    final.need(gate in NAMES, "adversarial-gate")
    if gate == "M09":
        return set(robustness_native.MATERIAL_FILES)
    return {
        "report.json",
        "campaign.json",
        "train.json",
        "validation.json",
        "probes.json",
        "triggered.json",
    } | {
        case["id"] + "/" + filename
        for case in poisoning.matrix()
        for filename in (
            "model.onnx",
            "metadata.json",
            "mutation.json",
            "validation-scores.json",
            "security-scores.json",
            "prediction.json",
            "result.json",
        )
    }


def case_inventory(root, gate):
    final.need(gate in NAMES, "adversarial-gate")
    if gate == "M08":
        controlled = case_ids(
            unittest.defaultTestLoader.loadTestsFromNames(poisoning_contracts.MODULES)
        )
        return (
            controlled
            | {"native:" + c["id"] for c in poisoning.matrix()}
            | {
                "primary-material-reconciliation",
                "candidate-lineage-readback",
                "candidate-prediction-replay",
                "candidate-source-unchanged",
            }
        )
    return robustness_contracts.case_ids(root) | {
        "candidate-lineage-readback",
        "frozen-primary-reconciliation",
        "candidate-python-onnx-parity",
        "candidate-full-probe-replay",
        "candidate-domain-abstain",
        "candidate-source-unchanged",
        "candidate-evasion-threshold",
    }


def check(root, gate, report, values, obj):
    refs = final.check_gate(
        gate,
        report,
        values,
        final.timestamp(now()),
        digest(canonical(sorted(case_inventory(root, gate)))),
    )
    final.same(
        sorted(refs),
        sorted(
            (final.PRIMARY[gate], "campaign", "primary_materials", "contracts", "candidate_binding")
        ),
        "adversarial-artifacts",
    )
    for ref in refs.values():
        final.need(digest(obj(ref)) == ref, "adversarial-preimage")
    manifest = decode(obj(refs["primary_materials"]))
    final.same(sorted(manifest), sorted(material_names(gate)), "adversarial-material-inventory")
    native = decode(obj(refs["campaign"]))
    packet = decode(obj(refs[final.PRIMARY[gate]]))
    final.same(native["campaign_id"], packet["campaign_id"], "adversarial-campaign")
    if gate == "M08":
        final.same(manifest["report.json"], refs["campaign"], "adversarial-campaign-file")
    else:
        final.same(native["artifact_hashes"], manifest, "adversarial-campaign-manifest")
    contracts = decode(obj(refs["contracts"]))
    final.same(contracts, contract_manifest(root, gate), "adversarial-contract-source")
    for mapping in (manifest, contracts):
        for ref in mapping.values():
            final.need(digest(obj(ref)) == ref, "adversarial-preimage")
    final.primary(gate, report, obj, values)
    return dict(primary_files=len(manifest), source_files=len(contracts))


def retain(root, state, values, gate, pin):
    final.need(gate in NAMES, "adversarial-gate")
    report = final.published_report(state, gate, pin)
    refs = report["artifact_hashes"]
    name = NAMES[gate]
    objects = {}

    def add(raw, expected=None):
        ref = digest(raw)
        if expected is not None:
            final.same(ref, expected, "adversarial-preimage")
        objects[ref] = raw
        return ref

    raw = final.pinned(safe_child(state, f"evidence/{name}-gate.json"), refs[final.PRIMARY[gate]])
    add(raw)
    primary = decode(raw)
    campaign = safe_child(state, name + "/" + hexadecimal(primary["campaign_id"], 32))
    raw = bounded_read(safe_child(state, f"evidence/{name}.json"))
    native = decode(raw)
    final.same(native["campaign_id"], primary["campaign_id"], "adversarial-campaign")
    add(raw if gate == "M08" else canonical(native), refs["campaign"])
    if gate == "M08":
        manifest = {n: add(bounded_read(safe_child(campaign, n))) for n in material_names(gate)}
    else:
        manifest = native["artifact_hashes"]
        final.same(sorted(manifest), sorted(material_names(gate)), "adversarial-material-inventory")
        for filename, expected in manifest.items():
            add(final.pinned(safe_child(campaign, filename), expected))
    add(canonical(manifest), refs["primary_materials"])
    contracts = contract_manifest(root, gate)
    add(canonical(contracts), refs["contracts"])
    base = root / "scripts" if gate == "M08" else root
    for filename, expected in contracts.items():
        add(final.pinned(safe_child(base, filename), expected))
    add(final.pinned(safe_child(campaign, "candidate-binding.json"), refs["candidate_binding"]))
    # Validate the complete graph before writing. Partial output from an I/O failure
    # cannot become a pass: verify always traverses every externally pinned object.
    check(root, gate, report, values, objects.__getitem__)
    for raw in objects.values():
        final.retain(state, raw)
    return verify(root, state, values, gate, pin)


def verify(root, state, values, gate, pin):
    final.need(gate in NAMES, "adversarial-gate")
    report = final.published_report(state, gate, pin)
    return check(root, gate, report, values, lambda ref: final.blob(state, ref))
