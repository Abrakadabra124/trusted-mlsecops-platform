"""Private original M11/M12 preimages and historical offline replay, never M18 acceptance."""

import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

from mlsecops import final_evidence as final
from mlsecops import inference_gate, trust_acceptance, trust_delivery, trust_gate
from mlsecops.contracts import (
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    require_fields,
    safe_child,
)
from mlsecops.storage import object_id
from scripts import frozen_candidate_transfer as transfer
from scripts import shared_serving_native as shared
from scripts import shared_serving_receipt
from scripts.candidate_lineage_native import KNOWN_OWNERS, OWNERS

LIMIT = 16 * 1024**2
TOTAL = 256 * 1024**2
MAX_FILES = transfer.MAX_FILES + 22
SCOPE = "M18-original-shared-primary-not-acceptance"
GATES = ("M11", "M12")
ARTIFACTS = (
    "config.json",
    "request.json",
    "reference.json",
    "probe.json",
    "root-rotation.json",
    "independent-authorities.json",
    "outage.json",
    "blackhole.json",
    "policy-change.json",
    "key-revocation.json",
    "model-revocation.json",
)
M11_FILES = {
    "frozen_binding": "trust-frozen",
    "kubernetes-serving": "kubernetes-serving",
    "release-key-native": "release-key-native",
    "release-key-serving": "release-key-serving",
    "trust-contracts": "trust-contracts",
}
M12_FILES = {"native": "inference-native", "contracts": "inference-contracts"}


def need(condition, reason):
    final.need(condition, "shared-retention-" + reason)


def authority(freeze_pin, freeze, expected, run_owner, report_pins, actual_pin, native_pin):
    # authority() checks shape only. No operational window or fresh-job authorization here.
    transfer.authority(freeze_pin, freeze, expected, run_owner, 1)
    require_fields(report_pins, GATES)
    for pin in (*report_pins.values(), actual_pin, native_pin):
        object_id(pin)
    return decode(
        canonical(
            dict(
                freeze_pin=freeze_pin,
                freeze=freeze,
                expected=expected,
                run_owner=run_owner,
                report_pins=report_pins,
                actual_pin=actual_pin,
                native_pin=native_pin,
            )
        )
    )


def methods(root):
    paths = [m.replace(".", "/") + ".py" for m in inference_gate.inference_contracts.MODULES]
    paths += [
        "scripts/inference_contracts.py",
        "scripts/evaluation_contracts.py",
        "scripts/kube_candidate_native.py",
        "scripts/kube_serving_native.py",
        "scripts/candidate_serving_reader.py",
        "scripts/kube_promotion_native.py",
        "data.lock",
    ]
    return trust_acceptance.materials(root), {p: digest(bounded_read(root / p)) for p in paths}


def inventory(root, reader, owner):
    """Read fixed paths / authenticated closure only; never enumerate consumer state."""
    files, objects = {}, {}

    def store(raw):
        need(0 < len(raw) <= LIMIT, "object-size")
        pin = digest(raw)
        objects[pin] = raw
        need(sum(map(len, objects.values())) <= TOTAL - final.LIMIT, "total-size")
        return pin

    def read(name, limit=LIMIT):
        raw = reader(name, min(limit, LIMIT))
        pin = store(raw)
        need(name not in files or files[name] == pin, "changed-file")
        files[name] = pin
        need(len(files) <= MAX_FILES, "file-count")
        return raw

    def document(name, pin):
        raw = read(name)
        need(digest(raw) == object_id(pin), "original-pin")
        value = decode(raw)
        need(raw == canonical(value) + b"\n", "producer-json")
        transfer.no_credentials(raw)
        return value

    closure, _, _ = transfer.checked_files(
        read, **{k: owner[k] for k in ("freeze_pin", "freeze", "expected")}
    )
    for name in (transfer.RECEIPT, *owner["freeze"]):
        raw = closure[name]
        need(raw == canonical(decode(raw)) + b"\n", "freeze-json")
    early = document(shared.EARLY, owner["actual_pin"])
    full = document(shared.FULL, owner["native_pin"])
    need(full["early_sha256"] == owner["actual_pin"], "handoff")
    actual = early["actual"]
    require_fields(actual["artifact_hashes"], ARTIFACTS)
    epoch = shared.hexadecimal(actual["qualification_campaign_id"], 32)
    for name in ARTIFACTS:
        document("candidate-inference/" + epoch + "/" + name, actual["artifact_hashes"][name])
    common = dict(
        actual["artifact_hashes"],
        shared_native=owner["native_pin"],
        pinned_actual=owner["actual_pin"],
        proposal_packet=owner["freeze"][transfer.delivery.PROPOSAL],
    )
    maps = methods(root)
    reports = {}
    for gate, mapping, method in zip(GATES, (M11_FILES, M12_FILES), maps, strict=True):
        report = document("evidence/" + gate + ".json", owner["report_pins"][gate])
        refs = report["artifact_hashes"]
        method_name = "method_materials" if gate == "M11" else "contract_materials"
        expected = common | {method_name: store(canonical(method))}
        for field, name in mapping.items():
            document("evidence/" + name + ".json", refs[field])
            expected[field] = files["evidence/" + name + ".json"]
        if gate == "M11":
            expected.update(
                storage_demo=owner["freeze"]["storage-demo.json"],
                signed_evaluation=owner["expected"]["evaluation_reference"],
            )
        final.same(refs, expected, "shared-artifact-inventory")
        for ref in refs.values():
            need(ref in objects, "missing-preimage")
        reports[gate] = report
    return files, objects, reports


def semantics(root, view, owner, reports):
    """Ordinary frozen/signature, historical permit, trust and inference checks."""

    def doc(name):
        return decode(bounded_read(safe_child(view, name)))

    index = doc(transfer.RECEIPT)
    values, keys, _ = transfer.delivery.frozen(root, view, index)
    final.same({k: values[k] for k in transfer.IDENTITY}, owner["expected"], "shared-candidate")
    source = {k: values[k] for k in transfer.delivery.SOURCE}
    early, full = doc(shared.EARLY), doc(shared.FULL)
    binding = early["binding"]
    context = dict(
        candidate_reference=values["candidate_reference"],
        evaluation_reference=values["evaluation_reference"],
        policy=decode(bounded_read(root / "policies/local-cpu.json")),
        trust=doc("storage-trust.json"),
        expected=source,
        owners=OWNERS,
        known_owners=list(KNOWN_OWNERS),
    )
    final.same(
        binding,
        dict(
            context=context,
            publisher_public=keys["approver"],
            source=source,
            **{k: values[k] for k in transfer.delivery.IDENTITY},
            proposal_issued_at=values["proposal_issued_at"],
            proposal_expires_at=values["proposal_expires_at"],
            input_files=owner["freeze"],
        ),
        "shared-original-binding",
    )
    original = early["owner"]
    final.subset(
        original,
        dict(
            source=source,
            proposal_sha256=owner["freeze"][transfer.delivery.PROPOSAL],
            inputs={k: v for k, v in owner["freeze"].items() if k != transfer.delivery.PROPOSAL},
        ),
        "shared-owner-inputs",
    )
    # producer_job belongs to the frozen producer, not the M11/M12 consumer job.
    final.subset(
        original["runner"],
        dict(
            GITHUB_RUN_ID=str(owner["run_owner"]["run_id"]),
            GITHUB_RUN_ATTEMPT=str(owner["run_owner"]["run_attempt"]),
        ),
        "shared-run-attempt",
    )
    controlled = full["controlled"]
    need("actual_inference" not in controlled, "controlled-actual")
    need(controlled["actual"] == early["prepared"]["actual"], "controlled-refusal")
    native = dict(controlled, actual_inference=early["actual"])
    for name in ("kubernetes-serving", "inference-native"):
        final.same(doc("evidence/" + name + ".json"), native, "shared-native")
    config = shared.retained(view, early)
    metrics = trust_gate.reconcile(native, source)
    rotation = doc("evidence/release-key-native.json")
    trust_gate.passed(rotation)
    final.subset(
        rotation,
        {k: source[k] for k in ("source_revision", "source_fingerprint")},
        "shared-rotation-source",
    )
    need(
        len(rotation["cases"]) == len(set(rotation["cases"])) == 37
        and rotation["head_sequence"] == rotation["policy_version"] == 4
        and len(set(rotation["rotations"])) == 3,
        "rotation",
    )
    metrics["signer_first_503_seconds"] = trust_gate.release_signers(
        doc("evidence/release-key-serving.json"), source
    )
    joins = trust_delivery.retained(view, native, binding)
    final.same(
        doc("evidence/trust-frozen.json"), dict(binding=binding, joins=joins), "shared-joins"
    )
    final.subset(reports["M11"]["metrics"], metrics | joins, "shared-trust-metrics")
    actual = native["actual_inference"]
    selected = inference_gate.joint_cases(actual, config["permit_envelope"])
    inference_gate.reconcile(
        dict(native, actual_inference=dict(actual, native=dict(actual["native"], cases=selected))),
        source,
    )
    final.subset(
        reports["M12"]["metrics"],
        dict(
            native_cases=len(selected),
            max_golden_error=actual["native"]["max_golden_error"],
        ),
        "shared-inference-metrics",
    )
    for gate, name in (("M11", "trust"), ("M12", "inference")):
        controls = doc("evidence/" + name + "-contracts.json")
        report = reports[gate]
        for packet, count in (
            (controls, controls["checks"]),
            (report, report["metrics"]["checks"]),
        ):
            cases = packet["cases"]
            need(
                packet["status"] == "pass"
                and type(count) is int
                and count == len(cases)
                and count > 0
                and len({c["id"] for c in cases}) == count,
                "cases",
            )
            for case in cases:
                require_fields(case, ("id", "status", "expected", "actual"))
                need(
                    case["status"] == "pass"
                    and canonical(case["expected"]) == canonical(case["actual"]),
                    "case-outcome",
                )
        if gate == "M12":
            final.same(report["cases"], controls["cases"] + selected, "shared-inference-cases")
        else:
            criteria = {
                "actual-candidate-binding",
                "five-clock-cache-faults",
                "still-valid-trust-version-replay",
                "independent-key-model-authorities",
                "signed-approval-expiry",
                "still-valid-release-sequence-replay",
                "authorized-and-denied-whole-bundle-rollback",
                "signer-sql-policy-history",
                *metrics["first_503_seconds"],
                *("signer-" + role for role in metrics["signer_first_503_seconds"]),
                "frozen-proposal-signed-evaluation",
                "production-refusal-controlled-subject-separation",
                "isolated-rotation-cleanup",
            }
            final.same(
                report["cases"],
                controls["cases"]
                + [
                    dict(id="M11-" + name, status="pass", expected=True, actual=True)
                    for name in sorted(criteria)
                ],
                "shared-trust-cases",
            )
    return shared_serving_receipt.receipt(
        view,
        dict(
            M11_PROPOSAL_SHA256=owner["freeze"][transfer.delivery.PROPOSAL],
            M12_PROPOSAL_SHA256=owner["freeze"][transfer.delivery.PROPOSAL],
            M11_DEMO_SHA256=owner["freeze"]["storage-demo.json"],
            M11_M12_ACTUAL_SHA256=owner["actual_pin"],
            M11_M12_NATIVE_SHA256=owner["native_pin"],
        ),
    )


def location(root, destination):
    runtime = safe_child(root, ".runtime")
    path = Path(destination).absolute()
    need(
        all(not p.is_symlink() and not p.is_junction() for p in (path, *path.parents)),
        "destination-link",
    )
    relative = path.resolve().relative_to(runtime)
    need(bool(relative.parts), "destination")
    return safe_child(runtime, relative.as_posix())


def verify(root, parent, files, objects, reports, owner):
    with TemporaryDirectory(prefix="shared-replay-", dir=parent) as temporary:
        view = Path(temporary)
        for name, pin in files.items():
            atomic_write(safe_child(view, name), objects[pin])
        result = semantics(root, view, owner, reports)
    final.clean(root, owner["expected"]["source_revision"], owner["expected"]["source_fingerprint"])
    return result


def retain(
    root,
    state,
    destination,
    *,
    freeze_pin,
    freeze,
    expected,
    run_owner,
    report_pins,
    actual_pin,
    native_pin,
):
    """Call after both reports and cluster cleanup, BEFORE the consumer context exits.

    Destination must be a new owned directory below the producer root/.runtime and
    outside the disposable state. Return the private index pin; emit nothing.
    """
    owner = authority(freeze_pin, freeze, expected, run_owner, report_pins, actual_pin, native_pin)
    final.clean(root, expected["source_revision"], expected["source_fingerprint"])
    target = location(root, destination)
    need(not target.exists() and not target.is_relative_to(Path(state).resolve()), "destination")
    files, objects, reports = inventory(
        root, lambda name, limit: bounded_read(safe_child(state, name), limit), owner
    )
    verify(root, safe_child(root, ".runtime"), files, objects, reports, owner)
    record = dict(
        schema_version=1,
        scope=SCOPE,
        classification=transfer.CLASSIFICATION,
        **owner,
        files=files,
        objects={k: len(v) for k, v in objects.items()},
    )
    raw = canonical(record) + b"\n"
    need(
        len(raw) <= final.LIMIT and sum(map(len, objects.values())) + len(raw) <= TOTAL,
        "index-size",
    )
    pin = digest(raw)
    # Exclusive ownership; failures remove only this newly created destination.
    target.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        for ref, content in {**objects, pin: raw}.items():
            atomic_write(safe_child(target, transfer.CAS + ref), content)
        replay(root, target, index_pin=pin, **owner)
    except BaseException:
        shutil.rmtree(target)
        raise
    return pin


def replay(
    root,
    destination,
    *,
    index_pin,
    freeze_pin,
    freeze,
    expected,
    run_owner,
    report_pins,
    actual_pin,
    native_pin,
):
    """Historical object-only replay with external pins, no Docker/SQL or fresh window."""
    owner = authority(freeze_pin, freeze, expected, run_owner, report_pins, actual_pin, native_pin)
    final.clean(root, expected["source_revision"], expected["source_fingerprint"])
    target = location(root, destination)
    raw = final.blob(target, object_id(index_pin), final.LIMIT)
    record = decode(raw)
    require_fields(
        record, ("schema_version", "scope", "classification", *owner, "files", "objects")
    )
    need(raw == canonical(record) + b"\n", "index-json")
    final.subset(
        record,
        dict(schema_version=1, scope=SCOPE, classification=transfer.CLASSIFICATION, **owner),
        "shared-external-owners",
    )
    files, lengths = record["files"], record["objects"]
    need(isinstance(files, dict) and 0 < len(files) <= MAX_FILES, "files")
    need(isinstance(lengths, dict) and 0 < len(lengths) <= MAX_FILES + 2, "objects")
    for ref, size in lengths.items():
        object_id(ref)
        need(type(size) is int and 0 < size <= LIMIT, "object-size")
    need(sum(lengths.values()) + len(raw) <= TOTAL, "total-size")

    def read(name, limit):
        ref = object_id(files[name])
        value = final.blob(target, ref, limit)
        need(len(value) == lengths[ref], "object-length")
        return value

    collected, objects, reports = inventory(root, read, owner)
    final.same(files, collected, "shared-file-inventory")
    final.same(lengths, {k: len(v) for k, v in objects.items()}, "shared-object-inventory")
    for ref, content in objects.items():
        need(final.blob(target, ref) == content, "stored-preimage")
    # Inspect these three bounded directory levels only, never recursively scan state.
    for directory, names in (
        (target, {"evidence"}),
        (target / "evidence", {"M18-objects"}),
        (target / "evidence/M18-objects", set(objects) | {index_pin}),
    ):
        need({p.name for p in directory.iterdir()} == names, "extra-files")
    result = verify(root, safe_child(root, ".runtime"), collected, objects, reports, owner)
    return dict(
        scope=SCOPE, classification=transfer.CLASSIFICATION, release_ready=False, receipt=result
    )
