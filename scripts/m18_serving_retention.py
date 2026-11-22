"""Collect original trio preimages, then replay ordinary verifiers from M18 objects.

No infrastructure operations, new reports, proposals, permits or M18 acceptance.
The private receipt is an index fragment, not an approval or a source of owner pins.
"""

import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from mlsecops import final_evidence as final
from mlsecops import material_bundle, privacy_gate, release_bundle
from mlsecops import performance_delivery as delivery
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    require_fields,
    safe_child,
)
from mlsecops.storage import object_id
from mlsecops.trust_acceptance import materials
from scripts import serving_campaign

GATES = ("M13", "M14", "M15")
MODES = dict(M13="privacy", M14="load", M15="monitoring")
FREEZE = "evidence/M18-frozen-inputs.json"
RECEIPT = "evidence/M18-serving-primary-private.json"
LIMIT = 16 * final.LIMIT  # The unchanged final_evidence.blob limit, including private packets.
SCOPE = "M18-original-serving-primary"


def owner(freeze_pin, reports, admissions):
    object_id(freeze_pin)
    for table in (reports, admissions):
        require_fields(table, GATES)
        for pin in table.values():
            object_id(pin)


def put(state, raw):
    final.need(0 < len(raw) <= LIMIT, "serving-object-size")
    pin = digest(raw)
    path = safe_child(state, "evidence/M18-objects/" + pin)
    if path.exists():
        final.need(final.blob(state, pin) == raw, "serving-existing-object")
    else:
        final.same(final.retain(state, raw), pin, "serving-retain")
    return pin


def inventory(root, read, store, *, freeze_pin, reports, admissions):
    """Explicit producer paths only. Canonical preimages must match original hashes."""
    index = decode(read(FREEZE, freeze_pin))
    require_fields(index["freeze"], delivery.FILES)
    for name, pin in index["freeze"].items():
        read(name, pin)
    method = canonical(materials(root))
    retained = {}
    for gate, mode in MODES.items():
        report = decode(read("evidence/" + gate + ".json", reports[gate]))
        refs = report["artifact_hashes"]
        final.same(store(method), refs["method_materials"], "serving-methods")
        contracts = read("evidence/" + mode + "-contracts.json")
        content = canonical(decode(contracts))
        final.need(contracts == content + b"\n", "serving-contract-file")
        final.same(store(content), refs["controlled_contracts"], "serving-contracts")
        name = "privacy-gate-private.json" if gate == "M13" else gate + "-frozen-private.json"
        admission = decode(read("evidence/" + name, admissions[gate]))
        component_pin = None if gate == "M13" else admission["component_sha256"]
        read("evidence/" + mode + "-gate.json", component_pin)
        value = decode(
            read("evidence/kubernetes-" + mode + "-private.json", admission["private_observation"])
        )
        epoch = privacy_gate.campaign(value[mode + "_campaign_id"])
        require_fields(value["artifact_hashes"], privacy_gate.ARTIFACTS)
        for filename, pin in value["artifact_hashes"].items():
            read("candidate-inference/" + epoch + "/" + filename, pin)
        if gate == "M13":
            retained[gate] = admissions[gate]
            privacy_files(read, store, value, admission)
        elif gate == "M14":
            for filename in ("start-request.json", "finish-request.json", "resources.json"):
                read(
                    "evidence/load/" + epoch + "/" + filename,
                    admission["retained_packets"][filename],
                )
        else:
            raw = read("evidence/monitoring-gate-private.json")
            native = decode(raw)
            final.need(raw == canonical(native) + b"\n", "serving-native-admission-format")
            final.same(
                native,
                {k: admission[k] for k in ("private_observation", "retained_packets")},
                "serving-native-admission",
            )
            retained[gate] = store(raw)
            for filename in ("binding.json", "packet.json", "feedback/proof.json"):
                read(
                    "evidence/monitoring/" + epoch + "/" + filename,
                    admission["retained_packets"][filename],
                )
            read(
                "evidence/kubernetes-monitoring-public.json",
                admission["retained_packets"]["public"],
            )
    return index, retained


def privacy_files(read, store, value, admission):
    epoch = privacy_gate.campaign(value["privacy_campaign_id"])
    cli = value["controlled_cli"]
    control = privacy_gate.campaign(cli["privacy_campaign_id"])
    directory = "evidence/privacy/" + epoch
    cli_path = "evidence/cli-privacy/" + control
    pins = admission["retained_packets"]
    read(directory + "/audit-evidence/packet.json", pins["actual_audit"])
    read(cli_path + "/closed-window/packet.json", pins["controlled_cli_packet"])
    read(cli_path + "/context.json")
    final.same(
        store(canonical(value["native"]["monitoring_proof"])),
        pins["monitoring"],
        "serving-monitoring-proof",
    )
    feedback = decode(read(directory + "/feedback/privacy.json", pins["feedback_privacy"]))
    read(directory + "/feedback/source-service/packet.json", feedback["service"]["sha256"])
    for prefix, path, windows in (
        ("actual", directory, value["native"]["operator_observation"]["service_observations"]),
        ("controlled_cli", cli_path, cli["service_windows"]),
    ):
        for namespace, receipt in windows.items():
            final.same(receipt["sha256"], pins[prefix + "_" + namespace], "serving-service-pin")
            read(path + "/services/" + namespace + "/packet.json", receipt["sha256"])


def signed_objects(state, index, files):
    """The exact existing retain_package closure, not a scan of the private store."""
    keys = decode(final.blob(state, files["trusted-keys.json"]))
    proposal = decode(final.blob(state, files[delivery.PROPOSAL]))
    pin = proposal["proposal_reference"]
    manifest = release_bundle.index(decode(final.blob(state, pin)), keys["approver"])
    capsule = decode(final.blob(state, manifest["materials"]["capsule"]))
    descriptors = material_bundle._index(capsule, keys["approver"])["objects"]
    # release_bundle.DOCUMENTS are the actual package.documents retained by the producer.
    return {
        index["policy_reference"],
        pin,
        manifest["materials"]["capsule"],
        *(manifest["materials"][k] for k in release_bundle.DOCUMENTS),
        *(row["sha256"] for row in descriptors),
    }


def verify(root, state, record):
    """Materialize only the captured allowlist; ordinary offline readers remain unchanged."""
    index = decode(final.blob(state, record["freeze_sha256"]))
    final.clean(root, index["source_revision"], index["source_fingerprint"])
    with TemporaryDirectory(prefix="m18-serving-", dir=state) as temporary:
        view = Path(temporary).resolve()
        for name, pin in record["files"].items():
            atomic_write(safe_child(view, name), final.blob(state, pin))
        for pin in signed_objects(state, index, record["files"]):
            atomic_write(safe_child(view, "evidence/M18-objects/" + pin), final.blob(state, pin))
        values, keys, _ = delivery.frozen(root, view, index)
        reports = {}
        for gate, pin in record["reports"].items():
            report = decode(final.blob(state, pin))
            serving_campaign.bind_report(gate, report, values)
            reports[gate] = report
            for ref in report["artifact_hashes"].values():
                final.blob(state, ref)
            if gate == "M13":
                component = decode(bounded_read(view / "evidence/privacy-gate.json"))
                final.subset(
                    component, dict(status="pass", release_ready=False), "serving-privacy-status"
                )
                final.subset(
                    report,
                    {
                        k: component[k]
                        for k in ("cases", "artifact_hashes", "input_digests", "source_revision")
                    },
                    "serving-privacy-component",
                )
                final.same(
                    report["metrics"],
                    dict(checks=component["checks"], **component["metrics"]),
                    "serving-privacy-metrics",
                )
                serving_campaign.privacy(
                    root, view, report, record["admissions"][gate], index, values, keys
                )
            else:
                admission = delivery.pinned(
                    view / f"evidence/{gate}-frozen-private.json", record["admissions"][gate]
                )
                for key in ("freeze", "policy_reference", *delivery.SOURCE):
                    final.same(admission["index"][key], index[key], "serving-frozen-owner")
                delivery.replay(
                    root,
                    view,
                    gate,
                    pins=index["freeze"],
                    report_pin=pin,
                    admission_pin=record["admissions"][gate],
                )
        final.retained(record, reports, lambda ref: final.blob(state, ref), values)
    return dict(
        scope=SCOPE,
        release_ready=False,
        reports=record["reports"],
        retained=record["retained"],
        source_revision=values["source_revision"],
        proposal_reference=values["proposal_reference"],
    )


def capture(root, state, *, freeze_pin, reports, admissions):
    owner(freeze_pin, reports, admissions)
    files = {}

    def read(name, pin=None):
        final.need(name not in files and len(files) < 256, "serving-file-inventory")
        raw = bounded_read(safe_child(state, name), LIMIT)
        if pin is not None:
            final.same(digest(raw), object_id(pin), "serving-original-pin")
        files[name] = put(state, raw)
        return raw

    _, retained = inventory(
        root,
        read,
        lambda raw: put(state, raw),
        freeze_pin=freeze_pin,
        reports=reports,
        admissions=admissions,
    )
    record = dict(
        schema_version=1,
        scope=SCOPE,
        freeze_sha256=freeze_pin,
        reports=reports,
        admissions=admissions,
        retained=retained,
        files=files,
    )
    verify(root, state, record)
    raw = canonical(record) + b"\n"
    path = safe_child(state, RECEIPT)
    if path.exists():
        final.need(bounded_read(path) == raw, "serving-capture-already-exists")
    else:
        atomic_write(path, raw)
    return put(state, raw)


def replay(root, state, receipt_pin, *, freeze_pin, reports, admissions):
    owner(freeze_pin, reports, admissions)
    record = decode(final.blob(state, receipt_pin))
    require_fields(
        record,
        ("schema_version", "scope", "freeze_sha256", "reports", "admissions", "retained", "files"),
    )
    final.subset(
        record,
        dict(
            schema_version=1,
            scope=SCOPE,
            freeze_sha256=freeze_pin,
            reports=reports,
            admissions=admissions,
        ),
        "serving-original-owners",
    )
    files = record["files"]
    final.need(isinstance(files, dict) and 0 < len(files) <= 256, "serving-file-inventory")
    used = set()

    def read(name, pin=None):
        used.add(name)
        ref = files[name]
        if pin is not None:
            final.same(ref, object_id(pin), "serving-replay-pin")
        return final.blob(state, ref)

    def checked(raw):
        pin = digest(raw)
        final.need(final.blob(state, pin) == raw, "serving-replay-preimage")
        return pin

    _, retained = inventory(
        root, read, checked, freeze_pin=freeze_pin, reports=reports, admissions=admissions
    )
    final.same(sorted(used), sorted(files), "serving-file-inventory")
    final.same(record["retained"], retained, "serving-private-admissions")
    return verify(root, state, record)


def assemble_draft(
    root,
    state,
    receipt_pin,
    *,
    freeze_pin,
    reports,
    admissions,
    proposal_reference,
    plan_pin,
    base_pin=None,
):
    """Return an immutable, private index draft after replaying the original trio."""
    verified = replay(
        root, state, receipt_pin, freeze_pin=freeze_pin, reports=reports, admissions=admissions
    )
    final.same(verified["proposal_reference"], object_id(proposal_reference), "draft-proposal")
    frozen = decode(final.blob(state, freeze_pin))
    # Early performance freezes predate the explicit version field.
    final.same(frozen.get("schema_version", 1), 1, "draft-freeze-version")
    header = dict(
        schema_version=1, **{k: frozen[k] for k in (*delivery.SOURCE, "freeze", "policy_reference")}
    )
    plan = decode(final.pinned(safe_child(state, "evidence/M18-plan.json"), plan_pin))
    final.need(isinstance(plan, dict), "draft-plan-shape")
    final.subset(
        plan,
        {k: header[k] for k in ("schema_version", "source_revision", "source_fingerprint")},
        "draft-plan-source",
    )
    # Use the same case and artifact inventories consumed by the final M18 verifier.
    for field in ("cases", "artifacts"):
        require_fields(plan.get(field), final.CHILDREN)
        for pin in plan[field].values():
            object_id(pin)
    for gate, pin in verified["reports"].items():
        report = decode(final.blob(state, pin))
        case_ids = sorted(row["id"] for row in report["cases"])
        final.same(digest(canonical(case_ids)), plan["cases"][gate], "draft-case-inventory")
        final.same(
            digest(canonical(sorted(report["artifact_hashes"]))),
            plan["artifacts"][gate],
            "draft-artifact-inventory",
        )
    identity = dict(
        **header,
        scope="M18-private-index-draft",
        status="inconclusive",
        release_ready=False,
        proposal_reference=proposal_reference,
        freeze_sha256=freeze_pin,
        plan=plan_pin,
    )
    draft = dict(**identity, reports={}, retained={})
    if base_pin is not None:
        draft = decode(final.blob(state, base_pin, final.LIMIT))
        require_fields(draft, (*identity, "reports", "retained"))
        final.subset(draft, identity, "draft-owner")
    for name, allowed in (("reports", final.CHILDREN), ("retained", ("M13", "M15"))):
        entries = draft[name]
        final.need(isinstance(entries, dict) and entries.keys() <= set(allowed), "draft-table")
        for gate, pin in entries.items():
            if gate not in verified[name]:
                final.blob(state, pin)  # Preserve only other gates with intact private preimages.
        for gate, pin in verified[name].items():
            final.same(entries.get(gate, pin), pin, "draft-conflicting-pin")
            entries[gate] = pin
    # A content-addressed write leaves the pinned parent and authoritative INDEX intact.
    raw = canonical(draft) + b"\n"
    final.need(len(raw) <= final.LIMIT, "draft-size")
    return dict(status="inconclusive", release_ready=False, index_sha256=put(state, raw))


def main(arguments=None):
    args = sys.argv[1:] if arguments is None else arguments
    final.need(args in (["capture"], ["replay"], ["assemble-draft"]), "serving-collector-arguments")
    root = Path(__file__).resolve().parents[1]
    state = root / ".runtime"
    pins = dict(
        freeze_pin=os.environ["M18_FREEZE_SHA256"],
        reports={g: os.environ[g + "_REPORT"] for g in GATES},
        admissions={g: os.environ[g + "_ADMISSION"] for g in GATES},
    )
    if args in (["capture"], ["assemble-draft"]):
        output_path = Path(os.environ["GITHUB_OUTPUT"])
        if args == ["capture"]:
            pin = capture(root, state, **pins)
        else:
            draft = assemble_draft(
                root,
                state,
                os.environ["M18_SERVING_PRIMARY_SHA256"],
                **pins,
                proposal_reference=os.environ["M18_PROPOSAL_REFERENCE"],
                plan_pin=os.environ["M18_PLAN_SHA256"],
                base_pin=os.environ.get("M18_DRAFT_BASE_SHA256"),
            )
            pin = draft["index_sha256"]
            print('{"status":"inconclusive","release_ready":false}')
        if args == ["capture"] or os.environ.get("GITHUB_ACTIONS") == "true":
            print("::add-mask::" + pin)
        with output_path.open("a", encoding="utf-8") as output:
            print("sha256=" + pin, file=output)
    else:
        result = replay(root, state, os.environ["M18_SERVING_PRIMARY_SHA256"], **pins)
        # Private admission/packet references stay in the private index fragment.
        print(
            canonical(
                {
                    k: result[k]
                    for k in (
                        "scope",
                        "release_ready",
                        "reports",
                        "source_revision",
                        "proposal_reference",
                    )
                }
            ).decode()
        )


if __name__ == "__main__":
    try:
        main()
    except (Rejected, OSError, KeyError, TypeError, ValueError):
        sys.exit("M18 serving primary verification failed")
