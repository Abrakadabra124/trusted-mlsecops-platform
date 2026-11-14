"""Retain original M23 bytes for M18; replay from objects without stage files.

collect/replay require external report/stage/transition/workspace/proposal pins,
the original run owner, frozen M18 values and the independently fixed case hash.
Only an allowlist of public owner files and existing private evidence is read.
No capture, service, cleanup, reviewer evidence or replacement report is issued.
The caller still owns native cleanup proof and full 22-child M18 acceptance.
"""

import tempfile
from pathlib import Path

from mlsecops import final_evidence as final
from mlsecops import security_events as schema
from mlsecops import security_gate as gate
from mlsecops import security_gate_candidate as candidate
from mlsecops import security_gate_sources as sources
from mlsecops.contracts import (
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    now,
    safe_child,
)
from scripts import m23_delivery

PIN_FIELDS = ("report", "proposal", "sources", "inventory", "outage", "transition", "workspace")
TRANSITION = "evidence/M23-delivery-transition.json"
SOURCE_FIELDS = ("source_revision", "source_fingerprint")
LIMIT = max(candidate.OUTAGE_LIMIT, 17 * 1024 * 1024)


def case_inventory(root):
    """Pre-run M23 case hash from this checkout's immutable verifier criteria.

    No report, measurement or runtime file supplies expected cases. Identity's
    fixed repetitions mirror the exact Counter enforced by identity.verify.
    Ordinary signed source/candidate replay is qualified against this inventory.
    """
    final.need(Path(root).resolve() == Path(__file__).resolve().parents[1], "security-case-root")
    identity = [*sources.identity.SINGLE_CASES]
    identity.extend(f"signed-identity-subject-and-route-{i}" for i in range(1, 7))
    for label, count in (
        ("bounded-private-http-output", 11),
        ("actual-http-identity-denied-after-delivery", 5),
        ("owned-http-exit-and-port-closed", 2),
    ):
        identity.extend([label] * count)
    cases = []
    for name, labels in (
        ("intake", [row[0] for row in sources.intake.CASES]),
        ("identity", identity),
        ("trust", list(sources.trust.CASES)),
        (
            "sequence",
            [
                f"{mode}:{label}"
                for mode in sources.sequence.MODES
                for label in sources.sequence.CASE_NAMES
            ]
            + ["source-unchanged"],
        ),
    ):
        cases.extend(sources._case_ids(name, labels))
    cases.extend(
        f"inventory:{label}:{index}" if count > 1 else f"inventory:{label}"
        for label, count in candidate.INVENTORY_CASES.items()
        for index in range(1, count + 1)
    )
    cases.extend(candidate.OUTAGE_PHASE_CASES)
    cases.extend(candidate.OUTAGE_FINAL_CASES)
    final.same(len(cases), len(set(cases)), "security-case-duplicates")
    return digest(canonical(sorted(cases)))


def object_bytes(state, pin):
    # Match the full M18 child verifier, including native outage packets >16 MiB.
    return final.blob(state, pin, 64 * final.LIMIT)


def anchors(root, values, pins, owner, expected_cases):
    schema.shape(pins, PIN_FIELDS)
    for pin in (*pins.values(), expected_cases):
        schema.hexadecimal(pin)
    schema.shape(owner, ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    for value in owner.values():
        final.need(
            type(value) is str
            and value.isascii()
            and value.isdecimal()
            and str(schema.integer(int(value))) == value,
            "security-run-owner",
        )
    final.clean(root, values["source_revision"], values["source_fingerprint"])


def gather(root, read, pins, values):
    """Resolve known paths, never scan private runtime directories by digest."""
    files, objects = {}, {}

    def take(name, pin=None, *, json_line=False):
        raw = read(name)
        body = raw
        if json_line:
            body = canonical(decode(raw, LIMIT))
            final.need(raw == body + b"\n", "security-json-line")
        if pin is not None:
            final.same(digest(body), schema.hexadecimal(pin), "security-material-pin")
        files[name] = digest(raw)
        objects[digest(raw)], objects[digest(body)] = raw, body
        return decode(raw, LIMIT)

    report = take("evidence/M23.json", pins["report"])
    final.evidence_text(objects[pins["report"]])
    stages = {name: take("evidence/M23-" + name + ".json", pins[name]) for name in gate.STAGES}
    source = stages["sources"]["binding"]
    schema.shape(source, ("schema_version", "source", "intake", "identity", "trust", "sequence"))
    schema.version(source["schema_version"])
    intake, identity, trust = (source[k] for k in ("intake", "identity", "trust"))
    take("evidence/security-source-private.json", intake["primary_file_sha256"])
    take("evidence/security-source-private.bindings.json", intake["binding_sha256"])
    base = "security-identity-primary/" + schema.hexadecimal(identity["primary_sha256"])
    take(base + ".json", identity["primary_sha256"])
    take(base + ".bindings.json", identity["binding_sha256"])
    base = "evidence/trust-service-" + schema.hexadecimal(trust["run_id"], 32)
    take(base + ".primary.json", trust["primary_sha256"])
    take(base + ".binding.json", trust["binding_sha256"])
    take("evidence/security-sequence-private.json", source["sequence"]["primary_sha256"])
    inventory = stages["inventory"]["binding"]
    take(candidate.INVENTORY_PUBLIC, inventory["public_sha256"])
    take(candidate.INVENTORY_PRIMARY, inventory["primary_sha256"], json_line=True)
    take(candidate.INVENTORY_BINDING, inventory["binding_sha256"], json_line=True)
    outage = stages["outage"]["binding"]
    final.same(outage["proposal_sha256"], pins["proposal"], "security-original-proposal")
    take(candidate.PROPOSAL, pins["proposal"])
    public = take(candidate.outage.PUBLIC, outage["public_sha256"])
    primary = take(candidate.outage.PRIVATE, outage["primary_sha256"])
    base = "evidence/security-outage/" + schema.hexadecimal(primary["security_campaign_id"], 32)
    schema.shape(public["retained_sha256"], ("binding.json", "packet.json", "operator.json"))
    retained = {
        name: take(base + "/" + name, pin) for name, pin in public["retained_sha256"].items()
    }
    # recovery.json has no direct report hash; the pinned binding contains its full body.
    final.same(
        take(base + "/recovery.json"), retained["binding.json"]["recovery"], "security-recovery"
    )
    transition = take(TRANSITION, pins["transition"])
    schema.shape(
        transition, ("schema_version", "inputs", "transition", "outage_delivery", "owner_files")
    )
    schema.version(transition["schema_version"])
    expected = {
        k: values[k]
        for k in (
            *SOURCE_FIELDS,
            "image_id",
            "candidate_reference",
            "evaluation_reference",
            "model_sha256",
            "release_subject",
            "proposal_reference",
        )
    }
    final.subset(
        transition["inputs"],
        expected | {"policy_digest": values["policy"]},
        "security-owner-candidate",
    )
    final.same(
        transition["inputs"]["files"][candidate.PROPOSAL],
        pins["proposal"],
        "security-owner-proposal",
    )
    schema.shape(transition["owner_files"], m23_delivery.OWNER_FILES)
    for name, pin in transition["owner_files"].items():
        take("kubernetes-security/" + name, pin)
    take("workspace.json", pins["workspace"])
    methods = canonical(gate.materials(root))
    final.same(digest(methods), report["artifact_hashes"]["method_materials"], "security-methods")
    objects[digest(methods)] = methods
    return report, files, objects


def replay_sources(root, state, manifest):
    """Use the existing file-only section verifiers in an isolated material view.

    sources.replay's native path guard requires root/.runtime. Its four section
    verifiers accept an explicit state; no global path overrides are necessary.
    """
    source = gate.source_state(root)
    methods = gate.materials(root)
    current = dict(source=source["source_revision"], fingerprint=source["source_fingerprint"])
    final.same(
        manifest["source"],
        current | {"methods_sha256": digest(canonical(methods))},
        "security-source",
    )
    hashes, routes = {}, {}
    intake = sources._intake(root, state, manifest["intake"], current, methods, hashes, routes)
    identity, identity_notice = sources._identity(
        state, manifest["identity"], current, methods, hashes, routes
    )
    trust, trust_notice = sources._trust(state, manifest["trust"], current, methods, hashes, routes)
    sequence, notices = sources._sequence(state, manifest["sequence"], current, hashes, routes)
    return dict(
        cases=[
            case
            for label, rows in (
                ("intake", intake),
                ("identity", identity),
                ("trust", trust),
                ("sequence", sequence),
            )
            for case in sources._case_ids(label, rows)
        ],
        routes=routes,
        sequence_notice_seconds=notices,
        heartbeat_notice_seconds=max(identity_notice, trust_notice),
        artifact_hashes=hashes,
    )


def verify(root, report, files, objects, *, values, pins, owner, expected_cases):
    schema.shape(report, m23_delivery.REPORT_FIELDS)
    # check_gate preserves the independent case inventory and original frozen values.
    refs = final.check_gate("M23", report, values, final.timestamp(now()), expected_cases)
    for pin in refs.values():
        schema.hexadecimal(pin)
        final.need(pin in objects and digest(objects[pin]) == pin, "security-artifact-preimage")
    source = {k: values[k] for k in SOURCE_FIELDS}
    methods = refs["method_materials"]
    with tempfile.TemporaryDirectory(prefix="m18-security-") as tmp:
        state = Path(tmp).resolve()
        for name, pin in files.items():
            atomic_write(safe_child(state, name), objects[pin])
        stages = {
            name: gate.read_stage(state, name, pins[name], source, methods, owner)
            for name in gate.STAGES
        }
        times = [
            final.timestamp(stages[name][field])
            for name in gate.STAGES
            for field in ("started_at", "finished_at")
        ]
        final.need(
            times == sorted(times) and times[-1] <= final.timestamp(report["finished_at"]),
            "security-stage-time",
        )
        source_result = replay_sources(root, state, stages["sources"]["binding"])
        candidate_result = candidate.replay(
            root,
            state,
            inventory_pin=stages["inventory"]["binding"],
            outage_pin=stages["outage"]["binding"],
        )
        final.need(
            final.timestamp(candidate_result["proposal_finished_at"]) <= times[0],
            "security-proposal-time",
        )
        evidence = gate.reconcile(source_result, candidate_result, source)
        evidence["artifact_hashes"].update(
            method_materials=methods, **{"stage-" + name: pins[name] for name in gate.STAGES}
        )
        for field in ("input_digests", "artifact_hashes", "cases"):
            final.same(report[field], evidence[field], "security-replayed-" + field)
        final.same(report["started_at"], stages["sources"]["started_at"], "security-start")
        final.same(
            report["metrics"],
            dict(checks=evidence["checks"], **evidence["metrics"]),
            "security-metrics",
        )
        final.same(report["residual_risks"], gate.LIMITATIONS, "security-limitations")
    final.primary("M23", report, objects.__getitem__, values)


def collect(root, state, *, values, pins, owner, expected_cases):
    """Return a private object index pin only after verifying every original byte."""
    anchors(root, values, pins, owner, expected_cases)

    def read(name):
        original = (
            "M23-retired-serving/" + name if name.startswith("kubernetes-security/") else name
        )
        return bounded_read(safe_child(state, original), LIMIT)

    report, files, objects = gather(root, read, pins, values)
    verify(
        root,
        report,
        files,
        objects,
        values=values,
        pins=pins,
        owner=owner,
        expected_cases=expected_cases,
    )
    index = dict(
        schema_version=1, pins=pins, owner=owner, expected_cases=expected_cases, files=files
    )
    index_raw = canonical(index) + b"\n"
    objects[digest(index_raw)] = index_raw
    # Validate existing objects before writing anything; never repair corruption silently.
    missing = []
    for pin, raw in objects.items():
        final.need(len(raw) <= 64 * final.LIMIT, "security-M18-object-limit")
        target = safe_child(state, "evidence/M18-objects/" + pin)
        if target.exists():
            final.need(object_bytes(state, pin) == raw, "security-existing-object")
        else:
            missing.append(raw)
    for raw in missing:
        final.retain(state, raw)
    for pin, raw in objects.items():
        final.need(object_bytes(state, pin) == raw, "security-object-readback")
    return dict(
        index_sha256=digest(index_raw),
        report_sha256=pins["report"],
        artifact_count=len(report["artifact_hashes"]),
        object_count=len(objects),
        release_ready=False,
    )


def replay(root, state, *, index_pin, values, pins, owner, expected_cases):
    """Use only CAS objects and the exact source checkout; original stages may be absent."""
    anchors(root, values, pins, owner, expected_cases)
    raw = object_bytes(state, index_pin)
    index = decode(raw)
    schema.shape(index, ("schema_version", "pins", "owner", "expected_cases", "files"))
    schema.version(index["schema_version"])
    final.need(raw == canonical(index) + b"\n", "security-index-format")
    final.same(index["pins"], pins, "security-index-pins")
    final.same(index["owner"], owner, "security-index-owner")
    final.same(index["expected_cases"], expected_cases, "security-case-inventory")
    final.need(type(index["files"]) is dict and 1 <= len(index["files"]) <= 64, "security-files")
    report, files, objects = gather(
        root, lambda name: object_bytes(state, index["files"][name]), pins, values
    )
    final.same(index["files"], files, "security-file-inventory")
    # Canonical aliases/method manifest must already exist, not merely be reconstructible.
    for pin, content in objects.items():
        final.need(object_bytes(state, pin) == content, "security-retained-preimage")
    verify(
        root,
        report,
        files,
        objects,
        values=values,
        pins=pins,
        owner=owner,
        expected_cases=expected_cases,
    )
    return dict(
        report_sha256=pins["report"],
        artifact_count=len(report["artifact_hashes"]),
        release_ready=False,
    )
