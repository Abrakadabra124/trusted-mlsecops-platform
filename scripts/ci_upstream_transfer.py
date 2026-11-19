"""Private opt-in original M02/M03/M07 receipts; existing M18 readers and AES only."""

import time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from mlsecops import ci_transfer, signing
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    safe_child,
)
from mlsecops.security_events import hexadecimal
from mlsecops.storage import object_id
from scripts import ci_candidate_transfer as bridge
from scripts import frozen_candidate_transfer as transfer
from scripts import m18_delivery_freeze as collector
from scripts import serving_campaign

GATES = ("M02", "M03", "M07")
PHASES = ("M13", "M14", "M15")
KIND = "original-upstream-receipts"
PRIMARY_PATHS = (
    "evidence/data-qualification.json",
    "evidence/integrity-qualification.json",
    "evidence/M03-filesystem.json",
    "evidence/M03-storage.json",
    "evidence/M03-pipeline.json",
    "evidence/evaluation-gate.json",
)
MAX_FILES = 12
MAX_TOTAL_BYTES = 64 * transfer.final.LIMIT
MAX_PACKET_BYTES = 4 * ((MAX_TOTAL_BYTES + 2) // 3) + 64 * 1024
MAX_ENVELOPE_BYTES = (
    MAX_PACKET_BYTES + len(ci_transfer.MAGIC) + ci_transfer.NONCE_BYTES + ci_transfer.TAG_BYTES
)


def _need(value):
    if not value:
        raise Rejected("ci_upstream_transfer_rejected")


def _pins(reports):
    _need(type(reports) is dict and reports.keys() == set(GATES))
    return {gate: object_id(reports[gate]) for gate in GATES}


def _inventory(reader):
    """Only original producer paths, never a directory scan or artifact-supplied path list."""
    files = {}

    def read(name, limit):
        raw = reader(name, limit)
        _need(type(raw) is bytes and 0 < len(raw) <= limit)
        transfer.no_credentials(raw)
        transfer.final.evidence_text(raw)
        files[name] = raw
        _need(sum(map(len, files.values())) <= MAX_TOTAL_BYTES)
        return raw

    for gate in GATES:
        read("evidence/" + gate + ".json", 16 * transfer.final.LIMIT)
    for name in PRIMARY_PATHS:
        read(name, transfer.final.LIMIT)
    packet = decode(files["evidence/evaluation-gate.json"])
    campaign = hexadecimal(packet["campaign_id"], 32)
    for name in ("contracts", "native", "budget"):
        read("evaluation-gate/" + campaign + "/" + name + ".json", transfer.final.LIMIT)
    return files


def _packet(owner, reports, files):
    return canonical(
        dict(
            schema_version=1,
            kind=KIND,
            authority=owner,
            reports=reports,
            files={name: signing.encode64(raw) for name, raw in files.items()},
        )
    )


def _unpack(raw, owner, reports):
    _need(type(raw) is bytes and len(raw) <= MAX_PACKET_BYTES)
    document = decode(raw, MAX_PACKET_BYTES)
    _need(
        type(document) is dict
        and document.keys() == {"schema_version", "kind", "authority", "reports", "files"}
    )
    encoded = document["files"]
    _need(type(encoded) is dict and len(encoded) == MAX_FILES)
    files = {name: signing.decode64(content) for name, content in encoded.items()}
    selected = _inventory(lambda name, limit: files[name])
    _need(selected.keys() == files.keys())
    # Exact canonical equality binds all nested owner/report maps, types,
    # gate-set and file bytes. No authority is adopted from this document.
    _need(raw == _packet(owner, reports, selected))
    return selected


@contextmanager
def _view(root, state, owner, reports, files):
    values, _ = bridge._fresh(root, state, owner)
    frozen, _, _ = transfer.checked_files(
        lambda name, limit: bounded_read(safe_child(state, name), limit),
        **{name: owner[name] for name in ("freeze_pin", "freeze", "expected")},
    )
    parent = safe_child(root, ".runtime/ci-upstream-transfers")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="reader-", dir=parent) as temporary:
        view = Path(temporary)
        for name, raw in (frozen | files).items():
            atomic_write(safe_child(view, name), raw)
        # These existing readers retain the exact primary preimages into the
        # owned view's M18 CAS. No writes go to the producer or caller state.
        collector.verify_early(root, view, values, {"M02": reports["M02"]}, intake_only=True)
        collector.verify_integrity(root, view, values, reports["M03"])
        collector.verify_evaluation(root, view, values, reports["M07"])
        for gate in GATES:
            report = transfer.final.published_report(view, gate, reports[gate])
            serving_campaign.bind_report(gate, report, values)
        values, current = bridge._fresh(root, view, owner)
        yield view, values, current


def seal(root, state, *, key, freeze_pin, freeze, expected, run_owner, reports, phase):
    """Export only original receipts plus their existing readers' required files.

    reports is a trusted producer's predeclared M02/M03/M07 pin map. Caller
    supplies the original frozen authority and key. All output remains private.
    """
    try:
        _need(type(phase) is str and phase in PHASES)
        owner = bridge._authority(key, freeze_pin, freeze, expected, run_owner, phase)
        reports = _pins(reports)
        files = _inventory(lambda name, limit: bounded_read(safe_child(state, name), limit))
        with _view(root, state, owner, reports, files) as (_, values, _):
            packet = _packet(owner, reports, files)
            _need(len(packet) <= MAX_PACKET_BYTES)
        issued = time.time_ns() // 1_000_000_000
        expires = min(
            values["proposal_expires_at"], issued + ci_transfer.TRANSPORT_TTL["candidate"]
        )
        context = bridge._context(owner, "upstream-" + phase, digest(packet), issued, expires)
        envelope = ci_transfer.seal(packet, key=key, context=context)
        ciphertext_pin = digest(envelope)
        # Include serialization, encryption, hash latency AND temporary cleanup
        # before the final real UTC/source check. Never renew the proposal.
        values, current = bridge._fresh(root, state, owner)
        bridge._window(context, values, current)
        return dict(
            envelope=envelope,
            context=context,
            ciphertext_sha256=ciphertext_pin,
            handling="private",
            release_ready=False,
        )
    except bridge.FAILURES:
        raise Rejected("ci_upstream_transfer_rejected") from None


def _attach(view, state, workspace_id, cleanup):
    """Attach verified receipts to an exclusively caller-owned consumer workspace."""
    marker = safe_child(state, "workspace.json")
    state = marker.parent
    expected = dict(
        product="trusted-mlsecops", schema_version=1, workspace_id=hexadecimal(workspace_id, 32)
    )
    _need(canonical(decode(bounded_read(marker, transfer.final.LIMIT))) == canonical(expected))
    files = _inventory(lambda name, limit: bounded_read(safe_child(view, name), limit))
    reports = {"evidence/" + gate + ".json" for gate in GATES}
    for name, raw in list(files.items()):
        if name not in reports:
            pin = digest(raw)
            _need(transfer.final.blob(view, pin) == raw)
            files[transfer.CAS + pin] = raw
    planned = {}
    for name, raw in files.items():
        path = safe_child(state, name)
        if path.exists():
            _need(name.startswith(transfer.CAS) and bounded_read(path, len(raw)) == raw)
        else:
            planned[path] = raw
    # Complete the collision/owner preflight before any mutation. Reserve only
    # these fixed evidence paths; never traverse/copy keys or runtime metadata.
    directories = {
        parent
        for path in planned
        for parent in path.parents
        if parent != state and parent.is_relative_to(state)
    }
    for directory in sorted(directories, key=lambda p: len(p.parts)):
        if not directory.exists():
            directory.mkdir(mode=0o700)
            cleanup.callback(directory.rmdir)
    for path, raw in planned.items():
        cleanup.callback(path.unlink, missing_ok=True)
        atomic_write(path, raw)
        _need(bounded_read(path, len(raw)) == raw)
    return state


@contextmanager
def materialize(
    root,
    state,
    envelope,
    *,
    key,
    freeze_pin,
    freeze,
    expected,
    run_owner,
    reports,
    phase,
    expected_context,
    ciphertext_pin,
    workspace_id=None,
):
    """Yield an owned frozen+receipt view and original pins for campaign consumers.

    state is the original frozen state or independently verified candidate view.
    No storage.json, runtime admission, transition, SQL client or key is copied.
    Context, ciphertext pin and report pins must arrive independently of the artifact.
    With workspace_id from consumer_candidate_state, attach only receipts/CAS
    to that existing state, without overwriting files; undo additions on exit.
    """
    with ExitStack() as cleanup:
        try:
            _need(type(phase) is str and phase in PHASES)
            owner = bridge._authority(key, freeze_pin, freeze, expected, run_owner, phase)
            reports = _pins(reports)
            _need(type(envelope) is bytes and len(envelope) <= MAX_ENVELOPE_BYTES)
            _need(
                type(expected_context) is dict
                and expected_context.keys() == ci_transfer.CONTEXT_FIELDS
            )
            context = expected_context.copy()
            _need(
                context
                == bridge._context(
                    owner,
                    "upstream-" + phase,
                    context["payload_sha256"],
                    context["issued_at"],
                    context["expires_at"],
                )
            )
            raw = ci_transfer.open(
                envelope,
                key=key,
                expected_context=context,
                expected_ciphertext_sha256=ciphertext_pin,
            )
            files = _unpack(raw, owner, reports)
            view, values, current = cleanup.enter_context(_view(root, state, owner, reports, files))
            bridge._window(context, values, current)
            if workspace_id is not None:
                view = _attach(view, state, workspace_id, cleanup)
                values, current = bridge._fresh(root, view, owner)
                bridge._window(context, values, current)
            summary = dict(reports=reports, handling="private", release_ready=False)
        except bridge.FAILURES:
            raise Rejected("ci_upstream_transfer_rejected") from None
        yield view, summary
