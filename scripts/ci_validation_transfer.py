"""Optional private validation bytes companion; no CLI, storage client or new authority."""

import time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from mlsecops import ci_transfer, datasets, signing
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    safe_child,
)
from scripts import ci_candidate_transfer as bridge
from scripts import frozen_candidate_transfer as transfer

KIND = "original-validation-companion"
PHASES = ("M13", "M14", "M15")
MAX_VALIDATION_BYTES = 16 * 1024 * 1024  # Existing dataset/monitoring reader limit.
MAX_PACKET_BYTES = 4 * ((MAX_VALIDATION_BYTES + 2) // 3) + 64 * 1024
MAX_ENVELOPE_BYTES = (
    MAX_PACKET_BYTES + len(ci_transfer.MAGIC) + ci_transfer.NONCE_BYTES + ci_transfer.TAG_BYTES
)
FIELDS = {"schema_version", "kind", "authority", "split_manifest", "validation"}


def _need(value):
    if not value:
        raise Rejected("ci_validation_transfer_rejected")


def _packet(owner, values, content):
    return canonical(
        dict(
            schema_version=1,
            kind=KIND,
            authority=owner,
            split_manifest=values["integrity_snapshot"]["manifest"],
            validation=signing.encode64(content),
        )
    )


def _validation(content, descriptor):
    _need(type(content) is bytes and len(content) <= MAX_VALIDATION_BYTES)
    _need(len(content) == descriptor["bytes"] and digest(content) == descriptor["sha256"])
    rows = decode(content)
    datasets.validate_rows(rows, descriptor["rows"])
    _need(canonical(rows) == content)


def _descriptor(state, values):
    # Called only after the existing full frozen reader authenticated the
    # release bundle and its signed dataset chain. Never accept a caller's
    # descriptor or a descriptor copied from the companion as authority.
    manifest = decode(transfer.final.blob(state, values["integrity_snapshot"]["manifest"]))
    return manifest["objects"]["validation.json"]


def _checked(packet, state, owner, values):
    _need(type(packet) is bytes and len(packet) <= MAX_PACKET_BYTES)
    document = decode(packet, MAX_PACKET_BYTES)
    _need(type(document) is dict and document.keys() == FIELDS)
    content = signing.decode64(document["validation"])
    # Canonical byte equality also rejects bool/int aliases, extra fields,
    # noncanonical base64 and foreign owner/freeze/split metadata.
    _need(packet == _packet(owner, values, content))
    descriptor = _descriptor(state, values)
    _validation(content, descriptor)
    return content, descriptor


def retain(root, state, validation_content, *, freeze_pin, freeze, expected, run_owner):
    """Return bounded private packet bytes; persistence belongs to the caller.

    state must be the original frozen state or an already verified materialized
    candidate view. Only exact validation bytes are accepted. No train/holdout
    selection, private key, SQL credential or arbitrary destination is accepted.
    """
    try:
        owner = dict(freeze_pin=freeze_pin, freeze=freeze, expected=expected, run_owner=run_owner)
        transfer.authority(**owner, clock=bridge._now())
        owner = decode(canonical(owner))  # Snapshot the externally supplied closed authority.
        _need(owner["run_owner"]["repository"] == ci_transfer.REPOSITORY)
        values, _ = bridge._fresh(root, state, owner)
        _validation(validation_content, _descriptor(state, values))
        packet = _packet(owner, values, validation_content)
        _need(len(packet) <= MAX_PACKET_BYTES)
        bridge._fresh(root, state, owner)
        return packet
    except bridge.FAILURES:
        raise Rejected("ci_validation_transfer_rejected") from None


def seal(root, state, packet, *, key, freeze_pin, freeze, expected, run_owner, phase):
    """Export retained private bytes with the existing AES-GCM transport primitive.

    No clock/nonce injection, key generation or signing. The domain-separated
    phase is validation-M13/M14/M15; the original proposal and 600-second inner
    window remain mandatory, with transport expiry min(original, issued+1800).
    """
    try:
        _need(type(phase) is str and phase in PHASES)
        owner = bridge._authority(key, freeze_pin, freeze, expected, run_owner, phase)
        values, _ = bridge._fresh(root, state, owner)
        _checked(packet, state, owner, values)
        issued = time.time_ns() // 1_000_000_000
        expires = min(
            values["proposal_expires_at"], issued + ci_transfer.TRANSPORT_TTL["candidate"]
        )
        context = bridge._context(owner, "validation-" + phase, digest(packet), issued, expires)
        envelope = ci_transfer.seal(packet, key=key, context=context)
        values, current = bridge._fresh(root, state, owner)
        bridge._window(context, values, current)
        return dict(
            envelope=envelope,
            context=context,
            ciphertext_sha256=digest(envelope),
            handling="private",
            release_ready=False,
        )
    except bridge.FAILURES:
        raise Rejected("ci_validation_transfer_rejected") from None


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
    phase,
    expected_context,
    ciphertext_pin,
):
    """Yield (owned validation.json, private summary) beside an existing frozen view.

    Context and ciphertext pin must arrive independently of the artifact. The
    original candidate view still requires its own independent manifest pin.
    Actual UTC freshness/source checks run before and after writing. Only this
    call's temporary directory is removed on exit, rejection or consumer error.
    """
    with ExitStack() as cleanup:
        try:
            _need(type(phase) is str and phase in PHASES)
            owner = bridge._authority(key, freeze_pin, freeze, expected, run_owner, phase)
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
                    "validation-" + phase,
                    context["payload_sha256"],
                    context["issued_at"],
                    context["expires_at"],
                )
            )
            packet = ci_transfer.open(
                envelope,
                key=key,
                expected_context=context,
                expected_ciphertext_sha256=ciphertext_pin,
            )
            values, current = bridge._fresh(root, state, owner)
            bridge._window(context, values, current)
            content, descriptor = _checked(packet, state, owner, values)
            parent = safe_child(root, ".runtime/ci-validation-transfers")
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            temporary = cleanup.enter_context(TemporaryDirectory(prefix="reader-", dir=parent))
            path = safe_child(Path(temporary), "validation.json")
            atomic_write(path, content)
            _validation(bounded_read(path, MAX_VALIDATION_BYTES), descriptor)
            values, current = bridge._fresh(root, state, owner)
            bridge._window(context, values, current)
            summary = dict(
                validation_sha256=descriptor["sha256"],
                bytes=descriptor["bytes"],
                rows=descriptor["rows"],
                handling="private",
                release_ready=False,
            )
        except bridge.FAILURES:
            raise Rejected("ci_validation_transfer_rejected") from None
        yield path, summary
