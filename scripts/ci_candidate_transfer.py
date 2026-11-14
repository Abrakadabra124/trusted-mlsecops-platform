"""Private frozen-candidate/AES bridge; explicit caller inputs, no CLI or publication."""

import time
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import BadZipFile

from mlsecops import ci_transfer
from mlsecops.contracts import Rejected, atomic_write, bounded_read, decode, digest, safe_child
from mlsecops.storage import object_id
from scripts import frozen_candidate_transfer as transfer
from scripts.serving_retention import PHASES

FAILURES = (ValueError, OSError, KeyError, TypeError, BadZipFile, OverflowError, RecursionError)


def _need(condition):
    if not condition:
        raise Rejected("ci_candidate_transfer_rejected")


def _now():
    # Match serving_retention.window's conservative ceil, never grant a
    # fractional extra second of the mandatory inner qualification window.
    return (time.time_ns() + 999_999_999) // 1_000_000_000


def _authority(key, freeze_pin, freeze, expected, run_owner, phase):
    _need(type(key) is bytes and len(key) == 32)
    _need(type(phase) is str and phase in PHASES)
    _need(all(type(value) is dict for value in (freeze, expected, run_owner)))
    # These closed maps contain scalars. Snapshot them before any I/O; never
    # infer missing authority from environment variables or archive contents.
    owner = dict(
        freeze_pin=freeze_pin,
        freeze=freeze.copy(),
        expected=expected.copy(),
        run_owner=run_owner.copy(),
    )
    transfer.authority(**owner, clock=_now())
    _need(owner["run_owner"]["repository"] == ci_transfer.REPOSITORY)
    return owner


def _context(owner, phase, payload_sha256, issued_at, expires_at):
    expected, run = owner["expected"], owner["run_owner"]
    return dict(
        repository=run["repository"],
        run_id=run["run_id"],
        run_attempt=run["run_attempt"],
        source_revision=expected["source_revision"],
        source_fingerprint=expected["source_fingerprint"],
        image_id=expected["image_id"],
        candidate_sha256=expected["candidate_reference"],
        proposal_sha256=expected["proposal_reference"],
        payload_sha256=payload_sha256,
        phase=phase,
        purpose="candidate",
        issued_at=issued_at,
        expires_at=expires_at,
    )


def _fresh(root, state, owner):
    """Recheck original verified authority at current time after materialization/I/O."""
    index = transfer.delivery.pinned(safe_child(state, transfer.RECEIPT), owner["freeze_pin"])
    _need(index["freeze"] == owner["freeze"])
    values, keys, policy = transfer.delivery.frozen(root, state, index)
    _need({field: values[field] for field in transfer.IDENTITY} == owner["expected"])
    approval = transfer.release_policy.checked(
        decode(transfer.final.blob(state, values["integrity_snapshot"]["approval"])),
        "source",
        keys["curator"],
    )
    local_policy = decode(bounded_read(safe_child(root, "policies/local-cpu.json")))
    transfer.final.clean(
        root, owner["expected"]["source_revision"], owner["expected"]["source_fingerprint"]
    )
    current = _now()
    transfer.window(values, current)  # The original 600-second minimum, unchanged.
    transfer.release_policy.window(policy, current)
    _need(policy["expires_at"] - current >= 600)
    transfer.datasets.validate_approval(
        approval, local_policy, moment=datetime.fromtimestamp(current, UTC)
    )
    return values, current


def _window(context, values, current):
    ttl = ci_transfer.TRANSPORT_TTL["candidate"]
    transfer.release_policy.window(context, current, maximum=ttl)
    _need(context["issued_at"] >= max(values["proposal_issued_at"], values["captured_at"]))
    _need(context["expires_at"] == min(values["proposal_expires_at"], context["issued_at"] + ttl))


def seal(root, state, *, key, freeze_pin, freeze, expected, run_owner, phase):
    """Export the exact original archive, then return private ciphertext and pins.

    All authority is caller-supplied. The existing exporter's owned plaintext
    archive remains private at its deterministic local path. No key/signature
    or replacement proposal is created. Returned metadata is private too.
    """
    try:
        owner = _authority(key, freeze_pin, freeze, expected, run_owner, phase)
        exported = transfer.export(root, state, **owner, clock=_now())
        raw = bounded_read(Path(exported["path"]), transfer.MAX_ARCHIVE)
        _need(digest(raw) == exported["archive_sha256"])
        manifest, _ = transfer.unpack(raw, exported["manifest_sha256"])
        # Transport uses ordinary integer Unix seconds, so an issued timestamp
        # must not be rounded into the future relative to ci_transfer's clock.
        issued = time.time_ns() // 1_000_000_000
        expires = min(
            manifest["proposal_window"]["expires_at"],
            issued + ci_transfer.TRANSPORT_TTL["candidate"],
        )
        context = _context(owner, phase, digest(raw), issued, expires)
        envelope = ci_transfer.seal(raw, key=key, context=context)
        ciphertext_pin = digest(envelope)
        values, current = _fresh(root, state, owner)
        _window(context, values, current)
        return dict(
            envelope=envelope,
            context=context,
            ciphertext_sha256=ciphertext_pin,
            manifest_sha256=exported["manifest_sha256"],
            handling="private",
            release_ready=False,
        )
    except FAILURES:
        raise Rejected("ci_candidate_transfer_rejected") from None


@contextmanager
def materialize(
    root,
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
    manifest_pin,
):
    """Yield an owned private state only after real AEAD and frozen-reader checks.

    Context, ciphertext pin and manifest pin must each arrive independently of
    the untrusted artifact. The yielded state and staged plaintext archive are
    removed on normal exit, verification failure, or a consumer exception.
    """
    with ExitStack() as cleanup:
        try:
            owner = _authority(key, freeze_pin, freeze, expected, run_owner, phase)
            object_id(manifest_pin)
            _need(
                type(expected_context) is dict
                and expected_context.keys() == ci_transfer.CONTEXT_FIELDS
            )
            context = expected_context.copy()
            _need(
                context
                == _context(
                    owner,
                    phase,
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
            _need(len(raw) <= transfer.MAX_ARCHIVE)
            parent = safe_child(root, ".runtime/ci-candidate-transfers")
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            temporary = cleanup.enter_context(TemporaryDirectory(prefix="reader-", dir=parent))
            archive = safe_child(Path(temporary), "candidate.zip")
            atomic_write(archive, raw)
            view, _ = cleanup.enter_context(
                transfer.materialize(
                    root, archive, manifest_pin=manifest_pin, **owner, clock=_now()
                )
            )
            values, current = _fresh(root, view, owner)
            _window(context, values, current)
            summary = dict(
                manifest_sha256=manifest_pin,
                ciphertext_sha256=ciphertext_pin,
                handling="private",
                release_ready=False,
            )
        except FAILURES:
            raise Rejected("ci_candidate_transfer_rejected") from None
        # Consumer exceptions propagate unchanged; ExitStack still removes only
        # the directories created by this call and the ordinary frozen reader.
        yield view, summary
