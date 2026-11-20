"""Private, bounded AES-256-GCM transport bytes, not proposal or release authority.

The caller supplies the key and independently trusted expected context/pin.
No filesystem, network, key generation, logging, or publication is performed.
"""

import hmac
import os
import re
import time
from collections.abc import Callable
from hashlib import sha256

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mlsecops.contracts import Rejected, canonical

REPOSITORY = "Abrakadabra124/trusted-mlsecops-platform"
PRIVATE_REPOSITORY = "Abrakadabra124/trusted-mlsecops-ci-private"
EXECUTION_REPOSITORIES = frozenset({REPOSITORY, PRIVATE_REPOSITORY})
MAGIC = b"MLSCIT\x01"
NONCE_BYTES = 12
TAG_BYTES = 16
MAX_PAYLOAD_BYTES = 256 * 1024 * 1024
MAX_ENVELOPE_BYTES = MAX_PAYLOAD_BYTES + len(MAGIC) + NONCE_BYTES + TAG_BYTES
MAX_INTEGER = 2**53 - 1
TRANSPORT_TTL = {"candidate": 1800, "evidence": 86400}
CONTEXT_FIELDS = frozenset(
    {
        "repository",
        "run_id",
        "run_attempt",
        "source_revision",
        "source_fingerprint",
        "image_id",
        "candidate_sha256",
        "proposal_sha256",
        "payload_sha256",
        "phase",
        "purpose",
        "issued_at",
        "expires_at",
    }
)


def _hex(value, size=64):
    return type(value) is str and len(value) == size and re.fullmatch(r"[0-9a-f]+", value)


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX_INTEGER


def _key(key):
    if type(key) is not bytes or len(key) != 32:
        raise Rejected("ci_transfer_key")


def _context(value):
    if type(value) is not dict or len(value) != len(CONTEXT_FIELDS):
        raise Rejected("ci_transfer_context")
    # All accepted values are immutable scalars. Do not consult the caller's
    # mutable dictionary again, including after invoking a test clock.
    ctx = value.copy()
    if any(type(field) is not str for field in ctx) or ctx.keys() != CONTEXT_FIELDS:
        raise Rejected("ci_transfer_context")
    if type(ctx["repository"]) is not str or ctx["repository"] not in EXECUTION_REPOSITORIES:
        raise Rejected("ci_transfer_context")
    for field in ("run_id", "run_attempt"):
        if not _integer(ctx[field], 1):
            raise Rejected("ci_transfer_context")
    for field, size in (
        ("source_revision", 40),
        ("source_fingerprint", 64),
        ("candidate_sha256", 64),
        ("proposal_sha256", 64),
        ("payload_sha256", 64),
    ):
        if not _hex(ctx[field], size):
            raise Rejected("ci_transfer_context")
    image_id = ctx["image_id"]
    if (
        type(image_id) is not str
        or len(image_id) != 71
        or not image_id.startswith("sha256:")
        or not _hex(image_id[7:])
    ):
        raise Rejected("ci_transfer_context")
    phase = ctx["phase"]
    if (
        type(phase) is not str
        or not 1 <= len(phase) <= 64
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", phase)
    ):
        raise Rejected("ci_transfer_context")
    purpose = ctx["purpose"]
    if type(purpose) is not str or purpose not in TRANSPORT_TTL:
        raise Rejected("ci_transfer_context")
    if not _integer(ctx["issued_at"]) or not _integer(ctx["expires_at"]):
        raise Rejected("ci_transfer_context")
    if not 0 < ctx["expires_at"] - ctx["issued_at"] <= TRANSPORT_TTL[purpose]:
        raise Rejected("ci_transfer_context")
    return ctx, MAGIC + b"\x00" + canonical(ctx)


def _time(ctx, clock):
    if clock is None:
        timestamp = time.time_ns() // 1_000_000_000
    else:
        if not callable(clock):
            raise Rejected("ci_transfer_clock")
        try:
            timestamp = clock()
        except Exception:
            raise Rejected("ci_transfer_clock") from None
    if not _integer(timestamp):
        raise Rejected("ci_transfer_clock")
    if not ctx["issued_at"] <= timestamp < ctx["expires_at"]:
        raise Rejected("ci_transfer_time")


def _payload_digest(payload, ctx):
    if not hmac.compare_digest(sha256(payload).hexdigest(), ctx["payload_sha256"]):
        raise Rejected("ci_transfer_payload_digest")


def seal(
    payload: bytes,
    *,
    key: bytes,
    context: dict,
    clock: Callable[[], int] | None = None,
) -> bytes:
    """Encrypt bytes with a fresh OS-random 96-bit nonce and closed canonical AAD.

    ``clock`` is only for offline tests; production callers must omit it.
    ``payload_sha256`` binds these exact plaintext bytes. The caller must still
    validate the inner frozen package and its original signed proposal expiry.
    """
    _key(key)
    if type(payload) is not bytes or len(payload) > MAX_PAYLOAD_BYTES:
        raise Rejected("ci_transfer_payload")
    ctx, aad = _context(context)
    _time(ctx, clock)
    _payload_digest(payload, ctx)
    try:
        nonce = os.urandom(NONCE_BYTES)
    except OSError:
        raise Rejected("ci_transfer_random") from None
    encrypted = AESGCM(key).encrypt(nonce, payload, aad)
    envelope = MAGIC + nonce + encrypted
    _time(ctx, clock)
    return envelope


def open(
    envelope: bytes,
    *,
    key: bytes,
    expected_context: dict,
    expected_ciphertext_sha256: str,
    clock: Callable[[], int] | None = None,
) -> bytes:
    """Authenticate and decrypt only an independently pinned complete envelope.

    The external SHA-256 covers magic/version, nonce, ciphertext and GCM tag.
    No context is read from the envelope. Authentication grants no release,
    proposal extension, signature, public classification, or one-time use.
    ``clock`` is only for offline tests; production callers must omit it.
    """
    _key(key)
    if (
        type(envelope) is not bytes
        or not len(MAGIC) + NONCE_BYTES + TAG_BYTES <= len(envelope) <= MAX_ENVELOPE_BYTES
        or not envelope.startswith(MAGIC)
    ):
        raise Rejected("ci_transfer_envelope")
    ctx, aad = _context(expected_context)
    _time(ctx, clock)
    if not _hex(expected_ciphertext_sha256) or not hmac.compare_digest(
        sha256(envelope).hexdigest(), expected_ciphertext_sha256
    ):
        raise Rejected("ci_transfer_pin")
    nonce_end = len(MAGIC) + NONCE_BYTES
    try:
        payload = AESGCM(key).decrypt(envelope[len(MAGIC) : nonce_end], envelope[nonce_end:], aad)
    except InvalidTag:
        raise Rejected("ci_transfer_authentication") from None
    _payload_digest(payload, ctx)
    _time(ctx, clock)
    return payload
