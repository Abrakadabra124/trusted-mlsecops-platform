"""Seal and open the original publisher's closed tip for private journal-tip.bin."""

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, decode, require_fields
from scripts import ci_campaign_journal as journal
from scripts import ci_private_assets as store

MAGIC = b"MLSTIP\x01"
KIND = "campaign-journal-tip"
LIMIT = 16384


def _need(ok):
    if not ok:
        raise Rejected("tip_witness_refused")


def _binding(journal_release, origin_release, run_owner, source, trusted_public):
    # The publisher can import this module to seal the result of its final append.
    from scripts.ci_original_publish import _origin

    binding = journal._binding(journal_release, run_owner, source, trusted_public)
    binding["origin"] = _origin(
        origin_release, binding["journal"]["release_id"], binding["run_owner"]
    )
    return binding


def _closed_tip(tip):
    require_fields(tip, ("step", "asset_id", "sha256"))
    _need(store._number(tip["step"]) == 8)
    store._number(tip["asset_id"])
    store._hex(tip["sha256"], 64)
    return tip.copy()


def _cipher(key):
    _need(type(key) is bytes and len(key) == 32)
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=MAGIC).derive(key)
    return AESGCM(derived)


def seal(
    tip, *, journal_release, origin_release, run_owner, source, trusted_public, key, key_path
) -> bytes:
    """Seal the final tip returned by journal.publisher under its pinned signing key."""
    binding = _binding(journal_release, origin_release, run_owner, source, trusted_public)
    record = dict(binding=binding, tip=_closed_tip(tip))
    cipher = _cipher(key)
    signed = signing.sign(record, KIND, key_path)
    signing.verify(signed, KIND, trusted_public)
    nonce = secrets.token_bytes(12)
    raw = MAGIC + nonce + cipher.encrypt(nonce, canonical(signed), MAGIC + canonical(binding))
    _need(len(raw) <= LIMIT)
    return raw


def open_witness(
    raw, *, journal_release, origin_release, run_owner, source, trusted_public, key
) -> dict:
    """Verify against the caller's independent pins and return only the exact step-eight tip."""
    offset = len(MAGIC) + 12
    _need(type(raw) is bytes and offset + 16 < len(raw) <= LIMIT and raw.startswith(MAGIC))
    binding = _binding(journal_release, origin_release, run_owner, source, trusted_public)
    try:
        plain = _cipher(key).decrypt(
            raw[len(MAGIC) : offset], raw[offset:], MAGIC + canonical(binding)
        )
    except InvalidTag:
        raise Rejected("tip_witness_authentication") from None
    signed = decode(plain, LIMIT)
    record = signing.verify(signed, KIND, trusted_public)
    require_fields(record, ("binding", "tip"))
    tip = _closed_tip(record["tip"])
    # Compare signed bytes to the expected binding even if the transport key is shared.
    expected = canonical(dict(binding=binding, tip=tip))
    _need(signed["payload"] == signing.encode64(expected))
    signature = signed["signatures"][0]["sig"]
    _need(signature == signing.encode64(signing.decode64(signature)))
    _need(plain == canonical(signed))
    return tip
