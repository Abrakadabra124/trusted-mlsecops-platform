"""Encrypted producer instructions for both consumers of the original frozen proposal."""

import secrets
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from mlsecops import ci_transfer, signing
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields
from mlsecops.security_events import hexadecimal
from mlsecops.storage import object_id
from scripts import ci_candidate_transfer as candidate
from scripts import ci_private_assets as store
from scripts import ci_upstream_transfer as upstream
from scripts import frozen_candidate_transfer as transfer

MAGIC = store.CONTROL_MAGIC
LIMIT = store.LIMITS[store.CONTROL]
KIND = "private-campaign-control"
PHASES = {
    "candidate-shared": "M11-M12",
    "candidate-serving": "M13",
    "upstream-serving": "upstream-M13",
    "validation-serving": "validation-M13",
}


def need(ok):
    if not ok:
        raise Rejected("campaign_control_rejected")


def cipher(key):
    need(type(key) is bytes and len(key) == 32)
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=MAGIC).derive(key)
    return AESGCM(derived)


def binding(run_owner, source):
    require_fields(run_owner, ("repository", "run_id", "run_attempt", "producer_job"))
    need(
        run_owner["repository"] == ci_transfer.REPOSITORY
        and run_owner["producer_job"] == "producer"
    )
    for name in ("run_id", "run_attempt"):
        need(type(run_owner[name]) is int and 1 <= run_owner[name] <= ci_transfer.MAX_INTEGER)
    require_fields(source, transfer.delivery.SOURCE)
    hexadecimal(source["source_revision"], 40)
    object_id(source["source_fingerprint"])
    image = source["image_id"]
    need(type(image) is str and image.startswith("sha256:"))
    object_id(image[7:])
    return MAGIC + canonical({"run_owner": run_owner, "source": source})


def checked(record, run_owner, source):
    require_fields(record, ("owner", "origin", "reports", "packets", "storage", "schema_version"))
    need(type(record["schema_version"]) is int and record["schema_version"] == 1)
    origin = record["origin"]
    require_fields(origin, ("workspace_id", "container_id", "offline_pin"))
    hexadecimal(origin["workspace_id"], 32)
    object_id(origin["container_id"])
    object_id(origin["offline_pin"])
    owner = record["owner"]
    require_fields(owner, ("freeze_pin", "freeze", "expected", "run_owner"))
    # The freeze reader supports environment lookup for legacy callers. Wire data must be explicit.
    require_fields(owner["freeze"], transfer.delivery.FILES)
    now = candidate._now()
    transfer.authority(**owner, clock=now)
    need(canonical(run_owner) == canonical(owner["run_owner"]))
    need({k: owner["expected"][k] for k in transfer.delivery.SOURCE} == source)
    require_fields(record["reports"], upstream.GATES)
    for pin in record["reports"].values():
        object_id(pin)
    storage = store.producer_receipt(
        record["storage"], run_owner | {"source_revision": source["source_revision"]}
    )
    require_fields(record["packets"], PHASES)
    for name, phase in PHASES.items():
        row = record["packets"][name]
        extra = ("manifest_sha256",) if name.startswith("candidate-") else ()
        require_fields(row, ("context", "ciphertext_sha256", "size", *extra))
        for field in ("ciphertext_sha256", *extra):
            object_id(row[field])
        need(
            type(row["size"]) is int
            and len(ci_transfer.MAGIC) + 28 <= row["size"] <= store.LIMITS[name]
        )
        asset = storage["assets"][name]
        need(asset["sha256"] == row["ciphertext_sha256"] and asset["size"] == row["size"])
        ctx, _ = ci_transfer._context(row["context"])
        expected = candidate._context(
            owner, phase, ctx["payload_sha256"], ctx["issued_at"], ctx["expires_at"]
        )
        need(ctx == expected)
        ci_transfer._time(ctx, lambda: now)
    shared, serving = (record["packets"][k] for k in ("candidate-shared", "candidate-serving"))
    need(shared["context"]["payload_sha256"] == serving["context"]["payload_sha256"])
    need(shared["manifest_sha256"] == serving["manifest_sha256"])
    return record


def attach(record, name, envelope):
    need(type(name) is str and name in PHASES)
    row = record["packets"][name]
    need(
        type(envelope) is bytes
        and len(envelope) == row["size"]
        and envelope.startswith(ci_transfer.MAGIC)
    )
    need(digest(envelope) == row["ciphertext_sha256"])
    return {k: v for k, v in row.items() if k != "size"} | dict(
        envelope=envelope, handling="private", release_ready=False
    )


def issue(*, owner, origin, reports, packets, storage, key):
    """Return private control bytes and the producer job's one-use public verification key."""
    require_fields(packets, PHASES)
    require_fields(owner, ("freeze_pin", "freeze", "expected", "run_owner"))
    require_fields(owner["expected"], transfer.IDENTITY)
    source = {k: owner["expected"][k] for k in transfer.delivery.SOURCE}
    aad = binding(owner["run_owner"], source)
    rows = {}
    for name, value in packets.items():
        extra = ("manifest_sha256",) if name.startswith("candidate-") else ()
        fields = ("context", "ciphertext_sha256", *extra)
        require_fields(value, (*fields, "envelope", "handling", "release_ready"))
        need(
            value["handling"] == "private"
            and value["release_ready"] is False
            and type(value["envelope"]) is bytes
        )
        rows[name] = {k: value[k] for k in fields} | {"size": len(value["envelope"])}
    # Snapshot scalars/maps before signing. The actual ciphertext never enters metadata.
    record = checked(
        decode(
            canonical(
                dict(
                    schema_version=1,
                    owner=owner,
                    origin=origin,
                    reports=reports,
                    packets=rows,
                    storage=storage,
                )
            ),
            limit=LIMIT,
        ),
        owner["run_owner"],
        source,
    )
    for name, value in packets.items():
        attach(record, name, value["envelope"])
    aead = cipher(key)
    with TemporaryDirectory(prefix="mlsecops-control-") as tmp:
        path = Path(tmp) / "issuer.pem"
        public = signing.create_key(path)
        signed = canonical(signing.sign(record, KIND, path))
    nonce = secrets.token_bytes(12)
    result = MAGIC + nonce + aead.encrypt(nonce, signed, aad)
    need(len(result) <= LIMIT)
    return result, public


def _authenticated(raw, *, trusted_public, key, run_owner, source):
    need(type(raw) is bytes and len(MAGIC) + 28 <= len(raw) <= LIMIT and raw.startswith(MAGIC))
    need(type(trusted_public) is str and len(trusted_public) == 44)
    aad = binding(run_owner, source)
    offset = len(MAGIC) + 12
    try:
        plain = cipher(key).decrypt(raw[len(MAGIC) : offset], raw[offset:], aad)
    except InvalidTag:
        raise Rejected("campaign_control_authentication") from None
    signed = decode(plain, limit=LIMIT)
    return signing.verify(signed, KIND, trusted_public)


def read(raw, *, trusted_public, key, run_owner, source):
    """Authenticate producer instructions and enforce the live admission windows."""
    record = _authenticated(
        raw, trusted_public=trusted_public, key=key, run_owner=run_owner, source=source
    )
    return checked(record, run_owner, source)


def verify_retained_control(raw, journal, *, key, run_owner, source):
    """Audit retained bytes against a trusted publisher journal. Return no admission authority."""
    require_fields(journal, ("storage", "issuer"))
    issuer = journal["issuer"]
    require_fields(issuer, ("public", "control_sha256", "storage_sha256"))
    need(type(raw) is bytes and len(raw) <= LIMIT and digest(raw) == issuer["control_sha256"])
    record = _authenticated(
        raw, trusted_public=issuer["public"], key=key, run_owner=run_owner, source=source
    )
    r = store._receipt(
        journal["storage"], run_owner | {"source_revision": source["source_revision"]}
    )
    pin = r["assets"].pop(store.CONTROL, None)
    if pin is not None:
        need(pin["size"] == len(raw) and pin["sha256"] == digest(raw))
    need(r == record["storage"] and digest(canonical(r)) == issuer["storage_sha256"])
    return True
