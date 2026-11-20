"""Private transport of a completed receiver's primary evidence for historical replay."""

import secrets
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from mlsecops import ci_transfer, signing
from mlsecops.contracts import Rejected, canonical, decode, digest, require_fields, safe_child
from mlsecops.storage import object_id
from scripts import ci_campaign_control as control
from scripts import ci_primary_carrier as carrier
from scripts import ci_serving_retention as serving
from scripts import m18_shared_retention as shared
from scripts.ci_primary_store import MAGIC

KIND = "receiver-primary"
HEADER_LIMIT = 128 * 1024
OWNER = ("freeze_pin", "freeze", "expected", "run_owner")
ROLES = {"shared": shared, "serving": serving}
GATES = {"shared": ("M11", "M12"), "serving": ("M13", "M14", "M15")}
CLEANUP = {"shared": ("sql", "cluster"), "serving": (*GATES["serving"], "SQL")}
OBSERVATIONS = (
    "index_pin",
    "arguments",
    "origin",
    "cleanup_owner",
    "cleanup",
    "gate_counts",
    "consumer_offline",
)
PROOFS = ("replay_sha256", "carrier_sha256")


def need(value):
    if not value:
        raise Rejected("receiver_primary_refused")


def context(role, run_owner, source):
    need(type(role) is str and role in ROLES)
    control.binding(run_owner, source)
    return dict(role=role, run_owner=run_owner.copy(), source=source.copy())


def cipher(key):
    need(type(key) is bytes and len(key) == 32)
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=MAGIC).derive(key)
    return AESGCM(derived)


def validate(record, binding):
    require_fields(record, ("binding", *OBSERVATIONS, *PROOFS))
    need(canonical(record["binding"]) == canonical(binding))
    role, run = binding["role"], binding["run_owner"]
    need(canonical(record["cleanup_owner"]) == canonical(run | {"producer_job": role}))
    require_fields(record["cleanup"], CLEANUP[role])
    need(all(v is True for v in record["cleanup"].values()))
    require_fields(record["gate_counts"], GATES[role])
    need(all(type(v) is int and 0 < v <= 100000 for v in record["gate_counts"].values()))
    origin = record["origin"]
    require_fields(origin, ("workspace_id", "container_id", "offline_pin"))
    control.hexadecimal(origin["workspace_id"], 32)
    for pin in (
        origin["container_id"],
        origin["offline_pin"],
        record["consumer_offline"],
        record["index_pin"],
        *(record[k] for k in PROOFS),
    ):
        object_id(pin)
    args = record["arguments"]
    if role == "shared":
        extra = ("report_pins", "actual_pin", "native_pin")
    else:
        extra = ("report_pins", "admission_pins", "transitions", "consumer_storage_pin")
    require_fields(args, (*OWNER, *extra))
    checked = ROLES[role].authority(**args)
    need(canonical(checked["run_owner"]) == canonical(run))
    need({k: checked["expected"][k] for k in binding["source"]} == binding["source"])


def seal(root, result, *, role, key, run_owner, source):
    """Return encrypted private bytes and a fresh receiver verification key after teardown."""
    binding = context(role, run_owner, source)
    aead = cipher(key)
    require_fields(result, ("destination", "replay", "release_ready", *OBSERVATIONS))
    need(result["release_ready"] is False and result["replay"].get("release_ready") is False)
    payload = carrier.pack(root, result["destination"], role=role, index_pin=result["index_pin"])
    record = {k: result[k] for k in OBSERVATIONS} | dict(
        binding=binding,
        replay_sha256=digest(canonical(result["replay"])),
        carrier_sha256=digest(payload),
    )
    validate(record, binding)
    with TemporaryDirectory(prefix="receiver-issuer-") as temporary:
        signer = Path(temporary) / "issuer.pem"
        public = signing.create_key(signer)
        header = canonical(signing.sign(record, KIND, signer))
    need(len(header) <= HEADER_LIMIT)
    size = len(MAGIC) + 12 + 16 + 4 + len(header) + len(payload)
    need(size <= ci_transfer.MAX_ENVELOPE_BYTES)
    plain = len(header).to_bytes(4, "big") + header + payload
    nonce = secrets.token_bytes(12)
    return MAGIC + nonce + aead.encrypt(nonce, plain, MAGIC + canonical(binding)), public


def replay(root, packet, *, role, key, run_owner, source, trusted_public, owner, origin):
    """Require receiver key and producer expectations from independent channels."""
    binding = context(role, run_owner, source)
    require_fields(owner, OWNER)
    need(
        type(packet) is bytes
        and len(MAGIC) + 32 < len(packet) <= ci_transfer.MAX_ENVELOPE_BYTES
        and packet.startswith(MAGIC)
    )
    offset = len(MAGIC) + 12
    try:
        plain = cipher(key).decrypt(
            packet[len(MAGIC) : offset], packet[offset:], MAGIC + canonical(binding)
        )
    except InvalidTag:
        raise Rejected("receiver_primary_authentication") from None
    size = int.from_bytes(plain[:4], "big")
    need(0 < size <= HEADER_LIMIT and 4 + size < len(plain))
    record = signing.verify(decode(plain[4 : 4 + size], HEADER_LIMIT), KIND, trusted_public)
    validate(record, binding)
    args = record["arguments"]
    need(canonical({k: args[k] for k in OWNER}) == canonical(owner))
    need(canonical(record["origin"]) == canonical(origin))
    payload = plain[4 + size :]
    need(digest(payload) == record["carrier_sha256"])
    runtime = serving.plain(safe_child(serving.plain(root), ".runtime"))
    runtime.mkdir(mode=0o700, exist_ok=True)
    with TemporaryDirectory(prefix="primary-restore-", dir=runtime) as temporary:
        destination = Path(temporary) / "retained"
        carrier.unpack(root, destination, payload, role=role, index_pin=record["index_pin"])
        result = ROLES[role].replay(root, destination, index_pin=record["index_pin"], **args)
    need(result["release_ready"] is False and digest(canonical(result)) == record["replay_sha256"])
    return result
