import base64
import binascii
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, require_fields

ROLES = ("curator", "evaluator", "approver", "trust")


def encode64(content):
    return base64.b64encode(content).decode("ascii")


def decode64(value):
    if not isinstance(value, str):
        raise Rejected("invalid_base64")
    try:
        return base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as error:
        raise Rejected("invalid_base64") from error


def pae(payload_type, payload):
    encoded_type = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(encoded_type), encoded_type, len(payload), payload)


def create_key(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.parent.is_symlink():
        raise Rejected("symlink_key")
    if not path.exists():
        key = Ed25519PrivateKey.generate()
        content = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with path.open("xb") as output:
            output.write(content)
        path.chmod(0o600)
    key = load_key(path)
    return encode64(key.public_key().public_bytes_raw())


def load_key(path):
    try:
        key = serialization.load_pem_private_key(bounded_read(path, 4096), password=None)
    except (ValueError, TypeError) as error:
        raise Rejected("invalid_signing_key") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise Rejected("wrong_key_algorithm")
    return key


def sign(payload, kind, key_path):
    key = load_key(key_path)
    payload_type = f"application/vnd.trusted-mlsecops.{kind}.v1+json"
    content = canonical(payload)
    public = key.public_key().public_bytes_raw()
    return {
        "payloadType": payload_type,
        "payload": encode64(content),
        "signatures": [
            {"keyid": digest(public), "sig": encode64(key.sign(pae(payload_type, content)))}
        ],
    }


def verify(envelope, kind, trusted_public):
    require_fields(envelope, ("payloadType", "payload", "signatures"))
    expected_type = f"application/vnd.trusted-mlsecops.{kind}.v1+json"
    if envelope["payloadType"] != expected_type:
        raise Rejected("wrong_payload_type")
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise Rejected("invalid_signature_count")
    require_fields(signatures[0], ("keyid", "sig"))
    public = decode64(trusted_public)
    payload = decode64(envelope["payload"])
    signature = decode64(signatures[0]["sig"])
    if signatures[0]["keyid"] != digest(public):
        raise Rejected("untrusted_key")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, pae(expected_type, payload))
    except (ValueError, InvalidSignature) as error:
        raise Rejected("invalid_signature") from error
    return decode(payload)
