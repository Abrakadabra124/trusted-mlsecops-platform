import ipaddress
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    digest,
    read_json,
    safe_child,
    write_json,
)

ROLES = ("ingestor", "curator", "publisher", "scorer", "promoter", "serving")
IDENTITIES = ("ca", "server", *(f"ml_{role}" for role in ROLES))
CLUSTER_HOST = "postgres.ml-storage.svc.cluster.local"


def server_names(host):
    if host == "127.0.0.1":
        return [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address(host))]
    if host == CLUSTER_HOST:
        return [x509.DNSName(host)]
    raise Rejected("storage_server_host_invalid")


def workspace_id(state):
    marker = read_json(safe_child(state, "workspace.json"))
    identity = marker.get("workspace_id")
    if (
        marker.get("product") != "trusted-mlsecops"
        or type(marker.get("schema_version")) is not int
        or marker["schema_version"] != 1
        or not isinstance(identity, str)
        or not re.fullmatch(r"[0-9a-f]{32}", identity)
    ):
        raise Rejected("storage_workspace_invalid")
    return identity


def issue(identity, issuer_key=None, issuer_certificate=None, server_host="127.0.0.1"):
    if identity not in IDENTITIES:
        raise Rejected("storage_certificate_identity_invalid")
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity)])
    moment = datetime.now(UTC)
    authority = identity == "ca"
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_certificate.subject if issuer_certificate else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(moment - timedelta(minutes=5))
        .not_valid_after(moment + timedelta(days=365 if authority else 90))
        .add_extension(
            x509.BasicConstraints(ca=authority, path_length=0 if authority else None), True
        )
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, authority, authority, False, False),
            True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
    )
    if not authority:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.SERVER_AUTH
                    if identity == "server"
                    else ExtendedKeyUsageOID.CLIENT_AUTH
                ]
            ),
            True,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False
        )
    if identity == "server":
        builder = builder.add_extension(
            x509.SubjectAlternativeName(server_names(server_host)),
            False,
        )
    return key, builder.sign(issuer_key or key, hashes.SHA256())


def write_pair(directory, identity, key, certificate):
    atomic_write(
        Path(directory) / f"{identity}.key",
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    atomic_write(
        Path(directory) / f"{identity}.crt", certificate.public_bytes(serialization.Encoding.PEM)
    )


def validate(state, server_host="127.0.0.1"):
    directory = safe_child(state, "storage-pki")
    marker = read_json(safe_child(directory, "identity.json"))
    if marker.get("workspace_id") != workspace_id(state) or marker.get("schema_version") != 1:
        raise Rejected("storage_pki_ownership_mismatch")
    expected = {f"{identity}.{suffix}" for identity in IDENTITIES for suffix in ("key", "crt")}
    if {path.name for path in directory.iterdir()} != expected | {"identity.json"}:
        raise Rejected("storage_pki_incomplete")
    certificates = {}
    try:
        authority = x509.load_pem_x509_certificate(bounded_read(directory / "ca.crt", 4096))
        for identity in IDENTITIES:
            content = bounded_read(safe_child(directory, f"{identity}.crt"), 4096)
            certificate = x509.load_pem_x509_certificate(content)
            key = serialization.load_pem_private_key(
                bounded_read(safe_child(directory, f"{identity}.key"), 4096), None
            )
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise Rejected("storage_key_algorithm_invalid")
            if certificate.public_key().public_numbers() != key.public_key().public_numbers():
                raise Rejected("storage_key_certificate_mismatch")
            certificate.verify_directly_issued_by(authority)
            if certificate.subject != x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, identity)]
            ):
                raise Rejected("storage_certificate_subject_mismatch")
            if identity == "server" and list(
                certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            ) != server_names(server_host):
                raise Rejected("storage_certificate_host_mismatch")
            if (
                not certificate.not_valid_before_utc
                <= datetime.now(UTC)
                < certificate.not_valid_after_utc
            ):
                raise Rejected("storage_certificate_expired_or_future")
            certificates[identity] = digest(content)
    except Rejected:
        raise
    except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound) as error:
        raise Rejected("storage_pki_invalid") from error
    if certificates != marker.get("certificates"):
        raise Rejected("storage_certificate_changed")
    return marker


def initialize(state, server_host="127.0.0.1"):
    server_names(server_host)
    identity = workspace_id(state)
    directory = safe_child(state, "storage-pki")
    if directory.exists():
        return validate(state, server_host)
    directory.mkdir(mode=0o700)
    authority_key, authority = issue("ca")
    write_pair(directory, "ca", authority_key, authority)
    for name in IDENTITIES[1:]:
        write_pair(directory, name, *issue(name, authority_key, authority, server_host))
    write_json(
        directory / "identity.json",
        {
            "schema_version": 1,
            "workspace_id": identity,
            "certificates": {
                name: digest(bounded_read(directory / f"{name}.crt", 4096)) for name in IDENTITIES
            },
        },
    )
    return validate(state, server_host)
