import ipaddress
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mlsecops.contracts import Rejected, canonical, digest, read_json, safe_child, write_json
from mlsecops.storage_bootstrap import IMAGE as PG_IMAGE
from mlsecops.storage_pki import issue, write_pair

ROLES = ("tracking_metadata", "tracking_auth")
LABEL = "org.trusted-mlsecops.tracking-service"
CONFIG_LABEL = "org.trusted-mlsecops.tracking-config"


def leaf(name, authority_key, authority):
    key = ec.generate_private_key(ec.SECP256R1())
    moment = datetime.now(UTC)
    server = name in ("server", "postgres")
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(authority.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(moment - timedelta(minutes=5))
        .not_valid_after(moment + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            True,
        )
    )
    if server:
        names = (
            [x509.DNSName("tracking-pg")]
            if name == "postgres"
            else [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        )
        certificate = certificate.add_extension(x509.SubjectAlternativeName(names), False)
    return key, certificate.sign(authority_key, hashes.SHA256())


def initialize(state, image, port):
    if (
        not isinstance(image, str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", image)
        or type(port) is not int
        or not 1024 <= port <= 65535
    ):
        raise Rejected("tracking_service_image_or_port_invalid")
    marker = state / "configuration.json"
    if marker.exists():
        current = read_json(marker)
        if (
            current["image"] != image
            or current["port"] != port
            or current["postgres_image"] != PG_IMAGE
        ):
            raise Rejected("tracking_service_change_requires_explicit_migration")
        return validate(state, current)
    if state.exists() and any(state.iterdir()):
        raise Rejected("tracking_service_partial_state_requires_recovery")
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    authority_key, authority = issue("ca")
    write_pair(state, "ca", authority_key, authority)
    for name in ("server", "postgres", *ROLES):
        write_pair(state, name, *leaf(name, authority_key, authority))
    write_json(
        state / "credentials.json",
        {
            role: secrets.token_urlsafe(48)
            for role in ("admin", "publisher", "reader", "foreign", "csrf")
        },
    )
    value = {
        "schema_version": 1,
        "identity": uuid.uuid4().hex,
        "image": image,
        "postgres_image": PG_IMAGE,
        "port": port,
        "files": {path.name: digest(path.read_bytes()) for path in state.iterdir()},
    }
    value["config_digest"] = digest(canonical(value))
    write_json(marker, value)
    return validate(state, value)


def validate(state, value, *, require_current_certificates=True):
    if value != read_json(state / "configuration.json"):
        raise Rejected("tracking_service_state_changed")
    unsigned = {key: item for key, item in value.items() if key != "config_digest"}
    if digest(canonical(unsigned)) != value["config_digest"]:
        raise Rejected("tracking_service_configuration_digest_invalid")
    for name, expected in value["files"].items():
        content = safe_child(state, name).read_bytes()
        if digest(content) != expected:
            raise Rejected("tracking_service_secret_or_certificate_changed")
        if name.endswith(".crt") and require_current_certificates:
            certificate = x509.load_pem_x509_certificate(content)
            if (
                not certificate.not_valid_before_utc
                <= datetime.now(UTC)
                < certificate.not_valid_after_utc
            ):
                raise Rejected("tracking_service_certificate_expired")
    return value


def configuration(state, spec):
    validate(state, spec)
    postgres = {
        "ca.crt": (state / "ca.crt").read_bytes(),
        "server.crt": (state / "postgres.crt").read_bytes(),
        "server.key": (state / "postgres.key").read_bytes(),
        "pg_hba.conf": (
            "local all postgres peer\nlocal all all reject\n"
            + "".join(f"hostssl {role} {role} 0.0.0.0/0 cert\n" for role in ROLES)
            + "host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n"
        ).encode(),
        "postgresql.conf": (
            b"listen_addresses = '*'\nunix_socket_directories = '/tmp'\n"
            b"unix_socket_permissions = 0700\nssl = on\nssl_min_protocol_version = 'TLSv1.3'\n"
            b"ssl_cert_file = '/var/lib/postgresql/config/server.crt'\n"
            b"ssl_key_file = '/var/lib/postgresql/config/server.key'\n"
            b"ssl_ca_file = '/var/lib/postgresql/config/ca.crt'\n"
            b"hba_file = '/var/lib/postgresql/config/pg_hba.conf'\n"
            b"max_connections = 32\nshared_buffers = '64MB'\nwork_mem = '4MB'\n"
            b"max_wal_size = '256MB'\nstatement_timeout = '30s'\nlock_timeout = '5s'\n"
            b"log_min_messages = warning\nlog_min_error_statement = panic\n"
            b"log_error_verbosity = terse\n"
        ),
    }
    server = {
        name: (state / name).read_bytes()
        for name in ("ca.crt", "server.crt", "server.key")
        + tuple(f"{role}.{suffix}" for role in ROLES for suffix in ("crt", "key"))
    }
    credentials = read_json(state / "credentials.json")
    server["bootstrap.json"] = canonical({name: credentials[name] for name in ("admin", "csrf")})
    return {"postgres": postgres, "server": server}
