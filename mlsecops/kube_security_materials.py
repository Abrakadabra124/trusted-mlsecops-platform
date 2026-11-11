"""Operator-owned audit identities. Fixed TLS purposes, pinned files, no implicit rekey."""

import ipaddress
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mlsecops import key_files, release_policy, security_event_config, signing
from mlsecops import kube_security_resources as resources
from mlsecops import security_event_tls as tls
from mlsecops import security_events as events
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    safe_child,
    write_json,
)

PRODUCERS = ("intake", "promoter", "trust", "serving", "controller", "collector")
SIGNERS = ("root", "receipt", *PRODUCERS)
FILES = (
    *(f"keys/{role}.pem" for role in SIGNERS),
    *(f"tls/{role}.{suffix}" for role in ("ca", *resources.ROLES) for suffix in ("crt", "key")),
    "registry.json",
    "ingress.token",
    "operator.token",
    "service.token",
)
IDENTITY_FIELDS = (
    "schema_version",
    "workspace",
    "environment",
    "initial_root",
    "policy",
    "registry_root",
    "registry_sha256",
    "files",
)


def context(workspace, environment, initial_root, policy):
    events.hexadecimal(workspace, 32)
    release_policy.name(environment)
    events.public_key(initial_root)
    events.hexadecimal(policy)
    return dict(
        workspace=workspace, environment=environment, initial_root=initial_root, policy=policy
    )


def address(value):
    if type(value) is not str:
        raise Rejected("kube_security_service_address")
    try:
        parsed = ipaddress.IPv4Address(value)
    except ValueError:
        raise Rejected("kube_security_service_address") from None
    if not any(parsed in network for network in tls.NETWORKS[:3]):
        raise Rejected("kube_security_service_address")
    return str(parsed)


def issue(role, issuer=None):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "security-" + role)])
    now = datetime.now(UTC)
    authority = role == "ca"
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject if issuer is None else issuer[1].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365 if authority else 90))
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
                    if role == "collector"
                    else ExtendedKeyUsageOID.CLIENT_AUTH
                ]
            ),
            True,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer[0].public_key()), False
        )
    if role == "collector":
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(tls.SERVICE_NAME)]), False
        )
    return key, builder.sign(key if issuer is None else issuer[0], hashes.SHA256())


def write(path, content):
    with key_files.opened(path, create=True) as stream:
        stream.write(content)


def read(directory, name):
    path = safe_child(directory, name)
    return bounded_read(path, 32768) if name == "registry.json" else key_files.read(path)


def create(directory, *, workspace, environment, initial_root, policy):
    expected = context(workspace, environment, initial_root, policy)
    directory = Path(directory)
    try:
        directory.mkdir(mode=0o700)
    except OSError:
        raise Rejected("kube_security_materials_exist_or_unavailable") from None
    for name in ("keys", "tls"):
        (directory / name).mkdir(mode=0o700)
    public = {role: signing.create_key(directory / f"keys/{role}.pem") for role in SIGNERS}
    ca = issue("ca")
    for role in ("ca", *resources.ROLES):
        key, cert = ca if role == "ca" else issue(role, ca)
        write(
            directory / f"tls/{role}.key",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        write(directory / f"tls/{role}.crt", cert.public_bytes(serialization.Encoding.PEM))
    now = time.time_ns() // 1_000_000
    registry = dict(
        schema_version=1,
        policy_sha256=policy,
        issued_at_ms=now,
        expires_at_ms=now + 86400000,
        receipt_public=public["receipt"],
        producers=[
            dict(
                public_key=public[role],
                role=role,
                epoch=secrets.token_hex(16),
                heartbeat_required=role == "trust",
            )
            for role in PRODUCERS
        ],
    )
    write_json(
        directory / "registry.json",
        signing.sign(registry, "security-event-config", directory / "keys/root.pem"),
    )
    for name in ("ingress", "operator", "service"):
        write(directory / (name + ".token"), secrets.token_hex(32).encode("ascii"))
    write_json(
        directory / "identity.json",
        dict(
            schema_version=1,
            **expected,
            registry_root=public["root"],
            registry_sha256=digest(canonical(registry)),
            files={name: digest(read(directory, name)) for name in FILES},
        ),
    )
    return load(directory, **expected)


@dataclass(frozen=True)
class Materials:
    directory: Path
    identity: dict
    registry: security_event_config.Registry

    def read(self, name):
        return read(self.directory, name)

    def provision(self, role):
        resources.identity(role)
        producer = next(p for p in self.registry.producers if p.role == role)
        return dict(
            schema_version=1,
            role=role,
            registry=decode(self.read("registry.json"), 32768),
            registry_root=self.identity["registry_root"],
            registry_sha256=self.registry.sha256,
            producer_id=producer.identity,
        )

    def runtime_files(self, role, pin, service_address):
        resources.identity(role)
        events.hexadecimal(pin)
        service_address = address(service_address)
        files = {
            "registry.json": self.read("registry.json"),
            "ca.crt": self.read("tls/ca.crt"),
            "tls.crt": self.read(f"tls/{role}.crt"),
            "tls.key": self.read(f"tls/{role}.key"),
            "ingress.token": self.read("ingress.token"),
        }
        profile = dict(
            schema_version=3 if role == "promoter" else 2,
            registry_file="/security/registry.json",
            registry_root=self.identity["registry_root"],
            registry_sha256=self.registry.sha256,
            state_directory="/audit/state",
            state_sha256=pin,
            ingress_token_file="/security/ingress.token",
            port=resources.PORT,
            tls=dict(
                ca_file="/security/ca.crt",
                certificate_file="/security/tls.crt",
                key_file="/security/tls.key",
            ),
        )
        if role == "collector":
            files.update(
                {
                    name + ".pem": self.read("keys/" + name + ".pem")
                    for name in ("receipt", "collector")
                }
            )
            files["operator.token"] = self.read("operator.token")
            profile.update(
                receipt_key_file="/security/receipt.pem",
                collector_key_file="/security/collector.pem",
                operator_token_file="/security/operator.token",
            )
            config_name = "collector.json"
        else:
            files["producer.pem"] = self.read(f"keys/{role}.pem")
            profile["producer_key_file"] = "/security/producer.pem"
            profile["tls"].update(address=service_address, server_name=tls.SERVICE_NAME)
            config_name = "audit.json" if role == "promoter" else "producer.json"
            if role == "trust":
                files["observer.json"] = canonical(
                    dict(
                        schema_version=1,
                        trust_client="/client",
                        environment=self.identity["environment"],
                        initial_root=self.identity["initial_root"],
                        producer_config="/security/producer.json",
                        rotations=[],
                    )
                )
            elif role == "serving":
                files["service.token"] = self.read("service.token")
                # Stable service identity across Pod/image replacement, not a model digest.
                files["identity-audit.json"] = canonical(
                    dict(
                        schema_version=1,
                        producer_config="/security/producer.json",
                        service_sha256=digest(
                            canonical(
                                {
                                    "workspace": self.identity["workspace"],
                                    "environment": self.identity["environment"],
                                    "role": "serving",
                                }
                            )
                        ),
                    )
                )
        files[config_name] = canonical(profile)
        return files


def load(directory, *, workspace, environment, initial_root, policy):
    expected = context(workspace, environment, initial_root, policy)
    directory = Path(directory)
    identity = read_json(safe_child(directory, "identity.json"))
    events.shape(identity, IDENTITY_FIELDS)
    events.version(identity["schema_version"])
    if (
        any(identity[name] != value for name, value in expected.items())
        or type(identity["files"]) is not dict
        or set(identity["files"]) != set(FILES)
    ):
        raise Rejected("kube_security_materials_binding")
    for name, reference in identity["files"].items():
        events.hexadecimal(reference)
        if digest(read(directory, name)) != reference:
            raise Rejected("kube_security_materials_changed")
    registry = security_event_config.Registry(
        read_json(safe_child(directory, "registry.json")),
        trusted_root=identity["registry_root"],
        expected_sha256=identity["registry_sha256"],
        clock_ms=time.time_ns() // 1_000_000,
    )
    if registry.policy_sha256 != policy:
        raise Rejected("kube_security_policy_binding")
    return Materials(directory, identity, registry)
