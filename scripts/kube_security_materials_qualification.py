"""Actual audit keys/certificates and role configuration, without any infrastructure."""

import importlib.util
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from mlsecops import kube_security_resources as resources
from mlsecops import security_event_config, security_event_tls, signing
from mlsecops.contracts import Rejected, decode, read_json, write_json


class AuditMaterials(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("mlsecops.kube_security_materials"))
        from mlsecops import kube_security_materials

        self.subject = kube_security_materials
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / "audit"
        self.authority = signing.create_key(self.directory / "model-root.pem")
        self.options = dict(
            workspace="a" * 32,
            environment="local-cpu",
            initial_root=self.authority,
            policy="b" * 64,
        )

    def created(self):
        return self.subject.create(self.root, **self.options)

    def test_invalid_context_cannot_create_any_keys_or_adopt_existing_directory(self):
        for name, value in (
            ("workspace", "bad"),
            ("environment", "../escape"),
            ("initial_root", "bad"),
            ("policy", "bad"),
        ):
            with self.assertRaises(Rejected):
                self.subject.create(self.root, **{**self.options, name: value})
            self.assertFalse(self.root.exists())
        self.root.mkdir()
        (self.root / "untouched").write_bytes(b"owner")
        with self.assertRaises(Rejected):
            self.created()
        self.assertEqual((self.root / "untouched").read_bytes(), b"owner")

    def test_signed_registry_has_all_six_roles_and_only_trust_requires_heartbeat(self):
        materials = self.created()
        self.assertNotEqual(materials.identity["registry_root"], self.authority)
        registry = materials.registry
        self.assertEqual(
            {p.role for p in registry.producers},
            {"intake", "controller", "serving", "promoter", "trust", "collector"},
        )
        self.assertEqual([p.role for p in registry.producers if p.heartbeat_required], ["trust"])
        self.assertEqual(registry.policy_sha256, self.options["policy"])
        self.assertEqual(len({p.public_key for p in registry.producers}), 6)
        for role in resources.ROLES:
            value = materials.provision(role)
            observed = security_event_config.Registry(
                value["registry"],
                trusted_root=value["registry_root"],
                expected_sha256=value["registry_sha256"],
                clock_ms=registry.issued_at_ms,
            )
            self.assertEqual(observed.producer(value["producer_id"]).role, role)
            self.assertFalse(any("key_file" in field or "token" in field for field in value))

    def test_separate_ca_purposes_fixed_dns_and_private_key_pairs(self):
        self.created()
        authority = x509.load_pem_x509_certificate((self.root / "tls/ca.crt").read_bytes())
        self.assertTrue(
            authority.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        )
        authority.verify_directly_issued_by(authority)
        for role in resources.ROLES:
            cert = x509.load_pem_x509_certificate((self.root / f"tls/{role}.crt").read_bytes())
            key = serialization.load_pem_private_key(
                (self.root / f"tls/{role}.key").read_bytes(), None
            )
            cert.verify_directly_issued_by(authority)
            self.assertEqual(cert.public_key().public_numbers(), key.public_key().public_numbers())
            self.assertFalse(
                cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            )
            purpose = (
                ExtendedKeyUsageOID.SERVER_AUTH
                if role == "collector"
                else ExtendedKeyUsageOID.CLIENT_AUTH
            )
            self.assertEqual(
                list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value),
                [purpose],
            )
            if role == "collector":
                self.assertEqual(
                    list(
                        cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                    ),
                    [x509.DNSName(security_event_tls.SERVICE_NAME)],
                )

    def test_repeat_uses_existing_identity_and_tampering_or_missing_files_refuses(self):
        initial = self.created()
        self.assertEqual(self.subject.load(self.root, **self.options).identity, initial.identity)
        with self.assertRaises(Rejected):
            self.created()
        for name, value in (
            ("workspace", "c" * 32),
            ("environment", "other"),
            ("initial_root", signing.create_key(self.directory / "foreign.pem")),
            ("policy", "c" * 64),
        ):
            with self.assertRaises(Rejected):
                self.subject.load(self.root, **{**self.options, name: value})
        key = self.root / "keys/promoter.pem"
        before = key.read_bytes()
        key.write_bytes(b"changed")
        with self.assertRaises(Rejected):
            self.subject.load(self.root, **self.options)
        key.write_bytes(before)
        (self.root / "tls/ca.crt").unlink()
        with self.assertRaises(Rejected):
            self.subject.load(self.root, **self.options)

    def test_exact_role_files_and_fixed_runtime_paths_never_export_ca_or_registry_root_key(self):
        materials = self.created()
        for role in resources.ROLES:
            files = materials.runtime_files(role, "c" * 64, "10.96.0.10")
            self.assertEqual(set(files), set(resources.FILES[role]))
            self.assertNotIn("ca.key", files)
            self.assertNotIn("root.pem", files)
            config_name = {
                "collector": "collector.json",
                "trust": "producer.json",
                "promoter": "audit.json",
                "serving": "producer.json",
            }[role]
            value = decode(files[config_name])
            self.assertEqual(value["schema_version"], 3 if role == "promoter" else 2)
            self.assertEqual(value["state_directory"], "/audit/state")
            self.assertEqual(value["state_sha256"], "c" * 64)
            self.assertEqual(value["registry_sha256"], materials.registry.sha256)
            self.assertEqual(value["port"], 8443)
            if role != "collector":
                self.assertEqual(value["tls"]["address"], "10.96.0.10")
                self.assertEqual(value["tls"]["server_name"], security_event_tls.SERVICE_NAME)
                self.assertFalse({"receipt.pem", "operator.token", "collector.pem"} & set(files))
            else:
                self.assertNotIn("address", value["tls"])
            if role == "trust":
                observer = decode(files["observer.json"])
                self.assertEqual(observer["initial_root"], self.authority)
                self.assertEqual(observer["trust_client"], "/client")
                self.assertEqual(observer["producer_config"], "/security/producer.json")
            resources.secret(self.options["workspace"], role, files)

    def test_runtime_rejects_unallocated_address_bad_pin_or_unknown_role(self):
        materials = self.created()
        for address in ("127.0.0.1", "localhost", "8.8.8.8", "::1", "169.254.169.254", None, []):
            with self.assertRaises(Rejected):
                materials.runtime_files("promoter", "c" * 64, address)
        with self.assertRaises(Rejected):
            materials.runtime_files("promoter", "bad", "10.0.0.1")
        for role in ("worker", [], None):
            with self.assertRaises(Rejected):
                materials.runtime_files(role, "c" * 64, "10.0.0.1")
            with self.assertRaises(Rejected):
                materials.provision(role)

    def test_serving_identity_is_bound_to_service_not_promoter_or_trust_key(self):
        materials = self.created()
        files = materials.runtime_files("serving", "c" * 64, "10.96.0.10")
        identity = decode(files["identity-audit.json"])
        self.assertEqual(set(identity), {"schema_version", "producer_config", "service_sha256"})
        self.assertEqual(identity["producer_config"], "/security/producer.json")
        self.assertEqual(len(identity["service_sha256"]), 64)
        self.assertEqual(files["producer.pem"], materials.read("keys/serving.pem"))
        for role in ("promoter", "trust", "collector", "root", "receipt"):
            self.assertNotEqual(files["producer.pem"], materials.read(f"keys/{role}.pem"))
        repeated = materials.runtime_files("serving", "d" * 64, "10.96.0.11")
        self.assertEqual(decode(repeated["identity-audit.json"]), identity)
        other = self.subject.create(
            self.directory / "other", **{**self.options, "workspace": "d" * 32}
        )
        other_files = other.runtime_files("serving", "c" * 64, "10.96.0.10")
        self.assertNotEqual(
            decode(other_files["identity-audit.json"])["service_sha256"], identity["service_sha256"]
        )

    def test_saved_policy_cannot_relabel_registry_and_expiry_never_generates_new_keys(self):
        materials = self.created()
        path = self.root / "identity.json"
        identity = read_json(path)
        changed = {**identity, "policy": "d" * 64}
        write_json(path, changed)
        with self.assertRaisesRegex(Rejected, "policy_binding"):
            self.subject.load(self.root, **{**self.options, "policy": "d" * 64})
        write_json(path, identity)
        with (
            patch.object(
                time, "time_ns", return_value=materials.registry.expires_at_ms * 1_000_000
            ),
            self.assertRaises(Rejected),
        ):
            self.subject.load(self.root, **self.options)
        self.assertEqual(read_json(path), identity)


if __name__ == "__main__":
    unittest.main()
