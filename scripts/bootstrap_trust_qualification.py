"""Original trust provisioning with real private files and signatures, no infrastructure."""

import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mlsecops import bootstrap, key_files, signing
from mlsecops.contracts import Rejected, canonical, digest, read_json

ROOT = Path(__file__).resolve().parents[1]


def snapshot(directory):
    return {
        path.relative_to(directory).as_posix(): digest(path.read_bytes())
        if path.is_file()
        else None
        for path in directory.rglob("*")
    }


class OriginalTrustTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.state = self.directory / "state"
        self.key = self.directory / "original.pem"
        self.public = signing.create_key(self.key)
        self.original = self.key.read_bytes()
        self.inventory = self.enterContext(
            patch.object(bootstrap, "collect", return_value={"scope": "controlled-test"})
        )

    def initialize(self, state=None, key=None):
        return bootstrap.initialize(
            ROOT,
            self.state if state is None else state,
            trust_key_path=self.key if key is None else key,
        )

    def assert_original_signature(self, state):
        public = read_json(state / "trusted-keys.json")
        self.assertEqual(set(public), {"curator", "evaluator", "approver", "trust"})
        self.assertEqual(public["trust"], self.public)
        self.assertEqual(len(set(public.values())), 4)
        statement = {"purpose": "bootstrap-original-trust-test", "sequence": 1}
        envelope = signing.sign(statement, "bootstrap-test", state / "keys/trust.pem")
        self.assertEqual(signing.verify(envelope, "bootstrap-test", self.public), statement)
        for role in ("curator", "evaluator", "approver"):
            with self.assertRaises(Rejected):
                signing.verify(envelope, "bootstrap-test", public[role])
            signed = signing.sign(statement, "bootstrap-test", state / f"keys/{role}.pem")
            self.assertEqual(signing.verify(signed, "bootstrap-test", public[role]), statement)

    def test_bad_inputs_rejected_before_inventory_or_state_creation(self):
        wrong = ec.generate_private_key(ec.SECP256R1())
        original = signing.load_key(self.key)
        cases = (
            b"",
            b"not-a-private-key",
            original.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            original.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(b"fixture-password"),
            ),
            wrong.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            self.original + b"\n" * (4097 - len(self.original)),
        )
        self.inventory.side_effect = AssertionError("invalid key reached inventory")
        for index, raw in enumerate(cases):
            with self.subTest(case=index):
                self.key.write_bytes(raw)
                with self.assertRaises(Rejected):
                    self.initialize()
                self.assertFalse(self.state.exists())
                self.assertEqual(digest(self.key.read_bytes()), digest(raw))

    def test_exact_reader_limit_is_preserved_without_reserialization(self):
        raw = self.original + b"\n" * (4096 - len(self.original))
        self.key.write_bytes(raw)
        self.initialize()
        self.assertEqual(digest((self.state / "keys/trust.pem").read_bytes()), digest(raw))
        self.assert_original_signature(self.state)

    def test_missing_key_and_directory_rejected_before_inventory(self):
        self.inventory.side_effect = AssertionError("invalid path reached inventory")
        for path in (self.directory / "missing.pem", self.directory):
            with self.subTest(kind=path.name), self.assertRaises(Rejected):
                self.initialize(key=path)
            self.assertFalse(self.state.exists())

    def test_hardlinked_key_is_not_imported(self):
        link = self.directory / "hardlink.pem"
        try:
            os.link(self.key, link)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"hardlinks unavailable: {type(error).__name__}")
        self.inventory.side_effect = AssertionError("hardlinked key reached inventory")
        with self.assertRaises(Rejected):
            self.initialize(key=link)
        self.assertFalse(self.state.exists())
        self.assertEqual(digest(self.key.read_bytes()), digest(self.original))

    def test_symlink_key_and_parent_are_not_imported(self):
        link = self.directory / "link.pem"
        parent = self.directory / "linked-parent"
        try:
            link.symlink_to(self.key)
            parent.symlink_to(self.directory, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlinks unavailable: {type(error).__name__}")
        self.inventory.side_effect = AssertionError("symlink key reached inventory")
        for path in (link, parent / self.key.name):
            with self.subTest(path=path.name), self.assertRaises(Rejected):
                self.initialize(key=path)
            self.assertFalse(self.state.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX ownership/mode checks require POSIX")
    def test_group_readable_key_rejected_before_inventory(self):
        self.key.chmod(0o640)
        self.inventory.side_effect = AssertionError("non-private key reached inventory")
        with self.assertRaisesRegex(Rejected, "signing_key_file_permissions"):
            self.initialize()
        self.assertFalse(self.state.exists())

    def test_denied_key_read_is_closed_without_state_or_inventory(self):
        self.inventory.side_effect = AssertionError("unreadable key reached inventory")
        with patch.object(key_files.os, "open", side_effect=PermissionError("fixture denial")):
            with self.assertRaises(Rejected):
                self.initialize()
        self.assertFalse(self.state.exists())

    def test_unowned_state_is_not_adopted_even_with_valid_original_key(self):
        self.state.mkdir()
        (self.state / "foreign-data").write_bytes(b"owned-by-another-caller")
        before = snapshot(self.state)
        self.inventory.side_effect = AssertionError("unowned workspace reached inventory")
        with self.assertRaises(Rejected):
            self.initialize()
        self.assertEqual(snapshot(self.state), before)

    def test_inventory_failure_leaves_absent_or_empty_state_untouched(self):
        self.inventory.side_effect = Rejected("incompatible_docker_profile")
        for existing in (False, True):
            if existing:
                self.state.mkdir()
            with (
                self.subTest(existing=existing),
                self.assertRaisesRegex(Rejected, "incompatible_docker_profile"),
            ):
                self.initialize()
            self.assertEqual(self.state.exists(), existing)
            self.assertEqual(snapshot(self.state), {})

    def test_fresh_import_preserves_bytes_and_actual_signing_identity(self):
        result = self.initialize()
        self.assert_original_signature(self.state)
        self.assertEqual(
            digest((self.state / "keys/trust.pem").read_bytes()), digest(self.original)
        )
        self.assertEqual(digest(self.key.read_bytes()), digest(self.original))
        self.assertEqual(
            result["public_keys_digest"],
            digest(canonical(read_json(self.state / "trusted-keys.json"))),
        )
        self.assertEqual(
            set(result),
            {"workspace_digest", "public_keys_digest", "policy_digest", "schema_version"},
        )
        self.assertFalse(any((self.state / "evidence").iterdir()))

    def test_retry_accepts_same_identity_without_overwriting_any_role(self):
        first = self.initialize()
        (self.state / "approved/sentinel").write_bytes(b"retained-data")
        before = snapshot(self.state)

        def key_metadata():
            return {
                path.name: (path.stat().st_ino, path.stat().st_mtime_ns)
                for path in (self.state / "keys").iterdir()
            }

        original_metadata = key_metadata()
        # Different PEM whitespace still represents the same identity. It must not overwrite.
        self.key.write_bytes(self.original + b"\n")
        self.assertEqual(self.initialize(), first)
        self.assertEqual(snapshot(self.state), before)
        self.assertEqual(key_metadata(), original_metadata)
        self.assertEqual(bootstrap.initialize(ROOT, self.state), first)
        self.assertEqual(snapshot(self.state), before)
        self.assertEqual(key_metadata(), original_metadata)
        self.assert_original_signature(self.state)

    def test_supplied_key_can_match_a_default_initialized_workspace(self):
        first = bootstrap.initialize(ROOT, self.state)
        before = snapshot(self.state)
        self.assertEqual(self.initialize(key=self.state / "keys/trust.pem"), first)
        self.assertEqual(snapshot(self.state), before)

    def test_changed_external_key_rejected_before_inventory_and_without_rotation(self):
        self.initialize()
        before = snapshot(self.state)
        foreign = self.directory / "foreign.pem"
        signing.create_key(foreign)
        self.inventory.side_effect = AssertionError("rotation reached inventory")
        with self.assertRaises(Rejected):
            self.initialize(key=foreign)
        self.assertEqual(snapshot(self.state), before)
        self.assert_original_signature(self.state)

    def test_registry_or_existing_private_key_mismatch_never_repairs_state(self):
        for role in ("curator", "evaluator", "approver", "trust", "registry"):
            state = self.directory / role
            self.initialize(state)
            if role == "registry":
                registry = read_json(state / "trusted-keys.json")
                registry["trust"] = registry["approver"]
                (state / "trusted-keys.json").write_bytes(canonical(registry))
            else:
                (state / f"keys/{role}.pem").write_bytes(b"invalid-existing-key")
            before = snapshot(state)
            with self.subTest(role=role), self.assertRaises(Rejected):
                self.initialize(state)
            self.assertEqual(snapshot(state), before)

    def test_missing_registry_or_role_on_retry_never_regenerates(self):
        for name in ("trusted-keys.json", *(f"keys/{role}.pem" for role in signing.ROLES)):
            state = self.directory / name.replace("/", "-")
            self.initialize(state)
            (state / name).unlink()
            before = snapshot(state)
            with self.subTest(name=name), self.assertRaises(Rejected):
                self.initialize(state)
            self.assertEqual(snapshot(state), before)

    def test_input_replaced_after_preflight_does_not_change_imported_identity(self):
        replacement = self.directory / "replacement.pem"
        signing.create_key(replacement)

        def inventory(root):
            self.key.write_bytes(replacement.read_bytes())
            return {"scope": "controlled-test"}

        self.inventory.side_effect = inventory
        self.initialize()
        self.assert_original_signature(self.state)
        self.assertEqual(
            digest((self.state / "keys/trust.pem").read_bytes()), digest(self.original)
        )

    def test_interrupted_key_creation_preserves_owner_and_never_regenerates_on_retry(self):
        create = bootstrap.create_key
        for role in ("curator", "evaluator", "approver"):
            state = self.directory / ("interrupted-" + role)

            def interrupted(path):
                if Path(path).stem == role:
                    raise KeyboardInterrupt()
                return create(path)

            with self.subTest(role=role), patch.object(bootstrap, "create_key", interrupted):
                with self.assertRaises(KeyboardInterrupt):
                    self.initialize(state)
            identity = read_json(state / "workspace.json")
            self.assertRegex(identity["workspace_id"], "^[0-9a-f]{32}$")
            before = snapshot(state)
            for supplied in (True, False):
                with self.assertRaises(Rejected):
                    if supplied:
                        self.initialize(state)
                    else:
                        bootstrap.initialize(ROOT, state)
                self.assertEqual(snapshot(state), before)

    def test_interruption_before_registry_publish_cannot_be_silently_completed(self):
        write = bootstrap.write_json

        def interrupted(path, value):
            if Path(path).name == "trusted-keys.json":
                raise KeyboardInterrupt()
            write(path, value)

        with patch.object(bootstrap, "write_json", interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.initialize()
        self.assertTrue((self.state / "workspace.json").is_file())
        self.assertFalse((self.state / "trusted-keys.json").exists())
        before = snapshot(self.state)
        with self.assertRaises(Rejected):
            self.initialize()
        self.assertEqual(snapshot(self.state), before)

    def test_interrupted_private_write_keeps_owner_and_never_repairs_partial_key(self):
        opened = key_files.opened

        @contextmanager
        def interrupted(path, *, create=False):
            with opened(path, create=create) as stream:
                if create and Path(path) == self.state / "keys/trust.pem":
                    stream.write(self.original[:20])
                    raise KeyboardInterrupt()
                yield stream

        with patch.object(key_files, "opened", interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.initialize()
        self.assertTrue((self.state / "workspace.json").is_file())
        self.assertFalse((self.state / "trusted-keys.json").exists())
        self.assertEqual((self.state / "keys/trust.pem").stat().st_size, 20)
        before = snapshot(self.state)
        with self.assertRaises(Rejected):
            self.initialize()
        self.assertEqual(snapshot(self.state), before)

    def test_exclusive_import_does_not_replace_a_key_created_during_initialization(self):
        create = bootstrap.create_key
        foreign = self.directory / "foreign.pem"
        signing.create_key(foreign)

        def collision(path):
            public = create(path)
            if Path(path).stem == "approver":
                target = self.state / "keys/trust.pem"
                with key_files.opened(target, create=True) as output:
                    output.write(foreign.read_bytes())
            return public

        with patch.object(bootstrap, "create_key", collision):
            with self.assertRaises(Rejected):
                self.initialize()
        self.assertEqual(
            digest((self.state / "keys/trust.pem").read_bytes()), digest(foreign.read_bytes())
        )
        self.assertFalse((self.state / "trusted-keys.json").exists())
        before = snapshot(self.state)
        with self.assertRaises(Rejected):
            self.initialize()
        self.assertEqual(snapshot(self.state), before)

    def test_interruption_after_registry_publish_can_retry_without_replacing_identity(self):
        write = bootstrap.write_json

        def interrupted(path, value):
            if Path(path).name == "inventory.json":
                raise OSError("fixture inventory write failed")
            write(path, value)

        with patch.object(bootstrap, "write_json", interrupted):
            with self.assertRaises(OSError):
                self.initialize()
        before = snapshot(self.state)
        self.initialize()
        after = snapshot(self.state)
        self.assertEqual({name: after[name] for name in before}, before)
        self.assertEqual(set(after) - set(before), {"inventory.json"})
        self.assert_original_signature(self.state)


if __name__ == "__main__":
    unittest.main()
