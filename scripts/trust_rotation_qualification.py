"""A planned authority-key transition needs both owners and preserves revocations."""

import copy
import unittest

from mlsecops import signing, trust, trust_rotation
from mlsecops.contracts import Rejected, canonical, digest
from scripts import trust_qualification as fixtures


class RotationContracts(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.TrustContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.old_key = self.fixture.key
        self.old_public = self.fixture.public
        self.new_key = self.old_key.parent / "following.pem"
        self.new_public = signing.create_key(self.new_key)
        self.fixture.payload.update(revoked_artifacts=["b" * 64], revoked_keys=["c" * 64])
        self.previous = self.fixture.envelope()
        self.clock = int(self.fixture.wall)
        self.following = {
            **copy.deepcopy(self.fixture.payload),
            "version": 2,
            "issued_at": self.clock,
            "revoked_keys": sorted(["c" * 64, digest(signing.decode64(self.old_public))]),
        }
        self.intent = {
            "schema_version": 1,
            "environment": "local-cpu",
            "current_root": self.old_public,
            "next_root": self.new_public,
            "previous_version": 1,
            "previous_sha256": digest(canonical(self.previous)),
            "next_version": 2,
            "next_sha256": "0" * 64,
            "issued_at": self.clock,
            "expires_at": self.clock + 300,
        }

    def package(self):
        document = signing.sign(self.following, "trust-policy", self.new_key)
        intent = {**self.intent, "next_sha256": digest(canonical(document))}
        return {
            "schema_version": 1,
            "authorization": signing.sign(intent, "trust-root-rotation", self.old_key),
            "acceptance": signing.sign(intent, "trust-root-rotation", self.new_key),
            "document": document,
        }

    def check(self, package=None, **changes):
        return trust_rotation.verify(
            self.package() if package is None else package,
            **{
                "previous": self.previous,
                "environment": "local-cpu",
                "current_root": self.old_public,
                "next_root": self.new_public,
                "clock": self.clock,
                **changes,
            },
        )

    def test_dual_signed_transition_preserves_policy_and_retains_old_key_revocation(self):
        result = self.check()
        self.assertEqual(result["previous_sha256"], digest(canonical(self.previous)))
        self.assertEqual(result["next_version"], 2)
        self.assertEqual(result["next_root"], self.new_public)
        payload = trust.validate(self.package()["document"], self.new_public, "local-cpu")
        self.assertEqual(payload["revoked_artifacts"], ["b" * 64])
        self.assertIn(digest(signing.decode64(self.old_public)), payload["revoked_keys"])

    def test_one_owner_or_different_signed_intents_cannot_rotate(self):
        for field in ("authorization", "acceptance", "document"):
            package = self.package()
            package[field]["signatures"] = []
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.check(package)
        package = self.package()
        changed = signing.verify(package["acceptance"], "trust-root-rotation", self.new_public)
        changed["expires_at"] -= 1
        package["acceptance"] = signing.sign(changed, "trust-root-rotation", self.new_key)
        with self.assertRaises(Rejected):
            self.check(package)

    def test_identity_history_time_and_strict_schema_are_bound(self):
        original = copy.deepcopy(self.intent)
        for field, value in (
            ("schema_version", True),
            ("environment", "foreign"),
            ("current_root", self.new_public),
            ("next_root", self.old_public),
            ("previous_version", True),
            ("previous_version", 0),
            ("previous_sha256", "0" * 64),
            ("next_version", 3),
            ("issued_at", self.clock + 1),
            ("expires_at", self.clock),
            ("expires_at", self.clock + 601),
            ("extra", "forbidden"),
        ):
            self.intent = {**original, field: value}
            with self.subTest(field=field, value=value), self.assertRaises(Rejected):
                self.check()
        self.intent = original
        for changes in (
            {"clock": self.clock + 300},
            {"environment": "foreign"},
            {"next_root": self.old_public},
            {"next_root": "short"},
        ):
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                self.check(**changes)
        for package in (
            {},
            {**self.package(), "schema_version": True},
            {**self.package(), "extra": True},
        ):
            with self.assertRaises(Rejected):
                self.check(package)

    def test_transition_cannot_change_policy_erase_revocations_or_skip_versions(self):
        original = copy.deepcopy(self.following)
        for field, value in (
            ("promotion_policy_sha256", "d" * 64),
            ("revoked_artifacts", []),
            ("revoked_keys", ["c" * 64]),
            ("version", 3),
            ("issued_at", self.clock - 1),
            ("expires_at", self.clock + 299),
        ):
            self.following = {**original, field: value}
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.check()
        self.following = original
        for key in (self.old_public, self.new_public):
            self.fixture.payload["revoked_keys"] = sorted(["c" * 64, digest(signing.decode64(key))])
            self.previous = self.fixture.envelope()
            self.intent["previous_sha256"] = digest(canonical(self.previous))
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.check()

    def test_bounded_envelopes_canonical_keys_and_document_digest_are_enforced(self):
        with self.assertRaisesRegex(Rejected, "rotation_root_invalid"):
            self.check(next_root=signing.encode64(b"short"))
        package = self.package()
        package["acceptance"] = "x" * 1048576
        with self.assertRaisesRegex(Rejected, "rotation_package_size"):
            self.check(package)
        package = self.package()
        intent = signing.verify(package["authorization"], "trust-root-rotation", self.old_public)
        intent["next_sha256"] = "0" * 64
        package["authorization"] = signing.sign(intent, "trust-root-rotation", self.old_key)
        package["acceptance"] = signing.sign(intent, "trust-root-rotation", self.new_key)
        with self.assertRaisesRegex(Rejected, "rotation_signed_binding"):
            self.check(package)


if __name__ == "__main__":
    unittest.main()
