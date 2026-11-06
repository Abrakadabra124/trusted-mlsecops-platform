"""Real signatures for operator-authorized release signer transitions."""

import copy
import unittest
from unittest.mock import patch

from mlsecops import release_key_rotation, signing
from mlsecops.contracts import Rejected, canonical, digest
from scripts import release_policy_qualification as policy_fixtures


class ReleaseKeyRotationContracts(unittest.TestCase):
    def setUp(self):
        self.fixture = policy_fixtures.ReleasePolicyContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.clock = self.fixture.clock
        self.new_key = self.fixture.directory / "next-publisher.pem"
        self.new_public = signing.create_key(self.new_key)
        self.after = copy.deepcopy(self.fixture.policy)
        self.after.update(version=2, issued_at=self.clock)
        self.after["identities"]["publisher"]["public_key"] = self.new_public
        self.head = {"sequence": 3, "request_sha256": "a" * 64}
        self.intent = {
            "schema_version": 1,
            "environment": "local-cpu",
            "role": "publisher",
            "previous_policy_sha256": self.fixture.pin,
            "next_policy_sha256": digest(canonical(self.after)),
            "sequence": self.head["sequence"],
            "request_sha256": self.head["request_sha256"],
            "issued_at": self.clock,
            "expires_at": self.clock + 300,
        }

    def package(self, *, intent=None, after=None):
        return {
            "schema_version": 1,
            "authorization": signing.sign(
                self.intent if intent is None else intent,
                "release-key-rotation",
                self.fixture.keys["root"],
            ),
            "previous_policy": self.fixture.envelope,
            "next_policy": signing.sign(
                self.after if after is None else after,
                "promotion-policy",
                self.fixture.keys["root"],
            ),
        }

    def check(self, package=None, **changes):
        return release_key_rotation.verify(
            self.package() if package is None else package,
            **{
                "trusted_root": self.fixture.public["root"],
                "expected_policy": self.fixture.pin,
                "head": self.head,
                "environment": "local-cpu",
                "clock": self.clock,
                **changes,
            },
        )

    def test_authorized_transition_binds_current_head_without_issuing_release(self):
        package = self.package()
        before = canonical(package)
        result = self.check(package)
        self.assertEqual(result["intent"], self.intent)
        self.assertEqual(
            result["previous_key"], digest(signing.decode64(self.fixture.public["publisher"]))
        )
        self.assertEqual(result["next_key"], digest(signing.decode64(self.new_public)))
        self.assertEqual(result["previous_version"], 1)
        self.assertEqual(result["next_version"], 2)
        self.assertFalse(result["release_ready"])
        self.assertEqual(canonical(package), before)

    def test_signed_intent_cannot_select_other_head_policy_or_environment(self):
        for changes in (
            {"head": {**self.head, "sequence": 4}},
            {"head": {**self.head, "request_sha256": "b" * 64}},
            {"expected_policy": "c" * 64},
            {"environment": "other"},
            {"trusted_root": self.fixture.public["publisher"]},
        ):
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                self.check(**changes)

    def test_valid_root_signature_does_not_authorize_other_policy_changes(self):
        variants = []
        for field, value in (("version", 1), ("version", 3), ("environment", "other")):
            variants.append({**self.after, field: value})
        changed = copy.deepcopy(self.after)
        changed["identities"]["publisher"]["issuer"] = "other-issuer"
        variants.append(changed)
        variants.append(copy.deepcopy(self.fixture.policy))
        for after in variants:
            intent = {**self.intent, "next_policy_sha256": digest(canonical(after))}
            with self.subTest(after=after), self.assertRaises(Rejected):
                self.check(self.package(intent=intent, after=after))

    def test_each_release_role_rotates_separately(self):
        for role in ("publisher", "assessor", "approver"):
            after = copy.deepcopy(self.fixture.policy)
            after.update(version=2, issued_at=self.clock)
            after["identities"][role]["public_key"] = self.new_public
            intent = {**self.intent, "role": role, "next_policy_sha256": digest(canonical(after))}
            with self.subTest(role=role):
                result = self.check(self.package(intent=intent, after=after))
                self.assertEqual(
                    result["previous_key"], digest(signing.decode64(self.fixture.public[role]))
                )
                self.assertEqual(result["next_key"], digest(signing.decode64(self.new_public)))

    def test_unsigned_foreign_wrong_domain_and_swapped_policies_fail(self):
        package = self.package()
        variants = []
        for field in ("authorization", "previous_policy", "next_policy"):
            changed = copy.deepcopy(package)
            changed[field]["signatures"] = []
            variants.append(changed)
        for key, kind in (
            (self.new_key, "release-key-rotation"),
            (self.fixture.keys["root"], "promotion-policy"),
        ):
            variants.append({**package, "authorization": signing.sign(self.intent, kind, key)})
        variants.append(
            {
                **package,
                "previous_policy": package["next_policy"],
                "next_policy": package["previous_policy"],
            }
        )
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(Rejected):
                self.check(changed)

    def test_exact_schemas_bounded_package_and_depth(self):
        package = self.package()
        for changed in (
            None,
            [],
            {},
            {**package, "schema_version": True},
            {**package, "schema_version": 2},
            {**package, "extra": 1},
            {**package, "authorization": {"payload": "x" * 1048576}},
        ):
            with self.assertRaises(Rejected):
                self.check(changed if changed is not None else [])
        nested = []
        for _ in range(1100):
            nested = [nested]
        with self.assertRaises(Rejected):
            self.check({**package, "authorization": nested})
        with patch.object(release_key_rotation, "canonical", side_effect=RecursionError):
            with self.assertRaisesRegex(Rejected, "nesting"):
                self.check(package)
        for intent in (
            {**self.intent, "extra": 1},
            {k: v for k, v in self.intent.items() if k != "role"},
        ):
            with self.assertRaises(Rejected):
                self.check(self.package(intent=intent))
        for head in (
            None,
            {},
            {**self.head, "sequence": True},
            {**self.head, "sequence": 0},
            {**self.head, "request_sha256": "latest"},
        ):
            with self.assertRaises(Rejected):
                self.check(head=head)

    def test_ambiguous_signed_roles_and_context_are_rejected(self):
        for field, values in (
            ("schema_version", (True, 2)),
            ("role", (None, [], "root", "trainer")),
            ("previous_policy_sha256", ("f" * 64,)),
            ("next_policy_sha256", ("f" * 64, "latest")),
            ("sequence", (True, 4)),
            ("request_sha256", ("f" * 64,)),
            ("environment", ("foreign",)),
        ):
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(Rejected):
                    self.check(self.package(intent={**self.intent, field: value}))

    def test_key_rotation_cannot_weaken_gates_or_change_another_role(self):
        variants = []
        changed = copy.deepcopy(self.after)
        changed["required_gates"] = changed["required_gates"][:-1]
        variants.append(changed)
        changed = copy.deepcopy(self.after)
        changed["identities"]["assessor"]["public_key"] = self.fixture.public["publisher"]
        variants.append(changed)
        for public in (
            self.fixture.public["root"],
            self.fixture.public["approver"],
            self.fixture.public["publisher"],
        ):
            changed = copy.deepcopy(self.after)
            changed["identities"]["publisher"]["public_key"] = public
            variants.append(changed)
        for after in variants:
            with self.subTest(after=after), self.assertRaises(Rejected):
                self.check(
                    self.package(
                        after=after,
                        intent={**self.intent, "next_policy_sha256": digest(canonical(after))},
                    )
                )

    def test_transition_has_its_own_short_window_inside_both_policies(self):
        for changes in (
            {"issued_at": self.clock + 1},
            {"expires_at": self.clock},
            {"expires_at": self.clock + 601},
            {"issued_at": True},
            {"issued_at": self.clock - 1},
        ):
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                self.check(self.package(intent={**self.intent, **changes}))
        for changes in ({"issued_at": self.clock - 70}, {"expires_at": self.clock + 100}):
            after = {**self.after, **changes}
            with self.assertRaises(Rejected):
                self.check(
                    self.package(
                        after=after,
                        intent={**self.intent, "next_policy_sha256": digest(canonical(after))},
                    )
                )
        self.fixture.policy["expires_at"] = self.clock + 100
        self.fixture.pin = digest(canonical(self.fixture.policy))
        self.fixture.envelope = signing.sign(
            self.fixture.policy, "promotion-policy", self.fixture.keys["root"]
        )
        with self.assertRaises(Rejected):
            self.check(
                self.package(intent={**self.intent, "previous_policy_sha256": self.fixture.pin})
            )


if __name__ == "__main__":
    unittest.main()
