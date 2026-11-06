"""Controlled fixture transitions still pass the production cryptographic verifier."""

import copy
import unittest

from mlsecops import release_authorization, release_key_rotation, release_policy
from mlsecops.contracts import Rejected, canonical, digest
from scripts import promotion_qualification as fixtures
from scripts import release_signer_fixture


class SignerFixtureContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.PromotionAdmissionContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.PromotionAdmissionContracts.tearDownClass()

    def setUp(self):
        self.fixture = fixtures.PromotionAdmissionContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.authorization = self.fixture.fixture
        self.clock = self.fixture.clock + 3
        self.image = self.fixture.arguments["expected_serving_image"]
        self.head = {"sequence": 3, "request_sha256": "a" * 64}

    def prepare(self, **changes):
        return release_signer_fixture.prepare(
            self.fixture,
            self.image,
            **{"role": "publisher", "head": self.head, "clock": self.clock, **changes},
        )

    def test_role_rotation_preserves_model_and_rebinds_every_signed_release_material(self):
        for role in release_policy.ROLES:
            with self.subTest(role=role):
                previous = self.fixture.arguments["expected_policy"]
                old_arguments = copy.deepcopy(self.fixture.arguments)
                original_model = self.authorization.bundle.materials.fixture.model
                original_context = canonical(self.fixture.arguments["context"])
                package = self.prepare(role=role)
                transition = release_key_rotation.verify(
                    package,
                    trusted_root=self.fixture.arguments["trusted_root"],
                    expected_policy=previous,
                    head=self.head,
                    environment="local-cpu",
                    clock=self.clock,
                )
                self.assertEqual(transition["intent"]["role"], role)
                self.assertEqual(
                    transition["intent"]["next_policy_sha256"],
                    self.fixture.arguments["expected_policy"],
                )
                verified = release_authorization.verify(**self.fixture.arguments, clock=self.clock)
                self.assertFalse(verified["release_ready"])
                self.assertEqual(self.authorization.bundle.materials.fixture.model, original_model)
                self.assertEqual(canonical(self.fixture.arguments["context"]), original_context)
                self.assertEqual(self.authorization.approval["sequence"], self.head["sequence"] + 1)
                self.assertEqual(set(self.fixture.arguments["reports"]), set(release_policy.GATES))
                for field in ("package", "assurance_envelope", "approval_envelope"):
                    with self.assertRaises(Rejected):
                        release_authorization.verify(
                            **{**self.fixture.arguments, field: old_arguments[field]},
                            clock=self.clock,
                        )
                self.head = {
                    "sequence": self.head["sequence"] + 1,
                    "request_sha256": digest(canonical(package)),
                }
                self.clock += 3

    def test_missing_gate_does_not_become_accepted_after_resigning(self):
        self.prepare()
        reports = dict(self.fixture.arguments["reports"])
        reports.pop("M22")
        with self.assertRaisesRegex(Rejected, "release_gate_set_incomplete"):
            release_authorization.verify(
                **{**self.fixture.arguments, "reports": reports}, clock=self.clock
            )

    def test_invalid_scope_is_rejected_before_mutating_the_fixture(self):
        original = copy.deepcopy(self.fixture.arguments)
        for changes in (
            {"role": "root"},
            {"head": {**self.head, "extra": 1}},
            {"head": {**self.head, "sequence": True}},
            {"clock": True},
            {"clock": self.authorization.policy["expires_at"]},
            {"head": {**self.head, "sequence": 9007199254740991}},
        ):
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                self.prepare(**changes)
            self.assertEqual(self.fixture.arguments, original)


if __name__ == "__main__":
    unittest.main()
