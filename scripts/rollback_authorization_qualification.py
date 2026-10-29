"""Rollback is a fresh approval of an unchanged bundle, never a sequence reset."""

import copy
import unittest

from mlsecops.contracts import Rejected, canonical
from mlsecops.signing import sign
from scripts import release_authorization_qualification as fixtures


class RollbackAuthorization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.ReleaseAuthorizationContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.ReleaseAuthorizationContracts.tearDownClass()

    def setUp(self):
        self.fixture = fixtures.ReleaseAuthorizationContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.original_package = canonical(self.fixture.package["envelope"])
        self.fixture.approval.update(
            schema_version=2,
            action="rollback",
            sequence=3,
            rollback={
                "from_sequence": 2,
                "from_request_sha256": "a" * 64,
                "target_request_sha256": "b" * 64,
            },
        )

    def test_new_signed_sequence_authorizes_unchanged_target_bundle(self):
        decision = self.fixture.check()
        self.assertEqual(decision["sequence"], 3)
        self.assertEqual(decision["rollback"], self.fixture.approval["rollback"])
        self.assertEqual(decision["subject_sha256"], self.fixture.release["subject_sha256"])
        self.assertFalse(decision["release_ready"])
        self.assertEqual(canonical(self.fixture.package["envelope"]), self.original_package)

    def test_legacy_approval_cannot_claim_rollback_or_new_sequence(self):
        self.fixture.approval.pop("rollback")
        self.fixture.approval["schema_version"] = 1
        with self.assertRaisesRegex(Rejected, "release_approval_binding"):
            self.fixture.check()
        self.fixture.approval["action"] = "promote"
        with self.assertRaisesRegex(Rejected, "release_approval_binding"):
            self.fixture.check()

    def test_rollback_intent_shape_and_sequence_are_strict(self):
        valid = copy.deepcopy(self.fixture.approval)
        for field, value in (
            ("action", "promote"),
            ("sequence", 1),
            ("sequence", 2),
            ("sequence", 4),
            ("sequence", True),
            ("rollback", {}),
            ("rollback", None),
            ("schema_version", True),
            ("schema_version", 3),
        ):
            with self.subTest(field=field, value=value):
                self.fixture.approval = {**valid, field: value}
                with self.assertRaises(Rejected):
                    self.fixture.check()
        for field, value in (
            ("from_sequence", 0),
            ("from_sequence", True),
            ("from_sequence", 1),
            ("from_request_sha256", "invalid"),
            ("target_request_sha256", "a" * 64),
            ("target_request_sha256", None),
            ("extra", "not-allowed"),
        ):
            with self.subTest(field=field):
                self.fixture.approval = {**valid, "rollback": {**valid["rollback"], field: value}}
                with self.assertRaises(Rejected):
                    self.fixture.check()

    def test_rollback_still_requires_reports_assurance_validity_and_approver(self):
        with self.assertRaises(Rejected):
            self.fixture.check(assurance_envelope=None)
        with self.assertRaises(Rejected):
            self.fixture.check(reports={})
        with self.assertRaises(Rejected):
            self.fixture.check(clock=self.fixture.approval["expires_at"])
        wrong = sign(
            self.fixture.approval, "release-approval", self.fixture.authorities.keys["assessor"]
        )
        with self.assertRaises(Rejected):
            self.fixture.check(approval_envelope=wrong)


if __name__ == "__main__":
    unittest.main()
