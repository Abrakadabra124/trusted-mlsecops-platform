import copy
import unittest
from unittest.mock import patch

from mlsecops import release_authorization
from mlsecops.contracts import Rejected
from scripts import kube_approval_fixture as approvals
from scripts import promotion_qualification as fixtures
from scripts.kube_rollback_native import variant
from scripts.serving_native import bind_real_runtime


class ApprovalFixtureContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.PromotionAdmissionContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.PromotionAdmissionContracts.tearDownClass()

    def test_signed_expiry_and_new_sequence_are_verified_by_real_authorization(self):
        fixture = fixtures.PromotionAdmissionContracts()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        image = fixture.arguments["expected_serving_image"]
        bind_real_runtime(fixture, image)
        unexpired_original = copy.deepcopy(fixture.arguments)
        clock = fixture.clock
        with patch.object(approvals.time, "time", return_value=clock + 10):
            expires = approvals.shorten(fixture)
        self.assertEqual(expires, clock + 100)
        old = dict(fixture.arguments)
        context = copy.deepcopy(old["context"])
        first = release_authorization.verify(**old, clock=expires - 1)
        self.assertEqual(first["sequence"], 1)
        self.assertEqual(first["expires_at"], expires)
        with self.assertRaisesRegex(Rejected, "expired"):
            release_authorization.verify(**old, clock=expires)
        approvals.renew(fixture, image)
        self.assertEqual(fixture.arguments["context"], context)
        second = release_authorization.verify(**fixture.arguments, clock=expires + 1)
        self.assertEqual(second["sequence"], 2)
        self.assertNotEqual(second["subject_sha256"], first["subject_sha256"])
        self.assertGreater(second["expires_at"], first["expires_at"])
        self.assertFalse(second["release_ready"])
        previous = release_authorization.verify(**unexpired_original, clock=expires + 1)
        self.assertEqual(previous["sequence"], 1)
        self.assertGreater(previous["expires_at"], expires + 1)
        self.assertNotEqual(previous["subject_sha256"], second["subject_sha256"])
        with self.assertRaisesRegex(Rejected, "sequence"):
            approvals.renew(fixture, image)
        with patch.object(approvals.time, "time", return_value=clock + 1800):
            with self.assertRaisesRegex(Rejected, "window"):
                approvals.shorten(fixture)

    def test_two_real_models_have_different_bytes_scores_and_contexts(self):
        fixture = fixtures.PromotionAdmissionContracts()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        image = fixture.arguments["expected_serving_image"]
        features, scores = bind_real_runtime(fixture, image)
        prior = copy.deepcopy(fixture.arguments)
        from mlsecops.contracts import digest

        old_model = digest(fixture.fixture.bundle.materials.fixture.model)
        approvals.renew(fixture, image)
        new_model, new_scores = variant(fixture, image, features)
        self.assertNotEqual(old_model, new_model)
        self.assertGreater(max(abs(a - b) for a, b in zip(scores, new_scores, strict=True)), 1e-5)
        self.assertNotEqual(
            prior["context"]["candidate_reference"],
            fixture.arguments["context"]["candidate_reference"],
        )
        old = release_authorization.verify(**prior, clock=fixture.clock)
        new = release_authorization.verify(**fixture.arguments, clock=fixture.clock)
        self.assertNotEqual(old["subject_sha256"], new["subject_sha256"])
        self.assertEqual((old["sequence"], new["sequence"]), (1, 2))


if __name__ == "__main__":
    unittest.main()
