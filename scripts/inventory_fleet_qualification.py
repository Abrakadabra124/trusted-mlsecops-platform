"""Four live deployment roles and their shared qualification trust authority."""

import unittest

from mlsecops.contracts import Rejected, canonical, digest
from scripts import candidate_serving_reader_qualification as fixtures


class SharedAuthority(unittest.TestCase):
    def test_signed_member_keeps_permit_identity_and_obeys_shared_dataset_revocation(self):
        from mlsecops import signing
        from mlsecops.candidate_serving_reader import fleet_policy

        fx = fixtures.CandidateReaderContracts()
        fx.setUpClass()
        self.addCleanup(fx.tearDownClass)
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        pin = digest(canonical(fx.permit))
        roster = dict(
            schema_version=1,
            campaign_id=fx.permit["campaign_id"],
            environment="local-cpu",
            permits=dict(current=pin, previous="1" * 64, independent="2" * 64),
        )
        envelope = signing.sign(roster, "inventory-qualification-fleet", fx.key)
        self.assertEqual(
            fleet_policy(envelope, fx.public, fx.permit["campaign_id"], pin),
            digest(canonical(roster)),
        )
        fx.policy["promotion_policy_sha256"] = digest(canonical(roster))
        reader = fx.reader(fleet_envelope=envelope)
        loaded = reader.load()
        self.assertEqual(loaded.permit_sha256, pin)
        fx.policy.update(
            version=2, revoked_artifacts=[fx.verified["manifest"]["materials"]["split_manifest"]]
        )
        with self.assertRaisesRegex(Rejected, "trust_artifact_revoked"):
            reader.check(loaded)
        for campaign, member, env in (
            ("c" * 32, pin, envelope),
            (roster["campaign_id"], "f" * 64, envelope),
            (roster["campaign_id"], pin, signing.sign(roster, "release-approval", fx.key)),
        ):
            with self.subTest(member=member), self.assertRaises(Rejected):
                fleet_policy(env, fx.public, campaign, member)
