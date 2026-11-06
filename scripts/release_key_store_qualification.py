"""Real signed authorization/online lease; only the SQL transport is mocked."""

import copy
import unittest
from unittest.mock import Mock, patch

from mlsecops import promotion_state, release_key_store, signing, trust
from mlsecops.contracts import Rejected, canonical, digest
from scripts import release_key_rotation_qualification as fixtures


class ReleaseKeyStoreContracts(unittest.TestCase):
    def setUp(self):
        self.rotation = fixtures.ReleaseKeyRotationContracts()
        self.rotation.setUp()
        self.addCleanup(self.rotation.doCleanups)
        self.package = self.rotation.package()
        self.reference = digest(canonical(self.package))
        self.old_key = self.rotation.check()["previous_key"]
        self.online_key = self.rotation.fixture.directory / "online-root.pem"
        self.online_public = signing.create_key(self.online_key)
        self.online = {
            "schema_version": 1,
            "environment": "local-cpu",
            "version": 2,
            "promotion_policy_sha256": self.rotation.intent["next_policy_sha256"],
            "issued_at": self.rotation.clock - 10,
            "expires_at": self.rotation.clock + 500,
            "revoked_keys": [self.old_key],
            "revoked_artifacts": [],
        }
        self.lease = trust.Lease(
            lambda: (
                signing.sign(self.online, "trust-policy", self.online_key),
                self.rotation.clock,
            ),
            trusted_root=self.online_public,
            environment="local-cpu",
            minimum_version=2,
            wall_clock=lambda: self.rotation.clock,
            monotonic_clock=lambda: 100,
        )
        self.before = {
            "policy_sha256": self.rotation.fixture.pin,
            "head": self.rotation.head,
            "clock": self.rotation.clock,
            "rotation_sha256": None,
        }
        self.after = {
            **self.before,
            "policy_sha256": self.online["promotion_policy_sha256"],
            "rotation_sha256": self.reference,
        }
        self.execute = Mock(
            side_effect=[canonical(self.before).decode(), "", canonical(self.after).decode()]
        )
        patcher = patch.object(promotion_state, "migration_version", return_value=2)
        patcher.start()
        self.addCleanup(patcher.stop)

    def rotate(self, **changes):
        return release_key_store.rotate(
            "owned",
            self.package,
            **{
                "trusted_root": self.rotation.fixture.public["root"],
                "expected_policy": self.rotation.fixture.pin,
                "environment": "local-cpu",
                "lease": self.lease,
                "backend": lambda _: ("owned", self.execute),
                **changes,
            },
        )

    def test_committed_transition_is_read_back_without_selecting_a_release(self):
        result = self.rotate()
        self.assertFalse(result["release_ready"])
        self.assertFalse(result["reused"])
        self.assertEqual(result["rotation_sha256"], self.reference)
        self.assertEqual(result["head"], self.rotation.head)
        self.assertEqual(result["policy_sha256"], self.online["promotion_policy_sha256"])
        sql = self.execute.call_args_list[1].args[1]
        self.assertIn("FOR UPDATE", sql)
        self.assertLess(
            sql.index("FROM ml_promotion.heads"), sql.index("FROM ml_promotion.authorities")
        )
        self.assertNotIn("UPDATE ml_promotion.heads", sql)
        self.assertNotIn("INSERT INTO ml_promotion.events", sql)
        self.assertIn("release_rotation_head_changed", sql)
        self.assertIn("release_rotation_expired", sql)
        self.assertIn("release_rotation_history_conflict", sql)

    def test_exact_retry_only_reads_and_checks_fresh_trust(self):
        self.execute.side_effect = [canonical(self.after).decode()]
        result = self.rotate()
        self.assertTrue(result["reused"])
        self.assertEqual(self.execute.call_count, 1)
        self.online["revoked_keys"] = []
        self.online["version"] += 1
        self.execute.side_effect = [canonical(self.after).decode()]
        with self.assertRaisesRegex(Rejected, "trust_unrevocation"):
            self.rotate()

    def test_old_signer_must_be_revoked_and_new_policy_current_before_write(self):
        for field, value, reason in (
            ("revoked_keys", [], "release_rotation_old_key_not_revoked"),
            ("promotion_policy_sha256", self.rotation.fixture.pin, "trust_policy_changed"),
            ("revoked_artifacts", [self.reference], "trust_artifact_revoked"),
        ):
            with self.subTest(field=field):
                original = copy.deepcopy(self.online)
                self.online[field] = value
                self.lease.payload = None
                self.lease.observed_digest = None
                self.lease.revocations = {"revoked_keys": set(), "revoked_artifacts": set()}
                self.execute.side_effect = [canonical(self.before).decode()]
                with self.assertRaisesRegex(Rejected, reason):
                    self.rotate()
                self.online = original

    def test_revoked_policy_owner_or_any_successor_role_stops_write(self):
        keys = [self.rotation.fixture.public["root"]] + [
            identity["public_key"] for identity in self.rotation.after["identities"].values()
        ]
        for public in keys:
            self.online["version"] += 1
            self.online["revoked_keys"] = sorted(
                set(self.online["revoked_keys"]) | {digest(signing.decode64(public))}
            )
            self.execute.side_effect = [canonical(self.before).decode()]
            with self.assertRaisesRegex(Rejected, "trust_key_revoked"):
                self.rotate()

    def test_wrong_context_head_or_receipt_never_writes(self):
        for field, value, reason in (
            ("policy_sha256", "b" * 64, "release_rotation_policy_conflict"),
            ("head", {**self.rotation.head, "sequence": 4}, "release_rotation_binding"),
            ("clock", self.rotation.clock + 3, "release_rotation_clock_skew"),
        ):
            self.execute.side_effect = [canonical({**self.before, field: value}).decode()]
            with self.assertRaisesRegex(Rejected, reason):
                self.rotate()
        self.execute.side_effect = [canonical({**self.after, "rotation_sha256": "b" * 64}).decode()]
        with self.assertRaisesRegex(Rejected, "release_rotation_policy_conflict"):
            self.rotate()
        with self.assertRaisesRegex(Rejected, "release_rotation_trust_environment"):
            self.rotate(environment="other")
        with patch.object(promotion_state, "migration_version", return_value=1):
            with self.assertRaisesRegex(Rejected, "release_rotation_migration_required"):
                self.rotate()

    def test_ambiguous_commit_or_bad_readback_never_returns_success(self):
        for third in (
            None,
            {**self.after, "rotation_sha256": None},
            {**self.after, "head": {**self.rotation.head, "sequence": 4}},
            {**self.after, "policy_sha256": "a" * 64},
        ):
            self.execute.side_effect = [
                canonical(self.before).decode(),
                "",
                canonical(third).decode(),
            ]
            with self.assertRaises(Rejected):
                self.rotate()
        self.execute.side_effect = [canonical(self.before).decode(), Rejected("unknown_commit")]
        with self.assertRaisesRegex(Rejected, "unknown_commit"):
            self.rotate()

    def test_post_commit_expired_lease_is_not_success_or_automatic_rollback(self):
        calls = 0
        real = self.lease.check

        def check(**arguments):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise Rejected("trust_lease_expired")
            return real(**arguments)

        with patch.object(self.lease, "check", side_effect=check):
            with self.assertRaisesRegex(Rejected, "trust_lease_expired"):
                self.rotate()
        self.assertEqual(self.execute.call_count, 3)


if __name__ == "__main__":
    unittest.main()
