import copy
import tempfile
import unittest
from pathlib import Path

from mlsecops import signing, trust
from mlsecops.contracts import Rejected, canonical, digest


class TrustContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.key = Path(temporary.name) / "root.pem"
        self.public = signing.create_key(self.key)
        self.wall = 2000000000.0
        self.monotonic = 100.0
        self.payload = {
            "schema_version": 1,
            "environment": "local-cpu",
            "version": 1,
            "promotion_policy_sha256": "a" * 64,
            "issued_at": int(self.wall) - 1,
            "expires_at": int(self.wall) + 3600,
            "revoked_artifacts": [],
            "revoked_keys": [],
        }
        self.failure = None
        self.delay = 0
        self.lease = trust.Lease(
            self.read,
            trusted_root=self.public,
            environment="local-cpu",
            minimum_version=1,
            wall_clock=lambda: self.wall,
            monotonic_clock=lambda: self.monotonic,
        )

    def read(self):
        self.advance(self.delay)
        if self.failure:
            raise self.failure
        return self.envelope(), int(self.wall)

    def envelope(self):
        return signing.sign(self.payload, "trust-policy", self.key)

    def advance(self, seconds):
        self.wall += seconds
        self.monotonic += seconds

    def check(self, **changes):
        return self.lease.check(
            **{"policy_sha256": "a" * 64, "artifacts": ["b" * 64], "keys": [], **changes}
        )

    def test_no_offline_start_and_exact_deadline(self):
        with self.assertRaisesRegex(Rejected, "trust_lease_unavailable"):
            self.check()
        self.lease.refresh()
        self.advance(59.999)
        self.assertEqual(self.check()["version"], 1)
        self.advance(0.001)
        with self.assertRaisesRegex(Rejected, "trust_lease_expired"):
            self.check()

    def test_outage_does_not_restart_deadline(self):
        self.lease.refresh()
        self.advance(50)
        self.failure = trust.Unavailable("trust_service_unavailable")
        with self.assertRaises(trust.Unavailable):
            self.lease.refresh()
        self.check()
        self.advance(10)
        with self.assertRaisesRegex(Rejected, "trust_lease_expired"):
            self.check()

    def test_latency_consumes_lease_and_expiry_can_shorten_it(self):
        self.delay = 59
        self.lease.refresh()
        self.advance(1)
        with self.assertRaisesRegex(Rejected, "trust_lease_expired"):
            self.check()
        self.delay = 60
        with self.assertRaisesRegex(Rejected, "trust_lease_expired"):
            self.lease.refresh()
        self.delay = 0
        self.payload["version"] += 1
        self.payload["expires_at"] = int(self.wall) + 5
        self.lease.refresh()
        self.advance(5)
        with self.assertRaises(Rejected):
            self.check()

    def test_known_revocation_and_policy_change_deny_without_grace(self):
        self.lease.refresh()
        self.payload["version"] = 2
        self.payload["revoked_artifacts"] = ["b" * 64]
        self.lease.refresh()
        with self.assertRaisesRegex(Rejected, "trust_artifact_revoked"):
            self.check()
        self.check(artifacts=["c" * 64])
        self.payload["version"] = 3
        self.payload["revoked_keys"] = ["d" * 64]
        self.lease.refresh()
        with self.assertRaisesRegex(Rejected, "trust_key_revoked"):
            self.check(artifacts=[], keys=["d" * 64])
        with self.assertRaisesRegex(Rejected, "trust_policy_changed"):
            self.check(policy_sha256="e" * 64)

    def test_version_rollback_and_same_version_equivocation_cancel_cache(self):
        self.payload["version"] = 3
        self.lease.refresh()
        for version in (2, 3):
            with self.subTest(version=version):
                self.payload["version"] = version
                self.payload["expires_at"] -= 1
                with self.assertRaisesRegex(Rejected, "trust_version_replay"):
                    self.lease.refresh()
                with self.assertRaisesRegex(Rejected, "trust_lease_unavailable"):
                    self.check()

    def test_bad_response_cannot_fall_back_to_last_good_policy(self):
        self.lease.refresh()
        self.failure = Rejected("invalid_signature")
        with self.assertRaisesRegex(Rejected, "invalid_signature"):
            self.lease.refresh()
        with self.assertRaisesRegex(Rejected, "trust_lease_unavailable"):
            self.check()

    def test_clock_rollback_forward_jump_and_monotonic_rollback_deny(self):
        for wall_delta, monotonic_delta in ((-0.1, 0), (30, 0), (0, -1)):
            with self.subTest(wall=wall_delta, monotonic=monotonic_delta):
                self.setUp()
                self.lease.refresh()
                self.wall += wall_delta
                self.monotonic += monotonic_delta
                with self.assertRaisesRegex(Rejected, "trust_clock_invalid"):
                    self.check()

    def test_policy_signature_exact_schema_and_bounded_sets(self):
        original = copy.deepcopy(self.payload)
        mutations = [
            {"schema_version": True},
            {"version": 0},
            {"environment": "foreign"},
            {"expires_at": int(self.wall) - 1},
            {"issued_at": int(self.wall) + 1},
            {"expires_at": int(self.wall) + 86401},
            {"promotion_policy_sha256": "alias"},
            {"revoked_artifacts": ["b" * 64, "b" * 64]},
            {"revoked_keys": ["c" * 64, "b" * 64]},
            {"revoked_keys": ["f" * 64] * 513},
            {"unknown": True},
        ]
        for mutation in mutations:
            with self.subTest(mutation=tuple(mutation)):
                self.payload = {**original, **mutation}
                with self.assertRaises(Rejected):
                    self.lease.refresh()
        self.payload = original
        envelope = self.envelope()
        envelope["payload"] = signing.encode64(canonical({**original, "version": 2}))
        with self.assertRaisesRegex(Rejected, "invalid_signature"):
            trust.validate(envelope, self.public, "local-cpu", int(self.wall))

    def test_root_revocation_and_immutable_update_rules(self):
        current = copy.deepcopy(self.payload)
        newer = {**current, "version": 2, "revoked_keys": [digest(signing.decode64(self.public))]}
        trust.successor(current, newer)
        self.payload = newer
        with self.assertRaisesRegex(Rejected, "trust_root_revoked"):
            self.lease.refresh()
        for changed in (
            {**newer, "version": 1},
            {**newer, "version": 4},
            {**newer, "version": 3, "revoked_keys": []},
        ):
            with self.assertRaises(Rejected):
                trust.successor(newer, changed)

    def test_repeated_unrevocation_after_cache_clear_still_fails(self):
        self.payload["revoked_artifacts"] = ["b" * 64]
        self.payload["revoked_keys"] = ["c" * 64]
        self.lease.refresh()
        self.payload.update(version=2, revoked_artifacts=[], revoked_keys=[])
        for _ in range(2):
            with self.assertRaisesRegex(Rejected, "trust_unrevocation"):
                self.lease.refresh()
        self.payload.update(version=3, revoked_artifacts=["b" * 64], revoked_keys=["c" * 64])
        self.lease.refresh()
        self.advance(60)
        with self.assertRaisesRegex(Rejected, "trust_lease_expired"):
            self.check()
        self.payload.update(version=4, revoked_artifacts=[], revoked_keys=[])
        with self.assertRaisesRegex(Rejected, "trust_unrevocation"):
            self.lease.refresh()

    def test_root_revocation_latches_even_after_invalid_and_newer_responses(self):
        self.payload["revoked_keys"] = [digest(signing.decode64(self.public))]
        with self.assertRaisesRegex(Rejected, "trust_root_revoked"):
            self.lease.refresh()
        self.payload.update(version=2, revoked_keys=[])
        with self.assertRaisesRegex(Rejected, "trust_root_revoked"):
            self.lease.refresh()

    def test_delayed_server_time_cannot_extend_document_expiry(self):
        self.payload["expires_at"] = int(self.wall) + 5

        def delayed_read():
            server_clock = int(self.wall) + 2
            self.advance(2)
            return self.envelope(), server_clock

        self.lease.reader = delayed_read
        with self.assertRaisesRegex(Rejected, "trust_lease_expired"):
            self.lease.refresh()

    def test_invalid_root_server_skew_and_input_references(self):
        with self.assertRaisesRegex(Rejected, "trust_root_invalid"):
            trust.Lease(
                self.read,
                trusted_root=signing.encode64(b"short"),
                environment="local-cpu",
                minimum_version=1,
            )
        self.lease.reader = lambda: (self.envelope(), int(self.wall) + 3)
        with self.assertRaisesRegex(Rejected, "trust_server_clock_skew"):
            self.lease.refresh()
        self.lease.reader = self.read
        self.lease.refresh()
        for changed in (
            {"artifacts": "b" * 64},
            {"keys": ["a" * 64] * 4097},
            {"artifacts": ["alias"]},
        ):
            with self.assertRaises(Rejected):
                self.check(**changed)
        trust.validate(self.envelope(), self.public, "local-cpu")

    def test_nonfinite_and_boolean_clocks_are_terminal(self):
        for value in (float("nan"), float("inf"), True, -1):
            with self.subTest(value=value):
                lease = trust.Lease(
                    self.read,
                    trusted_root=self.public,
                    environment="local-cpu",
                    minimum_version=1,
                    wall_clock=lambda: value,
                )
                with self.assertRaisesRegex(Rejected, "trust_clock_invalid"):
                    lease.refresh()


if __name__ == "__main__":
    unittest.main()
