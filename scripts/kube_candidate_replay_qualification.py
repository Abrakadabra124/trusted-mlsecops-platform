import copy
import unittest

from mlsecops import kube_candidate_clock as clock
from mlsecops import kube_candidate_replay as replay
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, digest
from scripts import kube_candidate_clock_qualification as fixtures


class CandidateReplayContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.CandidateClockContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.CandidateClockContracts.tearDownClass()

    def setUp(self):
        self.base = fixtures.CandidateClockContracts()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.lease = self.base.reader.trust
        self.saved = replay.capture(self.lease)

    def advance(self):
        # Local authority is a signed fixture. Native uses two real SQL updates.
        self.base.fixture.policy["version"] = 3
        self.base.engine.check()
        self.assertEqual(self.lease.floor, 3)

    def response(self, saved=None, current=None, server_clock=None):
        envelope, stamp = self.lease.reader()
        return replay.response(
            self.lease,
            self.saved if saved is None else saved,
            envelope if current is None else current,
            stamp if server_clock is None else server_clock,
        )

    def test_actual_reader_rejects_still_valid_signed_replay_and_never_calls_worker(self):
        self.advance()
        report = clock.exercise(
            self.base.engine,
            self.base.request,
            self.base.body,
            self.base.expected,
            self.base.check,
            fault="version-replay",
            reader_factory=self.base.fresh,
            replayed=self.saved,
        )
        self.assertEqual(report["cause"], "trust_version_replay")
        proof = report["replay"]
        self.assertEqual(proof["prior_version"], 1)
        self.assertEqual(proof["current_version"], 3)
        self.assertEqual(proof["prior_document_sha256"], digest(self.saved))
        self.assertGreater(proof["prior_valid_seconds"], 0)
        self.assertEqual([row["status"] for row in report["trace"]], [503] * 5)
        self.assertEqual(self.base.worker.predict.call_count, 1)
        self.assertIsNone(self.lease.payload)
        self.assertTrue(self.base.engine.generation.is_set())
        self.base.restored()

    def test_capture_requires_document_already_observed_by_real_lease(self):
        before = self.lease.floor
        self.base.fixture.policy["version"] = 2
        with self.assertRaisesRegex(Rejected, "candidate_replay_capture_binding"):
            replay.capture(self.lease)
        self.assertEqual(self.lease.floor, before)

    def test_valid_response_preserves_signed_bytes_and_high_water(self):
        self.advance()
        old, proof = self.response()
        self.assertEqual(canonical(old), self.saved)
        self.assertEqual(self.lease.floor, 3)
        self.assertEqual(proof["current_document_sha256"], self.lease.observed_digest)

    def test_equal_version_or_artificial_floor_cannot_qualify(self):
        with self.assertRaisesRegex(Rejected, "candidate_replay_binding"):
            self.response()
        self.advance()
        self.lease.floor = 4
        with self.assertRaisesRegex(Rejected, "candidate_replay_binding"):
            self.response()

    def test_cache_or_observed_digest_mismatch_cannot_qualify(self):
        self.advance()
        for field, value in (("payload", None), ("observed_digest", "f" * 64)):
            original = getattr(self.lease, field)
            with self.subTest(field=field):
                setattr(self.lease, field, value)
                with self.assertRaisesRegex(Rejected, "candidate_replay_binding"):
                    self.response()
                setattr(self.lease, field, original)

    def test_changed_policy_or_revocations_are_not_attributed_to_version_replay(self):
        self.advance()
        for field, value in (
            ("promotion_policy_sha256", "f" * 64),
            ("revoked_artifacts", ["f" * 64]),
            ("revoked_keys", ["f" * 64]),
        ):
            payload = {**self.base.fixture.policy, field: value}
            envelope = signing.sign(payload, "trust-policy", self.base.fixture.key)
            with self.subTest(field=field):
                self.lease.payload = payload
                self.lease.observed_digest = digest(canonical(envelope))
                with self.assertRaisesRegex(Rejected, "candidate_replay_binding"):
                    self.response(current=envelope)

    def test_corrupt_signature_and_noncanonical_or_mutable_capture_reject(self):
        self.advance()
        envelope, _ = self.lease.reader()
        bad = copy.deepcopy(envelope)
        bad["signatures"][0]["sig"] = signing.encode64(b"x" * 64)
        for value in (canonical(bad), self.saved + b" ", bytearray(self.saved), b"{"):
            with self.subTest(kind=type(value).__name__), self.assertRaises(Rejected):
                self.response(saved=value)

    def test_expired_old_document_cannot_qualify_even_when_current_is_valid(self):
        self.base.fixture.wall += 1300
        self.base.fixture.monotonic += 1300
        self.base.fixture.policy.update(
            version=3,
            issued_at=int(self.base.fixture.wall),
            expires_at=int(self.base.fixture.wall) + 1200,
        )
        self.lease.refresh()
        with self.assertRaises(Rejected):
            self.response()

    def test_skewed_server_clock_cannot_be_presented_as_replay(self):
        self.advance()
        with self.assertRaisesRegex(Rejected, "candidate_replay_server_clock"):
            self.response(server_clock=int(self.base.fixture.wall) - 10)

    def test_unsigned_current_document_cannot_establish_high_water_evidence(self):
        self.advance()
        current, _ = self.lease.reader()
        current["signatures"] = []
        with self.assertRaisesRegex(Rejected, "invalid_signature_count"):
            self.response(current=current)

    def test_replay_capture_is_mandatory_and_not_accepted_for_other_faults(self):
        for fault, saved in (("version-replay", None), ("server-skew", self.saved)):
            with (
                self.subTest(fault=fault),
                self.assertRaisesRegex(Rejected, "candidate_clock_fault"),
            ):
                clock.exercise(
                    self.base.engine,
                    self.base.request,
                    self.base.body,
                    self.base.expected,
                    self.base.check,
                    fault=fault,
                    reader_factory=self.base.fresh,
                    replayed=saved,
                )
        self.assertTrue(self.base.engine.check()["ready"])


if __name__ == "__main__":
    unittest.main()
