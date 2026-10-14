import unittest
from unittest.mock import MagicMock, patch

import psycopg

from mlsecops import promotion, storage, trust
from mlsecops.contracts import Rejected, decode
from mlsecops.signing import sign
from scripts import release_authorization_qualification as fixtures
from scripts import trust_qualification as trust_fixtures


class PromotionAdmissionContracts(unittest.TestCase):
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
        fixture = self.fixture
        self.arguments = {
            "package": fixture.package,
            "policy_envelope": fixture.policy_envelope,
            "assurance_envelope": sign(
                fixture.assurance, "release-assurance", fixture.authorities.keys["assessor"]
            ),
            "approval_envelope": sign(
                fixture.approval, "release-approval", fixture.authorities.keys["approver"]
            ),
            "reports": fixture.reports,
            "context": fixture.bundle.materials.context,
            "trusted_root": fixture.authorities.public["root"],
            "expected_policy": fixture.policy_hash,
            "expected_serving_image": fixture.bundle.arguments["expected_serving_image"],
        }
        self.clock = fixture.clock
        self.trust_fixture = trust_fixtures.TrustContracts()
        self.trust_fixture.setUp()
        self.addCleanup(self.trust_fixture.doCleanups)
        self.trust_fixture.wall = float(self.clock)
        self.trust_fixture.payload.update(
            promotion_policy_sha256=fixture.policy_hash,
            issued_at=self.clock - 1,
            expires_at=self.clock + 3600,
        )
        self.lease = self.trust_fixture.lease
        self.values = {}
        self.head = None
        self.calls = []
        self.connection = MagicMock()
        self.connection.__enter__.return_value = self.connection
        self.connection.execute.side_effect = self.execute

    def execute(self, query, parameters=None):
        self.calls.append(query)
        cursor = MagicMock()
        if "clock_timestamp" in query:
            cursor.fetchone.return_value = (self.clock,)
        elif "record_selection" in query:
            reference = parameters[0]
            payload = decode(self.values[reference])
            self.assertEqual(payload["sequence"], 1)
            if self.head is not None and self.head != reference:
                raise Rejected("controlled_sequence_conflict")
            self.head = reference
            cursor.fetchone.return_value = (reference,)
        else:
            self.assertIn("FROM ml_promotion.events", query)
            cursor.fetchone.return_value = (self.head,)
        return cursor

    def run_admission(self, **changes):
        with (
            self.fixture.bundle.memory_storage(self.values),
            patch.object(storage, "connect", return_value=self.connection),
        ):
            return promotion.promote(
                "promoter", **{**self.arguments, "trust_lease": self.lease, **changes}
            )

    def test_missing_online_trust_or_revoked_model_denies_before_writes(self):
        with self.assertRaisesRegex(Rejected, "promotion_online_trust_required"):
            self.run_admission(trust_lease=None)
        self.assertEqual(self.values, {})
        model = self.fixture.package["capsule"]["objects"]
        self.trust_fixture.payload["revoked_artifacts"] = sorted(
            {reference for _, reference in model}
        )
        with self.assertRaisesRegex(Rejected, "trust_artifact_revoked"):
            self.run_admission()
        self.assertEqual(self.values, {})
        self.assertIsNone(self.head)

    def test_trust_loss_after_journal_commit_does_not_return_activation(self):
        original = self.execute

        def failed_trust(query, parameters=None):
            cursor = original(query, parameters)
            if "record_selection" in query:
                self.trust_fixture.failure = trust.Unavailable("trust_service_unavailable")
            return cursor

        self.connection.execute.side_effect = failed_trust
        with self.assertRaisesRegex(trust.Unavailable, "trust_service_unavailable"):
            self.run_admission()
        self.assertIsNotNone(self.head)

    def test_trust_environment_cannot_be_substituted(self):
        self.lease.environment = "foreign"
        with self.assertRaisesRegex(Rejected, "promotion_trust_environment_mismatch"):
            self.run_admission()
        self.assertEqual(self.values, {})

    def test_ancestor_and_signer_revocations_are_in_admission_scope(self):
        from mlsecops import signing
        from mlsecops.contracts import digest

        projection = decode(self.fixture.package["documents"]["asset_projection"])
        self.trust_fixture.payload["revoked_artifacts"] = [
            projection["graph"]["assets"][0]["sha256"]
        ]
        with self.assertRaisesRegex(Rejected, "trust_artifact_revoked"):
            self.run_admission()
        self.assertEqual(self.values, {})
        self.trust_fixture.payload["version"] = 2
        self.trust_fixture.payload["revoked_keys"] = [
            digest(signing.decode64(self.arguments["trusted_root"]))
        ]
        decision = promotion.release_authorization.verify(**self.arguments, clock=self.clock)
        scope = promotion.trust_scope(self.arguments, decision, self.fixture.policy)
        self.assertIn(self.trust_fixture.payload["revoked_keys"][0], scope["keys"])

    def test_each_signed_material_reference_is_independently_revocable(self):
        from mlsecops.contracts import canonical, digest

        package = self.arguments["package"]
        split = decode(package["documents"]["split_manifest"])
        projection = decode(package["documents"]["asset_projection"])
        references = {
            "proposal_reference": digest(canonical(package["envelope"])),
            "source_approval": self.arguments["context"]["trust"]["source_approval_digest"],
            "lineage_id": projection["bindings"]["lineage_id"],
            "source_fingerprint": projection["bindings"]["source_fingerprint"],
            **{name: item["sha256"] for name, item in split["objects"].items()},
            **{
                name: digest(canonical(self.arguments[name]))
                for name in ("policy_envelope", "assurance_envelope", "approval_envelope")
            },
        }
        for label, reference in references.items():
            with self.subTest(material=label):
                self.values.clear()
                self.head = None
                self.trust_fixture.payload["revoked_artifacts"] = [reference]
                self.lease = trust.Lease(
                    self.trust_fixture.read,
                    trusted_root=self.trust_fixture.public,
                    environment="local-cpu",
                    minimum_version=1,
                    wall_clock=lambda: self.trust_fixture.wall,
                    monotonic_clock=lambda: self.trust_fixture.monotonic,
                )
                with self.assertRaisesRegex(Rejected, "trust_artifact_revoked"):
                    self.run_admission()
                self.assertEqual(self.values, {})
                self.assertIsNone(self.head)

    def test_same_authorization_retries_after_time_passes_without_new_request(self):
        first = self.run_admission()
        before = dict(self.values)
        self.clock += 1
        self.assertEqual(self.run_admission(), first)
        self.assertEqual(self.values, before)
        self.assertFalse(first["release_ready"])
        self.assertEqual(first["state"], "recorded-not-activated")

    def test_real_missing_assurance_rejects_before_any_storage_write(self):
        with self.assertRaisesRegex(Rejected, "release_assurance_required"):
            self.run_admission(assurance_envelope=None)
        self.assertEqual(self.values, {})
        self.assertIsNone(self.head)

    def test_caller_cannot_override_server_clock_or_use_serving_credentials(self):
        with self.assertRaisesRegex(Rejected, "clock_override_forbidden"):
            self.run_admission(clock=self.clock)
        with (
            patch.object(storage, "connection_parameters", return_value={"user": "ml_serving"}),
            self.assertRaisesRegex(Rejected, "storage_identity"),
        ):
            promotion.promote("serving", **self.arguments)

    def test_receipt_and_readback_failures_never_return_success(self):
        with patch.object(storage, "put", return_value="0" * 64):
            with self.assertRaisesRegex(Rejected, "receipt_mismatch"):
                promotion.publish("promoter", b"controlled")
        original = self.execute

        def altered(query, parameters=None):
            cursor = original(query, parameters)
            if "record_selection" in query:
                cursor.fetchone.return_value = ("0" * 64,)
            return cursor

        self.connection.execute.side_effect = altered
        with self.assertRaisesRegex(Rejected, "state_receipt_mismatch"):
            self.run_admission()
        self.head = None

        def bad_readback(query, parameters=None):
            cursor = original(query, parameters)
            if "FROM ml_promotion.events" in query:
                cursor.fetchone.return_value = None
            return cursor

        self.connection.execute.side_effect = bad_readback
        with self.assertRaisesRegex(Rejected, "state_readback_mismatch"):
            self.run_admission()

    def test_database_failures_are_unconfirmed_not_silent_success_or_auto_retry(self):
        self.connection.execute.side_effect = psycopg.OperationalError("private endpoint")
        with self.assertRaisesRegex(Rejected, "clock_unavailable:unavailable"):
            self.run_admission()
        self.assertEqual(self.values, {})

        def failed_commit(query, parameters=None):
            if "record_selection" in query:
                raise psycopg.OperationalError("private commit outcome")
            return self.execute(query, parameters)

        self.connection.execute.side_effect = failed_commit
        with self.assertRaisesRegex(Rejected, "commit_unconfirmed:unavailable"):
            self.run_admission()
        self.assertIsNone(self.head)


if __name__ == "__main__":
    unittest.main()
