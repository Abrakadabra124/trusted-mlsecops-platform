import unittest
from unittest.mock import MagicMock, patch

import psycopg

from mlsecops import promotion, storage
from mlsecops.contracts import Rejected, decode
from mlsecops.signing import sign
from scripts import release_authorization_qualification as fixtures


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
            return promotion.promote("promoter", **{**self.arguments, **changes})

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
