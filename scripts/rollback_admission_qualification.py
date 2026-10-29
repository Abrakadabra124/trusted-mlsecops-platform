"""Production promoter/Reader rollback path with a controlled SQL transport."""

import copy
import unittest
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import psycopg

from mlsecops import promotion, release_reader, signing, storage
from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts import promotion_qualification as fixtures


class RollbackAdmission(unittest.TestCase):
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
        first = self.fixture.run_admission()
        self.target = first["request_sha256"]
        self.original = decode(self.fixture.values[self.target])
        current = {
            **self.original,
            "sequence": 2,
            "subject_sha256": "c" * 64,
            "proposal_reference": "d" * 64,
        }
        self.previous = digest(canonical(current))
        self.fixture.values[self.previous] = canonical(current)
        self.events = {1: (1, self.target, None), 2: (2, self.previous, self.target)}
        self.head = (2, self.previous)
        self.fixture.connection.execute.side_effect = self.execute
        self.approval = {
            **self.fixture.fixture.approval,
            "schema_version": 2,
            "action": "rollback",
            "sequence": 3,
            "rollback": {
                "from_sequence": 2,
                "from_request_sha256": self.previous,
                "target_request_sha256": self.target,
            },
        }

    def execute(self, query, parameters=None):
        cursor = MagicMock()
        if query.startswith("SELECT floor(extract"):
            value = (self.fixture.clock,)
        elif "record_selection" in query:
            reference = parameters[0]
            selection = decode(self.fixture.values[reference])
            if self.head != (selection["sequence"], reference):
                if selection["sequence"] != self.head[0] + 1:
                    raise Rejected("controlled_sequence_conflict")
                self.events[selection["sequence"]] = (
                    selection["sequence"],
                    reference,
                    self.head[1],
                )
                self.head = (selection["sequence"], reference)
            value = (reference,)
        elif "authority.policy_sha256" in query:
            value = (*self.head, self.original["policy_sha256"], self.head[1], self.fixture.clock)
        elif "FROM ml_promotion.heads" in query:
            event = self.events.get(self.head[0])
            value = (*self.head, None if event is None else event[2])
        elif query.startswith("SELECT request_sha256 FROM ml_promotion.events"):
            event = self.events.get(parameters[1])
            value = None if event is None else (event[1],)
        elif "FROM ml_promotion.events" in query and "sequence = %s" in query:
            value = self.events.get(parameters[1])
        elif "FROM ml_promotion.events" in query and "request_sha256 = %s" in query:
            value = next((r for r in self.events.values() if r[1] == parameters[1]), None)
        else:
            raise AssertionError("Unexpected controlled query: " + query)
        cursor.fetchone.return_value = value
        return cursor

    @contextmanager
    def transport(self):
        with (
            self.fixture.fixture.bundle.memory_storage(self.fixture.values),
            patch.object(storage, "connect", return_value=self.fixture.connection),
            patch.object(release_reader.time, "time", return_value=self.fixture.clock),
        ):
            original_get = storage.get.side_effect
            if hasattr(self, "target_bytes"):
                storage.get.side_effect = lambda client, table, reference: (
                    self.target_bytes
                    if reference == self.target
                    else original_get(client, table, reference)
                )
            yield

    def submit(self):
        envelope = signing.sign(
            self.approval, "release-approval", self.fixture.fixture.authorities.keys["approver"]
        )
        with self.transport():
            return promotion.promote(
                "promoter",
                **{**self.fixture.arguments, "approval_envelope": envelope},
                trust_lease=self.fixture.lease,
            )

    def reader(self):
        return release_reader.Reader(
            "serving",
            **{
                name: self.fixture.arguments[name]
                for name in ("context", "trusted_root", "expected_policy", "expected_serving_image")
            },
            trust_lease=self.fixture.lease,
            minimum_sequence=3,
        )

    def test_rollback_and_retry_restore_exact_bundle_with_forward_sequence(self):
        first = self.submit()
        values = copy.deepcopy(self.fixture.values)
        events = copy.deepcopy(self.events)
        self.assertEqual(self.submit(), first)
        self.assertEqual(self.fixture.values, values)
        self.assertEqual(self.events, events)
        self.assertEqual(first["sequence"], 3)
        self.assertEqual(first["subject_sha256"], self.original["subject_sha256"])
        self.assertEqual(first["proposal_reference"], self.original["proposal_reference"])
        self.assertEqual(self.events[3][2], self.previous)
        with self.transport():
            reader = self.reader()
            loaded = reader.load()
            reader.check(loaded)
        self.assertEqual(loaded.sequence, 3)
        self.assertEqual(loaded.model, self.fixture.fixture.bundle.materials.fixture.model)

    def test_unknown_target_event_is_rejected_before_publication(self):
        self.approval["rollback"]["target_request_sha256"] = "e" * 64
        before = copy.deepcopy(self.fixture.values)
        with self.assertRaisesRegex(Rejected, "rollback_target_history"):
            self.submit()
        self.assertEqual(self.fixture.values, before)
        self.assertEqual(self.head, (2, self.previous))

    def test_wrong_from_event_or_changed_head_is_rejected_before_publication(self):
        before = copy.deepcopy(self.fixture.values)
        self.approval["rollback"]["from_request_sha256"] = "e" * 64
        with self.assertRaisesRegex(Rejected, "rollback_from_history"):
            self.submit()
        self.approval["rollback"]["from_request_sha256"] = self.previous
        self.head = (2, "e" * 64)
        with self.assertRaisesRegex(Rejected, "rollback_head_changed"):
            self.submit()
        self.assertEqual(self.fixture.values, before)

    def test_reader_rejects_inconsistent_previous_event_link(self):
        self.submit()
        self.events[3] = (3, self.head[1], "e" * 64)
        with self.transport(), self.assertRaisesRegex(Rejected, "rollback_head_changed"):
            self.reader().load()

    def test_revoked_target_model_cannot_be_used_as_rollback(self):
        model = digest(self.fixture.fixture.bundle.materials.fixture.model)
        self.fixture.trust_fixture.payload["version"] += 1
        self.fixture.trust_fixture.payload["revoked_artifacts"] = [model]
        before = copy.deepcopy(self.fixture.values)
        with self.assertRaisesRegex(Rejected, "trust_artifact_revoked"):
            self.submit()
        self.assertEqual(self.fixture.values, before)

    def test_unavailable_history_is_not_an_authorized_rollback(self):
        original = self.execute

        def unavailable(query, parameters=None):
            if "FROM ml_promotion.events" in query:
                raise psycopg.OperationalError("synthetic unavailable history")
            return original(query, parameters)

        self.fixture.connection.execute.side_effect = unavailable
        before = copy.deepcopy(self.fixture.values)
        with self.assertRaisesRegex(Rejected, "rollback_history_unavailable"):
            self.submit()
        self.assertEqual(self.fixture.values, before)

    def test_missing_from_event_and_nonhistorical_target_are_rejected(self):
        old = self.events.pop(2)
        with self.assertRaisesRegex(Rejected, "rollback_from_history"):
            self.submit()
        self.events[2] = old
        for sequence in (True, 0, 2, 3):
            self.events[1] = (sequence, self.target, None)
            with (
                self.subTest(sequence=sequence),
                self.assertRaisesRegex(Rejected, "rollback_target_history"),
            ):
                self.submit()

    def test_target_bytes_and_bundle_binding_are_checked(self):
        for value in (None, b"changed"):
            self.target_bytes = value
            with self.assertRaisesRegex(Rejected, "rollback_target_integrity"):
                self.submit()
        del self.target_bytes
        valid = copy.deepcopy(self.original)
        for field, value in (
            ("sequence", 2),
            ("environment", "other"),
            ("policy_sha256", "e" * 64),
            ("subject_sha256", "e" * 64),
            ("proposal_reference", "e" * 64),
        ):
            content = canonical({**valid, field: value})
            reference = digest(content)
            self.fixture.values[reference] = content
            self.events[1] = (1, reference, None)
            self.approval["rollback"]["target_request_sha256"] = reference
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(Rejected, "rollback_target_binding"),
            ):
                self.submit()

    def test_revoked_target_selection_fails_closed(self):
        self.fixture.trust_fixture.payload["version"] += 1
        self.fixture.trust_fixture.payload["revoked_artifacts"] = [self.target]
        before = copy.deepcopy(self.fixture.values)
        with self.assertRaisesRegex(Rejected, "trust_artifact_revoked"):
            self.submit()
        self.assertEqual(self.fixture.values, before)

    def test_missing_head_fails_closed(self):
        original = self.execute

        def missing(query, parameters=None):
            if "FROM ml_promotion.heads" in query:
                result = MagicMock()
                result.fetchone.return_value = None
                return result
            return original(query, parameters)

        self.fixture.connection.execute.side_effect = missing
        with self.assertRaisesRegex(Rejected, "rollback_head_changed"):
            self.submit()

    def test_proposal_receipt_mismatch_does_not_record_rollback(self):
        with patch.object(promotion.release_bundle, "publish", return_value="e" * 64):
            with self.assertRaisesRegex(Rejected, "promotion_proposal_receipt_mismatch"):
                self.submit()
        self.assertEqual(self.head, (2, self.previous))


if __name__ == "__main__":
    unittest.main()
