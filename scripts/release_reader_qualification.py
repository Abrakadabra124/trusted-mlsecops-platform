import copy
import unittest
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, asdict
from unittest.mock import MagicMock, patch

import psycopg

from mlsecops import release_reader, signing, storage, trust
from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts import promotion_qualification as fixtures


class ReleaseReaderContracts(unittest.TestCase):
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
        self.receipt = self.fixture.run_admission()
        self.arguments = self.fixture.arguments
        self.selection = decode(self.fixture.values[self.fixture.head])
        self.authorization = decode(self.fixture.values[self.selection["authorization_reference"]])
        self.row = (
            1,
            self.fixture.head,
            self.arguments["expected_policy"],
            self.fixture.head,
            self.fixture.clock,
        )
        self.connection = MagicMock()
        self.connection.__enter__.return_value = self.connection
        self.connection.execute.return_value.fetchone.side_effect = lambda: self.row
        self.options = {
            key: self.arguments[key]
            for key in ("context", "trusted_root", "expected_policy", "expected_serving_image")
        }
        self.options.update(trust_lease=self.fixture.lease, minimum_sequence=1)

    @contextmanager
    def transport(self):
        with (
            self.fixture.fixture.bundle.memory_storage(self.fixture.values) as writes,
            patch.object(storage, "connect", return_value=self.connection),
            patch.object(release_reader.time, "time", side_effect=lambda: self.fixture.clock),
        ):
            yield writes

    def reader(self, **options):
        return release_reader.Reader("serving", **{**self.options, **options})

    def replace_selection(self, **fields):
        self.selection.update(fields)
        content = canonical(self.selection)
        reference = digest(content)
        self.fixture.values[reference] = content
        self.row = (self.selection["sequence"], reference, self.row[2], reference, self.row[4])

    def replace_authorization(self, **fields):
        self.authorization.update(fields)
        content = canonical(self.authorization)
        reference = digest(content)
        self.fixture.values[reference] = content
        self.replace_selection(authorization_reference=reference)

    def test_signed_read_returns_exact_immutable_bytes_without_readiness_or_writes(self):
        with self.transport() as writes:
            reader = self.reader()
            loaded = reader.load()
            self.assertEqual(loaded.model, self.fixture.fixture.bundle.materials.fixture.model)
            self.assertEqual(loaded.model_sha256, digest(loaded.model))
            self.assertEqual(loaded.subject_sha256, self.receipt["subject_sha256"])
            self.assertEqual(loaded.request_sha256, self.fixture.head)
            self.assertEqual(loaded.audit_context.kind, "release-selection")
            self.assertEqual(loaded.audit_context.selection_sha256, self.fixture.head)
            self.assertEqual(loaded.audit_context.bundle_sha256, loaded.subject_sha256)
            self.assertEqual(loaded.audit_context.model_sha256, digest(loaded.model))
            self.assertFalse(loaded.audit_context.release_ready)
            self.assertFalse(loaded.release_ready)
            self.assertNotIn(repr(loaded.model), repr(loaded))
            self.assertEqual(reader.check(loaded)["version"], 1)
            self.assertEqual(writes, [])
            with self.assertRaises(FrozenInstanceError):
                loaded.model = b"replacement"
            reference = loaded.model_sha256
            self.fixture.values[reference] = b"replaced-after-read"
            self.assertEqual(digest(loaded.model), reference)
            with self.assertRaisesRegex(Rejected, "integrity"):
                reader.load()
            with self.assertRaisesRegex(Rejected, "serving_release_not_current"):
                reader.check(loaded)

    def test_private_trace_binds_primary_source_run_report_and_authorization(self):
        package, context = self.arguments["package"], self.arguments["context"]
        objects = package["capsule"]["objects"]
        record = decode(objects[("candidates", context["candidate_reference"])])
        metadata = decode(objects[("candidates", record["metadata_object"])])
        statement = signing.verify(
            decode(objects[("manifests", record["dataset_reference"])]),
            "stored-dataset",
            context["trust"]["curator"],
        )
        provenance = signing.verify(
            decode(objects[("lineage", statement["lineage_object"])]),
            "data-lineage",
            context["trust"]["curator"],
        )
        with self.transport() as writes:
            loaded = self.reader().load()
        trace = loaded.audit_context
        self.assertEqual(trace.schema_version, 2)
        self.assertEqual(
            asdict(trace.lineage),
            {
                "source_revision": metadata["source_revision"],
                "source_fingerprint": metadata["source_fingerprint"],
                "source_sha256": provenance["source_sha256"],
                "source_approval_sha256": statement["source_approval_digest"],
                "dataset_sha256": record["dataset_reference"],
                "lineage_sha256": statement["lineage_object"],
                "run_sha256": record["metadata_object"],
                "evaluation_sha256": context["evaluation_reference"],
            },
        )
        self.assertEqual(trace.authorization_sha256, self.selection["authorization_reference"])
        for name in ("assurance_sha256", "approval_sha256"):
            self.assertEqual(getattr(trace, name), self.authorization["decision"][name])
        self.assertEqual(writes, [])
        self.assertFalse(trace.release_ready)

    def test_unapproved_structural_selection_never_returns_model(self):
        self.replace_authorization(assurance_envelope=None)
        with self.transport(), self.assertRaisesRegex(Rejected, "release_assurance_required"):
            self.reader().load()

    def test_every_selection_binding_is_rechecked(self):
        original = copy.deepcopy(self.selection)
        mutations = {
            "subject_sha256": "0" * 64,
            "policy_sha256": "0" * 64,
            "sequence": 2,
            "issued_at": self.fixture.clock - 1,
            "expires_at": self.selection["expires_at"] - 1,
            "environment": "foreign",
        }
        with self.transport():
            for field, value in mutations.items():
                with self.subTest(field=field):
                    self.selection = copy.deepcopy(original)
                    self.replace_selection(**{field: value})
                    with self.assertRaises(Rejected):
                        self.reader().load()

    def test_forged_cached_decision_and_authorization_schema_fail(self):
        for fields in (
            {"decision": {**self.authorization["decision"], "sequence": 2}},
            {"schema_version": True},
            {"extra": "not-permitted"},
            {"reports": []},
            {"reports": {}},
        ):
            with self.subTest(fields=tuple(fields)), self.transport():
                previous = copy.deepcopy(self.authorization)
                self.replace_authorization(**fields)
                with self.assertRaises(Rejected):
                    self.reader().load()
                self.authorization = previous

    def test_each_missing_or_corrupt_cas_object_is_rejected(self):
        with self.transport():
            for reference, content in list(self.fixture.values.items()):
                for replacement in (None, b"corrupt"):
                    with self.subTest(reference=reference, replacement=replacement):
                        if replacement is None:
                            del self.fixture.values[reference]
                        else:
                            self.fixture.values[reference] = replacement
                        with self.assertRaises(Rejected):
                            self.reader().load()
                        self.fixture.values[reference] = content

    def test_head_changes_during_load_cannot_return_old_bundle(self):
        with self.transport():
            self.connection.execute.return_value.fetchone.side_effect = [
                self.row,
                (2, "a" * 64, self.row[2], "a" * 64, self.row[4]),
            ]
            with self.assertRaisesRegex(Rejected, "serving_head_changed"):
                self.reader().load()

    def test_invalid_head_policy_event_sequence_and_time_are_rejected(self):
        original = self.row
        rows = [None, (0, None, self.row[2], None, self.row[4])]
        for index, value in ((0, True), (1, "latest"), (2, "a" * 64), (3, "b" * 64), (4, True)):
            values = list(original)
            values[index] = value
            rows.append(tuple(values))
        rows.extend((*original[:4], original[4] + delta) for delta in (-3, 3))
        with self.transport():
            for row in rows:
                with self.subTest(row=row):
                    self.row = row
                    with self.assertRaises(Rejected):
                        self.reader().load()

    def test_external_sequence_floor_and_live_head_check(self):
        with self.transport():
            with self.assertRaisesRegex(Rejected, "serving_sequence_replay"):
                self.reader(minimum_sequence=2).load()
            reader = self.reader()
            loaded = reader.load()
            self.row = (2, "a" * 64, self.row[2], "a" * 64, self.row[4])
            with self.assertRaisesRegex(Rejected, "serving_head_changed"):
                reader.check(loaded)

    def test_sql_failures_are_redacted_and_wrong_identity_cannot_read(self):
        with self.transport():
            with self.assertRaisesRegex(Rejected, "serving_storage_identity"):
                release_reader.Reader("promoter", **self.options).load()
            self.connection.execute.side_effect = psycopg.OperationalError("PRIVATE-CANARY")
            with self.assertRaisesRegex(Rejected, "^serving_head_unavailable$"):
                self.reader().load()

    def test_foreign_trust_and_missing_lease_fail(self):
        with self.transport():
            for lease in (None, MagicMock(environment="foreign")):
                with self.subTest(lease=lease), self.assertRaises(Rejected):
                    self.reader(trust_lease=lease).load()

    def test_revoked_selection_and_authorization_and_model_deny(self):
        references = (
            self.fixture.head,
            self.selection["authorization_reference"],
            digest(self.fixture.fixture.bundle.materials.fixture.model),
        )
        with self.transport():
            for reference in references:
                with self.subTest(reference=reference):
                    self.fixture.trust_fixture.payload["version"] += 1
                    fixture = self.fixture.trust_fixture
                    fixture.payload["revoked_artifacts"] = [reference]
                    lease = trust.Lease(
                        fixture.read,
                        trusted_root=fixture.public,
                        environment="local-cpu",
                        minimum_version=1,
                        wall_clock=lambda: fixture.wall,
                        monotonic_clock=lambda: fixture.monotonic,
                    )
                    with self.assertRaisesRegex(Rejected, "trust_artifact_revoked"):
                        self.reader(trust_lease=lease).load()

    def test_load_requires_online_trust_but_existing_check_has_bounded_lease(self):
        with self.transport():
            reader = self.reader()
            loaded = reader.load()
            self.fixture.trust_fixture.failure = trust.Unavailable("trust_service_unavailable")
            self.assertEqual(reader.check(loaded)["version"], 1)
            with self.assertRaises(trust.Unavailable):
                self.reader().load()
            self.fixture.trust_fixture.monotonic += 60
            self.fixture.trust_fixture.wall += 60
            self.fixture.clock += 60
            self.row = (*self.row[:4], self.fixture.clock)
            with self.assertRaisesRegex(Rejected, "trust_lease_expired"):
                reader.check(loaded)

    def test_expiry_during_material_read_never_returns_model(self):
        with self.transport():
            original = self.connection.execute.return_value.fetchone.side_effect
            calls = 0

            def clock_advance():
                nonlocal calls
                calls += 1
                if calls == 2:
                    self.fixture.clock = self.selection["expires_at"]
                    self.row = (*self.row[:4], self.fixture.clock)
                return original()

            self.connection.execute.return_value.fetchone.side_effect = clock_advance
            with self.assertRaisesRegex(Rejected, "serving_release_expired"):
                self.reader().load()

    def test_document_digest_and_canonical_form_and_size_are_checked(self):
        with self.transport():
            for content, reference, limit, reason in (
                (b"{}", "a" * 64, 100, "serving_material_integrity"),
                (b"{ }", digest(b"{ }"), 100, "serving_noncanonical_material"),
                (b"{}", digest(b"{}"), 1, "document_too_large"),
            ):
                with (
                    self.subTest(reason=reason),
                    patch.object(storage, "get", return_value=content),
                ):
                    with self.assertRaisesRegex(Rejected, reason):
                        release_reader.document("serving", reference, limit)

    def test_report_size_is_bounded_before_bundle_loading(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate), self.transport():
                size = release_reader.release_policy.MAX_DOCUMENT + (0 if aggregate else 1)
                content = b" " * size
                reference = digest(content)
                self.fixture.values[reference] = content
                self.replace_authorization(
                    reports={gate: reference for gate in self.authorization["reports"]}
                )
                with self.assertRaisesRegex(Rejected, "serving_reports?_size"):
                    self.reader().load()

    def test_check_rejects_expired_release_and_clears_current(self):
        with self.transport():
            reader = self.reader()
            loaded = reader.load()
            advance = loaded.expires_at - self.fixture.clock
            self.fixture.clock += advance
            self.fixture.trust_fixture.advance(advance)
            self.row = (*self.row[:4], self.fixture.clock)
            with self.assertRaisesRegex(Rejected, "serving_release_expired"):
                reader.check(loaded)
            with self.assertRaisesRegex(Rejected, "serving_release_not_current"):
                reader.check(loaded)

    def test_failed_load_does_not_clear_sequence_equivocation_history(self):
        with self.transport():
            reader = self.reader()
            loaded = reader.load()
            self.replace_selection(subject_sha256="a" * 64)
            for _ in range(2):
                with self.assertRaisesRegex(Rejected, "serving_sequence_replay"):
                    reader.load()
            with self.assertRaisesRegex(Rejected, "serving_release_not_current"):
                reader.check(loaded)

    def test_expiry_during_final_trust_refresh_is_not_missed(self):
        fixture = self.fixture.fixture
        approval = {**fixture.approval, "expires_at": self.fixture.clock + 30}
        envelope = signing.sign(approval, "release-approval", fixture.authorities.keys["approver"])
        self.replace_authorization(
            approval_envelope=envelope,
            decision={
                **self.authorization["decision"],
                "approval_sha256": digest(canonical(approval)),
                "expires_at": approval["expires_at"],
            },
        )
        self.replace_selection(expires_at=approval["expires_at"])
        with self.transport():
            original = self.fixture.trust_fixture.read
            calls = 0

            def delayed():
                nonlocal calls
                calls += 1
                if calls == 2:
                    elapsed = self.selection["expires_at"] - self.fixture.clock
                    self.fixture.clock += elapsed
                    self.fixture.trust_fixture.advance(elapsed)
                    self.row = (*self.row[:4], self.fixture.clock)
                return original()

            self.fixture.lease.reader = delayed
            with self.assertRaisesRegex(Rejected, "serving_release_expired"):
                self.reader().load()

    def test_storage_clock_rollback_during_load_is_rejected(self):
        with self.transport():
            original = self.connection.execute.return_value.fetchone.side_effect
            calls = 0

            def reversed_clock():
                nonlocal calls
                calls += 1
                if calls == 2:
                    self.fixture.clock -= 1
                    self.row = (*self.row[:4], self.fixture.clock)
                return original()

            self.connection.execute.return_value.fetchone.side_effect = reversed_clock
            with self.assertRaisesRegex(Rejected, "serving_release_expired"):
                self.reader().load()


if __name__ == "__main__":
    unittest.main()
