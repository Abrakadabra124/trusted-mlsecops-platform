import copy
import unittest
from unittest.mock import patch

from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts import audit_correlation_probe as probe
from scripts import candidate_serving_reader_qualification as candidates
from scripts import release_reader_qualification as releases
from scripts.audit_export_qualification import encoded, records


class CorrelationProbeContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        releases.ReleaseReaderContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        releases.ReleaseReaderContracts.tearDownClass()

    def release(self):
        fixture = releases.ReleaseReaderContracts()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        expected = probe.release(
            fixture.arguments["package"],
            fixture.arguments["context"],
            fixture.selection,
            fixture.authorization,
            fixture.arguments["trusted_root"],
        )
        with fixture.transport():
            loaded = fixture.reader().load()
        return fixture, expected, loaded

    def candidate(self):
        fixture = candidates.CandidateReaderContracts()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        expected = probe.candidate(
            fixture.package,
            fixture.bundle.materials.context,
            signing.sign(fixture.permit, "candidate-serving-qualification", fixture.key),
            fixture.public,
            fixture.bundle.materials.public,
        )
        return fixture, expected, fixture.reader().load()

    def test_independent_primary_materials_match_both_verified_reader_contexts(self):
        from dataclasses import asdict

        for factory in (self.release, self.candidate):
            fixture, expected, loaded = factory()
            self.assertEqual(expected, asdict(loaded.audit_context))
            source = [encoded(records(bound=expected))]
            result = probe.scan(source, expected)
            self.assertEqual(result["correlated_requests"], 1)
            self.assertEqual(result["completed_200"], 1)
            self.assertEqual(result["without_context"], 0)
            self.assertFalse(result["release_ready"])
            for private in expected["lineage"].values():
                self.assertNotIn(private.encode(), canonical(result))
            self.assertEqual(
                result["scope"], expected["kind"] + "-private-correlation-not-full-M13"
            )

    def test_every_wrong_but_valid_hash_is_rejected_against_independent_expected_materials(self):
        fixture, expected, loaded = self.release()
        for field in expected["lineage"]:
            wrong = copy.deepcopy(expected)
            wrong["lineage"][field] = ("0" if wrong["lineage"][field][0] != "0" else "1") * len(
                wrong["lineage"][field]
            )
            with self.subTest(field=field), self.assertRaisesRegex(Rejected, "correlation_context"):
                probe.scan([encoded(records(bound=wrong))], expected)
        for field in (
            "selection_sha256",
            "authorization_sha256",
            "assurance_sha256",
            "approval_sha256",
            "bundle_sha256",
            "model_sha256",
        ):
            wrong = {**expected, field: "f" * 64}
            with self.subTest(field=field), self.assertRaisesRegex(Rejected, "correlation_context"):
                probe.scan([encoded(records(bound=wrong))], expected)
        objects = fixture.arguments["package"]["capsule"]["objects"]
        dataset = signing.verify(
            decode(objects[("manifests", expected["lineage"]["dataset_sha256"])]),
            "stored-dataset",
            fixture.arguments["context"]["trust"]["curator"],
        )
        evaluation = signing.verify(
            decode(objects[("evaluations", expected["lineage"]["evaluation_sha256"])]),
            "stored-evaluation",
            fixture.arguments["context"]["trust"]["evaluator"],
        )
        for field, wrong_hash in (
            ("dataset_sha256", dataset["dataset_id"]),
            ("lineage_sha256", dataset["lineage_id"]),
            ("source_approval_sha256", dataset["approval_object"]),
            ("evaluation_sha256", digest(canonical(evaluation["report"]))),
            (
                "evaluation_sha256",
                digest(
                    signing.decode64(
                        decode(objects[("evaluations", expected["lineage"]["evaluation_sha256"])])[
                            "payload"
                        ]
                    )
                ),
            ),
        ):
            wrong = copy.deepcopy(expected)
            self.assertNotEqual(wrong_hash, wrong["lineage"][field])
            wrong["lineage"][field] = wrong_hash
            with self.subTest(field=field), self.assertRaises(Rejected):
                probe.scan([encoded(records(bound=wrong))], expected)

    def test_legacy_missing_mixed_or_unfinished_windows_cannot_claim_correlation(self):
        fixture, expected, loaded = self.candidate()
        legacy = {name: value for name, value in expected.items() if name != "lineage"}
        legacy["schema_version"] = 1
        for bound in (
            legacy,
            {**expected, "lineage": {}},
            {**expected, "approval_sha256": "a" * 64},
        ):
            with self.assertRaises(Rejected):
                probe.scan([encoded(records(bound=bound))], expected)
        for wrong_expected in (legacy, {}, None):
            with self.assertRaises(Rejected):
                probe.scan([encoded(records(bound=expected))], wrong_expected)
        mixed = records(bound=expected) + records(bound=legacy, request="3" * 32)
        for index, record in enumerate(mixed, start=1):
            record.update(sequence=index, recorded_at_ns=100 + index)
        for source in (
            [],
            [encoded(mixed)],
            [encoded(records(bound=expected)[:-1])],
            [encoded(records(status=503, bound=None))],
        ):
            with self.assertRaises(Rejected):
                probe.scan(source, expected)

    def test_failure_after_intent_and_preselection_do_not_count_as_successful_inference(self):
        fixture, expected, loaded = self.candidate()
        success = records(bound=expected)
        failure = records(bound=expected, request="2" * 32)
        for record in failure[2:]:
            record["event"].update(status=503, context=None)
        denied = records(status=503, bound=None, request="3" * 32)
        aborted = records(bound=expected, request="4" * 32)[:3]
        aborted[-1]["event"].update(stage="aborted", status=None, context=None)
        values = success + failure + denied + aborted
        for index, record in enumerate(values, start=1):
            record.update(sequence=index, recorded_at_ns=100 + index)
        result = probe.scan([encoded(values)], expected)
        self.assertEqual(result["correlated_requests"], 3)
        self.assertEqual(result["completed_200"], 1)
        self.assertEqual(result["failed_after_intent"], 2)
        self.assertEqual(result["without_context"], 1)

    def test_retention_cannot_hide_complete_legacy_requests_from_fresh_campaign(self):
        fixture, expected, loaded = self.candidate()
        legacy = {name: value for name, value in expected.items() if name != "lineage"}
        legacy["schema_version"] = 1
        values = records(bound=legacy) + records(bound=expected, request="3" * 32)
        for index, record in enumerate(values, start=1):
            record.update(sequence=index, recorded_at_ns=100 + index)
        with self.assertRaisesRegex(Rejected, "audit_correlation_context_mismatch"):
            probe.scan([encoded(values)], expected)
        with self.assertRaisesRegex(Rejected, "audit_correlation_window_start"):
            probe.scan([encoded(values[4:])], expected)

    def test_primary_authority_and_material_mismatches_fail_closed(self):
        fixture, expected, loaded = self.release()
        for selection in (
            {**fixture.selection, "authorization_reference": "f" * 64},
            {**fixture.selection, "subject_sha256": "f" * 64},
        ):
            with self.assertRaises(Rejected):
                probe.release(
                    fixture.arguments["package"],
                    fixture.arguments["context"],
                    selection,
                    fixture.authorization,
                    fixture.arguments["trusted_root"],
                )
        broken = copy.deepcopy(fixture.authorization)
        broken["approval_envelope"]["payload"] = signing.encode64(b"{}")
        with self.assertRaises(Rejected):
            probe.release(
                fixture.arguments["package"],
                fixture.arguments["context"],
                fixture.selection,
                broken,
                fixture.arguments["trusted_root"],
            )
        candidate, expected, loaded = self.candidate()
        for field in ("proposal_sha256", "subject_sha256", "model_sha256"):
            permit = {**candidate.permit, field: "f" * 64}
            with self.assertRaises(Rejected):
                probe.candidate(
                    candidate.package,
                    candidate.bundle.materials.context,
                    signing.sign(permit, "candidate-serving-qualification", candidate.key),
                    candidate.public,
                    candidate.bundle.materials.public,
                )
        package = copy.deepcopy(candidate.package)
        reference = expected["lineage"]["run_sha256"]
        package["capsule"]["objects"][("candidates", reference)] = b"{}"
        with self.assertRaises(Rejected):
            probe.materials(package, candidate.bundle.materials.context)
        original = signing.verify

        def inconsistent(envelope, kind, public):
            payload = original(envelope, kind, public)
            return {**payload, "source_sha256": "f" * 64} if kind == "data-lineage" else payload

        with patch.object(probe.signing, "verify", side_effect=inconsistent):
            with self.assertRaisesRegex(Rejected, "audit_correlation_source_binding"):
                probe.materials(candidate.package, candidate.bundle.materials.context)

    def test_closed_snapshot_is_unchanged_and_mismatch_has_constant_diagnostic(self):
        fixture, expected, loaded = self.candidate()
        source = [encoded(records(bound=expected))]
        with patch.object(probe.audit_snapshot, "read_closed", side_effect=[source, source]):
            self.assertEqual(probe.exercise("unused", expected)["status"], "pass")
        with patch.object(probe.audit_snapshot, "read_closed", side_effect=[source, []]):
            with self.assertRaisesRegex(Rejected, "^audit_correlation_source_changed$"):
                probe.exercise("unused", expected)


if __name__ == "__main__":
    unittest.main()
