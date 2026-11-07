"""Cryptographically bound reference construction; controlled worker, no native gate claim."""

import copy
import unittest
from unittest.mock import Mock, patch

from mlsecops import monitoring, monitoring_reference, prediction_protocol, signing
from mlsecops.contracts import Rejected, canonical, digest
from scripts import candidate_lineage_qualification as lineage_fixtures
from scripts import release_bundle_qualification as release_fixtures


class ReferenceContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        release_fixtures.ReleaseBundleContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        release_fixtures.ReleaseBundleContracts.tearDownClass()

    def setUp(self):
        self.make()

    def make(self, *, count=1000, positives=None, suffix=b"", duplicate=False):
        self.rows = [
            {
                "entity_id": index + 1000,
                "features": [(index % 10 + 0.5) / 10] * 6,
                "label": int(index % 10 >= 5) if positives is None else int(index < positives),
            }
            for index in range(count)
        ]
        if duplicate:
            self.rows[-1]["entity_id"] = self.rows[0]["entity_id"]
        self.content = canonical(self.rows) + suffix
        fixture_class = lineage_fixtures.CandidateLineageContracts
        policy = {**fixture_class.policy, "rows": count + 464, "split_counts": [64, count, 400]}
        self.fixture = release_fixtures.ReleaseBundleContracts()
        with (
            patch.object(fixture_class, "policy", policy),
            patch.object(
                fixture_class, "split_contents", {"validation": self.content}, create=True
            ),
        ):
            self.fixture.setUp()
        self.package = self.fixture.create()
        self.key = self.fixture.materials.fixture.directory / "reference.pem"
        self.public = signing.create_key(self.key)
        self.time_ms = self.fixture.clock * 1000 + 10
        self.worker = Mock(side_effect=self.response)

    def response(self, request):
        return prediction_protocol.response(
            request,
            [row[0] for row in request["features"]],
            self.fixture.materials.fixture.bound["report"]["scan"],
        )

    def build(self, **changes):
        arguments = {key: value for key, value in self.fixture.arguments.items() if key != "clock"}
        arguments.update(
            validation_content=self.content,
            run_worker=self.worker,
            signing_key=self.key,
            clock=lambda: self.time_ms,
        )
        return monitoring_reference.build(self.package, **{**arguments, **changes})

    def test_reference_is_computed_from_signed_validation_bytes_and_bound_worker_predictions(self):
        result = self.build()
        reference = signing.verify(result["envelope"], "monitor-reference", self.public)
        monitoring.validate_reference(reference)
        self.assertEqual(
            (reference["observations"], reference["positive_labels"], reference["true_positives"]),
            (1000, 500, 500),
        )
        self.assertEqual(reference["frozen_at_ms"], self.time_ms)
        self.assertTrue(
            all(counts == [0] + [100] * 10 + [0] for counts in reference["histograms"].values())
        )
        manifest = signing.verify(
            self.package["envelope"], "model-release", self.fixture.materials.public
        )
        self.assertEqual(reference["bundle_sha256"], digest(canonical(manifest)))
        self.assertEqual(reference["model_sha256"], manifest["materials"]["model"])
        self.assertEqual(reference["dataset_sha256"], manifest["materials"]["dataset_manifest"])
        self.assertEqual(reference["evaluation_sha256"], manifest["materials"]["evaluation_report"])
        self.assertEqual(result["evidence"]["validation_sha256"], digest(self.content))
        self.assertEqual(result["evidence"]["prediction_receipt"]["rows"], 1000)
        self.assertFalse(result["evidence"]["release_ready"])
        self.assertNotIn("features", canonical(result["evidence"]).decode())

    def test_altered_missing_wrong_type_or_noncanonical_split_is_rejected_before_worker(self):
        for content in (
            self.content + b" ",
            self.content.replace(b"0.05", b"0.06", 1),
            b"[]",
            None,
        ):
            self.worker.reset_mock()
            with self.subTest(kind=type(content).__name__), self.assertRaises(Rejected):
                self.build(validation_content=content)
            self.worker.assert_not_called()

    def test_package_material_tampering_is_rejected_before_worker(self):
        original = copy.deepcopy(self.package)
        self.package["documents"]["split_manifest"] += b" "
        with self.assertRaises(Rejected):
            self.build()
        self.worker.assert_not_called()
        self.package = original
        self.package["envelope"]["signatures"][0]["sig"] = signing.encode64(b"x" * 64)
        with self.assertRaises(Rejected):
            self.build()
        self.worker.assert_not_called()

    def test_insufficient_rows_or_positive_labels_cannot_be_replaced_with_duplicates(self):
        for options in ({"count": 999}, {"positives": 199}):
            self.make(**options)
            with self.assertRaises(Rejected):
                self.build()
            self.worker.assert_not_called()

    def test_reference_signer_is_separate_from_existing_candidate_authorities(self):
        for key in (
            self.fixture.materials.key,
            self.fixture.materials.fixture.directory / "curator.pem",
            self.fixture.materials.fixture.directory / "evaluator.pem",
        ):
            with (
                self.subTest(key=key.name),
                self.assertRaisesRegex(Rejected, "monitor_reference_roles"),
            ):
                self.build(signing_key=key)
            self.worker.assert_not_called()

    def test_signed_noncanonical_or_duplicate_rows_still_fail_before_worker(self):
        for options in ({"suffix": b" "}, {"duplicate": True}):
            self.make(**options)
            with self.assertRaises(Rejected):
                self.build()
            self.worker.assert_not_called()

    def test_wrong_model_row_or_scan_response_never_gets_a_signed_reference(self):
        def corrupt(request, variant):
            output = self.response(request)
            if variant == "model":
                output["model_digest"] = "f" * 64
            elif variant == "row":
                output["predictions"][0]["row_id"] = "wrong"
            else:
                output["scan"]["errors"] = 1
            return output

        for variant in ("model", "row", "scan"):
            with patch.object(monitoring_reference.signing, "sign") as sign:
                with self.assertRaises(Rejected):
                    self.build(run_worker=lambda request: corrupt(request, variant))
                sign.assert_not_called()

    def test_worker_failure_clock_rollback_or_package_expiry_cannot_issue_reference(self):
        with self.assertRaises(RuntimeError):
            self.build(run_worker=Mock(side_effect=RuntimeError("controlled")))
        for clocks in (
            (self.time_ms, self.time_ms - 1),
            (self.time_ms, self.fixture.attributes["expires_at"] * 1000),
            (True,),
        ):
            with (
                self.subTest(clocks=clocks),
                patch.object(monitoring_reference.signing, "sign") as sign,
            ):
                with self.assertRaises(Rejected):
                    self.build(clock=Mock(side_effect=clocks))
                sign.assert_not_called()

    def test_input_package_mutation_by_worker_cannot_change_verified_pins(self):
        expected = self.build()

        def worker(request):
            self.package["documents"]["asset_projection"] = canonical(
                {"bindings": {"source_fingerprint": "f" * 64}}
            )
            return self.response(request)

        actual = self.build(run_worker=worker)
        first = signing.verify(expected["envelope"], "monitor-reference", self.public)
        second = signing.verify(actual["envelope"], "monitor-reference", self.public)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
