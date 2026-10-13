import copy
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from mlsecops import artifact_intake, intake_denial, storage, storage_pipeline
from mlsecops.contracts import Rejected, canonical, digest
from scripts import candidate_lineage_qualification as fixtures


class IntakeDenialContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.CandidateLineageContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.CandidateLineageContracts.tearDownClass()

    def setUp(self):
        self.fixture = fixtures.CandidateLineageContracts()
        self.fixture.setUp()
        self.reads = []
        self.writes = []
        self.get_patch = patch.object(storage, "get", side_effect=self.get)
        self.put_patch = patch.object(storage, "put", side_effect=self.put)
        self.get_patch.start()
        self.put_patch.start()
        self.addCleanup(self.put_patch.stop)
        self.addCleanup(self.get_patch.stop)

    def get(self, client, table, reference):
        self.reads.append(table)
        if table not in {"candidates", "evaluations"}:
            raise AssertionError("denial reader must not fetch datasets or labels")
        try:
            content = self.fixture.objects[(table, reference)]
        except KeyError:
            raise Rejected("storage_object_missing") from None
        if digest(content) != reference:
            raise Rejected("storage_object_integrity_failed")
        return content

    def put(self, client, table, content):
        self.assertEqual(table, "evaluations")
        self.writes.append(content)
        return self.fixture.put(table, content)

    def failure(self, reason="worker_deadline"):
        def executor(image, request):
            if reason == "model_parse_rejected":
                return artifact_intake.response(request, reason=reason), {"image_id": image}
            if reason == "protocol":
                return {"private-password": "secret"}, {"image_id": image}
            raise Rejected(reason)

        fixture = self.fixture
        with self.assertRaises(artifact_intake.IntakeFailure) as failure:
            artifact_intake.inspect_candidate(
                fixture.model,
                digest(fixture.model),
                fixture.expected["image_id"],
                fixture.expected["image_id"],
                executor,
            )
        return failure.exception.report

    def publish(self, report=None, access=None, key=None):
        fixture = self.fixture
        return intake_denial.publish(
            "scorer",
            fixture.candidate_ref,
            fixture.policy,
            fixture.trust,
            key or fixture.directory / "evaluator.pem",
            access or fixture.bound["holdout_access"],
            report or self.failure(),
        )

    def read(self, reference, candidate=None, trust=None):
        fixture = self.fixture
        return intake_denial.read(
            "promoter",
            reference,
            candidate or fixture.candidate_ref,
            fixture.policy,
            trust or fixture.trust,
        )

    def test_signed_failure_has_exact_subject_and_never_approval(self):
        for reason in (
            "worker_deadline",
            "worker_failed",
            "unknown-private-error",
            "protocol",
            "model_parse_rejected",
        ):
            with self.subTest(reason=reason):
                report = self.failure(reason)
                reference = self.publish(report)
                result = self.read(reference)
                self.assertEqual(result["intake"], report)
                self.assertEqual(result["decision"], "deny-evaluation")
                self.assertIs(result["release_ready"], False)
                self.assertEqual(result["intake"]["approved_outputs"], [])
                self.assertNotIn(b"private", canonical(result))
        self.assertEqual(set(self.reads), {"candidates", "evaluations"})

    def test_same_observation_is_idempotent_without_new_holdout_claim(self):
        report = self.failure()
        with patch("mlsecops.holdout_budget.reserve") as reserve:
            first = self.publish(report)
            second = self.publish(report)
            self.assertEqual(first, second)
            self.assertEqual(self.writes[-1], self.writes[-2])
            self.read(first)
        reserve.assert_not_called()

    def test_success_or_forged_failure_is_never_signed(self):
        original = self.failure()
        for field, value in (
            ("status", "pass"),
            ("approved_outputs", [digest(self.fixture.model)]),
            ("origin", "worker"),
            ("reason", "private-path"),
            ("inspected", 1),
            ("model_digest", "0" * 64),
            ("image_id", "sha256:" + "0" * 64),
            ("response_digest", "0" * 64),
            ("finished_at", "invalid"),
            ("extra", "private-password"),
        ):
            with self.subTest(field=field), patch.object(intake_denial, "sign") as signer:
                with self.assertRaises(Rejected):
                    self.publish({**original, field: value})
                signer.assert_not_called()
        self.assertEqual(self.writes, [])

    def test_worker_failure_must_keep_its_real_response_digest(self):
        report = self.failure("model_parse_rejected")
        for field, value in (
            ("response_digest", None),
            ("origin", "controller"),
            ("status", "inconclusive"),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.publish({**report, field: value})

    def test_unknown_origin_and_invalid_reason_types_are_rejected(self):
        report = self.failure()
        for field, value in (("origin", "external"), ("reason", [])):
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.publish({**report, field: value})
        with self.assertRaises(Rejected):
            intake_denial.RecordedDenial("1" * 64, "pass")

    def test_missing_holdout_material_and_changed_reservation_bytes_are_rejected(self):
        with (
            patch.object(
                storage_pipeline,
                "load_candidate",
                return_value=(
                    self.fixture.record,
                    {**self.fixture.metadata, "materials": {}},
                    self.fixture.model,
                ),
            ),
            self.assertRaisesRegex(Rejected, "intake_denial_holdout_missing"),
        ):
            self.publish()
        original = self.fixture.bound["holdout_access"]["reservation"]
        with (
            patch.object(
                storage,
                "get",
                side_effect=lambda client, table, reference: (
                    b"changed" if reference == original else self.get(client, table, reference)
                ),
            ),
            self.assertRaisesRegex(Rejected, "intake_denial_reservation_mismatch"),
        ):
            self.publish()

    def test_bounded_envelope_and_readback_are_verified(self):
        reference = self.publish()
        original = self.read(reference)
        for content in (b"x" * (intake_denial.MAX_BYTES + 1), b"wrong digest"):
            with (
                patch.object(
                    storage,
                    "get",
                    side_effect=lambda client, table, identifier: (
                        content if identifier == reference else self.get(client, table, identifier)
                    ),
                ),
                self.assertRaisesRegex(Rejected, "intake_denial_envelope_invalid"),
            ):
                self.read(reference)
        with (
            patch.object(intake_denial, "MAX_BYTES", 1),
            self.assertRaisesRegex(Rejected, "intake_denial_envelope_limit"),
        ):
            self.publish()
        with (
            patch.object(intake_denial, "verify", return_value={"changed": True}),
            self.assertRaisesRegex(Rejected, "intake_denial_signer_mismatch"),
        ):
            self.publish()
        with (
            patch.object(intake_denial, "read", return_value={**original, "release_ready": True}),
            self.assertRaisesRegex(Rejected, "intake_denial_persistence_mismatch"),
        ):
            self.publish()

    def test_reader_cli_is_read_only_and_exit_zero_is_not_approval(self):
        reference = self.publish()
        fixture = self.fixture
        arguments = [
            "intake_denial",
            "--client",
            "promoter",
            "--candidate",
            fixture.candidate_ref,
            "--denial",
            reference,
            "--trust",
            "trust.json",
        ]
        for unavailable in (False, True):
            output, errors = io.StringIO(), io.StringIO()

            def config(path):
                if unavailable:
                    raise OSError("private-password")
                return fixture.trust if path.name == "trust.json" else fixture.policy

            with (
                self.subTest(unavailable=unavailable),
                patch("sys.argv", arguments),
                patch.object(intake_denial, "read_json", side_effect=config),
                patch.object(storage, "put") as writer,
                patch.object(intake_denial, "sign") as signer,
                redirect_stdout(output),
                redirect_stderr(errors),
            ):
                self.assertEqual(intake_denial.main(), int(unavailable))
            writer.assert_not_called()
            signer.assert_not_called()
            self.assertNotIn("private-password", errors.getvalue())
            if not unavailable:
                self.assertIn('"decision":"deny-evaluation"', output.getvalue())

    def test_controller_failure_exit_remains_nonzero_and_reference_is_sanitized(self):
        from mlsecops import controller

        output = io.StringIO()
        with (
            patch("sys.argv", ["controller", "--request", "fixture.json"]),
            patch.object(controller, "read_json", return_value={}),
            patch.object(
                controller, "execute", side_effect=intake_denial.RecordedDenial("1" * 64, "fail")
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(controller.main(), 1)
        self.assertIn('"denial_reference":"' + "1" * 64 + '"', output.getvalue())
        self.assertIn('"release_ready":false', output.getvalue())

    def test_native_playbook_requires_explicit_disposable_state_and_redacts_errors(self):
        from scripts import intake_denial_native

        arguments = ["denial_native", "--state", "unused"]
        with (
            patch("sys.argv", arguments),
            patch.object(intake_denial_native, "qualify") as qualifier,
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(intake_denial_native.main(), 2)
        qualifier.assert_not_called()
        for error in (Rejected("denial_native_stale_candidate"), OSError("private-password")):
            output = io.StringIO()
            with (
                patch("sys.argv", [*arguments, "--confirm-disposable"]),
                patch.object(intake_denial_native, "qualify", side_effect=error),
                redirect_stdout(output),
            ):
                self.assertEqual(intake_denial_native.main(), 1)
            self.assertNotIn("private-password", output.getvalue())
            self.assertIn('"release_ready":false', output.getvalue())

    def test_wrong_or_missing_reservation_is_rejected(self):
        original = self.fixture.bound["holdout_access"]
        for field, value in (
            ("holdout_digest", "0" * 64),
            ("policy_digest", "0" * 64),
            ("reservation", "0" * 64),
            ("slot", True),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.publish(access={**original, field: value})
        del self.fixture.objects[("evaluations", original["reservation"])]
        with self.assertRaises(Rejected):
            self.publish()
        self.assertEqual(self.writes, [])

    def test_valid_signature_does_not_allow_subject_or_state_changes(self):
        payload = self.read(self.publish())
        for field, value in (
            ("schema_version", True),
            ("schema_version", 2),
            ("candidate_reference", "0" * 64),
            ("dataset_reference", "0" * 64),
            ("lineage_id", "0" * 64),
            ("run_id", "0" * 32),
            ("policy_digest", "0" * 64),
            ("decision", "approve"),
            ("release_ready", True),
            ("release_ready", 0),
            ("extra", "unexpected"),
        ):
            invalid = {**payload, field: value}
            reference = self.fixture.signed("evaluations", invalid, "intake-denial", "evaluator")
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.read(reference)

    def test_wrong_signer_and_payload_type_are_rejected(self):
        with self.assertRaises(Rejected):
            self.publish(key=self.fixture.directory / "curator.pem")
        reference = self.publish()
        with self.assertRaises(Rejected):
            self.read(
                reference, trust={**self.fixture.trust, "evaluator": self.fixture.public["curator"]}
            )
        payload = self.read(reference)
        wrong = self.fixture.signed("evaluations", payload, "stored-evaluation", "evaluator")
        with self.assertRaisesRegex(Rejected, "wrong_payload_type"):
            self.read(wrong)
        with self.assertRaisesRegex(Rejected, "wrong_payload_type"):
            storage_pipeline.read_evaluation(
                "promoter",
                reference,
                self.fixture.candidate_ref,
                self.fixture.policy,
                self.fixture.trust,
            )

    def test_invalid_storage_receipt_and_failed_readback_cannot_report_durable_success(self):
        with patch.object(storage, "put", return_value="0" * 64), self.assertRaises(Rejected):
            self.publish()
        with patch.object(intake_denial, "read", side_effect=Rejected("unavailable")):
            with self.assertRaises(Rejected):
                self.publish()
        self.assertEqual(len(self.writes), 1)

    def test_storage_outage_does_not_resume_prediction_or_evaluation_signing(self):
        fixture = self.fixture
        report = self.failure()
        for unavailable in (False, True):
            context = (
                patch.object(storage, "put", side_effect=Rejected("storage_write_rejected:08006"))
                if unavailable
                else patch.object(storage, "put", side_effect=self.put)
            )
            with (
                self.subTest(unavailable=unavailable),
                context,
                patch.object(
                    storage_pipeline.storage_dataset,
                    "read_manifest",
                    return_value=(fixture.manifest, fixture.statement),
                ),
                patch.object(
                    storage_pipeline.storage_dataset,
                    "read_dataset",
                    return_value=({"holdout": []}, fixture.manifest, fixture.statement),
                ),
                patch.object(
                    storage_pipeline.holdout_budget,
                    "reserve",
                    return_value=fixture.bound["holdout_access"],
                ),
                patch.object(
                    storage_pipeline,
                    "evaluate_verified_candidate",
                    side_effect=artifact_intake.IntakeFailure(copy.deepcopy(report)),
                ),
                patch.object(storage_pipeline, "sign") as evaluator,
            ):
                with self.assertRaises(Rejected) as failure:
                    storage_pipeline.evaluate(
                        "scorer",
                        fixture.candidate_ref,
                        fixture.policy,
                        fixture.expected["image_id"],
                        fixture.trust,
                        fixture.directory / "evaluator.pem",
                    )
                evaluator.assert_not_called()
                if unavailable:
                    self.assertEqual(str(failure.exception), "intake_denial_persistence_failed")
                else:
                    self.assertIsInstance(failure.exception, intake_denial.RecordedDenial)
                    self.read(failure.exception.reference)


if __name__ == "__main__":
    unittest.main()
