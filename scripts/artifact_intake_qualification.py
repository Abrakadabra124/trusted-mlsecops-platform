import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import artifact_intake, model, pipeline, worker
from mlsecops.bootstrap import initialize
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from mlsecops.datasets import generate
from mlsecops.signing import decode64

IMAGE = "sha256:" + "1" * 64


class ArtifactIntakeContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.trained = worker.train(
            {"action": "train", "train": generate(rows=1000), "seed": 17, "features": [[0.5] * 6]}
        )
        cls.content = decode64(cls.trained["model"])

    @staticmethod
    def executor(image, request):
        return worker.execute(request), {"image_id": IMAGE}

    def inspect(self, content=None, executor=None):
        content = self.content if content is None else content
        return artifact_intake.inspect_candidate(
            content, digest(content), IMAGE, IMAGE, executor or self.executor
        )

    def test_actual_model_passes_fresh_independent_inspection(self):
        receipt = self.inspect()
        self.assertEqual(receipt["status"], "pass")
        self.assertEqual(receipt["approved_outputs"], [digest(self.content)])
        self.assertEqual(receipt["inspected"], 1)
        self.assertEqual(receipt["scan"]["inspected_nodes"], 2)
        artifact_intake.validate_receipt(receipt, self.content, IMAGE)

    def test_evidence_must_not_precede_workspace_ownership(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            unowned = state / "unowned"
            write_json(unowned / "evidence/intake.json", {"fixture": True})
            with patch("mlsecops.bootstrap.collect", return_value={"fixture": True}):
                with self.assertRaisesRegex(Rejected, "refusing_nonempty_unowned_workspace"):
                    initialize(root, unowned)
                owned = state / "owned"
                original = initialize(root, owned)
                write_json(owned / "evidence/intake.json", {"fixture": True})
                self.assertEqual(initialize(root, owned), original)

    def test_scanner_has_no_features_labels_or_signer_and_does_not_create_runtime(self):
        captured = []

        def executor(image, request):
            captured.append(request)
            with patch.object(
                model.ort, "InferenceSession", side_effect=AssertionError("runtime forbidden")
            ):
                return self.executor(image, request)

        self.inspect(executor=executor)
        self.assertEqual(
            set(captured[0]), {"schema_version", "action", "inspection_id", "model", "model_digest"}
        )
        self.assertEqual(captured[0]["action"], "inspect")

    def test_renamed_pickle_empty_and_malformed_payload_cannot_be_approved(self):
        for content in (b"\x80\x04N.", b"", b"not-an-onnx-file"):
            with self.subTest(content=content), self.assertRaises(Rejected):
                self.inspect(content)

    def test_known_unsafe_model_keeps_failed_report_not_transport_success(self):
        with self.assertRaises(artifact_intake.IntakeFailure) as failure:
            self.inspect(b"\x80\x04N.")
        report = failure.exception.report
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["model_digest"], digest(b"\x80\x04N."))
        self.assertEqual(report["approved_outputs"], [])
        self.assertEqual(report["inspected"], 0)

    def test_wrong_expected_digest_never_launches_worker(self):
        with patch.object(worker, "execute") as execute, self.assertRaises(Rejected):
            artifact_intake.inspect_candidate(self.content, "0" * 64, IMAGE, IMAGE, self.executor)
        execute.assert_not_called()

    def test_request_rejects_shape_identity_subject_and_size(self):
        request = artifact_intake.request_for(self.content, "1" * 32)
        for field, value in (
            ("schema_version", True),
            ("schema_version", 2),
            ("action", "predict"),
            ("inspection_id", "stale"),
            ("inspection_id", None),
            ("model_digest", "0" * 64),
            ("model", "!invalid!"),
            ("labels", []),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                artifact_intake.validate_request({**request, field: value})
        for content in (None, b"", "bytes-required"):
            with self.subTest(content=content), self.assertRaises(Rejected):
                artifact_intake.request_for(content, "1" * 32)
        with patch.object(artifact_intake, "MAX_BYTES", len(self.content)):
            with self.assertRaisesRegex(Rejected, "intake_request_limit"):
                artifact_intake.request_for(self.content, "1" * 32)
            with self.assertRaisesRegex(Rejected, "intake_content_limit"):
                artifact_intake.request_for(self.content + b"extra", "1" * 32)
            with self.assertRaisesRegex(Rejected, "intake_request_contract"):
                artifact_intake.validate_request(request)

    def test_invalid_response_reason_and_size(self):
        request = artifact_intake.request_for(self.content, "1" * 32)
        for reason in ("private-error", [], True):
            with self.subTest(reason=reason), self.assertRaises(Rejected):
                artifact_intake.response(request, reason=reason)
        with self.assertRaisesRegex(Rejected, "intake_response_limit"):
            artifact_intake.checked_response({"oversized": "x" * 65536}, request)

    def test_invalid_expected_image_and_execution_request_binding(self):
        for image in ("latest", None):
            with self.subTest(image=image), self.assertRaises(Rejected):
                artifact_intake.inspect_candidate(
                    self.content, digest(self.content), IMAGE, image, self.executor
                )

        def executor(image, request):
            output, execution = self.executor(image, request)
            execution["input_digest"] = "0" * 64
            return output, execution

        with self.assertRaises(artifact_intake.IntakeFailure):
            self.inspect(executor=executor)

    def test_unknown_scanner_rejection_is_redacted(self):
        with patch.object(worker, "inspect_model", side_effect=Rejected("private-parser-path")):
            with self.assertRaises(artifact_intake.IntakeFailure) as failure:
                self.inspect()
        self.assertEqual(failure.exception.report["reason"], "model_profile_rejected")
        self.assertNotIn(b"private-parser-path", canonical(failure.exception.report))

    def test_worker_rejection_cannot_be_forged_into_no_findings(self):
        def executor(image, request):
            result, execution = self.executor(image, request)
            result["status"] = "pass"
            return result, execution

        with self.assertRaises(artifact_intake.IntakeFailure):
            self.inspect(b"\x80\x04N.", executor)

    def test_stale_nonce_and_other_model_report_are_rejected(self):
        previous = []

        def capture(image, request):
            result = self.executor(image, request)
            previous.append(copy.deepcopy(result))
            return result

        self.inspect(executor=capture)
        with self.assertRaises(artifact_intake.IntakeFailure):
            self.inspect(executor=lambda *args: previous[0])

        def swapped(image, request):
            result, execution = self.executor(image, request)
            result["model_digest"] = "0" * 64
            return result, execution

        with self.assertRaises(artifact_intake.IntakeFailure):
            self.inspect(executor=swapped)

    def test_zero_partial_wrong_tool_policy_and_extra_outputs_are_rejected(self):
        for field, value in (
            ("inspected", 0),
            ("inspected", True),
            ("skipped", 1),
            ("errors", 1),
            ("unsupported", 1),
            ("approved_outputs", []),
            ("approved_outputs", ["0" * 64]),
            ("approved_outputs", [digest(self.content), digest(self.content)]),
        ):

            def executor(image, request):
                result, execution = self.executor(image, request)
                result[field] = value
                return result, execution

            with (
                self.subTest(field=field, value=value),
                self.assertRaises(artifact_intake.IntakeFailure),
            ):
                self.inspect(executor=executor)
        for field in ("policy_version", "onnx_version"):

            def executor(image, request):
                result, execution = self.executor(image, request)
                result["scan"][field] = "obsolete"
                return result, execution

            with self.subTest(field=field), self.assertRaises(artifact_intake.IntakeFailure):
                self.inspect(executor=executor)

    def test_wrong_image_malformed_or_private_output_is_not_persisted(self):
        for result in (
            ("private-password", {"image_id": IMAGE}),
            ({"private-password": "secret"}, {"image_id": IMAGE}),
            ({}, {"image_id": "private-password"}),
        ):
            with (
                self.subTest(kind=type(result[0])),
                self.assertRaises(artifact_intake.IntakeFailure) as failure,
            ):
                self.inspect(executor=lambda *args: result)
            self.assertNotIn(b"private-password", canonical(failure.exception.report))

    def test_timeout_crash_and_missing_runtime_are_inconclusive(self):
        for error in (
            Rejected("worker_deadline"),
            Rejected("worker_failed"),
            OSError("private-password"),
        ):

            def executor(*args):
                raise error

            with (
                self.subTest(error=type(error)),
                self.assertRaises(artifact_intake.IntakeFailure) as failure,
            ):
                self.inspect(executor=executor)
            report = failure.exception.report
            self.assertEqual(report["status"], "inconclusive")
            self.assertEqual(report["approved_outputs"], [])
            self.assertNotIn(b"private-password", canonical(report))

    def test_executor_cannot_mutate_pending_request_to_change_subject(self):
        def executor(image, request):
            request["inspection_id"] = "0" * 32
            return self.executor(image, request)

        with self.assertRaises(artifact_intake.IntakeFailure):
            self.inspect(executor=executor)

    def test_failed_intake_never_reaches_prediction(self):
        actions = []

        def executor(image, request):
            actions.append(request["action"])
            return {}, {"image_id": IMAGE}

        policy = read_json(Path(__file__).resolve().parents[1] / "policies/local-cpu.json")
        with self.assertRaises(artifact_intake.IntakeFailure):
            pipeline.evaluate_verified_candidate(
                {"image_id": IMAGE, "model_digest": digest(self.content)},
                self.content,
                [],
                {},
                policy,
                IMAGE,
                executor,
            )
        self.assertEqual(actions, ["inspect"])

    def test_scoped_role_allows_intake_only_for_scorer(self):
        from mlsecops.controller_worker import documents

        profile = {
            "image": "example/worker@" + IMAGE,
            "image_id": IMAGE,
            "config_id": IMAGE,
            "manifest_id": IMAGE,
            "source_fingerprint": "1" * 64,
            "source_revision": "2" * 40,
        }
        request = artifact_intake.request_for(self.content, "3" * 32)
        config, job = documents(profile, "scorer", request)
        self.assertEqual(job["metadata"]["namespace"], "ml-eval")
        self.assertTrue(config["immutable"])
        with self.assertRaises(Rejected):
            documents(profile, "publisher", request)

    def test_signed_reader_binding_rejects_altered_receipt(self):
        receipt = self.inspect()
        for field, value in (
            ("schema_version", True),
            ("status", "fail"),
            ("model_digest", "0" * 64),
            ("image_id", "sha256:" + "0" * 64),
            ("request_digest", "0" * 64),
            ("response_digest", "0" * 64),
            ("bytes", 0),
            ("approved_outputs", []),
            ("finished_at", "invalid"),
            ("finished_at", "2000-01-01T00:00:00+00:00"),
            ("finished_at", "2026-01-01T00:00:00"),
            ("finished_at", None),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                artifact_intake.validate_receipt({**receipt, field: value}, self.content, IMAGE)

    def test_file_path_escape_and_changed_conversion_output_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "model.onnx"
            path.write_bytes(self.content)
            for name in ("../model.onnx", str(path.resolve()), "C:\\outside.onnx"):
                with self.subTest(name=name), self.assertRaises(Rejected):
                    artifact_intake.inspect_file(
                        root, name, digest(self.content), IMAGE, IMAGE, self.executor
                    )
            content, report = artifact_intake.inspect_file(
                root, "model.onnx", digest(self.content), IMAGE, IMAGE, self.executor
            )
            self.assertEqual(content, self.content)
            self.assertEqual(report["status"], "pass")

            def mutate(image, request):
                path.write_bytes(self.content + b"changed")
                return self.executor(image, request)

            with self.assertRaisesRegex(Rejected, "intake_input_changed"):
                artifact_intake.inspect_file(
                    root, "model.onnx", digest(self.content), IMAGE, IMAGE, mutate
                )

    def test_file_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "model.onnx"
            path.write_bytes(self.content)
            (root / "link.onnx").symlink_to(path)
            with self.assertRaises(Rejected):
                artifact_intake.inspect_file(
                    root, "link.onnx", digest(self.content), IMAGE, IMAGE, self.executor
                )


if __name__ == "__main__":
    unittest.main()
