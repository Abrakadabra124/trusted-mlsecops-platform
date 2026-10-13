import contextlib
import copy
import importlib.metadata
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import artifact_intake
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from mlsecops.datasets import generate
from mlsecops.prediction_protocol import PredictionBatch
from mlsecops.prediction_protocol import response as prediction_response
from mlsecops.signing import encode64
from scripts import robust_training_experiment as experiment
from scripts import robust_training_native as native


class ExperimentContracts(unittest.TestCase):
    def test_missing_abstentions_or_hidden_execution_rejected(self):
        decisions = [{"decision": "abstain", "reason": "outside-support", "score": None}] * 12
        self.assertEqual(native.check_abstentions(decisions, 7, 7), 12)
        for invalid, after in (([], 7), (decisions[:11], 7), (decisions, 8)):
            with self.assertRaisesRegex(Rejected, "abstain_contract"):
                native.check_abstentions(invalid, 7, after)

    def test_exact_clean_ap_loss_boundary_without_float_subtraction_false_fail(self):
        baseline, candidate = self.summaries(), self.summaries()
        candidate["new-73043"]["quality"]["auprc"] = 0.87
        self.assertEqual(experiment.decide(baseline, candidate)["status"], "pass")
        candidate["new-73043"]["quality"]["auprc"] = 0.86999999
        self.assertEqual(experiment.decide(baseline, candidate)["status"], "fail")

    def test_training_and_intake_readback_rejects_semantic_swaps(self):
        request, response, profile = self.response()
        profile["training_seed"] = 17
        image = "sha256:" + "1" * 64
        recorded = {}

        def executor(selected, inspection):
            output = artifact_intake.response(inspection, response["scan"])
            recorded.update({"request-1.json": inspection, "response-1.json": output})
            return output, {"image_id": selected}

        receipt = artifact_intake.inspect_candidate(
            b"fixture", digest(b"fixture"), image, image, executor
        )
        recorded.update(
            {
                "request-0.json": request,
                "response-0.json": response,
                "train.json": request["train"],
                "validation.json": [{"features": request["features"][0]}],
                "baseline-parity.json": {"rows": 1, "max_error": 0.0, "label_mismatches": 0},
                "baseline-intake.json": receipt,
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            campaign = Path(directory)
            for name, value in recorded.items():
                write_json(campaign / name, value)
            native.reconcile_training(campaign, "baseline", 0, b"fixture", profile, image)
            for name, field, changed in (
                ("response-0.json", "input_digest", "0" * 64),
                ("request-0.json", "seed", 18),
                ("baseline-parity.json", "max_error", 1e-6),
                ("baseline-intake.json", "image_id", "sha256:" + "2" * 64),
                ("request-1.json", "inspection_id", "0" * 32),
                ("response-1.json", "request_digest", "0" * 64),
            ):
                write_json(campaign / name, {**recorded[name], field: changed})
                with self.subTest(name=name), self.assertRaises(Rejected):
                    native.reconcile_training(campaign, "baseline", 0, b"fixture", profile, image)
                write_json(campaign / name, recorded[name])
            with self.assertRaises(Rejected):
                native.reconcile_training(campaign, "baseline", 0, b"foreign", profile, image)

    def test_cleanup_timeout_does_not_leave_stale_pass_or_expose_command(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            write_json(
                state / "workspace.json",
                {"product": "trusted-mlsecops", "schema_version": 1, "workspace_id": "1" * 32},
            )
            stream = io.StringIO()
            with (
                patch("sys.argv", ["research", "--state", str(state)]),
                patch.object(
                    native, "qualify", side_effect=subprocess.TimeoutExpired("SECRET-COMMAND", 30)
                ),
                contextlib.redirect_stdout(stream),
                contextlib.redirect_stderr(stream),
            ):
                self.assertEqual(native.main(), 1)
            self.assertNotIn("SECRET", stream.getvalue())
            self.assertEqual(
                read_json(state / "evidence/robust-training.json")["execution_status"], "incomplete"
            )

    def test_primary_prediction_replay_binds_model_features_nonce_and_row_order(self):
        _, trained, _ = self.response()
        features = [[0.5] * 6, [0.4] * 6]
        request = PredictionBatch(b"fixture", features).request
        output = prediction_response(request, [0.6, 0.7], trained["scan"])
        self.assertEqual(
            experiment.replay_scores(request, output, b"fixture", features), [0.6, 0.7]
        )
        for content, values in ((b"foreign", features), (b"fixture", features[::-1])):
            with self.assertRaisesRegex(Rejected, "material_binding"):
                experiment.replay_scores(request, output, content, values)
        for field, value in (
            ("batch_id", "0" * 32),
            ("predictions", output["predictions"][::-1]),
            ("scan", {}),
            ("request_digest", "0" * 64),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                experiment.replay_scores(request, {**output, field: value}, b"fixture", features)

    def test_cli_failure_replaces_old_pass_and_redacts_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            write_json(
                state / "workspace.json",
                {"product": "trusted-mlsecops", "schema_version": 1, "workspace_id": "1" * 32},
            )
            report = state / "evidence/robust-training.json"
            write_json(report, {"status": "pass"})
            stream = io.StringIO()
            with (
                patch("sys.argv", ["robust-training", "--state", str(state)]),
                patch.object(native, "qualify", side_effect=OSError("SECRET")),
                contextlib.redirect_stdout(stream),
            ):
                self.assertEqual(native.main(), 1)
            self.assertEqual(read_json(report)["status"], "fail")
            self.assertNotIn("SECRET", stream.getvalue())
            for status, code in (("pass", 0), ("fail", 1), ("inconclusive", 2)):
                with (
                    patch("sys.argv", ["robust-training", "--state", str(state)]),
                    patch.object(
                        native, "qualify", return_value={"status": status, "release_ready": False}
                    ),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(native.main(), code)
                self.assertEqual(read_json(report)["status"], status)

    def test_missing_and_tampered_primary_materials_block_reconciliation(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            with self.assertRaisesRegex(Rejected, "incomplete_material_set"):
                native.reconcile(state, {}, {}, {})
            for name in native.MATERIAL_FILES:
                write_json(state / name, {})
            hashes = {name: digest((state / name).read_bytes()) for name in native.MATERIAL_FILES}
            write_json(state / "train.json", [])
            with self.assertRaisesRegex(Rejected, "persisted_material_changed"):
                native.reconcile(state, hashes, dict.fromkeys(native.ARMS, "0" * 64), {})

    def response(self):
        request = {
            "action": "train",
            "train": generate(rows=100),
            "features": [[0.5] * 6],
            "seed": 17,
        }
        response = {
            "schema_version": 1,
            "action": "train",
            "seed": 17,
            "input_digest": digest(canonical(request)),
            "model": encode64(b"fixture"),
            "model_digest": digest(b"fixture"),
            "python_scores": [0.6],
            "onnx_scores": [0.6],
            "versions": {
                name: importlib.metadata.version(name)
                for name in ("numpy", "scikit-learn", "skl2onnx", "onnx", "onnxruntime")
            },
            "scan": {
                "format": "onnx",
                "inspected_nodes": 2,
                "unsupported": 0,
                "skipped": 0,
                "errors": 0,
                "policy_version": "linear-onnx-v2",
                "onnx_version": importlib.metadata.version("onnx"),
            },
        }
        return request, response, {"parity_tolerance": 1e-5, "model_limit_bytes": 100}

    def test_response_binding_model_and_parity_fail_closed(self):
        request, response, profile = self.response()
        self.assertEqual(experiment.training_response(request, response, profile)[0], b"fixture")
        for name, value in (
            ("action", "research-robust-train"),
            ("schema_version", True),
            ("input_digest", "0" * 64),
            ("seed", 18),
            ("versions", {}),
            ("model_digest", "0" * 64),
            ("onnx_scores", [0.4]),
            ("scan", {}),
            ("python_scores", [float("nan")]),
        ):
            with self.subTest(name=name), self.assertRaises(Rejected):
                experiment.training_response(request, {**response, name: value}, profile)

    def test_optimization_receipt_cannot_hide_nonconvergence_or_change_policy(self):
        rules = experiment.protocol()["training"]
        receipt = {
            "schema_version": 1,
            "algorithm": rules["algorithm"],
            "policy_digest": digest(canonical(rules)),
            "training_rows": 100,
            "scipy_version": importlib.metadata.version("scipy"),
            "status": "numerically-converged",
            "iterations": 20,
            "initial_objective": 0.5,
            "final_objective": 0.4,
            "projected_gradient_inf": 1e-7,
        }
        experiment.check_optimization(receipt, 100)
        for name, value in (
            ("policy_digest", "0" * 64),
            ("iterations", True),
            ("iterations", 501),
            ("training_rows", 101),
            ("final_objective", 0.6),
            ("final_objective", float("nan")),
            ("projected_gradient_inf", 1e-4),
            ("scipy_version", "unknown"),
        ):
            with self.subTest(name=name), self.assertRaises((Rejected, ValueError)):
                experiment.check_optimization({**receipt, name: value}, 100)

    def test_new_probes_are_disjoint_and_duplicate_geometry_rejected(self):
        original = generate(rows=100)
        self.assertEqual(set(experiment.probes(original)), set(experiment.PROBES))
        with (
            patch.object(experiment, "generate", return_value=copy.deepcopy(original)),
            self.assertRaisesRegex(Rejected, "probe_overlap"),
        ):
            experiment.probes(original)

    def summaries(self):
        return {
            name: {
                "quality": {"quality_component": "pass", "auprc": 0.9},
                "evasion": {"status": "pass"},
            }
            for name in experiment.PROBES
        }

    def test_each_probe_required_and_baseline_evasion_failure_preserved(self):
        baseline, candidate = self.summaries(), self.summaries()
        baseline["known-73041"]["evasion"]["status"] = "fail"
        self.assertEqual(experiment.decide(baseline, candidate)["status"], "pass")
        for name in experiment.PROBES:
            invalid = copy.deepcopy(candidate)
            invalid[name]["evasion"]["status"] = "fail"
            self.assertEqual(experiment.decide(baseline, invalid)["status"], "fail")
        with self.assertRaises(Rejected):
            experiment.decide(baseline, {})

    def test_utility_cannot_be_traded_for_robustness_or_insufficient_evidence(self):
        baseline, candidate = self.summaries(), self.summaries()
        candidate["new-73043"]["quality"]["auprc"] = 0.86
        self.assertEqual(experiment.decide(baseline, candidate)["status"], "fail")
        for status in ("fail", "inconclusive"):
            baseline = self.summaries()
            baseline["new-73047"]["quality"]["quality_component"] = status
            result = experiment.decide(baseline, self.summaries())
            self.assertEqual(result["status"], status)
            self.assertFalse(result["release_ready"])


if __name__ == "__main__":
    unittest.main()
