import contextlib
import copy
import importlib.metadata
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, bounded_read, canonical, digest, now, read_json, write_json
from mlsecops.datasets import generate
from mlsecops.inventory import command, source_fingerprint
from mlsecops.prediction_protocol import response
from mlsecops.signing import encode64
from scripts import poisoning_evidence, poisoning_native
from scripts.poisoning import matrix, trigger

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "sha256:" + "a" * 64


def worker(image, request):
    scan = {
        "format": "onnx",
        "inspected_nodes": 2,
        "unsupported": 0,
        "skipped": 0,
        "errors": 0,
        "policy_version": "linear-onnx-v2",
        "onnx_version": importlib.metadata.version("onnx"),
    }
    execution = {
        "image_id": image,
        "elapsed_seconds": 0.1,
        "network": "none",
        "memory_limit_bytes": 4 * 1024**3,
        "cpu_limit": 2,
        "deadline_seconds": 600,
    }
    scores = [0.9] * len(request["features"])
    if request["action"] == "predict":
        return response(request, scores, scan), execution
    model = b"controlled-not-onnx-" + digest(canonical(request)).encode()
    return {
        "schema_version": 1,
        "action": "train",
        "model": encode64(model),
        "model_digest": digest(model),
        "input_digest": digest(canonical(request)),
        "python_scores": scores,
        "onnx_scores": scores,
        "scan": scan,
        "seed": request["seed"],
        "versions": {
            name: importlib.metadata.version(name)
            for name in ("numpy", "onnx", "onnxruntime", "scikit-learn", "skl2onnx")
        },
    }, execution


class EvidenceContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "case"
        self.case = matrix()[1]
        self.profile = read_json(ROOT / "policies/local-cpu.json")
        self.train, self.validation = generate(17, 2000), generate(29, 100)
        self.probes = generate(73031, 1500)
        self.triggered = trigger(self.probes)
        self.inputs = {"image": IMAGE, "source": source_fingerprint(ROOT)}
        self.revision = command(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
        self.started = now()
        with patch.object(poisoning_native, "run_worker", side_effect=worker):
            self.record, self.scores = poisoning_native.execute(
                ROOT,
                self.directory,
                self.case,
                self.train,
                self.validation,
                (self.probes, self.triggered),
                self.profile,
                IMAGE,
            )
        self.record["metrics"] = {"status": "pass"}
        write_json(self.directory / "result.json", self.record)
        self.finished = now()

    def check(self):
        return poisoning_evidence.case_materials(
            self.directory,
            self.case,
            self.profile,
            self.train,
            self.validation,
            self.probes,
            self.triggered,
            self.inputs,
            self.revision,
            self.started,
            self.finished,
        )

    def replace(self, name, value):
        write_json(self.directory / f"{name}.json", value)
        self.record["artifacts"][name] = digest(bounded_read(self.directory / f"{name}.json"))
        write_json(self.directory / "result.json", self.record)

    def test_valid_materials_are_read_without_mutation(self):
        before = {path.name: digest(path.read_bytes()) for path in self.directory.iterdir()}
        record, scores = self.check()
        self.assertEqual(record, self.record)
        self.assertEqual(scores, self.scores)
        self.assertEqual(
            before, {path.name: digest(path.read_bytes()) for path in self.directory.iterdir()}
        )

    def test_artifact_tamper_missing_and_unsafe_path(self):
        path = self.directory / "model.onnx"
        original = path.read_bytes()
        path.write_bytes(original + b"tamper")
        with self.assertRaises(Rejected):
            self.check()
        path.unlink()
        with self.assertRaises(Rejected):
            self.check()

    def test_malformed_record_and_run_identity(self):
        for value in (None, [], {"id": "other"}):
            write_json(self.directory / "result.json", value)
            with self.assertRaises(Rejected):
                self.check()
        write_json(self.directory / "result.json", self.record)
        metadata = read_json(self.directory / "metadata.json")
        metadata["run_id"] = "invalid"
        self.record["run_id"] = "invalid"
        self.replace("metadata", metadata)
        with self.assertRaisesRegex(Rejected, "run_identity"):
            self.check()

    def test_model_size_limit(self):
        self.profile["model_limit_bytes"] = 1
        with self.assertRaisesRegex(Rejected, "model_limit"):
            self.check()

    def test_rehashed_scores_still_fail_response_binding(self):
        altered = self.scores.copy()
        altered[0] = 0.1
        self.replace("security-scores", altered)
        with self.assertRaisesRegex(Rejected, "prediction"):
            self.check()

    def test_rehashed_metadata_cannot_change_training_authority(self):
        original = read_json(self.directory / "metadata.json")
        for field, value in (
            ("input_digest", "0" * 64),
            ("source_revision", "f" * 40),
            ("source_fingerprint", "0" * 64),
            ("image_id", "sha256:" + "0" * 64),
            ("policy_digest", "0" * 64),
            ("status", "approved"),
            ("validation_probability_digest", "0" * 64),
            ("created_at", "2000-01-01T00:00:00+00:00"),
            ("validation_parity_max_error", True),
            ("versions", {}),
        ):
            with self.subTest(field=field):
                altered = copy.deepcopy(original)
                altered[field] = value
                self.replace("metadata", altered)
                with self.assertRaises(Rejected):
                    self.check()
        self.replace("metadata", original)

    def test_rehashed_mutation_receipt_cannot_change_attacker_budget(self):
        receipt = read_json(self.directory / "mutation.json")
        receipt["changed_rows"] = 0
        self.replace("mutation", receipt)
        with self.assertRaisesRegex(Rejected, "mutation"):
            self.check()

    def test_rehashed_prediction_cannot_change_request_or_boundary(self):
        original = read_json(self.directory / "prediction.json")
        for section, field, value in (
            ("protocol", "request_digest", "0" * 64),
            ("protocol", "batch_id", "../outside"),
            ("protocol", "rows", False),
            ("execution", "network", "host"),
            ("execution", "cpu_limit", True),
            ("execution", "elapsed_seconds", -1),
            ("scan", "skipped", 1),
        ):
            with self.subTest(section=section, field=field):
                altered = copy.deepcopy(original)
                altered[section][field] = value
                self.replace("prediction", altered)
                with self.assertRaises(Rejected):
                    self.check()
        self.replace("prediction", original)


class CampaignContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.state = Path(cls.temporary.name)
        with (
            patch.object(poisoning_native, "run_worker", side_effect=worker),
            patch.object(poisoning_native, "resolve_image", return_value=IMAGE),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            cls.report = poisoning_native.qualify(ROOT, cls.state, IMAGE)
        cls.campaign = cls.state / "poisoning" / cls.report["campaign_id"]

    def check(self, report=None):
        return poisoning_evidence.reconcile(ROOT, self.state, report or self.report, IMAGE)

    def test_complete_report_recomputed_from_primary_materials(self):
        outcome = self.check()
        self.assertEqual(outcome["status"], "pass")
        self.assertEqual(outcome["evidence_integrity"], "pass")
        self.assertEqual(outcome["verified_cases"], 35)
        self.assertEqual(outcome["release_ready"], False)
        self.assertEqual(outcome["full_M08"], "inconclusive")

    def test_stale_incomplete_or_foreign_header_rejected(self):
        for field, value in (
            ("campaign_id", "../outside"),
            ("source_revision", "0" * 40),
            ("status", "pass-for-release"),
            ("schema_version", True),
            ("training_runs", 34),
            ("release_ready", True),
            ("execution_status", "partial"),
            ("finished_at", "2999-01-01T00:00:00+00:00"),
            ("source_dirty", 1),
            ("cases", self.report["cases"][:-1]),
            ("input_digests", {}),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.report)
                changed[field] = value
                with self.assertRaises(Rejected):
                    self.check(changed)

    def test_rewritten_result_and_summary_cannot_forge_metrics(self):
        changed = copy.deepcopy(self.report)
        changed["cases"][0]["metrics"]["asr_delta"] = 0.5
        result_path = self.campaign / changed["cases"][0]["id"] / "result.json"
        report_path = self.campaign / "report.json"
        original_result, original_report = result_path.read_bytes(), report_path.read_bytes()
        try:
            write_json(result_path, changed["cases"][0])
            write_json(report_path, changed)
            with self.assertRaisesRegex(Rejected, "metrics"):
                self.check(changed)
        finally:
            result_path.write_bytes(original_result)
            report_path.write_bytes(original_report)

    def test_changed_source_snapshot_rejected(self):
        path = self.campaign / "train.json"
        original = path.read_bytes()
        try:
            rows = read_json(path)
            rows[0]["label"] = 1 - rows[0]["label"]
            write_json(path, rows)
            with self.assertRaisesRegex(Rejected, "material"):
                self.check()
        finally:
            path.write_bytes(original)


class OutputContracts(unittest.TestCase):
    def test_linked_state_is_rejected_before_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            report = state / "evidence/poisoning.json"
            output = state / "evidence/reconciliation.json"
            write_json(report, {"campaign_id": "a" * 32})
            write_json(output, {"preserve": True})
            original = output.read_bytes()
            actual_is_symlink = Path.is_symlink
            with (
                patch(
                    "sys.argv",
                    [
                        "poisoning-evidence",
                        "--state",
                        str(state),
                        "--report",
                        str(report),
                        "--output",
                        str(output),
                    ],
                ),
                patch.object(
                    Path, "is_symlink", lambda path: path == state or actual_is_symlink(path)
                ),
                patch.object(poisoning_evidence, "resolve_image", return_value=IMAGE),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(poisoning_evidence.main(), 1)
            self.assertEqual(output.read_bytes(), original)

    def test_cli_records_integrity_error_without_stale_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            report = state / "evidence/poisoning.json"
            output = state / "evidence/reconciliation.json"
            write_json(report, {})
            write_json(output, {"status": "pass"})
            with (
                patch(
                    "sys.argv",
                    [
                        "poisoning-evidence",
                        "--state",
                        str(state),
                        "--report",
                        str(report),
                        "--output",
                        str(output),
                    ],
                ),
                patch.object(poisoning_evidence, "resolve_image", return_value=IMAGE),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(poisoning_evidence.main(), 1)
            self.assertEqual(read_json(output)["evidence_integrity"], "fail")
            self.assertEqual(read_json(report), {})

    def test_cli_preserves_verified_robustness_failure_and_inconclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            report = state / "evidence/poisoning.json"
            output = state / "evidence/reconciliation.json"
            write_json(report, {})
            for status, code in (("pass", 0), ("fail", 1), ("inconclusive", 2)):
                result = {"status": status, "evidence_integrity": "pass", "release_ready": False}
                with (
                    self.subTest(status=status),
                    patch(
                        "sys.argv",
                        [
                            "poisoning-evidence",
                            "--state",
                            str(state),
                            "--report",
                            str(report),
                            "--output",
                            str(output),
                        ],
                    ),
                    patch.object(poisoning_evidence, "resolve_image", return_value=IMAGE),
                    patch.object(poisoning_evidence, "reconcile", return_value=result),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(poisoning_evidence.main(), code)
                    self.assertEqual(read_json(output), result)

    def test_cli_cannot_overwrite_source_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            report = state / "evidence/poisoning.json"
            write_json(report, {"preserve": True})
            original = report.read_bytes()
            with (
                patch(
                    "sys.argv",
                    [
                        "poisoning-evidence",
                        "--state",
                        str(state),
                        "--report",
                        str(report),
                        "--output",
                        str(report),
                    ],
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(poisoning_evidence.main(), 1)
            self.assertEqual(report.read_bytes(), original)

    def test_cli_cannot_write_into_campaign_or_outside_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            for output in (state / "poisoning/report.json", state / "outside.json"):
                with (
                    self.subTest(output=output),
                    patch(
                        "sys.argv",
                        ["poisoning-evidence", "--state", str(state), "--output", str(output)],
                    ),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(poisoning_evidence.main(), 1)
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
