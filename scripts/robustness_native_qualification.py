import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, atomic_write, bounded_read, digest, read_json, write_json
from mlsecops.datasets import generate
from scripts import robustness, robustness_native


class ResearchEvidenceTests(unittest.TestCase):
    def fixture(self, directory):
        for name in robustness_native.MATERIAL_FILES:
            write_json(directory / name, {})
        rows = generate(seed=73041, rows=3000)
        clean = [0.5] * len(rows)
        selected = robustness.select(
            [row["features"] for row in rows], clean, [[0.4] * len(rows)] * 4
        )
        write_json(directory / "probes.json", rows)
        write_json(directory / "clean.json", clean)
        write_json(directory / "attack.json", selected)
        write_json(directory / "metrics.json", robustness.compare(rows, clean, selected["scores"]))
        atomic_write(directory / "model.onnx", b"controlled-not-executable-model")
        hashes = {
            name: digest(bounded_read(directory / name))
            for name in robustness_native.MATERIAL_FILES
        }
        return hashes, hashes["model.onnx"]

    def test_reloads_complete_materials_and_preserves_statistical_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            result = robustness_native.reconcile(directory, *self.fixture(directory))
            self.assertEqual(result["status"], "fail")

    def test_missing_tampered_or_wrong_model_blocks_reconciliation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            hashes, model = self.fixture(directory)
            with self.assertRaisesRegex(Rejected, "incomplete_material_set"):
                robustness_native.reconcile(directory, {}, model)
            with self.assertRaisesRegex(Rejected, "model_binding"):
                robustness_native.reconcile(directory, hashes, "0" * 64)
            write_json(directory / "clean.json", [0.8] * 3000)
            with self.assertRaisesRegex(Rejected, "persisted_material_changed"):
                robustness_native.reconcile(directory, hashes, model)

    def test_rewritten_summary_and_selected_rows_rejected_even_with_updated_hash(self):
        for name, field, value, reason in (
            ("attack.json", "scores", [0.3] * 3000, "selection_binding"),
            ("metrics.json", "status", "pass", "metrics_binding"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                hashes, model = self.fixture(directory)
                document = read_json(directory / name)
                document[field] = value
                write_json(directory / name, document)
                hashes[name] = digest(bounded_read(directory / name))
                with self.assertRaisesRegex(Rejected, reason):
                    robustness_native.reconcile(directory, hashes, model)

    def test_owned_workspace_identity_is_required_without_creating_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            for marker in (
                {},
                {"product": "foreign", "schema_version": 1, "workspace_id": "1" * 32},
                {"product": "trusted-mlsecops", "schema_version": True, "workspace_id": "1" * 32},
            ):
                write_json(state / "workspace.json", marker)
                with self.assertRaisesRegex(Rejected, "unowned_state"):
                    robustness_native.owned(state)
            write_json(
                state / "workspace.json",
                {"product": "trusted-mlsecops", "schema_version": 1, "workspace_id": "1" * 32},
            )
            robustness_native.owned(state)
            self.assertEqual({path.name for path in state.iterdir()}, {"workspace.json"})

    def test_cli_failure_does_not_retain_old_success_or_dump_sensitive_exception(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            write_json(
                state / "workspace.json",
                {"product": "trusted-mlsecops", "schema_version": 1, "workspace_id": "1" * 32},
            )
            output = state / "evidence/robustness.json"
            write_json(output, {"status": "pass"})
            stdout = io.StringIO()
            with (
                patch("sys.argv", ["robustness", "--state", str(state)]),
                patch.object(
                    robustness_native, "qualify", side_effect=OSError("SECRET fake-private-value")
                ),
                contextlib.redirect_stdout(stdout),
            ):
                self.assertEqual(robustness_native.main(), 1)
            self.assertEqual(read_json(output)["status"], "fail")
            self.assertNotIn("SECRET", stdout.getvalue())
            self.assertNotIn("SECRET", output.read_text())

    def test_cli_statistical_fail_is_not_suppressed(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            write_json(
                state / "workspace.json",
                {"product": "trusted-mlsecops", "schema_version": 1, "workspace_id": "1" * 32},
            )
            for status, code in (("pass", 0), ("fail", 1), ("inconclusive", 2)):
                with (
                    self.subTest(status=status),
                    patch("sys.argv", ["robustness", "--state", str(state)]),
                    patch.object(
                        robustness_native,
                        "qualify",
                        return_value={"status": status, "release_ready": False},
                    ),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(robustness_native.main(), code)
                    self.assertEqual(
                        read_json(state / "evidence/robustness.json")["status"], status
                    )


if __name__ == "__main__":
    unittest.main()
