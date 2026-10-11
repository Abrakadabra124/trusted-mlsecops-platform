import contextlib
import io
import json
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, write_json
from scripts import image_audit_publication


class PublicationContracts(unittest.TestCase):
    def test_module_entrypoint_reads_default_report_without_changing_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = {"status": "fail", "release_ready": False}
            write_json(root / ".runtime/evidence/image-audit.json", report)
            output = io.StringIO()
            script = Path(image_audit_publication.__file__)
            with (
                patch.object(
                    Path, "resolve", return_value=root / "scripts/image_audit_publication.py"
                ),
                contextlib.redirect_stdout(output),
                self.assertRaises(SystemExit) as stopped,
            ):
                runpy.run_path(str(script), run_name="__main__")
            self.assertEqual(stopped.exception.code, 0)
            self.assertEqual(json.loads(output.getvalue()), report)

    def test_large_report_survives_bounded_lines_without_dropping_findings(self):
        report = {
            "status": "fail",
            "release_ready": False,
            "components": [
                {
                    "name": "worker",
                    "findings": [
                        {
                            "id": f"CVE-2026-{index}",
                            "severity": "High",
                            "package": "libexample",
                            "installed": "1.0",
                            "fix": {"state": "not-fixed", "versions": []},
                        }
                        for index in range(4000)
                    ],
                }
            ],
        }
        self.assertGreater(len(canonical(report)), 65536)
        output = image_audit_publication.render(report)
        self.assertEqual(json.loads(output), report)
        self.assertLessEqual(max(len(line.encode()) for line in output.splitlines()), 16384)
        self.assertEqual(len(json.loads(output)["components"][0]["findings"]), 4000)

    def test_all_outcomes_and_unknown_fields_preserved_without_reclassification(self):
        for status in ("pass", "fail", "inconclusive"):
            report = {"status": status, "release_ready": False, "future_field": {"value": None}}
            self.assertEqual(json.loads(image_audit_publication.render(report)), report)

    def test_control_characters_and_unicode_are_escaped(self):
        report = {"status": "fail", "value": "\x1b[31m\r\n::warning::пример"}
        output = image_audit_publication.render(report)
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\r", output)
        self.assertTrue(output.isascii())
        self.assertEqual(json.loads(output), report)

    def test_oversized_and_nonfinite_fields_rejected_not_truncated(self):
        for report in (
            {"value": "x" * 16385},
            {"value": float("nan")},
            {"value": ["x" * 4096] * 5000},
        ):
            with self.subTest(kind=type(report["value"]).__name__), self.assertRaises(Rejected):
                image_audit_publication.render(report)

    def test_publication_does_not_change_report_or_scanner_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image-audit.json"
            report = {"status": "fail", "release_ready": False, "matches": 1000}
            write_json(path, report)
            before = path.read_bytes()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = image_audit_publication.main(path)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue()), report)
            self.assertEqual(path.read_bytes(), before)

    def test_missing_or_invalid_evidence_never_publishes_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "missing.json"
            for content in (None, b"invalid-private-data", canonical({"value": "x" * 16385})):
                if content is not None:
                    path.write_bytes(content)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(image_audit_publication.main(path), 2)
                report = json.loads(output.getvalue())
                self.assertEqual(report["status"], "inconclusive")
                self.assertFalse(report["release_ready"])
                self.assertNotIn("private-data", output.getvalue())


if __name__ == "__main__":
    unittest.main()
