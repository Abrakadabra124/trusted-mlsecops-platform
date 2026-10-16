import io
import json
import runpy
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from coverage import Coverage, CoverageData

from mlsecops.contracts import Rejected
from scripts import audit_branch_coverage


class AuditBranchCoverageContracts(unittest.TestCase):
    def test_real_multibranch_modules_are_measured_independently_in_both_orders(self):
        source = "def choose(value):\n    result = 0\n"
        for boundary in range(10):
            source += f"    if value > {boundary}:\n        result += 1\n"
        source += "    return result\n"
        for limits, status in (
            ((10, 10), "pass"),
            ((9, 9), "pass"),
            ((8, 10), "fail"),
            ((10, 8), "fail"),
        ):
            with self.subTest(limits=limits), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                (root / "mlsecops").mkdir()
                namespaces = []
                for name in audit_branch_coverage.FILES:
                    path = root / name
                    path.write_text(source, encoding="utf-8")
                    namespace = {"__file__": str(path)}
                    exec(compile(source, str(path), "exec"), namespace)
                    namespaces.append(namespace)
                data_file = root / "measurement"
                measurement = Coverage(data_file=str(data_file), branch=True, config_file=False)
                with measurement.collect():
                    for namespace, limit in zip(namespaces, limits, strict=True):
                        self.assertEqual(namespace["choose"](0), 0)
                        self.assertEqual(namespace["choose"](limit), limit)
                measurement.save()
                with patch.object(audit_branch_coverage, "ROOT", root):
                    report = audit_branch_coverage.check(data_file)
                self.assertEqual(report["status"], status)
                self.assertEqual(
                    [
                        (module["total_branches"], module["covered_branches"])
                        for module in report["modules"]
                    ],
                    [(20, 10 + limit) for limit in limits],
                )

    def measurement(self, first=(20, 19), second=(20, 19)):
        measurement = Mock()
        measurement.get_data.return_value.has_arcs.return_value = True
        measurement.get_data.return_value.measured_files.return_value = [
            str(audit_branch_coverage.ROOT / name) for name in audit_branch_coverage.FILES
        ]
        measurement.branch_stats.side_effect = [{10: first}, {20: second}]
        return measurement

    def test_each_module_must_meet_exact_threshold_without_rounding_or_averaging(self):
        for first, second, status in (
            ((20, 19), (20, 19), "pass"),
            ((10000, 9499), (100000, 100000), "fail"),
            ((100000, 100000), (20, 18), "fail"),
        ):
            with self.subTest(first=first, second=second):
                measurement = self.measurement(first, second)
                with patch.object(audit_branch_coverage, "Coverage", return_value=measurement):
                    report = audit_branch_coverage.check(".coverage-fixture")
                self.assertEqual(report["status"], status)
                self.assertFalse(report["release_ready"])
                self.assertEqual(len(report["modules"]), 2)
                self.assertEqual(report["minimum_branch_percent"], 95)
                self.assertEqual(report["modules"][0]["total_branches"], first[0])
                self.assertEqual(report["modules"][0]["covered_branches"], first[1])

    def test_missing_branch_mode_or_required_module_cannot_pass(self):
        for missing in ("arcs", "all", "one", "same-basename-outside-repository"):
            measurement = self.measurement()
            data = measurement.get_data.return_value
            if missing == "arcs":
                data.has_arcs.return_value = False
            elif missing == "all":
                data.measured_files.return_value = []
            elif missing == "one":
                data.measured_files.return_value = data.measured_files.return_value[:1]
            else:
                data.measured_files.return_value = [
                    str(Path.cwd() / Path(name).name) for name in audit_branch_coverage.FILES
                ]
            with (
                self.subTest(missing=missing),
                patch.object(audit_branch_coverage, "Coverage", return_value=measurement),
                self.assertRaises(Rejected),
            ):
                audit_branch_coverage.check(".coverage-fixture")

    def test_empty_or_impossible_branch_statistics_are_rejected(self):
        for stats in ({}, {1: (0, 0)}, {1: (2, -1)}, {1: (2, 3)}, {1: (True, 1)}, {1: (2, False)}):
            measurement = self.measurement()
            measurement.branch_stats.side_effect = None
            measurement.branch_stats.return_value = stats
            with (
                self.subTest(stats=stats),
                patch.object(audit_branch_coverage, "Coverage", return_value=measurement),
                self.assertRaises(Rejected),
            ):
                audit_branch_coverage.check(".coverage-fixture")

    def test_report_exclusions_and_external_configuration_cannot_hide_branches(self):
        measurement = self.measurement()
        with patch.object(audit_branch_coverage, "Coverage", return_value=measurement) as factory:
            audit_branch_coverage.check(".coverage-fixture")
        factory.assert_called_once_with(data_file=".coverage-fixture", config_file=False)
        self.assertEqual(
            [call.args for call in measurement.clear_exclude.call_args_list],
            [("exclude",), ("partial",)],
        )
        measurement.load.assert_called_once_with()

    def test_cli_denies_bad_measurement_without_exporting_paths_or_exception_text(self):
        for error in (Rejected("PRIVATE_CANARY"), OSError("PRIVATE_CANARY")):
            output = io.StringIO()
            with (
                patch.object(audit_branch_coverage, "check", side_effect=error),
                redirect_stdout(output),
            ):
                result = audit_branch_coverage.main(["PRIVATE_CANARY"])
            self.assertEqual(result, 2)
            self.assertNotIn("PRIVATE_CANARY", output.getvalue())
            self.assertEqual(json.loads(output.getvalue())["status"], "inconclusive")

    def test_cli_preserves_failed_status_and_returns_nonzero(self):
        for status, expected in (("pass", 0), ("fail", 2)):
            output = io.StringIO()
            with (
                patch.object(audit_branch_coverage, "check", return_value={"status": status}),
                redirect_stdout(output),
            ):
                self.assertEqual(audit_branch_coverage.main([".coverage-fixture"]), expected)
            self.assertEqual(json.loads(output.getvalue())["status"], status)

    def test_real_missing_empty_and_statement_only_databases_never_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "measurement"
            with self.assertRaises(Rejected):
                audit_branch_coverage.check(path)
            self.assertFalse(path.exists())
            data = CoverageData(basename=str(path))
            data.add_lines({str(audit_branch_coverage.ROOT / audit_branch_coverage.FILES[0]): [1]})
            data.write()
            with self.assertRaises(Rejected):
                audit_branch_coverage.check(path)
            data.erase()
            data = CoverageData(basename=str(path))
            data.add_arcs({})
            data.touch_files([str(audit_branch_coverage.ROOT / audit_branch_coverage.FILES[0])])
            data.write()
            with self.assertRaises(Rejected):
                audit_branch_coverage.check(path)

    def test_registered_modules_without_executed_arcs_are_not_fictitious_full_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "measurement"
            data = CoverageData(basename=str(path))
            data.add_arcs({})
            data.touch_files(
                [str(audit_branch_coverage.ROOT / name) for name in audit_branch_coverage.FILES]
            )
            data.write()
            report = audit_branch_coverage.check(path)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(all(module["covered_branches"] == 0 for module in report["modules"]))
            self.assertTrue(all(module["total_branches"] > 0 for module in report["modules"]))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(audit_branch_coverage.main([str(path)]), 2)
            self.assertEqual(json.loads(output.getvalue())["status"], "fail")

    def test_actual_cli_entrypoint_fails_closed_for_missing_measurement(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = str(Path(temporary) / "measurement")
            output = io.StringIO()
            with (
                patch.object(sys, "argv", ["audit_branch_coverage", path]),
                redirect_stdout(output),
                self.assertRaises(SystemExit) as stopped,
            ):
                runpy.run_path(audit_branch_coverage.__file__, run_name="__main__")
            self.assertEqual(stopped.exception.code, 2)
            self.assertEqual(json.loads(output.getvalue())["status"], "inconclusive")
            self.assertFalse(Path(path).exists())


if __name__ == "__main__":
    unittest.main()
