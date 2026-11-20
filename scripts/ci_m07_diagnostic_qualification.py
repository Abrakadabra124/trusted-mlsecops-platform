"""Public M07 projection contracts; synthetic canaries, no infrastructure."""

import copy
import importlib
import importlib.util
import io
import runpy
import sys
import unittest
from contextlib import chdir, redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mlsecops import holdout_budget, holdout_diagnostics
from mlsecops.contracts import canonical, decode, digest

CANARY = "PRIVATE-password-model-workspace-trace-DO-NOT-EXPORT"
REASONS = (
    "M07_component_cases_invalid",
    "M07_component_shape_invalid",
    "M07_controlled_contracts_failed",
    "M07_controlled_contracts_incomplete",
    "M07_controlled_contracts_scope_invalid",
    "M07_budget_binding_invalid",
    "M07_budget_shape_invalid",
    "M07_material_binding_invalid",
    "M07_stale_or_future_evidence",
    "M07_quality_state_invalid",
    "M07_material_shape_invalid",
    "M07_integrity_gate_not_accepted",
    "M07_integrity_candidate_mismatch",
    "M07_requires_fresh_owned_storage",
    "M07_source_changed_during_campaign",
    "M07_cleanup_identity_changed",
    "storage_connection_rejected",
    "holdout_qualification_failed:four-process-unique-atomic-claims",
    "holdout_qualification_failed:concurrent-over-budget-denied",
)


def report(**changes):
    return dict(gate="M07", status="fail", exit_code=1, residual_risks=[REASONS[0]], **changes)


def diagnostic():
    return dict(
        schema_version=1,
        diagnostic_only=True,
        complete=True,
        attempts=32,
        claimed_slots=list(range(2, 33)),
        rejection_codes={"holdout_budget_exhausted": 1},
        invalid_receipts=0,
    )


def connection():
    return dict(
        stage="connect",
        driver="operational",
        sqlstate="53300",
        message_hint="capacity-reported",
        elapsed_ms=60000,
        slot=32,
        prior_conflicts=31,
    )


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("scripts.ci_m07_diagnostic"),
            "M07 public projection helper is missing",
        )
        self.module = importlib.import_module("scripts.ci_m07_diagnostic")

    def project(self, value):
        before = copy.deepcopy(value)
        result = self.module.project(value)
        self.assertEqual(value, before)
        encoded = canonical(result)
        self.assertNotIn(CANARY.encode(), encoded)
        self.assertNotIn(digest(CANARY.encode()).encode(), encoded)
        self.assertIs(result["diagnostic_only"], True)
        self.assertIs(result["release_ready"], False)
        return result

    def test_exact_static_reasons_survive_without_private_report_fields(self):
        for reason in REASONS:
            value = report(
                inputs={CANARY: CANARY},
                model=CANARY,
                workspace=CANARY,
                pins=[digest(CANARY.encode())],
                rawtrace=CANARY,
            )
            value["residual_risks"] = [reason]
            self.assertEqual(
                self.project(value),
                dict(
                    gate="M07",
                    status="fail",
                    exit_code=1,
                    reason=reason,
                    diagnostic_only=True,
                    release_ready=False,
                ),
            )

    def test_unknown_reasons_never_escape_as_text_or_hash(self):
        for risk in (
            CANARY,
            digest(CANARY.encode()),
            "M07_" + CANARY,
            REASONS[-1] + ":" + CANARY,
            "x" * 200000,
            None,
            False,
            1,
            [],
            {},
        ):
            value = report()
            value["residual_risks"] = [risk]
            self.assertEqual(self.project(value)["reason"], "unclassified")
        for risks in (None, CANARY, [], [REASONS[0], CANARY], [CANARY] * 10000):
            value = report()
            value["residual_risks"] = risks
            self.assertEqual(self.project(value)["reason"], "unclassified")

    def test_malformed_report_header_is_fixed_unavailable(self):
        for value in (
            None,
            [],
            CANARY,
            {},
            report() | {"gate": "M03"},
            report() | {"status": CANARY},
            report() | {"status": []},
            report() | {"exit_code": True},
            report() | {"exit_code": "1"},
            report() | {"exit_code": 10**100},
            report() | {"exit_code": -1},
            report() | {"exit_code": 0},
        ):
            with self.subTest(value_type=type(value).__name__):
                self.assertEqual(self.project(value), self.module.project(None))

    def test_normal_31_original_receipts_and_one_budget_refusal(self):
        holdout = "a" * 64
        receipts = [
            dict(
                holdout_digest=holdout,
                slot=slot,
                reservation=digest(holdout_budget.reservation(holdout, slot)),
                policy_digest=digest(canonical(holdout_budget.policy())),
            )
            for slot in range(2, 33)
        ]
        receipts.append({"rejected": "holdout_budget_exhausted"})
        observed = holdout_diagnostics.check_claims(receipts, holdout)
        value = report(diagnostics={"holdout_concurrency": observed})
        value.update(status="pass", exit_code=0, residual_risks=[])
        output = self.project(value)
        self.assertEqual(output["holdout_concurrency"], diagnostic())
        observed["claimed_slots"].clear()
        self.assertEqual(len(output["holdout_concurrency"]["claimed_slots"]), 31)

    def test_valid_boundaries_and_inconclusive_are_only_observations(self):
        for attempts in (0, 33):
            observed = diagnostic() | dict(
                complete=False,
                attempts=attempts,
                claimed_slots=[],
                rejection_codes={"unclassified_rejection": 32},
                invalid_receipts=32,
            )
            value = report(diagnostics={"holdout_concurrency": observed})
            value.update(status="inconclusive", exit_code=2)
            self.assertEqual(self.project(value)["holdout_concurrency"], observed)
        observed = diagnostic() | {"claimed_slots": list(range(1, 33))}
        observed["rejection_codes"] = {code: 0 for code in holdout_diagnostics.REJECTION_CODES}
        self.assertEqual(
            self.project(report(diagnostics={"holdout_concurrency": observed}))[
                "holdout_concurrency"
            ],
            observed,
        )

    def invalid(self, observed):
        result = self.project(report(diagnostics={"holdout_concurrency": observed}))
        self.assertIs(result["diagnostic_invalid"], True)
        self.assertNotIn("holdout_concurrency", result)

    def test_closed_diagnostic_schema_rejects_extra_missing_and_wrong_types(self):
        for observed in (None, [], CANARY, diagnostic() | {CANARY: CANARY}):
            self.invalid(observed)
        for field in diagnostic():
            observed = diagnostic()
            del observed[field]
            self.invalid(observed)
        for field, values in (
            ("schema_version", (True, 2, "1")),
            ("diagnostic_only", (False, 1, CANARY)),
            ("complete", (1, None, CANARY)),
            ("attempts", (-1, 34, True, "32", 10**100)),
            ("claimed_slots", (None, (), [1] * 33, [0], [33], [True], [CANARY])),
            (
                "rejection_codes",
                (
                    None,
                    [],
                    {CANARY: 1},
                    {"unclassified": 1},
                    {"unclassified_rejection": -1},
                    {"unclassified_rejection": 33},
                    {"unclassified_rejection": True},
                    {"unclassified_rejection": 10**100},
                ),
            ),
            ("invalid_receipts", (-1, 33, True, CANARY)),
        ):
            for value in values:
                with self.subTest(field=field, value_type=type(value).__name__):
                    self.invalid(diagnostic() | {field: value})

    def test_diagnostics_container_is_also_closed(self):
        for value in (None, [], {}, CANARY, {"holdout_concurrency": diagnostic(), CANARY: CANARY}):
            result = self.project(report(diagnostics=value))
            self.assertIs(result["diagnostic_invalid"], True)
            self.assertNotIn("holdout_concurrency", result)

    def test_connection_diagnostics_use_existing_closed_contract(self):
        for failures in ([], [connection()], [connection()] * 32):
            observed = diagnostic() | {"connection_failures": failures}
            result = self.project(report(diagnostics={"holdout_concurrency": observed}))
            self.assertEqual(result["holdout_concurrency"], observed)
        for failures in (None, {}, [connection()] * 33, [connection() | {CANARY: CANARY}]):
            self.invalid(diagnostic() | {"connection_failures": failures})
        for field, bad in (
            ("stage", CANARY),
            ("driver", CANARY),
            ("sqlstate", CANARY),
            ("message_hint", CANARY),
            ("elapsed_ms", 60001),
            ("slot", 33),
            ("prior_conflicts", 0),
        ):
            self.invalid(diagnostic() | {"connection_failures": [connection() | {field: bad}]})

    def cli(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = self.module.main(arguments)
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn(CANARY, stdout.getvalue())
        self.assertNotIn(digest(CANARY.encode()), stdout.getvalue())
        return decode(stdout.getvalue().encode())

    def test_cli_returns_zero_for_failed_gate_and_preserves_original_file(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            value = report(private=CANARY)
            raw = canonical(value)
            path.write_bytes(raw)
            output = self.cli([str(path)])
            self.assertEqual(output["status"], "fail")
            self.assertEqual(output["exit_code"], 1)
            self.assertEqual(path.read_bytes(), raw)

    def test_cli_missing_invalid_huge_duplicate_and_read_errors_are_unavailable(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / (CANARY + ".json")
            unavailable = self.module.project(None)
            self.assertEqual(self.cli([str(path)]), unavailable)
            for raw in (
                CANARY.encode(),
                b"x" * (1024 * 1024 + 1),
                b'{"gate":"M07","gate":"M07"}',
                b"[[[[[[[[",
                b'"\xff"',
            ):
                path.write_bytes(raw)
                self.assertEqual(self.cli([str(path)]), unavailable)
            with patch.object(self.module, "bounded_read", side_effect=OSError(CANARY)):
                self.assertEqual(self.cli([str(path)]), unavailable)

    def test_cli_default_and_process_entrypoint_do_not_print_argument_secrets(self):
        with TemporaryDirectory() as folder, chdir(folder):
            path = Path(".runtime/evidence/M07.json")
            path.parent.mkdir(parents=True)
            path.write_bytes(canonical(report(private=CANARY)))
            self.assertEqual(self.cli([])["reason"], "M07_component_cases_invalid")
        with patch.object(sys, "argv", ["ci_m07_diagnostic", CANARY, CANARY]):
            self.assertEqual(self.cli(None), self.module.project(None))

    def test_real_unknown_claim_failure_roundtrip_retains_only_existing_safe_label(self):
        from scripts.holdout_budget_qualification import BudgetDiagnosticContracts

        receipts = BudgetDiagnosticContracts.receipts()
        receipts[-1] = {"rejected": CANARY}
        with self.assertRaises(holdout_diagnostics.ClaimFailure) as failure:
            holdout_diagnostics.check_claims(receipts, "a" * 64)
        value = report(diagnostics={"holdout_concurrency": failure.exception.diagnostics})
        value["residual_risks"] = [str(failure.exception)]
        result = self.project(value)
        self.assertNotIn("diagnostic_invalid", result)
        self.assertEqual(
            result["holdout_concurrency"]["rejection_codes"], {"unclassified_rejection": 1}
        )
        self.assertEqual(
            result["reason"], "holdout_qualification_failed:concurrent-over-budget-denied"
        )
        with TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            path.write_bytes(canonical(value))
            self.assertEqual(self.cli([str(path)]), result)

    def test_executable_entrypoint_emits_only_fixed_unavailable_and_exits_zero(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with TemporaryDirectory() as folder:
            path = Path(folder) / CANARY
            with patch.object(sys, "argv", ["ci_m07_diagnostic", str(path)]):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as stopped:
                        runpy.run_path(self.module.__file__, run_name="__main__")
        self.assertEqual(stopped.exception.code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(decode(stdout.getvalue().encode()), self.module.project(None))

    def test_cli_invalid_private_diagnostic_is_flagged_without_raw_values(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            value = report(diagnostics={"holdout_concurrency": diagnostic() | {CANARY: CANARY}})
            value["residual_risks"] = [CANARY]
            path.write_bytes(canonical(value))
            output = self.cli([str(path)])
            self.assertEqual(output["reason"], "unclassified")
            self.assertIs(output["diagnostic_invalid"], True)
            self.assertNotIn("holdout_concurrency", output)


if __name__ == "__main__":
    unittest.main()
