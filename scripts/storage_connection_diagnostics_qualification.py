"""Offline psycopg/process-result contracts; simulated atomic ledger, never a SQL server."""

import copy
import io
import pickle
import runpy
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import psycopg

from mlsecops import holdout_budget, holdout_budget_qualification, holdout_diagnostics, storage
from mlsecops import storage_connection_diagnostics as diagnostics
from mlsecops.contracts import Rejected, canonical, digest, write_json
from scripts import holdout_budget_qualification as fixtures


class ConnectionDiagnostics(unittest.TestCase):
    def detail(self, error=None, elapsed=5_000_000_000, slot=32):
        error = (
            psycopg.errors.ConnectionTimeout("PRIVATE-DRIVER-DETAIL") if error is None else error
        )
        return {**diagnostics.describe(error, elapsed), "slot": slot, "prior_conflicts": slot - 1}

    def check_failure(self, detail):
        receipts = fixtures.BudgetDiagnosticContracts.receipts()
        receipts[-1] = {"rejected": "storage_connection_rejected", "connection_failure": detail}
        with self.assertRaises(holdout_diagnostics.ClaimFailure) as result:
            holdout_diagnostics.check_claims(receipts, "a" * 64)
        self.assertEqual(
            str(result.exception), "holdout_qualification_failed:concurrent-over-budget-denied"
        )
        return result.exception.diagnostics

    def test_driver_error_is_not_budget_exhaustion_and_retains_only_safe_facts(self):
        for error, expected in (
            (
                psycopg.errors.ConnectionTimeout("connection timeout expired PRIVATE"),
                ("connection-timeout", "unavailable", "timeout-reported"),
            ),
            (
                psycopg.OperationalError("connection refused PRIVATE"),
                ("operational", "unavailable", "refusal-reported"),
            ),
            (
                psycopg.errors.TooManyConnections("too many clients PRIVATE"),
                ("operational", "53300", "capacity-reported"),
            ),
            (
                psycopg.errors.InvalidPassword("authentication failed PRIVATE"),
                ("operational", "28P01", "authentication-reported"),
            ),
            (
                psycopg.OperationalError("SSL error: PRIVATE certificate"),
                ("operational", "unavailable", "tls-reported"),
            ),
            (
                psycopg.OperationalError("server closed the connection PRIVATE"),
                ("operational", "unavailable", "server-close-reported"),
            ),
            (psycopg.InterfaceError("PRIVATE"), ("interface", "unavailable", "unclassified")),
            (psycopg.DatabaseError("PRIVATE"), ("database", "unavailable", "unclassified")),
            (psycopg.Error("PRIVATE"), ("other", "unavailable", "unclassified")),
        ):
            with (
                self.subTest(kind=type(error).__name__),
                patch.object(
                    storage, "connection_parameters", return_value={"user": "private-role"}
                ),
                patch.object(storage.psycopg, "connect", side_effect=error) as connect,
                patch.object(storage.time, "monotonic_ns", side_effect=[0, 5_000_000_000]),
            ):
                with self.assertRaisesRegex(Rejected, "^storage_connection_rejected$") as rejected:
                    storage.connect("private-client")
                value = rejected.exception.diagnostic
                self.assertEqual(
                    (value["driver"], value["sqlstate"], value["message_hint"]), expected
                )
                self.assertEqual(value["elapsed_ms"], 5000)
                self.assertNotIn(b"PRIVATE", canonical(value))
                self.assertNotIn(b"private-role", canonical(value))
                connect.assert_called_once_with(user="private-role")
                self.assertIs(rejected.exception.__cause__, error)
                restored = pickle.loads(pickle.dumps(rejected.exception))
                self.assertEqual(str(restored), "storage_connection_rejected")
                self.assertEqual(restored.diagnostic, value)
                self.assertIsNone(restored.__cause__)

    def test_unknown_sqlstate_message_and_elapsed_are_bounded(self):
        class Unknown(psycopg.Error):
            sqlstate = "private-state"

        value = self.detail(Unknown("PRIVATE" * 100000), elapsed=120_000_000_000)
        self.assertEqual(value["sqlstate"], "unclassified")
        self.assertEqual(value["elapsed_ms"], 60000)
        self.assertEqual(self.detail(elapsed=-1)["elapsed_ms"], 0)
        self.assertTrue(diagnostics.checked(value, 32))
        self.assertLess(len(canonical(value)), 256)
        self.assertNotIn(b"PRIVATE", canonical(value))

    def test_success_connection_parameters_and_client_validation_are_unchanged(self):
        expected = object()
        with (
            patch.object(
                storage, "connection_parameters", return_value={"sslmode": "verify-full"}
            ) as parameters,
            patch.object(storage.psycopg, "connect", return_value=expected) as connect,
        ):
            self.assertIs(storage.connect("client", expected_host="owner-host"), expected)
            parameters.assert_called_once_with("client", expected_host="owner-host")
            connect.assert_called_once_with(sslmode="verify-full")
        with (
            patch.object(
                storage,
                "connection_parameters",
                side_effect=Rejected("storage_client_config_invalid"),
            ),
            patch.object(storage.psycopg, "connect") as connect,
        ):
            with self.assertRaisesRegex(Rejected, "storage_client_config_invalid"):
                storage.connect("client")
            connect.assert_not_called()

    def test_readonly_budget_cli_keeps_constant_connection_rejection(self):
        error = diagnostics.ConnectionRejected(diagnostics.describe(psycopg.Error("PRIVATE"), 0))
        with (
            patch.object(storage, "get", side_effect=error),
            patch.object(sys, "argv", ["budget", "--client", "unused", "--holdout", "a" * 64]),
            redirect_stderr(io.StringIO()) as output,
        ):
            with self.assertRaises(SystemExit) as result:
                runpy.run_path(holdout_budget.__file__, run_name="__main__")
        self.assertEqual(result.exception.code, 1)
        self.assertEqual(
            output.getvalue(), "Holdout budget inspection rejected: storage_connection_rejected\n"
        )

    def test_failed_slot_and_known_conflicts_survive_worker_serialization_without_retry(self):
        error = diagnostics.ConnectionRejected(
            diagnostics.describe(psycopg.errors.ConnectionTimeout("PRIVATE"), 5_000_000_000)
        )
        for slot in (1, 32):
            with patch.object(
                storage, "claim", side_effect=[False] * (slot - 1) + [error]
            ) as claim:
                result = holdout_budget_qualification.attempt(("client", "a" * 64))
            self.assertEqual(claim.call_count, slot)
            self.assertEqual(result["rejected"], "storage_connection_rejected")
            self.assertEqual(result["connection_failure"]["slot"], slot)
            self.assertEqual(result["connection_failure"]["prior_conflicts"], slot - 1)
            observed = self.check_failure(pickle.loads(pickle.dumps(result))["connection_failure"])
            self.assertEqual(observed["claimed_slots"], list(range(2, 33)))
            self.assertEqual(observed["rejection_codes"], {"storage_connection_rejected": 1})
            self.assertEqual(observed["invalid_receipts"], 0)
            self.assertEqual(observed["connection_failures"], [result["connection_failure"]])
            self.assertNotIn(b"PRIVATE", canonical(observed))

    def test_four_concurrent_callers_keep_exact_acceptance_even_when_ledger_is_full(self):
        # The mocked server implements INSERT ... ON CONFLICT with an atomic lock.
        # Real reserve(), claim(), connect(), attempt() and check_claims() execute.
        # This reproduces the symptom, not the native transport's unknown cause.
        for failing in (False, True):
            lock = threading.RLock()
            ledger = {digest(holdout_budget.reservation("a" * 64, 1))}

            class Connection:
                def __enter__(inner):
                    return inner

                def __exit__(inner, *args):
                    lock.release()

                def execute(inner, statement, parameters):
                    self.assertIn("ON CONFLICT DO NOTHING RETURNING sha256", statement.as_string())
                    identifier, content = parameters
                    self.assertEqual(identifier, digest(content))
                    with lock:
                        inner.row = None if identifier in ledger else (identifier,)
                        ledger.add(identifier)
                    return inner

                def fetchone(inner):
                    return inner.row

            def connect():
                lock.acquire()
                if failing and len(ledger) == 32:
                    lock.release()
                    raise psycopg.errors.ConnectionTimeout("connection timeout expired PRIVATE")
                return Connection()

            with (
                patch.object(storage, "connection_parameters", return_value={}),
                patch.object(storage.psycopg, "connect", side_effect=connect),
                ThreadPoolExecutor(max_workers=4) as pool,
            ):
                receipts = list(
                    pool.map(holdout_budget_qualification.attempt, [("client", "a" * 64)] * 32)
                )
            self.assertEqual(len(ledger), 32)
            self.assertEqual(sorted(r["slot"] for r in receipts if "slot" in r), list(range(2, 33)))
            if failing:
                with self.assertRaises(holdout_diagnostics.ClaimFailure) as rejected:
                    holdout_diagnostics.check_claims(receipts, "a" * 64)
                self.assertEqual(
                    rejected.exception.diagnostics["rejection_codes"],
                    {"storage_connection_rejected": 1},
                )
                self.assertEqual(len(rejected.exception.diagnostics["connection_failures"]), 1)
            else:
                observed = holdout_diagnostics.check_claims(receipts, "a" * 64)
                self.assertEqual(observed["rejection_codes"], {"holdout_budget_exhausted": 1})
                self.assertNotIn("connection_failures", observed)

    def test_statement_or_uncertain_commit_failure_is_not_a_connection_failure(self):
        for stage in ("execute", "commit"):
            with patch.object(storage, "connect") as connect:
                connection = connect.return_value.__enter__.return_value
                connection.execute.return_value.fetchone.return_value = (
                    digest(holdout_budget.reservation("a" * 64, 1)),
                )
                target = connection.execute if stage == "execute" else connect.return_value.__exit__
                target.side_effect = psycopg.errors.ConnectionFailure("PRIVATE")
                result = holdout_budget_qualification.attempt(("client", "a" * 64))
            self.assertEqual(result, {"rejected": "storage_claim_rejected:08006"})
            connect.assert_called_once()

    def test_malformed_or_secret_diagnostics_are_rejected_without_echo(self):
        original = self.detail()
        for field in diagnostics.FIELDS:
            for bad in (None, True, "PRIVATE", [], {}, -1, 1000000):
                value = {**original, field: bad}
                self.assertFalse(diagnostics.checked(value, 32), (field, type(bad)))
                receipts = fixtures.BudgetDiagnosticContracts.receipts()
                receipts[-1] = {
                    "rejected": "storage_connection_rejected",
                    "connection_failure": value,
                }
                with self.assertRaises(holdout_diagnostics.ClaimFailure) as result:
                    holdout_diagnostics.check_claims(receipts, "a" * 64)
                self.assertEqual(result.exception.diagnostics["invalid_receipts"], 1)
                self.assertNotIn(b"PRIVATE", canonical(result.exception.diagnostics))
        for value in (
            None,
            [],
            {**original, "secret": "PRIVATE"},
            {k: v for k, v in original.items() if k != "slot"},
        ):
            self.assertFalse(diagnostics.checked(value, 32))
        self.assertFalse(diagnostics.checked(dict(original, prior_conflicts=30), 32))

    def test_diagnostic_cannot_decorate_budget_exhaustion_into_success(self):
        receipts = fixtures.BudgetDiagnosticContracts.receipts()
        receipts[-1]["connection_failure"] = self.detail()
        with self.assertRaises(holdout_diagnostics.ClaimFailure) as result:
            holdout_diagnostics.check_claims(receipts, "a" * 64)
        self.assertEqual(result.exception.diagnostics["invalid_receipts"], 1)
        self.assertNotIn("connection_failures", result.exception.diagnostics)

    def test_m07_failure_report_keeps_connection_context_and_nonzero_status(self):
        from mlsecops import acceptance, evaluation_gate

        detail = self.detail()
        receipts = fixtures.BudgetDiagnosticContracts.receipts()
        receipts[-1] = {"rejected": "storage_connection_rejected", "connection_failure": detail}
        with self.assertRaises(holdout_diagnostics.ClaimFailure) as failure:
            holdout_diagnostics.check_claims(receipts, "a" * 64)
        with TemporaryDirectory() as temporary:
            state = Path(temporary)
            write_json(state / "workspace.json", {})
            with patch.object(evaluation_gate, "qualify", side_effect=failure.exception):
                report = acceptance.report(
                    "M07", "local-cpu", Path(__file__).resolve().parents[1], state
                )
        self.assertEqual((report["status"], report["exit_code"]), ("fail", 1))
        self.assertEqual(
            report["diagnostics"]["holdout_concurrency"]["connection_failures"], [detail]
        )
        self.assertNotIn(b"PRIVATE-DRIVER-DETAIL", canonical(report))

    def test_all_connection_failures_stay_bounded_and_never_read_or_reserve(self):
        receipts = [
            {"rejected": "storage_connection_rejected", "connection_failure": self.detail(slot=i)}
            for i in range(1, 33)
        ]
        with patch.object(storage, "claim") as claim, patch.object(storage, "get") as read:
            with self.assertRaises(holdout_diagnostics.ClaimFailure) as result:
                holdout_diagnostics.check_claims(copy.deepcopy(receipts), "a" * 64)
        self.assertLess(len(canonical(result.exception.diagnostics)), 16384)
        self.assertEqual(len(result.exception.diagnostics["connection_failures"]), 32)
        claim.assert_not_called()
        read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
