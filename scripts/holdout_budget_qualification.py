import copy
import io
import runpy
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import psycopg

from mlsecops import holdout_budget, storage, storage_pipeline
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json


class BudgetContracts(unittest.TestCase):
    def test_exhaustion_survives_new_callers(self):
        ledger = set()

        def claim(client, table, content):
            self.assertEqual(table, "evaluations")
            identifier = digest(content)
            fresh = identifier not in ledger
            ledger.add(identifier)
            return fresh

        with patch.object(storage, "claim", side_effect=claim):
            receipts = [
                holdout_budget.reserve(f"process-{index}", "a" * 64)
                for index in range(holdout_budget.LIMIT)
            ]
            with self.assertRaisesRegex(Rejected, "^holdout_budget_exhausted$"):
                holdout_budget.reserve("new-candidate-new-process", "a" * 64)
            self.assertEqual(len(ledger), holdout_budget.LIMIT)
            self.assertEqual(len({item["reservation"] for item in receipts}), len(receipts))
            self.assertEqual(holdout_budget.reserve("client", "b" * 64)["slot"], 1)

    def test_invalid_holdout_never_writes(self):
        with patch.object(storage, "claim") as claim:
            for invalid in (None, True, "../data", "A" * 64, "a" * 63):
                with self.subTest(invalid=invalid), self.assertRaises(Rejected):
                    holdout_budget.reserve("client", invalid)
            claim.assert_not_called()

    def test_database_failure_does_not_retry_or_refund(self):
        with patch.object(
            storage, "claim", side_effect=Rejected("storage_connection_rejected")
        ) as claim:
            with self.assertRaisesRegex(Rejected, "storage_connection_rejected"):
                holdout_budget.reserve("client", "a" * 64)
            self.assertEqual(claim.call_count, 1)

    def test_receipt_matches_durable_slot(self):
        with patch.object(storage, "claim", return_value=True) as claim:
            receipt = holdout_budget.reserve("client", "a" * 64)
            self.assertEqual(receipt["reservation"], digest(claim.call_args.args[2]))
            self.assertEqual(receipt["policy_digest"], digest(canonical(holdout_budget.policy())))
            self.assertEqual(receipt["holdout_digest"], "a" * 64)

    def test_policy_cannot_be_changed_through_return_value(self):
        original = holdout_budget.policy()
        holdout_budget.policy()["maximum_attempts"] = 999
        self.assertEqual(holdout_budget.policy(), original)

    def test_reservation_is_independent_of_policy_and_run(self):
        original = holdout_budget.reservation("a" * 64, 1)
        with patch.object(holdout_budget, "policy", return_value={"new-policy": True}):
            self.assertEqual(holdout_budget.reservation("a" * 64, 1), original)

    def test_invalid_slot(self):
        for slot in (0, -1, True, 1.0, "1", holdout_budget.LIMIT + 1):
            with (
                self.subTest(slot=slot),
                self.assertRaisesRegex(Rejected, "holdout_budget_slot_invalid"),
            ):
                holdout_budget.reservation("a" * 64, slot)

    def test_inspection_does_not_reserve(self):
        def get(client, table, identifier):
            content = holdout_budget.reservation("a" * 64, 2)
            if identifier == digest(content):
                return content
            raise Rejected("storage_object_missing")

        with patch.object(storage, "get", side_effect=get), patch.object(storage, "claim") as claim:
            observed = holdout_budget.inspect("client", "a" * 64)
            self.assertEqual(observed["occupied_slots"], [2])
            self.assertEqual(observed["remaining_upper_bound"], holdout_budget.LIMIT - 1)
            claim.assert_not_called()

    def test_inspection_errors_are_not_empty_budget(self):
        with patch.object(storage, "get", side_effect=Rejected("storage_connection_rejected")):
            with self.assertRaisesRegex(Rejected, "storage_connection_rejected"):
                holdout_budget.inspect("client", "a" * 64)
        with patch.object(storage, "get", return_value=b"tampered"):
            with self.assertRaisesRegex(Rejected, "holdout_budget_ledger_mismatch"):
                holdout_budget.inspect("client", "a" * 64)


class ClaimContracts(unittest.TestCase):
    def test_only_new_committed_insert_grants_access(self):
        for row, expected in (((digest(b"slot"),), True), (None, False)):
            with self.subTest(row=row), patch.object(storage, "connect") as connect:
                connection = connect.return_value.__enter__.return_value
                connection.execute.return_value.fetchone.return_value = row
                self.assertIs(storage.claim("client", "evaluations", b"slot"), expected)
                connect.return_value.__exit__.assert_called_once()
                statement, parameters = connection.execute.call_args.args
                self.assertIn("DO NOTHING RETURNING sha256", statement.as_string())
                self.assertEqual(parameters, (digest(b"slot"), b"slot"))

    def test_uncertain_commit_is_not_success(self):
        with patch.object(storage, "connect") as connect:
            connection = connect.return_value.__enter__.return_value
            connection.execute.return_value.fetchone.return_value = (digest(b"slot"),)
            connect.return_value.__exit__.side_effect = psycopg.OperationalError("private detail")
            with self.assertRaisesRegex(Rejected, "^storage_claim_rejected:unavailable$"):
                storage.claim("client", "evaluations", b"slot")

    def test_wrong_database_return_is_not_success(self):
        with patch.object(storage, "connect") as connect:
            connection = connect.return_value.__enter__.return_value
            connection.execute.return_value.fetchone.return_value = ("a" * 64,)
            with self.assertRaisesRegex(Rejected, "storage_claim_verification_failed"):
                storage.claim("client", "evaluations", b"slot")

    def test_invalid_claim_is_local_rejection(self):
        with patch.object(storage, "connect") as connect:
            for content in (b"", "text", None):
                with self.subTest(content=content), self.assertRaises(Rejected):
                    storage.claim("client", "evaluations", content)
            with self.assertRaises(Rejected):
                storage.claim("client", "../table", b"slot")
            connect.assert_not_called()


class InspectionCLI(unittest.TestCase):
    def test_success_and_failure_exit_codes(self):
        arguments = ["budget", "--client", "client", "--holdout", "a" * 64]
        with (
            patch("sys.argv", arguments),
            patch.object(holdout_budget, "inspect", return_value={"scope": "controlled"}),
            redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(holdout_budget.main(), 0)
            self.assertIn("controlled", output.getvalue())
        with (
            patch("sys.argv", arguments),
            patch.object(
                holdout_budget, "inspect", side_effect=Rejected("storage_connection_rejected")
            ),
            redirect_stderr(io.StringIO()) as output,
        ):
            self.assertEqual(holdout_budget.main(), 1)
            self.assertIn("storage_connection_rejected", output.getvalue())

    def test_module_entrypoint_help_is_read_only(self):
        with (
            patch("sys.argv", ["budget", "--help"]),
            redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as result,
        ):
            runpy.run_module("mlsecops.holdout_budget", run_name="__main__")
        self.assertEqual(result.exception.code, 0)


class BudgetDiagnosticContracts(unittest.TestCase):
    @staticmethod
    def receipts():
        return [
            {
                "holdout_digest": "a" * 64,
                "slot": slot,
                "reservation": digest(holdout_budget.reservation("a" * 64, slot)),
                "policy_digest": digest(canonical(holdout_budget.policy())),
            }
            for slot in range(2, holdout_budget.LIMIT + 1)
        ] + [{"rejected": "holdout_budget_exhausted"}]

    def test_exact_exhaustion_retains_bounded_diagnostic_not_authorization(self):
        from mlsecops.holdout_diagnostics import check_claims

        observed = check_claims(self.receipts(), "a" * 64)
        self.assertEqual(observed["claimed_slots"], list(range(2, 33)))
        self.assertEqual(observed["rejection_codes"], {"holdout_budget_exhausted": 1})
        self.assertEqual(observed["attempts"], 32)
        self.assertEqual(observed["invalid_receipts"], 0)
        self.assertTrue(observed["diagnostic_only"])
        self.assertNotIn("pass", canonical(observed).decode())

    def test_sql_reasons_survive_without_becoming_expected_exhaustion(self):
        from mlsecops.holdout_diagnostics import ClaimFailure, check_claims

        for reason in (
            "storage_claim_rejected:55P03",
            "storage_claim_rejected:57014",
            "storage_claim_rejected:40001",
            "storage_claim_rejected:unavailable",
            "storage_connection_rejected",
            "storage_claim_verification_failed",
        ):
            receipts = self.receipts()
            receipts[-1] = {"rejected": reason}
            with self.subTest(reason=reason), self.assertRaises(ClaimFailure) as result:
                check_claims(receipts, "a" * 64)
            self.assertEqual(
                str(result.exception), "holdout_qualification_failed:concurrent-over-budget-denied"
            )
            self.assertEqual(result.exception.diagnostics["rejection_codes"], {reason: 1})

    def test_unknown_private_and_oversized_reasons_never_appear(self):
        from mlsecops.holdout_diagnostics import ClaimFailure, check_claims

        for reason in (
            "postgresql://private-password@internal/path",
            "storage_claim_rejected:55P03\nprivate-password",
            "private-password" * 10000,
            {"private-password": "secret"},
            None,
        ):
            receipts = self.receipts()
            receipts[-1] = {"rejected": reason}
            with self.subTest(kind=type(reason)), self.assertRaises(ClaimFailure) as result:
                check_claims(receipts, "a" * 64)
            encoded = canonical(result.exception.diagnostics)
            self.assertNotIn(b"private-password", encoded)
            self.assertLess(len(encoded), 2048)
            self.assertEqual(
                result.exception.diagnostics["rejection_codes"], {"unclassified_rejection": 1}
            )

    def test_malformed_and_excess_attempts_are_bounded_failures(self):
        from mlsecops.holdout_diagnostics import ClaimFailure, check_claims

        for receipts in (None, {}, [], self.receipts()[:31], self.receipts() * 1000):
            with self.subTest(kind=type(receipts)), self.assertRaises(ClaimFailure) as result:
                check_claims(receipts, "a" * 64)
            self.assertLess(len(canonical(result.exception.diagnostics)), 2048)
            self.assertFalse(result.exception.diagnostics["complete"])

    def test_wrong_receipt_shape_is_redacted_not_silently_accepted(self):
        from mlsecops.holdout_diagnostics import ClaimFailure, check_claims

        for replacement in (
            None,
            True,
            "private-password",
            {"reservation": "private-password", "slot": True},
            {**self.receipts()[0], "extra": "private-password"},
            {**self.receipts()[0], "slot": "private-password"},
            {**self.receipts()[0], "slot": True},
            {**self.receipts()[0], "slot": 1000000},
        ):
            receipts = self.receipts()
            receipts[0] = replacement
            with self.subTest(kind=type(replacement)), self.assertRaises(ClaimFailure) as result:
                check_claims(receipts, "a" * 64)
            self.assertEqual(result.exception.diagnostics["invalid_receipts"], 1)
            self.assertNotIn(b"private-password", canonical(result.exception.diagnostics))

    def test_context_digest_and_slot_cannot_be_swapped(self):
        from mlsecops.holdout_diagnostics import ClaimFailure, check_claims

        for field, value in (
            ("holdout_digest", "b" * 64),
            ("policy_digest", "b" * 64),
            ("reservation", "b" * 64),
            ("slot", 1),
        ):
            receipts = self.receipts()
            receipts[0][field] = value
            with self.subTest(field=field), self.assertRaises(ClaimFailure):
                check_claims(receipts, "a" * 64)
        receipts = self.receipts()
        receipts[0] = copy.deepcopy(receipts[1])
        with self.assertRaises(ClaimFailure):
            check_claims(receipts, "a" * 64)

    def test_maximum_reason_diversity_still_has_small_safe_output(self):
        from mlsecops.holdout_diagnostics import REJECTION_CODES, ClaimFailure, check_claims

        codes = sorted(REJECTION_CODES)
        receipts = [{"rejected": codes[index % len(codes)]} for index in range(32)]
        with self.assertRaises(ClaimFailure) as rejected:
            check_claims(receipts, "a" * 64)
        observed = rejected.exception.diagnostics
        self.assertEqual(sum(observed["rejection_codes"].values()), 32)
        self.assertLess(len(canonical(observed)), 2048)

    def test_diagnostic_does_not_reserve_or_read_holdout(self):
        from mlsecops.holdout_diagnostics import check_claims

        with patch.object(storage, "claim") as claim, patch.object(storage, "get") as read:
            check_claims(self.receipts(), "a" * 64)
        claim.assert_not_called()
        read.assert_not_called()

    def test_native_failure_carries_diagnostics_and_stops_only_owned_container(self):
        from mlsecops import holdout_budget_qualification as native
        from mlsecops.holdout_diagnostics import ClaimFailure

        receipts = self.receipts()
        receipts[-1] = {"rejected": "storage_claim_rejected:55P03"}
        result = {
            "evaluation": {
                "holdout_access": {"holdout_digest": "a" * 64, "slot": 1, "reservation": "b" * 64},
                "report": {"quality_component": "pass"},
            }
        }
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(native, "initialize"),
            patch.object(native, "bootstrap"),
            patch.object(native, "validate", return_value={"container_id": "owned-container"}),
            patch.object(native.storage_pipeline, "demo", return_value=result),
            patch.object(
                native.storage, "get", return_value=holdout_budget.reservation("a" * 64, 1)
            ),
            patch.object(native, "ProcessPoolExecutor") as pool,
            patch.object(native, "docker") as docker,
        ):
            pool.return_value.__enter__.return_value.map.return_value = receipts
            with self.assertRaises(ClaimFailure) as rejected:
                native.qualify(Path(temporary), Path(temporary) / "new-state", "image", 15452)
            self.assertEqual(
                rejected.exception.diagnostics["rejection_codes"],
                {"storage_claim_rejected:55P03": 1},
            )
            docker.assert_called_once_with(["stop", "owned-container"], timeout=60)

    def test_M07_failure_report_preserves_reason_without_private_material(self):
        from mlsecops import acceptance, evaluation_gate
        from mlsecops.holdout_diagnostics import ClaimFailure, check_claims

        receipts = self.receipts()
        receipts[-1] = {"rejected": "private-password"}
        with self.assertRaises(ClaimFailure) as rejected:
            check_claims(receipts, "a" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            write_json(state / "workspace.json", {})
            with patch.object(evaluation_gate, "qualify", side_effect=rejected.exception):
                report = acceptance.report(
                    "M07", "local-cpu", Path(__file__).resolve().parents[1], state
                )
        self.assertEqual((report["status"], report["exit_code"]), ("fail", 1))
        self.assertEqual(
            report["diagnostics"]["holdout_concurrency"], rejected.exception.diagnostics
        )
        self.assertNotIn(b"private-password", canonical(report))

    def test_native_cli_records_sanitized_failure_not_false_pass(self):
        from mlsecops import holdout_budget_qualification as native
        from mlsecops.holdout_diagnostics import ClaimFailure, check_claims

        receipts = self.receipts()
        receipts[-1] = {"rejected": "private-password"}
        with self.assertRaises(ClaimFailure) as rejected:
            check_claims(receipts, "a" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "diagnostic.json"
            with (
                patch("sys.argv", ["budget", "--output", str(output)]),
                patch.object(native, "qualify", side_effect=rejected.exception),
                redirect_stderr(io.StringIO()) as stderr,
            ):
                self.assertEqual(native.main(), 1)
            report = read_json(output)
            self.assertEqual(
                report["diagnostics"]["holdout_concurrency"], rejected.exception.diagnostics
            )
            self.assertNotIn("private-password", stderr.getvalue() + canonical(report).decode())


class ScorerOrdering(unittest.TestCase):
    def test_reservation_precedes_holdout_read_and_worker(self):
        policy = read_json(Path(__file__).resolve().parents[1] / "policies/local-cpu.json")
        metadata = {"dataset_id": "d", "lineage_id": "l"}
        manifest = {"objects": {"holdout.json": {"sha256": "a" * 64}}}
        statement = {"dataset_id": "d", "lineage_id": "l"}
        trust = {
            "curator": "curator",
            "source_approval_digest": "approval",
            "evaluator": "evaluator",
        }
        events = []

        def reserve(*arguments):
            events.append("reserve")
            return {"reservation": "b" * 64}

        def read(*arguments):
            events.append("holdout")
            return {"holdout": []}, manifest, statement

        with (
            patch.object(
                storage_pipeline,
                "load_candidate",
                return_value=({"dataset_reference": "ref"}, metadata, b"model"),
            ),
            patch.object(
                storage_pipeline.storage_dataset,
                "read_manifest",
                return_value=(manifest, statement),
            ) as read_manifest,
            patch.object(holdout_budget, "reserve", side_effect=reserve) as reservation,
            patch.object(
                storage_pipeline.storage_dataset, "read_dataset", side_effect=read
            ) as read_dataset,
            patch.object(
                storage_pipeline,
                "evaluate_verified_candidate",
                side_effect=lambda *args: events.append("worker") or {"status": "test"},
            ) as worker,
            patch.object(storage_pipeline, "sign", side_effect=lambda value, *args: value),
            patch.object(storage_pipeline, "verify", side_effect=lambda value, *args: value),
            patch.object(storage, "put", return_value="result"),
            patch.object(storage, "get") as get,
            patch.object(storage_pipeline, "read_evaluation") as reader,
        ):
            bound = {
                "schema_version": 1,
                "candidate_reference": "candidate",
                "dataset_reference": "ref",
                "lineage_id": "l",
                "holdout_access": {"reservation": "b" * 64},
                "report": {"status": "test"},
            }
            get.return_value = canonical(bound)
            reader.return_value = bound
            result = storage_pipeline.evaluate("client", "candidate", policy, "image", trust, "key")
            self.assertEqual(events, ["reserve", "holdout", "worker"])
            self.assertEqual(result["evaluation"], bound)
            read_manifest.assert_called_once()
            reservation.side_effect = Rejected("holdout_budget_exhausted")
            read_dataset.reset_mock()
            worker.reset_mock()
            with self.assertRaisesRegex(Rejected, "holdout_budget_exhausted"):
                storage_pipeline.evaluate("client", "new-candidate", policy, "image", trust, "key")
            read_dataset.assert_not_called()
            worker.assert_not_called()
            reservation.reset_mock()
            metadata["dataset_id"] = "changed"
            with self.assertRaisesRegex(Rejected, "stored_candidate_dataset_binding_mismatch"):
                storage_pipeline.evaluate("client", "candidate", policy, "image", trust, "key")
            reservation.assert_not_called()
            read_dataset.assert_not_called()


if __name__ == "__main__":
    unittest.main()
