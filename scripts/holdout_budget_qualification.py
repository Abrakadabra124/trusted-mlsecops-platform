import io
import runpy
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import psycopg

from mlsecops import holdout_budget, storage, storage_pipeline
from mlsecops.contracts import Rejected, canonical, digest, read_json


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
