"""Quarantine is a durable inbox, never a label or training authority."""

import io
import runpy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import feedback
from mlsecops.contracts import Rejected, canonical, decode, digest


def submission():
    return {
        "schema_version": 1,
        "model_sha256": "a" * 64,
        "bundle_sha256": "b" * 64,
        "records": [{"request_id": "c" * 32, "row_index": 0, "label": 1}],
    }


class FeedbackContracts(unittest.TestCase):
    def setUp(self):
        self.objects = {}
        self.client = Path.cwd() / ".runtime/fixture-client"
        self.role = "ingestor"
        self.addCleanup(patch.stopall)
        patch.object(
            feedback.storage,
            "connection_parameters",
            side_effect=lambda client: {"user": "ml_" + self.role},
        ).start()
        self.put = patch.object(feedback.storage, "put", side_effect=self.persist).start()
        self.get = patch.object(
            feedback.storage,
            "get",
            side_effect=lambda client, table, reference: self.objects[(table, reference)],
        ).start()

    def persist(self, client, table, content):
        self.assertEqual(table, "quarantine")
        key = digest(content)
        self.objects.setdefault((table, key), content)
        return key

    def test_retry_is_identical_and_curator_reads_only_unverified_records(self):
        result = feedback.submit(self.client, canonical(submission()))
        self.assertEqual(feedback.submit(self.client, canonical(submission())), result)
        self.assertEqual(len(self.objects), 1)
        self.assertEqual(result["status"], "quarantined")
        self.assertFalse(result["training_eligible"])
        self.assertFalse(result["verified_labels"])
        self.assertFalse(result["release_ready"])
        self.role = "curator"
        document = feedback.read(self.client, result["record_sha256"])
        self.assertEqual(document["records"], submission()["records"])
        self.assertEqual(document["kind"], "unverified-feedback")

    def test_roles_and_relative_clients_fail_before_database_write_or_read(self):
        for role in ("curator", "publisher", "scorer", "promoter", "serving"):
            self.role = role
            with self.subTest(role=role), self.assertRaises(Rejected):
                feedback.submit(self.client, canonical(submission()))
        self.role = "ingestor"
        with self.assertRaises(Rejected):
            feedback.read(self.client, "a" * 64)
        with self.assertRaises(Rejected):
            feedback.submit(Path("relative"), canonical(submission()))
        self.put.assert_not_called()
        self.get.assert_not_called()

    def test_unknown_fields_free_text_features_and_authority_flags_cannot_enter(self):
        for key in (
            "features",
            "comment",
            "principal",
            "verified_labels",
            "training_eligible",
            "signature",
        ):
            value = submission()
            value[key] = "PRIVATE-CANARY"
            with self.subTest(key=key), self.assertRaises(Rejected):
                feedback.submit(self.client, canonical(value))
        self.put.assert_not_called()

    def test_invalid_boundaries_duplicates_and_types_cannot_mutate_quarantine(self):
        values = []
        for key, value in (
            ("schema_version", True),
            ("model_sha256", "PRIVATE"),
            ("bundle_sha256", None),
            ("records", []),
            ("records", {}),
            ("records", submission()["records"] * 101),
        ):
            values.append({**submission(), key: value})
        for key, value in (
            ("request_id", "bad"),
            ("row_index", True),
            ("row_index", -1),
            ("row_index", 100),
            ("label", True),
            ("label", 2),
            ("extra", "PRIVATE"),
        ):
            item = {**submission()["records"][0], key: value}
            values.append({**submission(), "records": [item]})
        values.append({**submission(), "records": submission()["records"] * 2})
        for value in values:
            with self.subTest(value=value), self.assertRaises(Rejected):
                feedback.submit(self.client, canonical(value))
        for content in (b"x" * 16385, b"bad", bytearray(b"{}")):
            with self.assertRaises(Rejected):
                feedback.submit(self.client, content)
        self.put.assert_not_called()

    def test_changed_readback_or_manufactured_approval_is_rejected(self):
        result = feedback.submit(self.client, canonical(submission()))
        self.role = "curator"
        key = ("quarantine", result["record_sha256"])
        original = decode(self.objects[key])
        for field, value in (
            ("kind", "verified-labels"),
            ("training_eligible", True),
            ("verified_labels", True),
            ("release_ready", True),
        ):
            record = {**original, field: value}
            content = canonical(record)
            reference = digest(content)
            self.objects[("quarantine", reference)] = content
            with self.subTest(field=field), self.assertRaises(Rejected):
                feedback.read(self.client, reference)
        self.objects[key] = b"{}"
        with self.assertRaises(Rejected):
            feedback.read(self.client, result["record_sha256"])
        self.objects[key] = b"x" * 16385
        with self.assertRaises(Rejected):
            feedback.read(self.client, result["record_sha256"])

    def test_db_failure_or_wrong_write_reference_never_returns_success(self):
        for result in ("f" * 64, None):
            with (
                patch.object(feedback.storage, "put", return_value=result),
                self.assertRaises(Rejected),
            ):
                feedback.submit(self.client, canonical(submission()))
        with (
            patch.object(feedback.storage, "put", side_effect=Rejected("PRIVATE")),
            self.assertRaises(Rejected),
        ):
            feedback.submit(self.client, canonical(submission()))

    def test_feedback_cannot_be_used_as_existing_dataset_or_signed_ground_truth(self):
        from mlsecops import intake
        from mlsecops.release_policy import checked
        from mlsecops.signing import encode64

        record = feedback.document(canonical(submission()))
        with self.assertRaisesRegex(Rejected, "separate_verified_label"):
            intake.validate_submission(canonical(record), "source", "feedback", {}, self.client)
        with self.assertRaises(Rejected):
            checked(record, "monitor-labels", encode64(b"p" * 32))

    def test_cli_prints_only_receipt_and_redacts_failures(self):
        result = feedback.submit(self.client, canonical(submission()))
        for action in ("submit", "inspect"):
            arguments = [action, "--client", str(self.client)] + (
                ["--file", "private.json"]
                if action == "submit"
                else ["--reference", result["record_sha256"]]
            )
            self.role = "ingestor" if action == "submit" else "curator"
            with (
                patch.object(feedback, "enforce_privacy"),
                patch.object(feedback, "bounded_read", return_value=canonical(submission())),
                patch.object(sys, "stdout", io.StringIO()) as output,
            ):
                self.assertEqual(feedback.main(arguments), 0)
                self.assertEqual(decode(output.getvalue()), result)
                self.assertNotIn('"records":', output.getvalue())
        for arguments in (
            ["submit", "--client", str(self.client)],
            ["inspect", "--client", str(self.client)],
            ["invalid"],
        ):
            with (
                patch.object(feedback, "enforce_privacy"),
                patch.object(sys, "stdout", io.StringIO()),
                patch.object(sys, "stderr", io.StringIO()) as error,
            ):
                self.assertEqual(feedback.main(arguments), 1)
                self.assertEqual(error.getvalue(), "feedback_rejected\n")
        with (
            patch.object(feedback, "enforce_privacy", side_effect=KeyboardInterrupt),
            patch.object(sys, "stderr", io.StringIO()),
        ):
            self.assertEqual(feedback.main([]), 130)

    def test_module_entrypoint_enforces_private_process_before_input(self):
        with (
            patch("mlsecops.process_privacy.enforce", side_effect=Rejected("PRIVATE")),
            patch.object(sys, "stderr", io.StringIO()) as error,
            self.assertRaises(SystemExit) as result,
        ):
            runpy.run_path(feedback.__file__, run_name="__main__")
        self.assertEqual(result.exception.code, 1)
        self.assertEqual(error.getvalue(), "feedback_rejected\n")


if __name__ == "__main__":
    unittest.main()
