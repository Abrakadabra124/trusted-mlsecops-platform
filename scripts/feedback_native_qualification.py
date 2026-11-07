"""Primary quarantine records and direct database denials, without local infrastructure."""

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import psycopg

from mlsecops import feedback
from mlsecops.contracts import Rejected, canonical, read_json, write_json
from mlsecops.storage_schema import TABLES
from scripts import feedback_native as native


def packet():
    return {
        "http": [
            {
                "response": {
                    "model_sha256": "a" * 64,
                    "bundle_sha256": "b" * 64,
                    "request_id": "c" * 32,
                }
            }
        ]
    }


def proof():
    source = native.fixture(packet())
    record = feedback.document(canonical(source))
    receipt = feedback.receipt(record)
    before = {name: {"rows": 0, "bytes": 0, "sha256": "d" * 64, "invalid": 0} for name in TABLES}
    after = copy.deepcopy(before)
    after["quarantine"] = {
        "rows": 1,
        "bytes": len(canonical(record)),
        "sha256": "e" * 64,
        "invalid": 0,
    }
    denied = {"ingestor:insert-" + table: "42501" for table in TABLES if table != "quarantine"}
    denied.update(
        {
            role + ":read-quarantine": "42501"
            for role in ("publisher", "scorer", "serving", "promoter")
        }
    )
    denied.update(
        dict.fromkeys(
            (
                "curator:insert-quarantine",
                "ingestor:update-quarantine",
                "ingestor:delete-quarantine",
            ),
            "42501",
        )
    )
    return {
        "input": source,
        "stored": record,
        "receipt": receipt,
        "retry": copy.deepcopy(receipt),
        "inspection": copy.deepcopy(receipt),
        "before": before,
        "after": after,
        "after_retry": copy.deepcopy(after),
        "final": copy.deepcopy(after),
        "promotion_before": {"fixture": "unchanged"},
        "promotion_after": {"fixture": "unchanged"},
        "denials": denied,
        "dataset_refused": True,
        "label_refused": True,
    }


class FeedbackNativeContracts(unittest.TestCase):
    def test_bound_feedback_receipts_and_ledger_changes_are_recomputed(self):
        value = proof()
        result = native.verify(value, packet())
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["direct_database_denials"], 15)
        self.assertEqual(result["submitted_records"], 10)
        self.assertFalse(result["release_ready"])
        for field in ("input", "stored", "receipt", "retry", "inspection"):
            changed = copy.deepcopy(value)
            changed[field]["extra"] = "bad"
            with self.subTest(field=field), self.assertRaises(Rejected):
                native.verify(changed, packet())
        changed_packet = packet()
        changed_packet["http"][0]["response"]["request_id"] = "f" * 32
        with self.assertRaises(Rejected):
            native.verify(value, changed_packet)

    def test_duplicate_or_nonquarantine_mutation_cannot_be_counted_as_success(self):
        changes = (
            ("after", "train", "sha256", "f" * 64),
            ("after", "quarantine", "rows", 2),
            ("after", "quarantine", "bytes", 1),
            ("after", "quarantine", "sha256", "d" * 64),
            ("after_retry", "quarantine", "sha256", "f" * 64),
            ("final", "quarantine", "sha256", "f" * 64),
            ("before", "quarantine", "invalid", 1),
        )
        for stage, table, field, value in changes:
            changed = proof()
            changed[stage][table][field] = value
            with self.subTest(stage=stage, field=field), self.assertRaises(Rejected):
                native.verify(changed, packet())
        changed = proof()
        changed["promotion_after"] = {}
        with self.assertRaises(Rejected):
            native.verify(changed, packet())

    def test_missing_permissions_or_authority_refusal_is_not_success(self):
        for key, value in (("denials", {}), ("dataset_refused", False), ("label_refused", 1)):
            changed = proof()
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(Rejected):
                native.verify(changed, packet())
        changed = proof()
        changed.pop("stored")
        with self.assertRaises(Rejected):
            native.verify(changed, packet())

    def test_offline_reverification_requires_retained_primary_records_and_exact_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            destination = native.directory(state, "a" * 32) / "proof.json"
            value = proof()
            summary = native.verify(value, packet())
            with self.assertRaises(Rejected):
                native.reverify(state, "a" * 32, summary, packet())
            write_json(destination, value)
            self.assertEqual(native.reverify(state, "a" * 32, summary, packet()), summary)
            with self.assertRaises(Rejected):
                native.reverify(state, "a" * 32, {}, packet())
            value["stored"]["verified_labels"] = True
            write_json(destination, value)
            with self.assertRaises(Rejected):
                native.reverify(state, "a" * 32, summary, packet())

    def test_cli_requires_bounded_canonical_receipt_and_ledger_validates_owner(self):
        value = proof()
        receipt = value["receipt"]
        with patch.object(
            native.storage_snapshot, "binary_command", return_value=canonical(receipt) + b"\n"
        ) as command:
            self.assertEqual(native.cli(["inspect"]), receipt)
            self.assertEqual(command.call_args.kwargs, {"output_limit": 4096, "timeout": 30})
        for content in (canonical(receipt), b"not-json", b"x" * 4097):
            with (
                patch.object(native.storage_snapshot, "binary_command", return_value=content),
                self.assertRaises(Rejected),
            ):
                native.cli([])
        with (
            patch.object(
                native.storage_bootstrap, "validate", return_value={"container_id": "owned"}
            ) as owner,
            patch.object(
                native.storage_bootstrap, "admin", return_value=canonical(value["before"])
            ) as admin,
        ):
            self.assertEqual(native.ledger(Path("state")), value["before"])
            owner.assert_called_once_with(Path("state"))
            self.assertEqual(admin.call_args.args[0], "owned")

    def test_database_checks_accept_only_permission_denied_not_connection_failure(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.execute.side_effect = psycopg.errors.InsufficientPrivilege("PRIVATE")
        with patch.object(native.storage, "connect", return_value=connection) as connect:
            denied = native.denials(Path("state"), "a" * 64, b"content")
            self.assertEqual(denied, proof()["denials"])
            self.assertEqual(connect.call_count, 15)
        for failure in (None, psycopg.OperationalError("PRIVATE"), Rejected("connection")):
            connection.execute.side_effect = failure
            with (
                patch.object(native.storage, "connect", return_value=connection),
                self.assertRaises(Rejected),
            ):
                native.denials(Path("state"), "a" * 64, b"content")

    def test_hosted_flow_retains_real_records_and_rereads_them(self):
        value = proof()
        for accepted in (None, "dataset", "label"):
            with tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                campaign = "a" * 32
                write_json(
                    state / ("evidence/monitoring/" + campaign + "/packet.json"),
                    {"packet": packet()},
                )
                with (
                    patch.object(native, "hosted") as hosted,
                    patch.object(
                        native,
                        "ledger",
                        side_effect=[
                            value[key] for key in ("before", "after", "after_retry", "final")
                        ],
                    ),
                    patch.object(
                        native, "promotion_snapshot", return_value=value["promotion_before"]
                    ),
                    patch.object(native, "cli", return_value=value["receipt"]) as cli,
                    patch.object(native.feedback, "read", return_value=value["stored"]),
                    patch.object(native, "denials", return_value=value["denials"]),
                    patch.object(
                        native.intake,
                        "validate_submission",
                        side_effect=None if accepted == "dataset" else Rejected("denied"),
                    ),
                    patch.object(
                        native,
                        "checked",
                        side_effect=None if accepted == "label" else Rejected("denied"),
                    ),
                ):
                    if accepted:
                        with self.assertRaisesRegex(Rejected, "feedback_accepted_as_authority"):
                            native.qualify(state, {"monitoring_campaign_id": campaign})
                    else:
                        result = native.qualify(state, {"monitoring_campaign_id": campaign})
                        self.assertEqual(result, native.verify(value, packet()))
                        self.assertEqual(
                            read_json(native.directory(state, campaign) / "proof.json"), value
                        )
                        self.assertEqual(cli.call_count, 3)
                    hosted.assert_called_once()
        with (
            patch.object(native, "hosted", side_effect=Rejected("unowned")),
            patch.object(native, "read_json") as read,
            self.assertRaises(Rejected),
        ):
            native.qualify(Path("unused"), {})
        read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
