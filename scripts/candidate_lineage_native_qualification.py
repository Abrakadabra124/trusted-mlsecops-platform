import contextlib
import copy
import io
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from scripts import candidate_lineage_native as native
from scripts.asset_graph_fixture import fixture

ROOT = Path(__file__).resolve().parents[1]


class NativeLineageContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name)
        self.image = "sha256:" + "1" * 64
        self.fingerprint = "2" * 64
        self.revision = "3" * 40
        self.candidate = "4" * 64
        self.evaluation = "5" * 64
        write_json(self.state / "storage-trust.json", {})
        write_json(
            self.state / "storage-demo.json",
            {
                "candidate": {"candidate_reference": self.candidate},
                "evaluation_reference": self.evaluation,
                "evaluation": {"report": {"holdout_digest": "6" * 64}},
            },
        )
        graph, _, _ = fixture()
        included = {
            "dataset-a",
            "runtime-shared",
            "policy-shared",
            "run-a-current",
            "model-a-current",
        }
        self.projection = {
            "graph": {
                "schema_version": 1,
                "assets": [asset for asset in graph["assets"] if asset["asset_id"] in included],
            }
        }
        self.changed_case = None

    def get(self, client, table, reference):
        if table == "holdout":
            raise Rejected("storage_read_rejected:42501")
        return b"controlled"

    def collect(self, metadata_client, review_client, **arguments):
        if arguments["candidate_reference"] == "0" * 64:
            if self.changed_case == "bypass":
                return self.projection
            raise Rejected("wrong" if self.changed_case == "wrong" else "storage_object_missing")
        if arguments["evaluation_reference"] == "0" * 64:
            raise Rejected("storage_object_missing")
        if arguments["expected"]["source_revision"] == "0" * 40:
            raise Rejected("inventory_candidate_build_binding")
        if arguments["owners"]["dataset"] == "unknown-owner":
            raise Rejected("inventory_unknown_owner")
        for client, tables in (
            (metadata_client, ("manifests", "lineage")),
            (review_client, ("candidates", "evaluations")),
        ):
            for table in tables:
                native.storage.get(client, table, "7" * 64)
        if self.changed_case == "reads":
            native.storage.get(metadata_client, "train", "8" * 64)
        if self.changed_case == "file":
            write_json(self.state / "storage-demo.json", {"changed": True})
        return copy.deepcopy(self.projection)

    def qualify(self, **overrides):
        defaults = {
            "validate": {"return_value": {"container_id": "owned"}},
            "source_fingerprint": {"return_value": self.fingerprint},
            "command": {"return_value": self.revision},
            "resolve_image": {"return_value": self.image},
            "metadata_snapshot": {
                "return_value": {"evaluations": {"objects": 2, "digest": "a" * 64}}
            },
        }
        defaults.update(overrides)
        with contextlib.ExitStack() as stack:
            for name, settings in defaults.items():
                stack.enter_context(patch.object(native, name, **settings))
            stack.enter_context(patch.object(native.storage, "get", side_effect=self.get))
            stack.enter_context(
                patch.object(native.candidate_lineage, "collect", side_effect=self.collect)
            )
            return native.qualify(ROOT, self.state, self.image)

    def test_all_native_checks_and_no_promotion(self):
        result = self.qualify()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(len(result["cases"]), 10)
        self.assertFalse(result["release_ready"])
        self.assertEqual(result["full_M19"], "inconclusive")

    def test_negative_bypass_wrong_reason_and_unexpected_reads(self):
        for changed, reason in (
            ("bypass", "negative_bypass"),
            ("wrong", "wrong_rejection"),
            ("reads", "unexpected_reads"),
        ):
            self.changed_case = changed
            with self.subTest(changed=changed), self.assertRaisesRegex(Rejected, reason):
                self.qualify()

    def test_changed_sql_or_materials_are_rejected(self):
        with self.assertRaisesRegex(Rejected, "sql_changed"):
            self.qualify(metadata_snapshot={"side_effect": [{"before": True}, {"after": True}]})
        cases = {
            "source_fingerprint": [self.fingerprint, "changed"],
            "command": [self.revision, "changed"],
            "resolve_image": [self.image, "changed"],
            "validate": [{"container_id": "owned"}, {"container_id": "other"}],
        }
        for name, values in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(Rejected, "inputs_changed"):
                self.qualify(**{name: {"side_effect": values}})
        self.changed_case = "file"
        with self.assertRaisesRegex(Rejected, "inputs_changed"):
            self.qualify()

    def test_wrong_impact_cannot_be_accepted(self):
        with patch.object(native.asset_graph, "assess", return_value={"impacted_assets": []}):
            with self.assertRaisesRegex(Rejected, "impact_mismatch"):
                self.qualify()

    def test_actual_sql_snapshot_identity_bounds_and_hashes(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.execute.return_value.fetchall.return_value = [("a" * 64,)]
        connection.execute.return_value.fetchone.side_effect = [("ml_publisher",), ("ml_promoter",)]
        with patch.object(native.storage, "connect", return_value=connection):
            result = native.metadata_snapshot(self.state)
        self.assertEqual(set(result), {"manifests", "lineage", "candidates", "evaluations"})
        self.assertEqual(
            result["evaluations"], {"objects": 1, "digest": digest(canonical([("a" * 64,)]))}
        )
        connection.execute.return_value.fetchone.side_effect = [("wrong",)]
        with patch.object(native.storage, "connect", return_value=connection):
            with self.assertRaisesRegex(Rejected, "sql_identity"):
                native.metadata_snapshot(self.state)
        connection.execute.return_value.fetchone.side_effect = [("ml_publisher",)]
        connection.execute.return_value.fetchall.return_value = [("a" * 64,)] * 2001
        with patch.object(native.storage, "connect", return_value=connection):
            with self.assertRaisesRegex(Rejected, "fixture_too_large"):
                native.metadata_snapshot(self.state)

    def invoke(self, failure=None, report=None):
        with (
            patch.object(native.sys, "argv", ["native", "--state", str(self.state)]),
            patch.object(native, "qualify", side_effect=failure, return_value=report),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            return native.main()

    def test_cli_replaces_stale_pass_with_fail_and_publishes_success(self):
        output = self.state / "evidence/candidate-lineage-native.json"
        write_json(output, {"status": "pass", "release_ready": True})
        self.assertEqual(self.invoke(failure=Rejected("controlled")), 1)
        self.assertEqual(read_json(output), {"status": "fail", "release_ready": False})
        report = {
            "scope": "controlled",
            "status": "pass",
            "cases": [],
            "full_M19": "inconclusive",
            "release_ready": False,
        }
        self.assertEqual(self.invoke(report=report), 0)
        self.assertEqual(read_json(output), report)

    def test_cli_does_not_write_outside_state_or_leak_write_errors(self):
        with (
            patch.object(native, "safe_child", side_effect=Rejected("symlink_rejected")),
            patch.object(native, "write_json") as writer,
        ):
            self.assertEqual(self.invoke(), 1)
            writer.assert_not_called()
        with patch.object(native, "write_json", side_effect=OSError("private path unavailable")):
            self.assertEqual(self.invoke(), 1)

    def test_real_module_entrypoint_rejects_missing_storage_without_sql(self):
        with (
            patch.object(native.sys, "argv", ["native", "--state", str(self.state)]),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as stopped,
        ):
            runpy.run_path(str(Path(native.__file__)), run_name="__main__")
        self.assertEqual(stopped.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
