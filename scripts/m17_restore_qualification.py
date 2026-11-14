"""Controlled tests for the native restore adapter; no storage, network or model workers."""

import copy
import importlib.metadata
import io
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from mlsecops import prediction_protocol, signing, storage_backup, storage_schema, storage_snapshot
from mlsecops.contracts import Rejected, canonical, digest, write_json
from scripts import m17_restore_native as adapter
from scripts import promotion_recovery_qualification as promotion_fixtures


class Restore(unittest.TestCase):
    def setUp(self):
        self.real_create = storage_backup.create
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.state = self.root / ".runtime"
        self.target = self.state / "recovery" / "fresh"
        self.start = datetime.now(UTC)
        self.policy = {"repeat_tolerance": 0.000001}
        self.public = {
            role: signing.create_key(self.state / "keys" / (role + ".pem"))
            for role in signing.ROLES
        }
        self.trust = {k: self.public[k] for k in ("curator", "evaluator")}
        self.trust["source_approval_digest"] = "a" * 64
        self.model = b"evaluated model"
        self.image = "sha256:" + "a" * 64
        self.metadata = dict(
            model_digest=digest(self.model),
            image_id=self.image,
            lineage_id="3" * 64,
            dataset_id="2" * 64,
        )
        self.dataset = dict(
            dataset_reference="d" * 64,
            source_approval_digest="a" * 64,
            lineage_id="3" * 64,
            dataset_id="2" * 64,
        )
        self.training_scores = [0.25] * 1000
        self.metadata["validation_probability_digest"] = digest(canonical(self.training_scores))
        self.record = dict(
            schema_version=1,
            model_object=digest(self.model),
            metadata_object=digest(canonical(self.metadata)),
            scores_object=self.metadata["validation_probability_digest"],
            dataset_reference="d" * 64,
        )
        self.candidate = digest(canonical(self.record))
        self.evaluation = dict(
            candidate_reference=self.candidate,
            dataset_reference="d" * 64,
            lineage_id="3" * 64,
            report={"model_digest": digest(self.model)},
        )
        self.demo = dict(
            candidate=dict(candidate_reference=self.candidate, metadata=self.metadata),
            dataset=self.dataset,
            evaluation_reference="e" * 64,
            evaluation=self.evaluation,
        )
        for path, obj in (
            ("trusted-keys.json", self.public),
            ("storage-trust.json", self.trust),
            ("storage-demo.json", self.demo),
        ):
            write_json(self.state / path, obj)
        write_json(self.root / "policies/local-cpu.json", self.policy)
        self.demo_pin = digest((self.state / "storage-demo.json").read_bytes())
        self.keys_pin = digest(canonical(self.public))
        self.markers = [self.marker("a", 15439), self.marker("b", 15440)]
        self.archive = b"PGDMP-controlled"
        self.tables = {
            k: dict(rows=0, bytes=0, invalid=0, sha256=digest(b"")) for k in storage_schema.TABLES
        }
        self.tables["candidates"] = dict(rows=1, bytes=1, invalid=0, sha256="a" * 64)
        self.statement = dict(
            schema_version=1,
            format="postgres-custom-data-only",
            started_at=(self.start - timedelta(seconds=41)).isoformat(),
            completed_at=(self.start - timedelta(seconds=20)).isoformat(),
            recovery_point_at=(self.start - timedelta(seconds=40)).isoformat(),
            source_workspace="a" * 32,
            image=storage_backup.IMAGE,
            migration=storage_backup.migration(),
            policy_digest=digest(canonical(self.policy)),
            trusted_keys_digest=self.keys_pin,
            archive=dict(name="data.dump", sha256=digest(self.archive), bytes=len(self.archive)),
            tables=self.tables,
        )
        self.backup_pin = digest(canonical(self.statement))
        self.directory = self.state / "backups" / self.backup_pin
        write_json(
            self.directory / "manifest.json",
            signing.sign(self.statement, "storage-backup", self.state / "keys/trust.pem"),
        )
        (self.directory / "data.dump").write_bytes(self.archive)
        self.mock(adapter, "hosted")
        self.client_params = self.mock(
            adapter.storage, "connection_parameters", side_effect=self.client_parameters
        )
        self.mock(adapter.storage, "get", return_value=canonical(self.training_scores))
        self.mock(adapter.sandbox, "resolve_image", return_value=self.image)
        self.mock(
            adapter.storage_bootstrap,
            "validate",
            side_effect=lambda p: self.markers[p == self.target],
        )
        self.mock(
            adapter.storage_bootstrap,
            "inspect",
            return_value={"State": {"Running": False}, "Id": self.markers[0]["container_id"]},
        )
        self.backup = self.mock(
            adapter.storage_backup,
            "create",
            return_value=dict(
                backup_id=self.backup_pin, directory=str(self.directory), tables=self.tables
            ),
        )
        self.stop = self.mock(adapter, "stop_owned")
        self.restore = self.mock(adapter.storage_restore, "restore", side_effect=self.restoring)
        self.mock(adapter.storage_restore, "ledger", return_value=self.tables)
        self.load = self.mock(
            adapter.storage_pipeline, "load_candidate", side_effect=self.load_candidate
        )
        self.dataset_read = self.mock(
            adapter.storage_dataset, "read_dataset", side_effect=self.read_dataset
        )
        self.eval_read = self.mock(
            adapter.storage_pipeline, "read_evaluation", return_value=self.evaluation
        )
        self.worker = self.mock(adapter.sandbox, "run_worker", side_effect=self.predict)
        self.mock(
            adapter,
            "now",
            side_effect=[(self.start + timedelta(seconds=i)).isoformat() for i in (0, 2, 17)],
        )
        self.mock(adapter, "monotonic_ns", side_effect=[10**9, 18 * 10**9])

    def mock(self, module, name, **opts):
        return self.enterContext(patch.object(module, name, **opts))

    def marker(self, char, port):
        return dict(
            workspace_id=char * 32,
            container_id=char * 64,
            network_id=char * 64,
            volume=char + "-data",
            port=port,
            name=char,
        )

    def restoring(self, root, directory, target, public, port, *, expected_backup_id):
        self.stop.assert_called_once_with(self.state)
        self.assertEqual(
            (directory, public, expected_backup_id), (self.directory, self.public, self.backup_pin)
        )
        self.target.mkdir(parents=True)
        write_json(
            target / "trusted-keys.json",
            {k: signing.create_key(target / (k + ".pem")) for k in signing.ROLES},
        )
        write_json(target / "recovered-public-keys.json", public)
        receipt = dict(
            schema_version=self.statement["schema_version"],
            backup_id=self.backup_pin,
            source_workspace="a" * 32,
            target_workspace="b" * 32,
            container_id="b" * 64,
            port=port,
            restored_at=(self.start + timedelta(seconds=5)).isoformat(),
            elapsed_seconds=5,
            tables=self.tables,
            status="storage-restored-not-release-ready",
            release_ready=False,
        )
        if "promotion" in self.statement:
            receipt["promotion"] = self.statement["promotion"]
        write_json(target / "recovery.json", receipt)
        return {**receipt, "reused": False}

    def load_candidate(self, client, reference, policy):
        self.assertEqual(reference, self.candidate)
        return self.record, self.metadata, self.model

    def client_parameters(self, directory):
        return dict(
            host="127.0.0.1",
            port=self.markers[directory.parents[1] == self.target]["port"],
            user="ml_" + directory.name,
        )

    def read_dataset(self, client, reference, policy, public, approval, selected):
        self.assertEqual(
            (reference, public, approval), ("d" * 64, self.public["curator"], "a" * 64)
        )
        return {"validation": [{"features": [0.1] * 6}] * 1000}, {}, self.dataset

    def predict(self, image, request):
        self.assertEqual(image, self.image)
        self.assertEqual(prediction_protocol.validate_request(request), self.model)
        scan = dict(
            format="onnx",
            policy_version="linear-onnx-v2",
            inspected_nodes=2,
            unsupported=0,
            skipped=0,
            errors=0,
            onnx_version=importlib.metadata.version("onnx"),
        )
        return prediction_protocol.response(request, [0.25] * len(request["features"]), scan), {
            "image_id": image
        }

    def capture(self):
        return adapter.capture(
            self.root,
            self.state,
            self.target,
            self.image,
            demo_pin=self.demo_pin,
            keys_pin=self.keys_pin,
        )

    def replay(self, packet):
        return adapter.replay(
            packet,
            backup_pin=self.backup_pin,
            demo_pin=self.demo_pin,
            public=self.public,
            policy=self.policy,
        )

    def test_full_capture_replays_after_native_transports_are_gone(self):
        packet = self.capture()
        result = self.replay(packet)
        self.assertEqual(
            (
                result["rto_seconds"],
                result["rpo_seconds"],
                result["golden_rows"],
                result["max_error"],
            ),
            (17, 42, 1000, 0),
        )
        self.assertEqual(result["model_sha256"], digest(self.model))
        self.assertFalse(result["release_ready"])
        for action in (self.load, self.dataset_read, self.eval_read):
            self.assertEqual(
                [c.args[0].parents[1] for c in action.call_args_list], [self.state, self.target]
            )
        self.assertEqual(self.worker.call_count, 2)
        self.backup.assert_called_once_with(
            self.root, self.state, include_promotion=False, recovery_point=True
        )

    def scheduled(self):
        self.statement.update(
            schema_version=2, promotion=promotion_fixtures.PromotionRecoveryContracts().fixture()
        )
        self.backup_pin = digest(canonical(self.statement))
        self.directory = self.state / "backups" / self.backup_pin
        write_json(
            self.directory / "manifest.json",
            signing.sign(self.statement, "storage-backup", self.state / "keys/trust.pem"),
        )
        (self.directory / "data.dump").write_bytes(self.archive)

    def consume(self):
        return adapter.capture(
            self.root,
            self.state,
            self.target,
            self.image,
            demo_pin=self.demo_pin,
            keys_pin=self.keys_pin,
            backup_pin=self.backup_pin,
        )

    def test_scheduled_v2_restores_exact_external_pin_without_second_snapshot(self):
        self.scheduled()
        packet = self.consume()
        self.backup.assert_not_called()
        self.assertEqual(packet["receipt"]["promotion"], self.statement["promotion"])
        self.assertEqual(self.replay(packet)["backup_id"], self.backup_pin)

    def test_scheduled_archive_corruption_or_legacy_version_refused_before_outage(self):
        with self.assertRaises(Rejected):
            self.consume()
        self.scheduled()
        (self.directory / "data.dump").write_bytes(b"PGDMPbad")
        with self.assertRaises(Rejected):
            self.consume()
        self.stop.assert_not_called()
        self.restore.assert_not_called()
        self.backup.assert_not_called()

    def test_signed_scheduled_backup_from_other_workspace_rejected_before_outage(self):
        self.statement["source_workspace"] = "9" * 32
        self.scheduled()
        with self.assertRaisesRegex(Rejected, "backup_pin"):
            self.consume()
        self.backup.assert_not_called()
        self.stop.assert_not_called()

    def test_timer_cli_requests_signed_point_only_when_selected(self):
        for flag in ([], ["--recovery-point"]):
            with (
                patch.object(
                    sys,
                    "argv",
                    ["storage_backup", "--state", str(self.state), "--include-promotion", *flag],
                ),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(storage_backup.main(), 0)
            options = self.backup.call_args.kwargs
            self.assertTrue(options["include_promotion"])
            self.assertEqual(options.get("recovery_point", False), bool(flag))

    def test_preflight_refuses_reuse_or_wrong_external_input_before_backup(self):
        self.target.mkdir(parents=True)
        with self.assertRaises(Rejected):
            self.capture()
        self.target.rmdir()
        self.demo_pin = "f" * 64
        with self.assertRaises(Rejected):
            self.capture()
        self.backup.assert_not_called()
        self.stop.assert_not_called()

    def test_target_candidate_correct_but_wrong_evaluation_refuses_result(self):
        self.eval_read.side_effect = [
            self.evaluation,
            {**self.evaluation, "candidate_reference": "0" * 64},
        ]
        with self.assertRaises(Rejected):
            self.capture()

    def test_target_sharing_source_volume_rejected(self):
        self.markers[1]["volume"] = self.markers[0]["volume"]
        with self.assertRaises(Rejected):
            self.capture()

    def test_restored_evaluation_client_on_foreign_sql_port_is_refused_before_read(self):
        def redirected(directory):
            params = self.client_parameters(directory)
            if directory == self.target / "storage-clients/promoter":
                params["port"] = 15455
            return params

        self.client_params.side_effect = redirected
        with self.assertRaisesRegex(Rejected, "client_endpoint"):
            self.capture()
        self.assertEqual(self.eval_read.call_count, 1)

    def test_packet_refuses_changed_golden_subject_clock_pin_and_ledger(self):
        packet = self.capture()
        for change in (
            lambda p: p["restored"]["scores"].__setitem__(1, 0.9),
            lambda p: p["restored"].update(evaluation_reference="1" * 64),
            lambda p: p["restored"].update(features_sha256="1" * 64),
            lambda p: p["restored"].update(prediction_receipt=p["original"]["prediction_receipt"]),
            lambda p: p["target"].update(network_id=p["source"]["network_id"]),
            lambda p: p["receipt"].update(tables={}),
            lambda p: p.update(start_ns=p["finish_ns"] + 1),
            lambda p: p.update(finish_ns=p["start_ns"] + 901 * 10**9),
            lambda p: p.update(finished_at=(self.start + timedelta(seconds=901)).isoformat()),
            lambda p: p.update(started_at=(self.start - timedelta(hours=1)).isoformat()),
        ):
            value = copy.deepcopy(packet)
            change(value)
            with self.assertRaises(Rejected):
                self.replay(value)
        for kwargs in (
            {"backup_pin": "0" * 64},
            {"demo_pin": "0" * 64},
            {"public": {**self.public, "trust": self.public["curator"]}},
        ):
            with self.assertRaises(Rejected):
                adapter.replay(
                    packet,
                    **{
                        **dict(
                            backup_pin=self.backup_pin,
                            demo_pin=self.demo_pin,
                            public=self.public,
                            policy=self.policy,
                        ),
                        **kwargs,
                    },
                )

    def test_snapshot_clock_is_requested_from_the_export_transaction(self):
        @contextmanager
        def session(args, sql):
            self.assertIn("statement_timestamp()", sql)
            self.assertIn("pg_export_snapshot()", sql)
            yield (
                dict(
                    snapshot="00000001-00000002-1",
                    tables=self.tables,
                    promotion_absent=True,
                    recovery_point_at=self.statement["recovery_point_at"],
                ),
                None,
            )

        with patch.object(storage_snapshot, "json_session", side_effect=session):
            with storage_snapshot.snapshot("owned", recovery_point=True) as obs:
                self.assertEqual(obs["recovery_point_at"], self.statement["recovery_point_at"])

    def test_authority_guard_refuses_before_any_dump_even_for_measured_snapshot(self):
        @contextmanager
        def refused(args, query):
            self.assertIn("CASE WHEN to_regnamespace('ml_trust') IS NULL", query)
            yield None, None

        with (
            patch.object(storage_snapshot, "json_session", side_effect=refused),
            self.assertRaisesRegex(Rejected, "trust_authority_backup_forbidden"),
            storage_snapshot.snapshot("owned", recovery_point=True),
        ):
            self.fail("authority cannot be exported")

    def test_prediction_uses_rows_reread_from_target_storage(self):
        def changed_rows(*args):
            splits, manifest, statement = self.read_dataset(*args)
            if args[0].parents[1] == self.target:
                splits["validation"][0] = {"features": [0.9] * 6}
            return splits, manifest, statement

        self.dataset_read.side_effect = changed_rows
        with self.assertRaisesRegex(Rejected, "readback"):
            self.capture()

    def test_post_import_worker_image_mismatch(self):
        def wrong_image(*args):
            reply, execution = self.predict(*args)
            if self.worker.call_count == 2:
                execution["image_id"] = "sha256:" + "f" * 64
            return reply, execution

        self.worker.side_effect = wrong_image
        with self.assertRaisesRegex(Rejected, "worker_image"):
            self.capture()

    def test_matching_workers_that_disagree_with_evaluated_scores_refused_before_outage(self):
        def wrong_scores(*args):
            reply, execution = self.predict(*args)
            reply["predictions"][0]["score"] = 0.9
            return reply, execution

        self.worker.side_effect = wrong_scores
        with self.assertRaisesRegex(Rejected, "golden_parity"):
            self.capture()
        self.stop.assert_not_called()

    def test_live_source_cannot_count_as_offline_restore(self):
        adapter.storage_bootstrap.inspect.return_value["State"]["Running"] = True
        with self.assertRaisesRegex(Rejected, "source_online"):
            self.capture()

    def test_signed_point_must_be_inside_backup_window_and_recent_at_loss(self):
        packet = self.capture()
        for changes in (
            {"recovery_point_at": (self.start - timedelta(seconds=46)).isoformat()},
            {"recovery_point_at": (self.start - timedelta(seconds=1)).isoformat()},
            {
                "started_at": (self.start - timedelta(days=2)).isoformat(),
                "recovery_point_at": (self.start - timedelta(days=1, seconds=1)).isoformat(),
            },
            {"recovery_point_at": "2026-01-01"},
        ):
            statement = {**self.statement, **changes}
            envelope = signing.sign(statement, "storage-backup", self.state / "keys/trust.pem")
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                adapter.replay(
                    {**packet, "manifest": envelope},
                    backup_pin=digest(canonical(statement)),
                    demo_pin=self.demo_pin,
                    public=self.public,
                    policy=self.policy,
                )
        legacy = self.statement.copy()
        del legacy["recovery_point_at"]
        envelope = signing.sign(legacy, "storage-backup", self.state / "keys/trust.pem")
        self.assertEqual(
            storage_backup.verify_manifest(envelope, self.public, self.policy, moment=self.start),
            legacy,
        )
        with self.assertRaisesRegex(Rejected, "unmeasured_snapshot"):
            adapter.replay(
                {**packet, "manifest": envelope},
                backup_pin=digest(canonical(legacy)),
                demo_pin=self.demo_pin,
                public=self.public,
                policy=self.policy,
            )

    def test_real_backup_writer_signs_point_from_export_session(self):
        point = self.start - timedelta(seconds=10)
        observed = dict(
            snapshot="00000001-00000002-1", tables=self.tables, recovery_point_at=point.isoformat()
        )

        @contextmanager
        def session(name, *, include_promotion, recovery_point):
            self.assertTrue(recovery_point)
            self.assertFalse(include_promotion)
            yield observed

        with (
            patch.object(storage_backup, "validate", return_value=self.markers[0]),
            patch.object(
                storage_backup,
                "admin",
                side_effect=["f", "1:" + storage_backup.migration()["sha256"]],
            ),
            patch.object(storage_backup, "verify_configuration"),
            patch("mlsecops.promotion_state.require_legacy_backup_scope"),
            patch.object(storage_backup, "snapshot", side_effect=session),
            patch.object(storage_backup, "binary_command", return_value=self.archive),
            patch.object(
                storage_backup,
                "now",
                side_effect=[
                    (point - timedelta(seconds=2)).isoformat(),
                    (point + timedelta(seconds=2)).isoformat(),
                ],
            ),
        ):
            result = self.real_create(self.root, self.state, recovery_point=True)
        verified, archive = storage_backup.read_backup(
            Path(result["directory"]), self.public, self.policy
        )
        self.assertEqual(
            (archive, verified["recovery_point_at"]), (self.archive, observed["recovery_point_at"])
        )
        self.assertEqual(digest(canonical(verified)), result["backup_id"])
