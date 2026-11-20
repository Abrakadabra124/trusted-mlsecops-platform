"""Offline shared job contracts. Docker, hosted identity and private transport are controlled."""

import os
import shutil
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops import ci_transfer
from mlsecops.contracts import Rejected, bounded_read, digest, read_json, write_json
from scripts import ci_consumer_native as driver
from scripts import ci_consumer_native_qualification as native
from scripts import ci_shared_job as job
from scripts import m18_shared_retention as retention
from scripts import m18_shared_retention_qualification as signed_fixture

SOURCE = dict(source_revision="a" * 40, source_fingerprint="b" * 64, image_id="sha256:" + "c" * 64)
RUN = dict(repository=ci_transfer.REPOSITORY, run_id=123456, run_attempt=1, producer_job="producer")
LOCAL = RUN | {"producer_job": "shared"}
ORIGIN = dict(workspace_id="a" * 32, container_id="d" * 64, offline_pin="e" * 64)


class SharedJobTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.output = self.root / "public-output"
        self.enterContext(
            patch.dict(
                os.environ,
                GITHUB_REPOSITORY=RUN["repository"],
                GITHUB_RUN_ID="123456",
                GITHUB_RUN_ATTEMPT="1",
                GITHUB_JOB="shared",
                GITHUB_SHA=SOURCE["source_revision"],
                GITHUB_OUTPUT=str(self.output),
                M12_EARLY_SHA256="previous",
            )
        )
        self.args = dict(
            api=object(),
            source_api=object(),
            trust_key_path=self.root / "external.pem",
            key=bytes(range(32)),
            trusted_public="controlled public",
            run_owner=RUN.copy(),
            source=SOURCE.copy(),
        )
        self.host = self.enterContext(patch.object(driver, "hosted"))
        self.guard = Mock()
        self.enterContext(
            patch.dict(
                sys.modules, {"scripts.ci_campaign_guard": SimpleNamespace(authorize=self.guard)}
            )
        )
        self.source = self.enterContext(patch.object(driver, "source", return_value=SOURCE.copy()))
        self.docker = native.DockerBoundary()
        self.enterContext(patch.object(driver.storage_bootstrap, "docker", self.docker.docker))
        self.enterContext(patch.object(driver.cluster, "command", return_value=""))
        self.enterContext(
            patch("subprocess.Popen", side_effect=AssertionError("no infrastructure"))
        )
        self.enterContext(patch("socket.socket", side_effect=AssertionError("no network")))
        self.owner = dict(
            run_owner=RUN.copy(),
            expected=SOURCE.copy(),
            freeze_pin="1" * 64,
            freeze={p: "2" * 64 for p in driver.transfer.delivery.FILES},
        )
        self.origin = ORIGIN.copy()
        self.view = self.root / ".runtime/frozen-transfers/reader-controlled"
        self.prepared = dict(
            workspace_id="f" * 32,
            manifest_sha256="3" * 64,
            ciphertext_sha256="4" * 64,
            handling="private",
            release_ready=False,
            storage_imported=False,
        )
        self.sealed = {
            "candidate-shared": dict(
                context={"phase": "M11-M12"}, manifest_sha256="3" * 64, ciphertext_sha256="4" * 64
            )
        }
        self.after = lambda: None
        self.keep = False
        self.enterContext(
            patch.dict(
                sys.modules,
                {"scripts.ci_campaign_handoff": SimpleNamespace(open_consumer=self.handoff)},
            )
        )
        self.consumer = self.enterContext(
            patch.object(driver, "consumer", side_effect=self.consume)
        )
        self.replay = self.enterContext(
            patch.object(retention, "replay", side_effect=self.replay_after)
        )
        self.receipt = {"proposal_reference": "5" * 64}
        self.opens = 0

    @contextmanager
    def handoff(self, root, **args):
        self.assertEqual(root, self.root)
        self.assertEqual(
            args, {k: v for k, v in self.args.items() if k != "source_api"} | {"job": "shared"}
        )
        self.opens += 1
        native.workspace(self.view, "f" * 32)
        try:
            yield self.view, self.prepared, dict(owner=self.owner, origin=self.origin), self.sealed
        finally:
            if not self.keep:
                (self.view / "workspace.json").unlink()
                self.view.rmdir()
            self.after()

    def consume(self, root, local, state, prepared, owner, packet, witness, summary, marker):
        self.assertEqual(witness.record["run_owner"], LOCAL)
        self.assertEqual(witness.record["source"], SOURCE)
        self.assertEqual(marker, ORIGIN)
        self.assertEqual(owner["run_owner"], RUN)
        self.assertNotEqual(witness.record["workspace_id"], prepared["workspace_id"])
        self.assertEqual(packet, self.sealed["candidate-shared"])
        self.assertEqual(
            os.environ["M11_PROPOSAL_SHA256"], owner["freeze"][driver.transfer.delivery.PROPOSAL]
        )
        self.assertNotIn("M12_EARLY_SHA256", os.environ)
        Path(os.environ["GITHUB_OUTPUT"]).write_text("private nested output")
        summary.update(cleanup=dict(sql=True, cluster=True), gate_counts=dict(M11=3, M12=5))
        return dict(
            arguments=owner
            | dict(
                report_pins={"M11": "6" * 64, "M12": "7" * 64},
                actual_pin="8" * 64,
                native_pin="9" * 64,
            ),
            index_pin="a" * 64,
            receipt=self.receipt,
            consumer_offline="b" * 64,
        )

    def replay_after(self, root, destination, **arguments):
        self.assertFalse(self.view.exists())
        self.assertEqual(arguments["run_owner"], RUN)
        return dict(receipt=self.receipt.copy(), release_ready=False)

    def execute(self):
        return job.run(self.root, **self.args)

    def test_local_job_and_original_run_are_checked_before_private_read_or_witness(self):
        for env in (
            dict(GITHUB_JOB="producer"),
            dict(GITHUB_RUN_ID="123"),
            dict(GITHUB_RUN_ATTEMPT="2"),
            dict(GITHUB_SHA="9" * 40),
            dict(GITHUB_REPOSITORY="other/repo"),
        ):
            with self.subTest(env=env), patch.dict(os.environ, env), self.assertRaises(Rejected):
                self.execute()
        for override in (dict(producer_job="shared"), dict(run_attempt=True)):
            with (
                self.subTest(owner=override),
                patch.dict(self.args, run_owner=RUN | override),
                self.assertRaises(Rejected),
            ):
                self.execute()
        self.source.return_value = SOURCE | {"image_id": "sha256:" + "0" * 64}
        with self.assertRaises(Rejected):
            self.execute()
        self.assertEqual(self.opens, 0)
        self.assertFalse((self.root / ".runtime").exists())

    def test_signed_authority_used_for_consumer_local_identity_used_only_for_cleanup(self):
        result = self.execute()
        self.assertEqual(result["arguments"]["run_owner"], RUN)
        self.assertEqual(result["cleanup_owner"], LOCAL)
        self.assertEqual(result["origin"], ORIGIN)
        self.assertNotEqual(result["consumer_offline"], ORIGIN["offline_pin"])
        self.assertEqual(result["cleanup"], dict(sql=True, cluster=True))
        self.assertEqual(result["gate_counts"], dict(M11=3, M12=5))
        self.assertIs(result["release_ready"], False)
        self.assertEqual(os.environ["M12_EARLY_SHA256"], "previous")
        self.assertFalse(self.output.exists())
        self.replay.assert_called_once_with(
            self.root, result["destination"], index_pin=result["index_pin"], **result["arguments"]
        )
        with self.assertRaises(FileExistsError):
            self.execute()
        self.assertEqual(self.opens, 1)

    def test_remote_workflow_refusal_precedes_private_reads_and_local_resource_claim(self):
        self.guard.side_effect = Rejected("controlled public guard rejection")
        with self.assertRaises(Rejected):
            self.execute()
        self.guard.assert_called_once_with(
            self.root,
            source_api=self.args["source_api"],
            job="shared",
            run_owner=RUN,
            source=SOURCE,
        )
        self.source.assert_not_called()
        self.assertEqual(self.opens, 0)
        self.assertFalse((self.root / ".runtime").exists())

    def test_signed_record_wrong_producer_refuses_before_gate(self):
        self.owner["run_owner"]["producer_job"] = "shared"
        with self.assertRaises(Rejected):
            self.execute()
        self.consumer.assert_not_called()

    def test_wrong_packet_phase_refuses_before_gate(self):
        self.sealed["candidate-shared"]["context"]["phase"] = "M13"
        with self.assertRaises(Rejected):
            self.execute()
        self.consumer.assert_not_called()

    def test_foreign_materialization_pins_refused(self):
        self.prepared["manifest_sha256"] = "0" * 64
        with self.assertRaises(Rejected):
            self.execute()
        self.consumer.assert_not_called()

    def test_workspace_marker_must_match_private_materialization(self):
        self.prepared["workspace_id"] = "1" * 32
        with self.assertRaises(Rejected):
            self.execute()
        self.consumer.assert_not_called()

    def test_origin_workspace_collision_refused_before_local_sql(self):
        self.origin["workspace_id"] = self.prepared["workspace_id"]
        with self.assertRaises(Rejected):
            self.execute()
        self.consumer.assert_not_called()

    def test_materializer_must_remove_its_view_before_replay(self):
        self.keep = True
        with self.assertRaises(Rejected):
            self.execute()
        self.replay.assert_not_called()

    def test_inaccessible_view_cannot_prove_teardown(self):
        original = os.lstat

        def unreadable(path, *args, **kwargs):
            if str(path) == str(self.view):
                raise PermissionError("denied")
            return original(path, *args, **kwargs)

        self.after = lambda: self.enterContext(patch.object(os, "lstat", unreadable))
        with self.assertRaises(PermissionError):
            self.execute()
        self.replay.assert_not_called()

    def test_consumer_cannot_substitute_local_cleanup_owner_in_retention_arguments(self):
        def changed(*args):
            info = self.consume(*args)
            info["arguments"]["run_owner"] = LOCAL
            return info

        self.consumer.side_effect = changed
        with self.assertRaises(Rejected):
            self.execute()
        self.replay.assert_not_called()

    def test_gate_failure_and_failed_cleanup_preserve_first_exception(self):
        self.consumer.side_effect = KeyboardInterrupt("controlled interruption")
        with (
            patch.object(driver.recovery.Recovery, "cleanup", side_effect=OSError("disk")),
            self.assertRaises(KeyboardInterrupt) as error,
        ):
            self.execute()
        self.assertTrue(error.exception.__notes__)
        self.assertFalse(self.view.exists())
        self.replay.assert_not_called()

    def test_post_exit_receipt_divergence_refuses_result(self):
        self.replay.side_effect = lambda *a, **k: dict(receipt={}, release_ready=False)
        with self.assertRaises(Rejected):
            self.execute()
        self.replay.assert_called_once()

    def test_changed_final_source_refuses_result(self):
        def change():
            self.source.return_value = SOURCE | {"image_id": "sha256:" + "0" * 64}

        self.after = change
        with self.assertRaises(Rejected):
            self.execute()

    def test_changed_run_during_replay_cannot_replace_original_expectation(self):
        def change():
            self.args["run_owner"]["run_attempt"] = 2
            os.environ["GITHUB_RUN_ATTEMPT"] = "2"

        self.after = change
        with self.assertRaises(Rejected):
            self.execute()

    def test_cleanup_reloads_owned_ids_and_rejects_foreign_durable_record(self):
        result = self.execute()
        self.assertEqual(
            job.cleanup(
                self.root, source_api=self.args["source_api"], run_owner=RUN, source=SOURCE
            ),
            result["cleanup"],
        )
        local = result["destination"].parent.parent
        path = local / driver.recovery.RECORD
        record = read_json(path)
        record["run_owner"] = RUN.copy()
        write_json(path, record)
        with (
            patch.object(
                driver.recovery.Recovery, "cleanup", side_effect=AssertionError("foreign cleanup")
            ),
            self.assertRaises(Rejected),
        ):
            job.cleanup(self.root, source_api=self.args["source_api"], run_owner=RUN, source=SOURCE)

    def test_partial_cleanup_blocks_success(self):
        with (
            patch.object(driver.recovery.Recovery, "cleanup", return_value={"sql": True}),
            self.assertRaises(Rejected),
        ):
            self.execute()


class RetainedFlowTests(unittest.TestCase):
    """Ordinary driver, recovery, signatures, capture of retained bytes and offline replay."""

    @classmethod
    def setUpClass(cls):
        signed_fixture.SharedRetentionTests.setUpClass()
        cls.addClassCleanup(signed_fixture.SharedRetentionTests.doClassCleanups)

    def setUp(self):
        self.fx = signed_fixture.SharedRetentionTests()
        write_fixture = self.fx.file

        def shared_evidence(name, value):
            if name == driver.shared.EARLY:
                value["owner"]["runner"]["GITHUB_JOB"] = "shared"
                value["owner"]["workspace"] = "f" * 32
            return write_fixture(name, value)

        with patch.object(self.fx, "file", shared_evidence):
            self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.root = self.fx.root.resolve()
        self.owner = {k: self.fx.pins[k] for k in ("expected", "freeze_pin", "freeze")} | dict(
            run_owner=RUN
        )
        self.source = {k: self.owner["expected"][k] for k in driver.transfer.delivery.SOURCE}
        self.enterContext(
            patch.dict(
                os.environ,
                GITHUB_JOB="shared",
                GITHUB_RUN_ID="123456",
                GITHUB_RUN_ATTEMPT="1",
                GITHUB_REPOSITORY=RUN["repository"],
                GITHUB_SHA=self.source["source_revision"],
            )
        )
        self.enterContext(patch.object(driver, "hosted"))
        self.enterContext(
            patch.dict(
                sys.modules, {"scripts.ci_campaign_guard": SimpleNamespace(authorize=Mock())}
            )
        )
        self.enterContext(patch.object(driver, "source", return_value=self.source))
        self.enterContext(
            patch("subprocess.Popen", side_effect=AssertionError("no infrastructure"))
        )
        self.enterContext(patch("socket.socket", side_effect=AssertionError("no network")))
        self.enterContext(
            patch.dict(
                sys.modules,
                {"scripts.ci_campaign_handoff": SimpleNamespace(open_consumer=self.handoff)},
            )
        )
        self.corrupt_on_exit = False
        sql = driver.storage_bootstrap
        self.spec = dict(
            workspace_id="f" * 32,
            config_digest="c" * 64,
            name="consumer",
            volume="consumer-data",
            network="consumer-net",
            port=15440,
        )
        self.docker = native.DockerBoundary()
        self.enterContext(patch.object(sql, "docker", self.docker.docker))
        self.enterContext(patch.object(driver.recovery.storage_pki, "initialize"))
        self.enterContext(patch.object(sql, "specification", return_value=(self.spec, {})))
        self.enterContext(
            patch.object(
                sql, "validate", side_effect=lambda state: read_json(state / "storage.json")
            )
        )
        self.enterContext(patch.object(sql, "bootstrap", self.sql))
        self.enterContext(patch.object(driver, "import_candidate", self.imported))
        self.enterContext(
            patch.object(
                driver.cluster,
                "command",
                side_effect=lambda args: (
                    driver.cluster.NAME if "c" * 64 in self.docker.rows else ""
                ),
            )
        )
        self.enterContext(patch.object(driver.cluster, "bootstrap", self.cluster))
        self.enterContext(patch.object(driver.cluster, "validate_cluster"))
        self.enterContext(patch.object(driver.kube_storage, "bootstrap"))
        self.enterContext(
            patch.object(
                driver.shared,
                "capture",
                lambda root, state, img: read_json(state / driver.shared.EARLY),
            )
        )
        self.enterContext(
            patch.object(
                driver.shared,
                "late",
                lambda root, state, img, pin: read_json(state / driver.shared.FULL),
            )
        )
        self.enterContext(
            patch.object(
                driver.acceptance,
                "report",
                lambda gate, profile, root, *, state: read_json(state / f"evidence/{gate}.json"),
            )
        )

    @contextmanager
    def handoff(self, root, **args):
        self.assertEqual((args["run_owner"], args["job"]), (RUN, "shared"))
        values = self.fx.fx.fx.values
        issued = values["captured_at"]
        ctx = driver.bridge._context(
            self.owner,
            "M11-M12",
            "4" * 64,
            issued,
            min(issued + 1800, values["proposal_expires_at"]),
        )
        pins = dict(manifest_sha256="1" * 64, ciphertext_sha256="2" * 64)
        with tempfile.TemporaryDirectory(dir=root / ".runtime") as tmp:
            self.view = Path(tmp)
            shutil.copytree(self.fx.state, self.view, dirs_exist_ok=True)
            native.workspace(self.view, "f" * 32)
            yield (
                self.view,
                pins | dict(workspace_id="f" * 32),
                dict(owner=self.owner, origin=ORIGIN),
                {"candidate-shared": pins | dict(context=ctx)},
            )
        if self.corrupt_on_exit:
            target = root / job.LOCAL / driver.recovery.DIRECTORY / "retained"
            (target / driver.transfer.CAS / self.fx.pins["actual_pin"]).write_bytes(b"changed")

    def sql(self, state, *, port):
        self.assertEqual((state, port), (self.view, 15440))
        sql = driver.storage_bootstrap
        self.docker.add(
            "b" * 64, "consumer", {sql.WORKSPACE_LABEL: "f" * 32, sql.CONFIG_LABEL: "c" * 64}
        )
        write_json(state / "storage.json", self.spec | {"container_id": "b" * 64})

    def imported(self, root, state, **args):
        self.assertEqual(args["run_owner"], RUN)
        self.assertEqual(args["storage_pin"], digest(bounded_read(state / "storage.json")))
        return dict(
            status="pass",
            proposal_reference=args["expected"]["proposal_reference"],
            workspace_id=args["expected_workspace_id"],
            storage_pin=args["storage_pin"],
        )

    def cluster(self, state):
        self.docker.add(
            "c" * 64,
            driver.cluster.NODE,
            {
                driver.recovery.KIND_LABEL: driver.cluster.NAME,
                "io.x-k8s.kind.role": "control-plane",
            },
        )
        (state / "kubeconfig").write_bytes(b"controlled-kubeconfig")

    def execute(self):
        return job.run(
            self.root,
            source_api=object(),
            api=object(),
            trust_key_path=self.root / "external.pem",
            key=bytes(range(32)),
            trusted_public="controlled",
            run_owner=RUN,
            source=self.source,
        )

    def test_ordinary_post_teardown_replay_can_reopen_all_retained_private_preimages(self):
        result = self.execute()
        self.assertFalse(self.view.exists())
        self.assertFalse(self.docker.rows["b" * 64]["State"]["Running"])
        self.assertNotIn("c" * 64, self.docker.rows)
        self.assertEqual(result["arguments"], self.fx.pins | dict(run_owner=RUN))
        self.assertEqual(
            result["replay"],
            retention.replay(
                self.root,
                result["destination"],
                index_pin=result["index_pin"],
                **result["arguments"],
            ),
        )
        self.assertEqual(result["cleanup_owner"], LOCAL)
        self.assertEqual(result["origin"], ORIGIN)
        self.assertNotIn(ORIGIN["container_id"], self.docker.rows)
        record = read_json(result["destination"].parent / "recovery.json")
        self.assertEqual(record["run_owner"], LOCAL)
        self.assertEqual(record["sql"]["spec"]["workspace_id"], "f" * 32)
        self.assertEqual(set(record["sql"]["containers"]), {"b" * 64})

    def test_tamper_after_view_exit_invalidates_previous_in_view_replay(self):
        self.corrupt_on_exit = True
        with self.assertRaises(Rejected):
            self.execute()
        self.assertFalse(self.view.exists())
        self.assertFalse(self.docker.rows["b" * 64]["State"]["Running"])


if __name__ == "__main__":
    unittest.main()
