"""Pre-freeze orchestration using real workspace keys and controlled runtime boundaries."""

import io
import os
import runpy
import sys
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from subprocess import CalledProcessError
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from mlsecops import signing, storage_pki
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from scripts import ci_campaign_publish as publisher
from scripts import ci_original_bootstrap as adapter
from scripts.ci_campaign_guard_qualification import SourceRun


class OriginalBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(TemporaryDirectory())).resolve()
        self.root = self.tmp / "repo"
        self.root.mkdir()
        policy = Path(__file__).resolve().parents[1] / "policies/local-cpu.json"
        write_json(self.root / "policies/local-cpu.json", read_json(policy))
        self.state = self.root / ".runtime"
        self.state.mkdir()  # ci_campaign_image.receive already removed its owned transfer directory.
        self.trust = self.tmp / "issuer.pem"
        self.original_public = signing.create_key(self.trust)
        self.run = SourceRun(self)
        self.env = self.run.env
        self.env.update(
            GITHUB_WORKSPACE=str(self.root),
            RUNNER_TEMP=str(self.tmp),
            PATH="fixture",
            GITHUB_OUTPUT="public-file",
            PRIVATE_TEST_SECRET="canary",
            M07_FRESH_WORKSPACE_ID="stale",
            R1_SCOPED_TRAINING="0",
            M21_START_SHA256="stale",
        )
        self.enterContext(patch.object(os, "environ", self.env))
        # SourceRun models only environ on guard.os. The real isolation context also uses devnull.
        self.enterContext(patch.object(adapter.guard.os, "devnull", os.devnull, create=True))
        self.enterContext(patch.object(Path, "cwd", return_value=self.root))
        self.receipt = self.run.source | dict(
            schema_version=1,
            archive_sha256="d" * 64,
            tar_sha256="e" * 64,
            archive_bytes=150,
            tar_bytes=500,
        )
        adapter.native.owner_record(self.root, self.env, create=True)
        self.events = []
        self.refs = dict(
            candidate_reference="1" * 64, evaluation_reference="2" * 64, dataset_reference="3" * 64
        )
        self.marker = None
        self.inventory = dict(
            docker_cpus=4, docker_memory_bytes=15 * 1024**3, disk_free_bytes=12 * 1024**3
        )
        self.enterContext(patch.object(adapter.bootstrap, "collect", return_value=self.inventory))
        self.install = self.replace(adapter.install_ci_tools, "main", lambda: self.event("tools"))
        self.start = self.replace(adapter.cluster_owner, "start", self.cluster_start)
        self.cluster_cleanup = self.replace(
            adapter.cluster_owner, "cleanup", lambda state: self.event("cluster-clean")
        )
        self.sql = self.replace(adapter.sql, "bootstrap", self.sql_start)
        self.replace(adapter.sql, "validate", lambda state: read_json(state / "storage.json"))
        self.stop = self.replace(
            adapter.recovery, "stop_owned", lambda state: self.event("sql-stop")
        )
        self.offline = self.replace(
            adapter.receipt, "offline_pin", lambda state: self.event("sql-offline")
        )
        self.connection = MagicMock()
        self.connection.__enter__.return_value.execute.return_value.fetchone.return_value = (
            "ml_publisher",
        )
        self.connect = self.replace(adapter.storage, "connect", lambda path: self.connection)
        self.begin = self.replace(adapter.controller_intake, "begin", self.intake_start)
        self.cli = self.replace(adapter.subprocess, "run", self.gate)
        self.replace(
            adapter.producer, "prepare", lambda *a, **kw: self.fail("bootstrap must not freeze")
        )

    def replace(self, module, name, operation):
        return self.enterContext(patch.object(module, name, side_effect=operation))

    def event(self, name):
        self.assertNotIn("PRIVATE_TEST_SECRET", os.environ)
        self.assertNotIn("CANDIDATE_PUBLIC_TOKEN", os.environ)
        self.assertEqual(os.environ["GITHUB_OUTPUT"], os.devnull)
        self.events.append(name)

    def cluster_start(self, root, state):
        self.event("cluster-start")
        self.assertEqual((root, state), (self.root, self.state))
        self.assertEqual(os.environ["PATH"].split(os.pathsep)[0], str(state / "bin"))
        self.assertEqual(read_json(state / "trusted-keys.json")["trust"], self.original_public)
        write_json(state / "cluster.json", dict(workspace_id=storage_pki.workspace_id(state)))
        (state / adapter.cluster_owner.WITNESS).mkdir()

    def sql_start(self, state):
        self.event("sql-start")
        self.marker = dict(workspace_id=storage_pki.workspace_id(state), container_id="7" * 64)
        write_json(state / "storage.json", self.marker)
        return dict(status="ready", container_id=self.marker["container_id"])

    def intake_start(self, root, state):
        self.event("M21-start")
        self.assertEqual((root, state), (self.root, self.state))
        path = state / adapter.controller_intake.START
        write_json(path, dict(owner={"workspace": self.marker["workspace_id"]}))
        return digest(path.read_bytes())

    def gate(self, args, *, cwd, env, check):
        name = args[args.index("--gate") + 1]
        self.event(name)
        self.assertEqual(cwd, self.root)
        self.assertTrue(check)
        output = self.state / "evidence" / (name + ".json")
        self.assertEqual(
            args,
            [
                sys.executable,
                "-B",
                "-W",
                "error",
                "-m",
                "mlsecops.acceptance",
                "--gate",
                name,
                "--state",
                str(self.state),
                "--output",
                str(output),
            ],
        )
        self.assertFalse(
            set(env) & {"PRIVATE_TEST_SECRET", "CANDIDATE_PUBLIC_TOKEN", "CANDIDATE_TRUST_FILE"}
        )
        self.assertEqual(env["GITHUB_OUTPUT"], os.devnull)
        inputs = dict(source_fingerprint=self.run.source["source_fingerprint"])
        report = dict(
            gate=name,
            profile="local-cpu",
            status="pass",
            exit_code=0,
            source_dirty=False,
            source_revision=self.run.source["source_revision"],
            input_digests=inputs,
        )
        if name == "M07":
            start = digest((self.state / adapter.controller_intake.START).read_bytes())
            self.assertEqual(env["M21_START_SHA256"], start)
            self.assertEqual(env["R1_SCOPED_TRAINING"], "1")
            self.assertEqual(env["M07_FRESH_WORKSPACE_ID"], self.marker["workspace_id"])
            self.assertEqual(
                read_json(self.state / "evidence/ci-producer-inputs.json"),
                dict(start=start, workspace=self.marker["workspace_id"]),
            )
            inputs.update(self.refs, worker_image=self.run.source["image_id"])
            write_json(self.state / "evidence/M03.json", report | {"gate": "M03"})
            write_json(
                self.state / "storage-demo.json",
                dict(
                    dataset={"dataset_reference": self.refs["dataset_reference"]},
                    candidate={"candidate_reference": self.refs["candidate_reference"]},
                    evaluation_reference=self.refs["evaluation_reference"],
                ),
            )
            write_json(
                self.state / adapter.controller_intake.CAPTURE, dict(start=start, subject=self.refs)
            )
        else:
            self.assertFalse(
                set(env) & {"M21_START_SHA256", "R1_SCOPED_TRAINING", "M07_FRESH_WORKSPACE_ID"}
            )
            if name == "M01":
                inputs["worker_image"] = self.run.source["image_id"]
        write_json(output, report)

    def prepare(self):
        return adapter.prepare(
            self.root,
            source_api=self.run.api,
            trust_key_path=self.trust,
            image_receipt=self.receipt,
        )

    def test_same_live_state_is_ready_for_publish_after_one_native_m07(self):
        prepared = self.prepare()
        self.assertEqual(
            prepared, dict(state=self.state, run_owner=self.run.owner, source=self.run.source)
        )
        self.assertEqual(
            self.events,
            [
                "tools",
                "cluster-start",
                "sql-start",
                "M01",
                "M02",
                "M21-start",
                "M07",
                "cluster-clean",
            ],
        )
        self.assertEqual(self.run.requests, [("GET", p) for p in self.run.rows] * 2)
        self.connect.assert_called_once_with(self.state / "storage-clients/publisher")
        self.assertEqual(self.env["PATH"].split(os.pathsep)[0], str(self.state / "bin"))
        self.sql.assert_called_once_with(self.state)
        self.assertEqual(read_json(self.state / "storage.json"), self.marker)
        self.assertFalse((self.state / adapter.producer.CLAIM).exists())
        with self.assertRaises((Rejected, OSError)):
            self.prepare()
        self.sql.assert_called_once()
        self.stop.assert_not_called()

    def test_wrong_job_receipt_or_public_run_precedes_state_initialization(self):
        with patch.dict(self.env, GITHUB_JOB="shared"), self.assertRaises(Rejected):
            self.prepare()
        with patch.dict(self.receipt, image_id="sha256:" + "f" * 64), self.assertRaises(Rejected):
            self.prepare()
        with (
            patch.dict(self.run.rows[self.run.run_path], status="completed"),
            self.assertRaises(Rejected),
        ):
            self.prepare()
        self.assertEqual(list(self.state.iterdir()), [])

    def test_foreign_state_and_nonexternal_trust_never_start_resources(self):
        with (
            patch.object(self, "trust", self.root / "original.pem"),
            self.assertRaises((Rejected, OSError)),
        ):
            self.prepare()
        (self.state / "foreign").write_bytes(b"existing")
        with self.assertRaises(Rejected):
            self.prepare()
        self.start.assert_not_called()
        self.cluster_cleanup.assert_not_called()

    def test_capacity_does_not_fall_back_to_smaller_profile(self):
        self.inventory["docker_memory_bytes"] -= 1
        with self.assertRaises(Rejected):
            self.prepare()
        self.install.assert_not_called()
        self.start.assert_not_called()

    def test_ambiguous_cluster_start_attempts_owned_cleanup_only(self):
        original = RuntimeError("private start failure")
        self.start.side_effect = original
        with self.assertRaises(RuntimeError) as caught:
            self.prepare()
        self.assertIs(caught.exception, original)
        self.cluster_cleanup.assert_called_once_with(self.state)
        self.stop.assert_not_called()

    def test_partial_sql_without_receipt_never_stops_an_unidentified_container(self):
        original = RuntimeError("partial")
        self.sql.side_effect = original
        with self.assertRaises(RuntimeError) as caught:
            self.prepare()
        self.assertIs(caught.exception, original)
        self.assertTrue(caught.exception.__notes__)
        self.stop.assert_not_called()
        self.cluster_cleanup.assert_called_once_with(self.state)

    def test_cleanup_errors_do_not_replace_gate_error_or_skip_other_cleanup(self):
        original = CalledProcessError(2, ["fixture"])
        self.cli.side_effect = original
        self.cluster_cleanup.side_effect = RuntimeError("private diagnostics")
        with self.assertRaises(CalledProcessError) as caught:
            self.prepare()
        self.assertIs(caught.exception, original)
        self.assertTrue(caught.exception.__notes__)
        self.stop.assert_called_once_with(self.state)
        self.offline.assert_called_once_with(self.state)
        self.assert_diagnostic("M01", "CalledProcessError", cluster=True)

    def assert_diagnostic(self, stage, exception_class, *, cluster=False, sql=False):
        self.assertEqual(
            read_json(self.state / "evidence/original-bootstrap-error.private.json"),
            dict(
                code="original_bootstrap_failed",
                stage=stage,
                exception_class=exception_class,
                cluster_cleanup_unconfirmed=cluster,
                sql_cleanup_unconfirmed=sql,
            ),
        )

    def test_lost_cluster_cleanup_ack_is_private_and_never_retried_automatically(self):
        class SensitiveExceptionName(Exception):
            pass

        original = SensitiveExceptionName("sensitive error text")
        self.cluster_cleanup.side_effect = original
        with self.assertRaises(SensitiveExceptionName) as caught:
            self.prepare()
        self.assertIs(caught.exception, original)
        self.assertIn("producer_cluster_cleanup_unconfirmed", caught.exception.__notes__)
        self.cluster_cleanup.assert_called_once_with(self.state)
        self.assertTrue((self.state / adapter.cluster_owner.WITNESS).is_dir())
        self.assert_diagnostic("cluster_cleanup", "OtherError", cluster=True)
        self.offline.assert_called_once_with(self.state)

    def test_private_diagnostic_failure_keeps_primary_error(self):
        original = RuntimeError("primary")
        self.start.side_effect = original
        with (
            patch.object(adapter, "write_json", side_effect=OSError("disk")),
            self.assertRaises(RuntimeError) as caught,
        ):
            self.prepare()
        self.assertIs(caught.exception, original)
        self.assertIn("producer_private_diagnostic_unavailable", caught.exception.__notes__)

    def test_success_exit_cannot_certify_a_failed_or_unrelated_gate(self):
        def damaged(args, **kwargs):
            self.gate(args, **kwargs)
            path = Path(args[-1])
            data = read_json(path)
            write_json(path, data | dict(status="inconclusive"))

        self.cli.side_effect = damaged
        with self.assertRaises(Rejected):
            self.prepare()
        self.begin.assert_not_called()
        self.assertEqual(self.events.count("M01"), 1)
        self.offline.assert_called_once()

    def test_changed_sql_owner_never_authorizes_a_stop(self):
        def changed(*args, **kwargs):
            self.gate(*args, **kwargs)
            write_json(self.state / "storage.json", self.marker | dict(container_id="0" * 64))
            raise Rejected("gate refused")

        self.cli.side_effect = changed
        with self.assertRaisesRegex(Rejected, "gate refused") as caught:
            self.prepare()
        self.assertTrue(caught.exception.__notes__)
        self.stop.assert_not_called()
        self.cluster_cleanup.assert_called_once()

    def test_gate_that_evaluated_another_subject_never_hands_off_the_database(self):
        def substituted(args, **kwargs):
            self.gate(args, **kwargs)
            if args[args.index("--gate") + 1] == "M07":
                path = self.state / adapter.controller_intake.CAPTURE
                packet = read_json(path)
                packet["subject"]["evaluation_reference"] = "0" * 64
                write_json(path, packet)

        self.cli.side_effect = substituted
        with self.assertRaises(Rejected):
            self.prepare()
        self.offline.assert_called_once_with(self.state)
        self.assertEqual(self.events.count("M07"), 1)

    def test_publish_original_accepts_the_prepared_binding_and_reaches_freeze_once(self):
        bindings = self.prepare()
        at_freeze = RuntimeError("stop at ordinary producer boundary")
        with (
            adapter.guard.isolated_environment(),
            patch.object(adapter.producer, "prepare", side_effect=at_freeze) as freeze,
            self.assertRaises(RuntimeError) as caught,
        ):
            publisher.publish_original(
                self.root,
                **bindings,
                source_api=self.run.api,
                api=object(),
                key=b"x" * 32,
                checkpoint=lambda record: None,
            )
        self.assertIs(caught.exception, at_freeze)
        freeze.assert_called_once_with(self.root, self.state, key=b"x" * 32)
        self.assertEqual(self.events.count("M07"), 1)
        self.stop.assert_not_called()

    def test_partial_sql_with_durable_marker_is_stopped_and_verified(self):
        original = RuntimeError("lost acknowledgement")

        def interrupted(state):
            self.sql_start(state)
            raise original

        self.sql.side_effect = interrupted
        with self.assertRaises(RuntimeError) as caught:
            self.prepare()
        self.assertIs(caught.exception, original)
        self.assertEqual(read_json(self.state / "storage.json"), self.marker)
        self.stop.assert_called_once_with(self.state)
        self.offline.assert_called_once_with(self.state)

    def test_post_gate_publisher_connection_failure_stops_sql_after_cluster_cleanup(self):
        self.connection.__enter__.return_value.execute.return_value.fetchone.return_value = (
            "ml_scorer",
        )
        with self.assertRaises(Rejected):
            self.prepare()
        self.cluster_cleanup.assert_called_once_with(self.state)
        self.offline.assert_called_once_with(self.state)

    def test_module_entrypoint_masks_native_fd_output_and_primary_error(self):
        def noisy(*args):
            os.write(1, b"private information")
            os.write(2, b"private diagnostic")
            raise RuntimeError("private cause")

        self.start.side_effect = noisy
        output, errors = io.StringIO(), io.StringIO()
        supplied = dict(
            CANDIDATE_PUBLIC_TOKEN="fixture-public",
            CANDIDATE_TRUST_FILE=str(self.trust),
            SOURCE_IMAGE_RECEIPT=canonical(self.receipt).decode(),
        )
        with (self.tmp / "wire").open("w+b") as wire:
            with ExitStack() as scope:
                for fd in (1, 2):
                    saved = os.dup(fd)
                    scope.callback(os.close, saved)
                    scope.callback(os.dup2, saved, fd)
                    os.dup2(wire.fileno(), fd)
                scope.enter_context(patch.dict(self.env, supplied))
                scope.enter_context(patch.object(sys, "argv", ["ci_original_bootstrap", "prepare"]))
                scope.enter_context(
                    patch("scripts.ci_campaign_source.Client", return_value=self.run.api)
                )
                scope.enter_context(redirect_stdout(output))
                scope.enter_context(redirect_stderr(errors))
                with self.assertRaises(SystemExit) as stopped:
                    runpy.run_path(adapter.__file__, run_name="__main__")
            wire.seek(0)
            self.assertEqual(wire.read(), b"")
        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(
            (output.getvalue(), errors.getvalue()), ("original_bootstrap=refused\n", "")
        )
        self.cluster_cleanup.assert_called_once_with(self.state)

    def test_cli_takes_explicit_token_and_original_receipt_and_only_prints_status(self):
        supplied = dict(
            CANDIDATE_PUBLIC_TOKEN="fixture-public",
            CANDIDATE_TRUST_FILE=str(self.trust),
            SOURCE_IMAGE_RECEIPT=canonical(self.receipt).decode(),
        )
        output = io.StringIO()
        with (
            patch.dict(self.env, supplied),
            patch.object(adapter, "PublicClient", return_value=self.run.api) as client,
            redirect_stdout(output),
        ):
            self.assertEqual(adapter.main(["prepare"]), 0)
            client.assert_called_once_with("fixture-public")
        self.assertEqual(output.getvalue(), "original_bootstrap=pass\n")
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(adapter.main(["build"]), 1)
        self.assertEqual(output.getvalue(), "original_bootstrap=refused\n")
