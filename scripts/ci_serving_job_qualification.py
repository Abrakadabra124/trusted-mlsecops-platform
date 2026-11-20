"""Cross-job serving composition with the ordinary driver and controlled infrastructure."""

import importlib
import importlib.util
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, bounded_read, canonical, digest, write_json
from scripts import ci_campaign_handoff as handoff
from scripts import ci_campaign_handoff_qualification as signed
from scripts import ci_serving_native as native
from scripts import ci_serving_native_qualification as baseline
from scripts import ci_serving_recovery_qualification as recovery_fixture
from scripts.ci_producer_cluster_qualification import OWNER, SOURCE

RECEIVER = OWNER | {"producer_job": "serving"}
OUTPUTS = ("GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_STEP_SUMMARY", "GITHUB_STATE")


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("scripts.ci_serving_job"), "receiver missing")
        self.job = importlib.import_module("scripts.ci_serving_job")
        self.fx = fx = baseline.DriverTests()
        self.addCleanup(fx.doCleanups)
        fx.setUp()
        self.root = fx.root
        self.local = self.root / ".runtime/ci-serving-job"
        self.args = dict(
            api=object(),
            source_api=object(),
            run_owner=OWNER.copy(),
            source=SOURCE.copy(),
            trust_key_path=self.root / "external-trust.pem",
            key=fx.key,
            trusted_public="issuer",
        )
        self.files = {k: str(self.root / k) for k in OUTPUTS}
        self.enterContext(
            patch.dict(
                os.environ,
                self.files
                | {
                    "GITHUB_JOB": "serving",
                    "CANDIDATE_STORE_READ": "private-reader",
                    "PRIVATE_TEST_SECRET": "private-value",
                    "GITHUB_SHA": SOURCE["source_revision"],
                },
            )
        )
        self.before = dict(os.environ)
        self.admission = Mock(side_effect=self.admit)
        self.enterContext(
            patch.dict(
                sys.modules,
                {"scripts.ci_campaign_guard": SimpleNamespace(authorize=self.admission)},
            )
        )
        self.origin = {k: fx.marker[k] for k in ("workspace_id", "container_id")}
        self.origin["offline_pin"] = fx.offline
        self.consumer_pin = "9" * 64
        self.changed = lambda: None
        self.keep = False
        self.mock(handoff, "open_consumer", self.open)
        self.mock(native.lifecycle.Lifecycle, "begin", self.begin)
        self.mock(native.lifecycle.Lifecycle, "load", self.load)
        self.mock(native.shared_serving_receipt, "offline_pin", self.offline)

    def mock(self, obj, name, effect):
        return self.enterContext(patch.object(obj, name, side_effect=effect))

    def admit(self, root, *, source_api, job, run_owner, source):
        self.assertEqual(
            (root, source_api, job, run_owner, source),
            (self.root, self.args["source_api"], "serving", OWNER, SOURCE),
        )
        self.fx.event("admit")

    @contextmanager
    def open(self, root, **kw):
        fx = self.fx
        self.assertEqual(
            kw, {k: v for k, v in self.args.items() if k != "source_api"} | {"job": "serving"}
        )
        self.assertEqual(root, self.root)
        self.assertIn("admit", fx.events)
        fx.event("open")
        with tempfile.TemporaryDirectory(dir=self.root) as tmp:
            fx.state = state = Path(tmp) / "view"
            prepared = dict(
                workspace_id=fx.consumer_marker["workspace_id"],
                manifest_sha256=fx.envelopes["candidate"]["manifest_sha256"],
                ciphertext_sha256=fx.envelopes["candidate"]["ciphertext_sha256"],
            )
            write_json(
                state / "workspace.json",
                dict(
                    product="trusted-mlsecops",
                    schema_version=1,
                    workspace_id=prepared["workspace_id"],
                ),
            )
            record = dict(owner=fx.owner, origin=self.origin, reports=fx.upstream)
            packets = {k + "-serving": v for k, v in fx.envelopes.items()}
            self.prepared, self.packets = prepared, packets
            self.changed()
            fx.attached = True
            try:
                for gate, raw in fx.upstream_bytes.items():
                    baseline.atomic_write(state / f"evidence/{gate}.json", raw)
                yield state, prepared, record, packets
            finally:
                fx.attached = False
                fx.event("context_exit")
        if self.keep:
            state.mkdir(parents=True)

    def begin(self, local, state, *, run_owner, source):
        self.assertEqual(
            (local, state, run_owner, source), (self.local, self.fx.state, RECEIVER, SOURCE)
        )
        self.assertNotEqual(
            native.storage_pki.workspace_id(local), native.storage_pki.workspace_id(state)
        )
        self.fx.event("begin")
        self.fx.created = True
        return self.fx

    def load(self, local, *, run_owner, source):
        self.assertEqual((local, run_owner, source), (self.local, RECEIVER, SOURCE))
        self.fx.event("load")
        if not self.fx.created:
            raise Rejected("missing witness")
        return self.fx

    def offline(self, state):
        self.assertEqual(state, self.fx.state)
        self.assertTrue(state.exists() and self.fx.cleaned)
        self.fx.event("local_offline")
        return self.consumer_pin

    def run_job(self):
        return self.job.run(self.root, **self.args)

    def clean(self):
        return self.job.cleanup(
            self.root, **{k: self.args[k] for k in ("source_api", "run_owner", "source")}
        )

    def test_refused_public_admission_precedes_fetch_witness_or_cleanup(self):
        self.admission.side_effect = Rejected("refused")
        for invoke in (self.run_job, self.clean):
            with self.assertRaises(Rejected):
                invoke()
        self.assertFalse(self.local.exists())
        self.assertFalse(self.fx.events)

    def test_dirty_or_cross_attempt_cleanup_refused_without_private_fetch(self):
        self.fx.faults["admit"] = Rejected("wrong run")
        with self.assertRaises(Rejected):
            self.clean()
        self.assertNotIn("load", self.fx.events)

    def test_corrupt_signed_owner_precedes_sql(self):
        self.changed = lambda: self.fx.owner.update(run_owner=RECEIVER)
        with self.assertRaises(Rejected):
            self.run_job()
        self.assertNotIn("begin", self.fx.events)

    def test_foreign_materialization_pin_refused_before_sql(self):
        self.changed = lambda: self.prepared.update(manifest_sha256="0" * 64)
        with self.assertRaises(Rejected):
            self.run_job()
        self.assertNotIn("begin", self.fx.events)

    def test_collision_with_origin_rejected_before_sql(self):
        self.changed = lambda: self.origin.update(workspace_id=self.prepared["workspace_id"])
        with self.assertRaises(Rejected):
            self.run_job()
        self.assertNotIn("begin", self.fx.events)

    def test_validation_required_before_first_gate(self):
        self.changed = lambda: self.packets.pop("validation-serving")
        with self.assertRaises(Rejected):
            self.run_job()
        self.assertFalse(self.fx.gates_done)

    def test_ordinary_gates_use_producer_authority_and_replay_after_view_closes(self):
        result = self.run_job()
        self.assertEqual(result["origin"], self.origin)
        self.assertEqual(result["cleanup_owner"], RECEIVER)
        self.assertEqual(result["arguments"]["run_owner"], OWNER)
        self.assertEqual(result["consumer_offline"], self.consumer_pin)
        self.assertEqual(result["cleanup"], self.fx.cleanup_result)
        self.assertEqual(result["gate_counts"], dict.fromkeys(native.GATES, 1))
        self.assertIs(result["release_ready"], False)
        self.assertEqual(self.fx.gates_done, list(native.GATES))
        for left, right in (
            ("cleanup", "local_offline"),
            ("local_offline", "export"),
            ("export", "context_exit"),
            ("context_exit", "replay"),
        ):
            self.assertLess(self.fx.events.index(left), self.fx.events.index(right))
        self.assertEqual(self.fx.events.count("window"), 9)
        self.assertEqual(self.clean(), self.fx.cleanup_result)
        self.assertEqual(self.clean(), self.fx.cleanup_result)
        with self.assertRaises(Rejected):
            self.run_job()
        self.assertEqual(self.fx.events.count("open"), 1)

    def test_gates_cannot_publish_or_inherit_workflow_secrets(self):
        def gate(*args, **kwargs):
            self.assertNotIn("CANDIDATE_STORE_READ", os.environ)
            self.assertNotIn("PRIVATE_TEST_SECRET", os.environ)
            for name in OUTPUTS:
                with open(os.environ[name], "a", encoding="utf-8") as sink:
                    sink.write("private candidate material")
            return self.fx.gate(*args, **kwargs)

        self.mock(native.acceptance, "report", gate)
        self.run_job()
        self.assertEqual(dict(os.environ), self.before)
        self.assertTrue(all(not Path(path).exists() for path in self.files.values()))
        self.assertFalse(list(self.local.rglob("*.log")))

    def test_admission_receives_case_sensitive_hosted_image_label(self):
        with patch.dict(os.environ, ImageOS="ubuntu24"), self.job.private_process():
            self.assertEqual(os.environ.get("ImageOS"), "ubuntu24")

    def test_expired_validation_window_blocks_next_gate_without_reissue(self):
        def window(context, values, current):
            if self.fx.gates_done and context is self.fx.envelopes["validation"]["context"]:
                raise Rejected("expired packet")

        self.mock(native.bridge, "_window", window)
        with self.assertRaises(Rejected):
            self.run_job()
        self.assertEqual(self.fx.gates_done, ["M13"])
        self.assertNotIn("replay", self.fx.events)

    def test_source_drift_after_replay_refuses_success(self):
        def source(root, image):
            return SOURCE | {"image_id": "different"} if "replay" in self.fx.events else SOURCE

        self.mock(native.driver, "source", source)
        with self.assertRaises(Rejected):
            self.run_job()
        self.assertIn("replay", self.fx.events)

    def test_retained_replay_cannot_adopt_a_different_freeze(self):
        consume = native.consumer

        def changed(*args, **kwargs):
            dest, pin, owner = consume(*args, **kwargs)
            owner["freeze_pin"] = "0" * 64
            self.fx.retention_args["freeze_pin"] = owner["freeze_pin"]
            return dest, pin, owner

        self.mock(native, "consumer", changed)
        with self.assertRaises(Rejected):
            self.run_job()
        self.assertNotIn("replay", self.fx.events)

    def test_retained_replay_cannot_adopt_replaced_upstream_report(self):
        def change(root, state, destination, **args):
            result = self.fx.export(root, state, destination, **args)
            args["report_pins"]["M07"] = "0" * 64
            self.fx.retention_args["report_pins"]["M07"] = "0" * 64
            return result

        self.mock(native.exporter, "retain", change)
        with self.assertRaises(Rejected):
            self.run_job()
        self.assertNotIn("replay", self.fx.events)

    def test_interruption_cleans_inside_then_outside_context_without_replay(self):
        self.fx.faults["M14"] = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.run_job()
        events = self.fx.events
        self.assertLess(events.index("cleanup"), events.index("context_exit"))
        self.assertEqual(events.count("cleanup"), 2)
        self.assertNotIn("replay", events)
        self.assertEqual(dict(os.environ), self.before)

    def test_failed_local_inspection_refuses_retention(self):
        self.fx.faults["local_offline"] = Rejected("source still running")
        with self.assertRaises(Rejected):
            self.run_job()
        self.assertNotIn("export", self.fx.events)

    def test_remote_observation_cannot_be_supplied_as_a_local_producer_pin(self):
        with self.assertRaises(Rejected):
            native.consumer(
                self.root,
                self.local,
                self.root,
                {},
                self.fx.owner,
                {},
                self.fx.key,
                {},
                self.origin,
                self.origin["offline_pin"],
                self.fx.upstream,
                cleanup_owner=RECEIVER,
            )
        self.assertNotIn("tls", self.fx.events)

    def test_private_error_details_and_command_files_do_not_escape(self):
        self.fx.faults["M13"] = ValueError("private payload in reader error")
        with self.assertRaises(Rejected) as error:
            self.run_job()
        self.assertNotIn("private payload", str(error.exception))
        self.assertTrue(error.exception.__suppress_context__)
        self.assertEqual(dict(os.environ), self.before)

    def test_receiver_restart_during_export_prevents_replay(self):
        self.mock(native.shared_serving_receipt, "offline_pin", ["8" * 64, "7" * 64])
        with self.assertRaises(Rejected):
            self.run_job()
        self.assertIn("export", self.fx.events)
        self.assertNotIn("replay", self.fx.events)

    def test_context_exit_must_remove_view_before_replay(self):
        self.keep = True
        with self.assertRaises(Rejected):
            self.run_job()
        self.assertNotIn("replay", self.fx.events)

    def test_partial_recovery_does_not_certify_cleanup(self):
        self.fx.cleanup_result["M15"] = False
        with self.assertRaises(Rejected) as error:
            self.run_job()
        self.assertIn("serving_cleanup_unverified", error.exception.__notes__)
        self.assertNotIn("export", self.fx.events)


class DurableCleanupTests(unittest.TestCase):
    def test_same_job_reinspects_the_producer_after_local_cleanup(self):
        fixture = baseline.DriverTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()

        def offline(state):
            self.assertEqual(state, fixture.producer)
            return "0" * 64 if fixture.cleaned else fixture.offline

        with patch.object(native.shared_serving_receipt, "offline_pin", offline):
            result = fixture.execute()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(fixture.gates_done, list(native.GATES))
        self.assertNotIn("export", fixture.events)

    def test_after_view_loss_only_receiver_witness_can_retire_exact_resources_twice(self):
        from scripts import ci_serving_job as job

        fx = recovery_fixture.ServingRecoveryTests()
        self.addCleanup(fx.doCleanups)
        fx.setUp()
        fx.producer = fx.root / job.LOCAL
        write_json(
            fx.producer / "workspace.json",
            dict(product="trusted-mlsecops", schema_version=1, workspace_id="e" * 32),
        )
        fx.life = native.lifecycle.Lifecycle.begin(
            fx.producer, fx.state, run_owner=RECEIVER, source=SOURCE
        )
        sql_pin = fx.active()
        for phase in ("M13", "M14"):
            fx.life.transition(fx.state, phase, sql_pin)
        fx.state.rename(fx.root / "closed-view")
        self.enterContext(
            patch.dict(
                sys.modules, {"scripts.ci_campaign_guard": SimpleNamespace(authorize=Mock())}
            )
        )
        args = dict(source_api=object(), source=SOURCE, run_owner=OWNER)
        for drift in (
            dict(run_owner=OWNER | {"run_attempt": 2}),
            dict(source=SOURCE | {"source_revision": "1" * 40}),
        ):
            with self.assertRaises(Rejected):
                job.cleanup(fx.root, **(args | drift))
            self.assertTrue(fx.docker.rows[recovery_fixture.SQL_ID]["State"]["Running"])
            self.assertIn(recovery_fixture.IDS["M15"], fx.docker.rows)
        for _ in range(2):
            self.assertEqual(
                job.cleanup(fx.root, **args), dict.fromkeys((*native.GATES, "SQL"), True)
            )
            self.assertEqual(set(fx.docker.rows), {recovery_fixture.SQL_ID})
            self.assertFalse(fx.docker.rows[recovery_fixture.SQL_ID]["State"]["Running"])
            self.assertFalse(fx.docker.volumes)


class SignedHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        signed.HandoffTests.setUpClass()
        cls.addClassCleanup(signed.HandoffTests.doClassCleanups)

    def setUp(self):
        from scripts import ci_serving_job

        self.job = ci_serving_job
        self.fx = fx = signed.HandoffTests()
        self.addCleanup(fx.doCleanups)
        fx.setUp()
        self.args = dict(
            api=fx.api,
            source_api=object(),
            run_owner=fx.owner["run_owner"],
            source=fx.source,
            key=signed.KEY,
            trusted_public=fx.public,
            trust_key_path=fx.trust,
        )
        self.enterContext(
            patch.dict(
                sys.modules, {"scripts.ci_campaign_guard": SimpleNamespace(authorize=Mock())}
            )
        )
        for target in ("subprocess.Popen", "socket.socket"):
            self.enterContext(patch(target, side_effect=AssertionError("offline fixture")))

    def test_wrong_issuer_refuses_before_materialization_or_local_sql(self):
        with patch.object(native, "consumer") as consumer, self.assertRaises(Rejected):
            self.job.run(self.fx.root, **(self.args | {"trusted_public": "foreign"}))
        self.assertEqual(self.fx.downloaded(), ["producer-control"])
        consumer.assert_not_called()

    def test_real_handoff_attaches_signed_upstream_and_original_validation_and_trust(self):
        seen = {}

        def inspect(
            root,
            local,
            state,
            prepared,
            owner,
            sealed,
            key,
            progress,
            marker,
            offline,
            reports,
            *,
            cleanup_owner,
        ):
            for gate, pin in reports.items():
                signed.transfer.final.published_report(state, gate, pin)
            value = sealed["validation"]
            with signed.validation.materialize(
                root,
                state,
                value["envelope"],
                key=key,
                **owner,
                phase="M13",
                expected_context=value["context"],
                ciphertext_pin=value["ciphertext_sha256"],
            ) as (path, summary):
                seen.update(
                    validation=digest(bounded_read(path)),
                    reports=reports,
                    state=state,
                    trust_matches=bounded_read(state / "keys/trust.pem")
                    == bounded_read(self.fx.trust),
                    marker=marker,
                    cleanup_owner=cleanup_owner,
                    signed_owner=owner,
                )
            raise Rejected("end of transport fixture before SQL")

        with patch.object(native, "consumer", inspect), self.assertRaises(Rejected):
            self.job.run(self.fx.root, **self.args)
        rows = [dict(entity_id=i + 1000, label=i % 2, features=[0.5] * 6) for i in range(32)]
        self.assertEqual(seen["validation"], digest(canonical(rows)))
        self.assertTrue(seen["trust_matches"])
        self.assertEqual(seen["reports"], self.fx.reports)
        self.assertEqual(seen["marker"], self.fx.origin)
        self.assertEqual(seen["signed_owner"], self.fx.owner)
        self.assertFalse(seen["state"].exists())
        self.assertEqual(
            seen["cleanup_owner"], self.fx.owner["run_owner"] | {"producer_job": "serving"}
        )
        self.assertEqual(
            self.fx.downloaded(),
            ["producer-control", "candidate-serving", "upstream-serving", "validation-serving"],
        )
