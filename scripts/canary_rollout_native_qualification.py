"""Replay capture ownership, admission accounting and post-cleanup transitions."""

import asyncio
import os
import tempfile
import unittest
from contextlib import ExitStack, nullcontext, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from mlsecops import canary_journal
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.datasets import FEATURES
from mlsecops.load_golden import Golden
from scripts import canary_rollback_native as rollback
from scripts import canary_rollout_native as native


class Rollout(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.state = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.output = self.state / "step-output"
        self.stack.enter_context(patch.dict(os.environ, GITHUB_OUTPUT=str(self.output)))
        self.features = [[i / len(FEATURES) for i in range(len(FEATURES))]]
        self.golden = Golden.from_expected(
            dict(features=self.features, model="1" * 64, bundle="2" * 64, scores=[0.5])
        )
        self.source = dict(proposal_pin="a" * 64)
        self.pin = "b" * 64
        self.packet = dict(
            candidate=dict(image_id="sha256:" + "c" * 64),
            campaign="d" * 32,
            finished_at="2025-01-01T00:00:00+00:00",
            goldens=dict(candidate=dict(body=self.golden.body.decode())),
        )
        self.durable = dict(
            campaign=self.packet["campaign"],
            image=self.packet["candidate"]["image_id"],
            features=self.features,
        )
        self.stub(native, "hosted")
        self.stub(native, "validate", return_value=dict(container_id="owned"))
        self.inspect = self.stub(native, "inspect", return_value={"State": {"Running": False}})
        self.stub(native, "capture_inputs", return_value=self.source)
        self.stub(
            native,
            "owned_traffic",
            return_value=(self.source, self.pin, self.packet, {"requests": 800}),
        )
        self.drill = self.stub(rollback, "drill", return_value=self.durable)
        self.replay = self.stub(rollback, "replay", return_value=dict(recovery_ns=123))

    def stub(self, module, name, **kwargs):
        return self.stack.enter_context(patch.object(module, name, **kwargs))

    def freeze(self, record):
        pin = native.publish_pin(self.state, native.ROLLBACK_PACKET, record)
        self.stack.enter_context(patch.dict(os.environ, T19_ROLLBACK_SHA256=pin))
        return pin

    def test_two_independent_captures_replay_after_storage_stops(self):
        record = native.controlled_rollback(self.state, self.state)
        self.drill.assert_called_once_with(
            self.state, self.state, native.IMAGE, self.packet["campaign"], self.features
        )
        pin = self.freeze(record)
        self.assertEqual(self.output.read_text().strip(), "sha256=" + pin)
        self.assertEqual(
            native.measured(self.state, self.state),
            (self.packet, {"requests": 800}, {"recovery_ns": 123}),
        )
        self.inspect.assert_called_once_with("container", "owned")
        self.replay.assert_called_once_with(self.durable)
        self.assertEqual(pin, digest((self.state / native.ROLLBACK_PACKET).read_bytes()))

    def test_live_storage_wrong_pin_or_separately_valid_foreign_drill_rejected(self):
        record = native.controlled_rollback(self.state, self.state)
        self.freeze(record)
        self.inspect.return_value = {"State": {"Running": True}}
        with self.assertRaises(Rejected):
            native.measured(self.state, self.state)
        self.inspect.return_value = {"State": {"Running": False}}
        with patch.dict(os.environ, T19_ROLLBACK_SHA256="0" * 64), self.assertRaises(Rejected):
            native.measured(self.state, self.state)
        for field, change in (
            ("owner", {}),
            ("traffic_sha256", "f" * 64),
            ("schema_version", True),
            ("started_at", "2000-01-01T00:00:00+00:00"),
            ("drill", {**self.durable, "image": "sha256:" + "0" * 64}),
            ("drill", {**self.durable, "features": [[1] * len(FEATURES)]}),
            ("drill", {**self.durable, "campaign": "0" * 32}),
        ):
            with self.subTest(field=field):
                self.freeze({**record, field: change})
                with self.assertRaises(Rejected):
                    native.measured(self.state, self.state)
        self.replay.assert_not_called()

    def test_polls_until_first_503_and_returns_admission_counters(self):
        valid = Mock()
        valid.valid.return_value = True
        access = Mock()
        access.admissions.side_effect = [
            {"client": 10},
            {"client": 11},
            {"client": 11},
            {"client": 11},
        ]
        start = native.time.monotonic_ns()
        replies = [dict(status=k, reply={}, end_ns=start + 1) for k in (200, 503, 200)]
        with (
            patch.object(native, "sample", AsyncMock(side_effect=replies)),
            patch.object(asyncio, "sleep", AsyncMock()),
        ):
            result = asyncio.run(
                native.recover(
                    dict(candidate=1, stable=2),
                    dict(candidate=valid, stable=valid),
                    lambda: {"version": 2},
                    access,
                )
            )
        self.assertEqual(result["denial_admissions"], dict(before=11, after=11))
        self.assertEqual(result["restored"], replies[-1])
        self.assertEqual(result["candidate"], replies[:-1])

    def test_pre_admission_denial_cannot_hide_any_journalled_request(self):
        rid = "a" * 32
        opts = dict(subject="b" * 64, model="c" * 64, authority={"kind": "candidate-qualification"})
        summary = dict(status="pass", requests=dict(aborted=0, completed=1))
        entry = canonical(
            dict(
                event=dict(route="predict", stage="response_completed", status=503, request_id=rid)
            )
        )
        with patch.object(canary_journal.audit_export, "project", return_value=summary):
            extra = [dict(reply=dict(request_id=rid), status=503)]
            self.assertEqual(canary_journal.reconcile(entry, [], extra, **opts), 1)
            with self.assertRaises(Rejected):
                canary_journal.reconcile(entry, [], extra, pre_admission_denial=True, **opts)
            extra.append(dict(reply=dict(request_id="d" * 32), status=503))
            self.assertEqual(
                canary_journal.reconcile(entry, [], extra, pre_admission_denial=True, **opts), 1
            )
            with self.assertRaises(Rejected):
                canary_journal.reconcile(entry, [], extra, **opts)

    def test_ready_and_aborted_audits_cannot_substitute_for_predictions(self):
        options = dict(subject="1" * 64, model="2" * 64, authority={})
        log = canonical(dict(event=dict(route="ready", stage="response_completed", status=503)))
        for aborted, reason in ((1, "canary_journal_incomplete"), (0, "canary_journal_route")):
            summary = dict(status="pass", requests=dict(aborted=aborted, completed=1))
            with (
                patch.object(canary_journal.audit_export, "project", return_value=summary),
                self.assertRaisesRegex(Rejected, reason),
            ):
                canary_journal.reconcile(log, [], [], **options)

    def test_held_or_fenced_model_cannot_trigger_successful_capture(self):
        from scripts import canary_candidate_native, canary_stable_native

        engine = Mock(startup_failure=None)
        self.source.update(source={}, methods="e" * 64, runner={})
        self.stub(
            canary_stable_native,
            "stable_release",
            side_effect=lambda *args: nullcontext((engine, self.golden, {})),
        )
        self.stub(
            canary_candidate_native,
            "actual_candidate",
            side_effect=lambda *args: nullcontext((engine, self.golden, {}, Mock())),
        )
        self.stub(native, "listen", side_effect=lambda app: nullcontext(12345))
        run = self.stub(native.canary_campaign, "run", new_callable=AsyncMock)
        fault = self.stub(
            native, "recover", new_callable=AsyncMock, return_value={"controlled": True}
        )
        with redirect_stdout(StringIO()):
            run.return_value = {"decision": "hold", "stages": []}
            with self.assertRaisesRegex(Rejected, "canary_traffic_held"):
                native.traffic(self.state, self.state)
            fault.assert_not_called()
            run.return_value = {"decision": "complete", "stages": []}
            record = native.traffic(self.state, self.state)
            self.assertEqual(record["recovery"], {"controlled": True})
            self.assertEqual(record["journals"], dict(stable=digest(b""), candidate=digest(b"")))
            engine.startup_failure = {"phase": "reader"}
            with self.assertRaises(Rejected):
                native.traffic(self.state, self.state)
            self.assertEqual(run.await_count, 2)

    def test_recovery_needs_an_actual_denial_and_a_correct_restored_reply(self):
        golden = Mock()
        golden.valid.return_value = True
        access = Mock()
        access.admissions.return_value = {"client": 1}
        targets, goldens = dict(candidate=1, stable=2), dict(candidate=golden, stable=golden)
        reading = dict(status=200, reply={}, end_ns=native.time.monotonic_ns())
        for sequence in (
            [reading] * 200,
            [{**reading, "status": 503}, {**reading, "status": 500}],
            [{**reading, "status": 429}],
        ):
            with (
                patch.object(native, "sample", AsyncMock(side_effect=sequence)),
                patch.object(asyncio, "sleep", AsyncMock()),
                self.assertRaises(Rejected),
            ):
                asyncio.run(native.recover(targets, goldens, lambda: {}, access))
        with patch.object(
            native.load_measurement, "request", AsyncMock(return_value=(200, {"verified": 1}))
        ):
            value = asyncio.run(native.sample((12345, "0" * 64), self.golden))
        self.assertEqual((value["status"], value["reply"]), (200, {"verified": 1}))
        self.assertLessEqual(value["start_ns"], value["end_ns"])

    def test_normal_cli_does_not_publish_partial_outputs(self):
        import sys

        stage = self.stub(native, "publish_pin", return_value=self.pin)
        capture = self.stub(native, "traffic", return_value={})
        self.stub(native, "controlled_rollback", return_value={})
        self.stub(native, "measured", return_value=({}, {"requests": 800}, {"recovery_ns": 123}))
        with redirect_stdout(StringIO()):
            for action in ("capture", "rollback", "replay"):
                with patch.object(sys, "argv", ["runner", action]):
                    self.assertEqual(native.main(), 0)
            capture.side_effect = Rejected("capture-failed")
            for action in ("capture", "invalid"):
                with patch.object(sys, "argv", ["runner", action]):
                    self.assertEqual(native.main(), 1)
        self.assertEqual(stage.call_count, 2)

    def test_module_entrypoint_rejects_an_unowned_runner(self):
        import runpy
        import sys

        # Load the normal entry point without inheriting the unittest module object.
        with (
            patch.dict(sys.modules),
            patch.dict(os.environ, GITHUB_ACTIONS="false"),
            redirect_stdout(StringIO()),
        ):
            sys.modules.pop("scripts.canary_rollout_native", None)
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_module("scripts.canary_rollout_native", run_name="__main__")
        self.assertEqual(stopped.exception.code, 1)
