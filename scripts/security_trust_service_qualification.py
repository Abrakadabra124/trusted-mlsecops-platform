"""Periodic observer source and owned-process contract tests."""

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from mlsecops import security_trust_events as source
from mlsecops.contracts import Rejected, canonical, digest
from scripts import security_trust_events_qualification as fixtures


class SourceHeartbeat(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.SourceContracts("runTest")
        self.fx.continuous = True
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.path = self.fx.ef.directory / "observer.json"
        self.value = dict(
            schema_version=1,
            trust_client=str(self.fx.ef.directory / "client"),
            environment="local-cpu",
            initial_root=self.fx.fx.fx.old_public,
            producer_config=str(self.fx.ef.directory / "producer.json"),
            rotations=[],
        )
        self.path.write_bytes(canonical(self.value))
        self.pin = digest(self.path.read_bytes())

    def test_heartbeat_only_after_verified_history_and_confirmed_events(self):
        with (
            patch.object(
                source.security_event_delivery, "configured", return_value=self.fx.emitter
            ),
            patch.object(source, "read", return_value=self.fx.fx.history()),
            patch.object(self.fx.emitter, "heartbeat") as heartbeat,
        ):
            result = source.configured(str(self.path), expected=self.pin, heartbeat=True)
            heartbeat.assert_called_once_with()
            self.assertEqual(result["events"], 3)
            self.assertTrue(
                all(r["receipt"] is not None for r in self.fx.box.document()["records"])
            )
            self.assertFalse(result["release_ready"])

    def test_source_failure_never_masks_unavailability_with_heartbeat(self):
        with (
            patch.object(
                source.security_event_delivery, "configured", return_value=self.fx.emitter
            ),
            patch.object(source, "read", side_effect=Rejected("private")),
            patch.object(self.fx.emitter, "heartbeat") as heartbeat,
        ):
            with self.assertRaises(Rejected):
                source.configured(str(self.path), expected=self.pin, heartbeat=True)
            heartbeat.assert_not_called()

    def test_changed_configuration_rejected_before_sql_or_emitter(self):
        self.path.write_bytes(canonical({**self.value, "environment": "changed"}))
        with (
            patch.object(source, "read") as read,
            patch.object(source.security_event_delivery, "configured") as emitter,
        ):
            with self.assertRaisesRegex(Rejected, "configuration_changed"):
                source.configured(str(self.path), expected=self.pin, heartbeat=True)
            read.assert_not_called()
            emitter.assert_not_called()

    def test_delivery_and_history_failure_do_not_heartbeat(self):
        for failure in ("delivery", "history"):
            history = self.fx.fx.history()
            self.fx.offline = failure == "delivery"
            if failure == "history":
                history["head_version"] += 1
            with (
                self.subTest(failure=failure),
                patch.object(
                    source.security_event_delivery, "configured", return_value=self.fx.emitter
                ),
                patch.object(source, "read", return_value=history),
                patch.object(self.fx.emitter, "heartbeat") as heartbeat,
            ):
                with self.assertRaises(Rejected):
                    source.configured(str(self.path), expected=self.pin, heartbeat=True)
                heartbeat.assert_not_called()

    def test_heartbeat_failure_propagates_and_cli_requires_pin(self):
        with (
            patch.object(
                source.security_event_delivery, "configured", return_value=self.fx.emitter
            ),
            patch.object(source, "read", return_value=self.fx.fx.history()),
            patch.object(self.fx.emitter, "heartbeat", side_effect=Rejected("private")),
        ):
            with self.assertRaises(Rejected):
                source.configured(str(self.path), expected=self.pin, heartbeat=True)
        with (
            patch.object(source, "enforce"),
            patch.object(source, "configured") as configured,
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            self.assertEqual(source.main(["--config", str(self.path), "--heartbeat"]), 1)
            configured.assert_not_called()
        self.assertEqual(err.getvalue(), "trust_security_rejected\n")

    def test_native_campaign_refuses_before_local_infrastructure(self):
        from scripts import security_trust_service_native as native

        with (
            patch.object(native.sys, "platform", "win32"),
            patch.object(native, "disposable") as disposable,
        ):
            with self.assertRaisesRegex(Rejected, "hosted_required"):
                native.qualify()
            disposable.assert_not_called()

    def test_native_readback_keeps_operator_state_pin_and_registry(self):
        from scripts import security_trust_service_native as native

        settings = dict(state_directory=str(self.path.parent / "collector"), state_sha256="a" * 64)
        with patch.object(native.security_event_store, "platform"):
            store = native.collector_reader(settings, self.fx.registry)
            self.assertEqual(store.pin, settings["state_sha256"])
            self.assertIs(store.registry, self.fx.registry)
            with self.assertRaises(Rejected):
                native.collector_reader({**settings, "state_sha256": "invalid"}, self.fx.registry)

    def test_native_failure_diagnostics_exclude_private_state_and_keep_unknowns(self):
        from scripts import security_trust_service_native as native

        log = self.path.parent / "private-observer.log"
        log.write_bytes(b"PRIVATE-CANARY\ntrust_observer_check_failed\n")
        document = {"records": [{"receipt": None}, {"receipt": {"private": "value"}}]}
        result = native.failure_state(log, lambda: document, lambda: document)
        self.assertEqual(result["observer_failed_checks"], 1)
        self.assertEqual(result["outbox"], {"records": 2, "receipts": 1})
        self.assertNotIn(b"PRIVATE", canonical(result))
        self.assertNotIn(b"value", canonical(result))
        with patch.object(native, "bounded_read", side_effect=Rejected("private path")):
            result = native.failure_state(
                log, MagicMock(side_effect=Rejected("private")), lambda: document
            )
        self.assertIsNone(result["observer_failed_checks"])
        self.assertIsNone(result["outbox"])
        self.assertEqual(result["collector"], {"records": 2, "receipts": 1})

    def test_optional_heartbeat_registry_cannot_launch_continuous_source(self):
        other = fixtures.SourceContracts("runTest")
        other.setUp()
        self.addCleanup(other.doCleanups)
        with (
            patch.object(source.security_event_delivery, "configured", return_value=other.emitter),
            patch.object(source, "read", return_value=self.fx.fx.history()) as read,
            patch.object(self.fx.emitter, "heartbeat"),
        ):
            with self.assertRaisesRegex(Rejected, "heartbeat_profile"):
                source.configured(str(self.path), expected=self.pin, heartbeat=True)
            read.assert_not_called()

    def test_legacy_outbox_cannot_start_heartbeat_or_mutate_history(self):
        self.fx.box._document["schema_version"] = 1
        self.fx.box._document.pop("heartbeat")
        with (
            patch.object(
                source.security_event_delivery, "configured", return_value=self.fx.emitter
            ),
            patch.object(source, "read") as read,
        ):
            with self.assertRaisesRegex(Rejected, "heartbeat_profile"):
                source.configured(str(self.path), expected=self.pin, heartbeat=True)
            read.assert_not_called()


class ServiceContracts(unittest.TestCase):
    def setUp(self):
        # Import after collection: missing runtime is an explicit RED assertion.
        import importlib.util

        self.assertIsNotNone(
            importlib.util.find_spec("mlsecops.security_trust_service"),
            "periodic service not implemented",
        )
        from mlsecops import security_trust_service as service

        self.service = service
        self.path = str(Path("observer.json").resolve())
        with patch.object(service.source, "configuration", return_value=({}, "a" * 64)):
            self.observer = service.Observer(self.path)

    def process(self, *, code=0):
        process = MagicMock()
        process.poll.return_value = code
        return process

    def test_success_uses_fixed_pinned_child_with_no_output_or_shell(self):
        process = self.process()
        with patch.object(self.service.subprocess, "Popen", return_value=process) as spawn:
            self.assertTrue(self.observer.once())
        args, options = spawn.call_args
        self.assertEqual(
            args[0],
            [
                sys.executable,
                "-m",
                "mlsecops.security_trust_events",
                "--config",
                self.path,
                "--config-sha256",
                "a" * 64,
                "--heartbeat",
            ],
        )
        for name in ("stdin", "stdout", "stderr"):
            self.assertEqual(options[name], subprocess.DEVNULL)
        self.assertNotIn("shell", options)
        self.assertIsNone(self.observer.child)
        process.wait.assert_called()

    def test_failed_child_is_not_reported_success(self):
        with patch.object(self.service.subprocess, "Popen", return_value=self.process(code=1)):
            self.assertFalse(self.observer.once())
        self.assertIsNone(self.observer.child)

    def test_stop_during_spawn_reaps_owned_child(self):
        process = self.process(code=None)

        def spawn(*args, **kwargs):
            self.observer.stopped.set()
            return process

        with patch.object(self.service.subprocess, "Popen", side_effect=spawn):
            self.assertFalse(self.observer.once())
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=1)
        self.assertIsNone(self.observer.child)

    def test_timeout_kills_only_owned_child_and_retains_unconfirmed_reference(self):
        process = self.process(code=None)
        process.wait.side_effect = [subprocess.TimeoutExpired("private", 1), 0]
        with (
            patch.object(self.service.subprocess, "Popen", return_value=process),
            patch.object(self.service.time, "monotonic", side_effect=[0, 11]),
        ):
            self.assertFalse(self.observer.once())
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertIsNone(self.observer.child)
        process = self.process(code=None)
        process.wait.side_effect = subprocess.TimeoutExpired("private", 1)
        self.observer.child = process
        with self.assertRaisesRegex(Rejected, "cleanup_unconfirmed"):
            self.observer.close()
        self.assertIs(self.observer.child, process)
        process.wait.side_effect = None
        self.observer.close()

    def test_serial_periodic_checks_recover_from_spawn_failure_without_queue(self):
        waits = []
        count = 0

        def once():
            nonlocal count
            count += 1
            if count == 1:
                raise OSError("PRIVATE-CANARY")
            self.observer.stopped.set()
            return True

        with (
            patch.object(self.observer, "once", side_effect=once),
            patch.object(
                self.observer.stopped, "wait", side_effect=lambda value: waits.append(value)
            ),
            patch.object(self.service.time, "monotonic", side_effect=[0, 2, 30, 32]),
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            self.observer.run()
        self.assertEqual(count, 2)
        self.assertEqual(waits, [28, 28])
        self.assertEqual(err.getvalue(), "trust_observer_check_failed\n")

    def test_unclean_child_prevents_next_check(self):
        self.observer.child = self.process(code=None)
        self.observer.child.wait.side_effect = subprocess.TimeoutExpired("private", 1)
        with (
            patch.object(self.observer, "once", side_effect=Rejected("private")) as once,
            self.assertRaisesRegex(Rejected, "cleanup_unconfirmed"),
        ):
            self.observer.run()
        self.assertEqual(once.call_count, 1)

    def test_real_owned_python_timeout_is_reaped(self):
        spawn = subprocess.Popen
        children = []

        def start(*args, **kwargs):
            child = spawn(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            children.append(child)
            return child

        try:
            with (
                patch.object(self.service.subprocess, "Popen", side_effect=start),
                patch.object(self.service, "CHILD_SECONDS", 0.1),
            ):
                self.assertFalse(self.observer.once())
            self.assertIsNotNone(children[0].poll())
            self.assertIsNone(self.observer.child)
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)

    def test_stopped_or_busy_observer_cannot_launch(self):
        with patch.object(self.service.subprocess, "Popen") as spawn:
            self.observer.stopped.set()
            with self.assertRaisesRegex(Rejected, "lifecycle"):
                self.observer.once()
            self.observer.stopped.clear()
            self.observer.child = self.process()
            with self.assertRaisesRegex(Rejected, "lifecycle"):
                self.observer.once()
            spawn.assert_not_called()
            self.observer.close()

    def test_stop_during_wait_does_not_print_failure(self):
        process = self.process(code=None)

        def stop(_):
            self.observer.stopped.set()

        with (
            patch.object(self.service.subprocess, "Popen", return_value=process),
            patch.object(self.observer.stopped, "wait", side_effect=stop),
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            self.observer.run()
        process.terminate.assert_called_once()
        self.assertEqual(err.getvalue(), "")

    def test_process_exiting_during_terminate_or_kill_is_reaped(self):
        for stage in ("terminate", "kill"):
            with self.subTest(stage=stage):
                process = self.process(code=None)
                getattr(process, stage).side_effect = ProcessLookupError()
                if stage == "kill":
                    process.wait.side_effect = [subprocess.TimeoutExpired("private", 1), 0]
                self.observer.child = process
                self.observer.close()
                self.assertIsNone(self.observer.child)

    def test_main_restores_handlers_and_reports_only_finite_stopped_state(self):
        handlers = []

        def install(number, handler):
            handlers.append((number, handler))
            return "previous"

        def run():
            handlers[0][1](0, None)
            self.assertTrue(self.observer.stopped.is_set())

        with (
            patch.object(self.service, "enforce"),
            patch.object(self.service, "Observer", return_value=self.observer),
            patch.object(self.observer, "run", side_effect=run),
            patch.object(self.service.journal, "locked", return_value=contextlib.nullcontext()),
            patch.object(self.service.signal, "signal", side_effect=install),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(self.service.main(["--config", self.path]), 0)
        self.assertEqual(len(handlers), 4)
        self.assertEqual(handlers[-2][1], "previous")
        self.assertEqual(out.getvalue(), '{"release_ready":false,"state":"stopped"}\n')

    def test_main_failure_and_interrupt_have_constant_output(self):
        for error, code in ((ValueError("PRIVATE-CANARY"), 1), (KeyboardInterrupt(), 130)):
            with (
                patch.object(self.service, "enforce", side_effect=error),
                contextlib.redirect_stderr(io.StringIO()) as err,
                contextlib.redirect_stdout(io.StringIO()) as out,
            ):
                self.assertEqual(self.service.main(["--config", self.path]), code)
            self.assertEqual(err.getvalue(), "trust_observer_rejected\n")
            self.assertEqual(out.getvalue(), "")

    @unittest.skipUnless(sys.platform == "linux", "actual POSIX singleton lock")
    def test_second_supervisor_refused_before_child_on_real_directory_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o700)
            self.observer.path = str(Path(directory) / "observer.json")
            with (
                self.service.journal.locked(directory),
                patch.object(self.service, "enforce"),
                patch.object(self.service, "Observer", return_value=self.observer),
                patch.object(self.observer, "run") as run,
                contextlib.redirect_stderr(io.StringIO()) as err,
            ):
                self.assertEqual(self.service.main(["--config", self.observer.path]), 1)
                run.assert_not_called()
            self.assertEqual(err.getvalue(), "trust_observer_rejected\n")


if __name__ == "__main__":
    unittest.main()
