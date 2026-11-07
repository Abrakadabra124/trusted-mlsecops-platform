"""M14 must exercise the actual configured monitoring path, without weakening load limits."""

import asyncio
import copy
import functools
import os
import tempfile
import unittest
from contextlib import asynccontextmanager, nullcontext
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import load_monitoring as monitor
from mlsecops import monitoring_alerts, signing
from mlsecops.contracts import Rejected, canonical, digest
from scripts.load_golden_qualification import expected as golden_expected
from scripts.monitoring_qualification import reference
from scripts.monitoring_stream_qualification import context, decisions


@functools.lru_cache(maxsize=1)
def materials():
    with tempfile.TemporaryDirectory() as temporary:
        key = Path(temporary) / "reference.pem"
        public = signing.create_key(key)
        return {
            "reference": signing.sign(reference(), "monitor-reference", key),
            "reference_public": public,
        }


def expected():
    return {**golden_expected(), "monitoring": copy.deepcopy(materials())}


def proof(observations=1010, epoch="a" * 32):
    document = monitor.reference(expected())
    with tempfile.TemporaryDirectory() as temporary:
        key = Path(temporary) / "sink.pem"
        public = signing.create_key(key)
        binding = {
            "epoch": epoch,
            "reference_sha256": digest(canonical(document)),
            "sink_public": public,
            "state_sha256": "e" * 64,
        }
        admission = {
            "schema_version": 1,
            "state_sha256": binding["state_sha256"],
            "role": "producer",
            "epoch": epoch,
            "reference_sha256": binding["reference_sha256"],
            "previous_epochs": 0,
            "history_unavailable": False,
        }
        state = {
            "schema_version": 1,
            "reference_sha256": binding["reference_sha256"],
            "epoch": epoch,
            "state": "observing",
            "healthy": True,
            "faults": [],
            "observations": observations,
            "windows_evaluated": observations // 1000,
            "pending_windows": 0,
            "pending_alerts": 0,
            "alerts_delivered": 1,
            "delivery_failures": 0,
            "evicted_windows": 0,
            "unclosed_observations": observations % 1000,
            "epoch_admission": admission,
            "history_restored": False,
            "release_ready": False,
        }
        event = monitoring_alerts.event(
            reference_sha256=binding["reference_sha256"],
            window_sha256="c" * 64,
            evidence_sha256="d" * 64,
            epoch=epoch,
            sequence=1,
            kind="data_drift",
            admitted_at_ms=2000,
        )
        acknowledgement = {
            "schema_version": 1,
            "event_sha256": digest(canonical(event)),
            "epoch": epoch,
            "sequence": 1,
            "reference_sha256": binding["reference_sha256"],
            "received_at_ms": 2001,
        }
        receipt = {
            "kind": event["kind"],
            "window_sha256": event["window_sha256"],
            "event_sha256": acknowledgement["event_sha256"],
            "received_at_ms": 2001,
            "delivery_seconds": 0.001,
            "admitted_ns": 0,
            "finished_ns": 1000000,
            "event": event,
            "envelope": signing.sign(acknowledgement, "monitor-alert-receipt", key),
        }
        return {"binding": binding, "state": state, "receipts": [receipt]}


class MonitoredLoadContracts(unittest.TestCase):
    def test_reference_is_authenticated_and_bound_to_actual_golden_candidate(self):
        self.assertEqual(monitor.reference(expected()), reference())
        for field in ("model", "bundle"):
            value = expected()
            value[field] = "f" * 64
            with self.assertRaises(Rejected):
                monitor.reference(value)
        value = expected()
        value["monitoring"]["reference"]["payload"] = signing.encode64(canonical({}))
        with self.assertRaises(Rejected):
            monitor.reference(value)

    def test_healthy_collector_count_and_authentic_receipt_are_required(self):
        value = proof()
        result = monitor.verify(value, monitor.reference(expected()), "a" * 32, 1010)
        self.assertEqual(result["observations"], 1010)
        self.assertTrue(result["enabled"])
        self.assertFalse(result["release_ready"])
        for field, replacement in (
            ("healthy", False),
            ("state", "inactive"),
            ("faults", ["scheduler"]),
            ("observations", 1009),
            ("pending_windows", 1),
            ("pending_alerts", 1),
            ("epoch", "b" * 32),
            ("windows_evaluated", 0),
            ("history_restored", True),
            ("release_ready", True),
            ("alerts_delivered", 2),
        ):
            changed = copy.deepcopy(value)
            changed["state"][field] = replacement
            with self.subTest(field=field), self.assertRaises(Rejected):
                monitor.verify(changed, monitor.reference(expected()), "a" * 32, 1010)
        for field, replacement in (
            ("previous_epochs", 1),
            ("history_unavailable", True),
            ("role", "sink"),
        ):
            changed = copy.deepcopy(value)
            changed["state"]["epoch_admission"][field] = replacement
            with self.assertRaises(Rejected):
                monitor.verify(changed, monitor.reference(expected()), "a" * 32, 1010)

    def test_forged_late_changed_or_missing_receipt_never_becomes_enabled_proof(self):
        value = proof()
        for field, replacement in (
            ("envelope", {}),
            ("finished_ns", 120000000000),
            ("delivery_seconds", 0.002),
            ("event_sha256", "f" * 64),
            ("kind", "telemetry_gap"),
            ("received_at_ms", 2002),
        ):
            changed = copy.deepcopy(value)
            changed["receipts"][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(Rejected):
                monitor.verify(changed, monitor.reference(expected()), "a" * 32, 1010)
        value["receipts"] = []
        with self.assertRaises(Rejected):
            monitor.verify(value, monitor.reference(expected()), "a" * 32, 1010)

    def test_binding_unknown_fields_and_counter_types_are_strict(self):
        value = proof()
        for field, replacement in (
            ("epoch", "bad"),
            ("reference_sha256", "f" * 64),
            ("sink_public", "bad"),
            ("state_sha256", "bad"),
        ):
            changed = copy.deepcopy(value)
            changed["binding"][field] = replacement
            with self.subTest(field=field), self.assertRaises(Rejected):
                monitor.verify(changed, monitor.reference(expected()), "a" * 32, 1010)
        for field in ("observations", "pending_alerts", "delivery_failures", "evicted_windows"):
            changed = copy.deepcopy(value)
            changed["state"][field] = True
            with self.assertRaises(Rejected):
                monitor.verify(changed, monitor.reference(expected()), "a" * 32, 1010)
        value["unexpected"] = "PRIVATE"
        with self.assertRaises(Rejected):
            monitor.verify(value, monitor.reference(expected()), "a" * 32, 1010)

    def test_request_accounting_includes_initial_warmup_overload_and_recovery(self):
        observation = {"records": [{"status": 200}, {"status": 429}, {"status": 200}]}
        overload = {"correct": 8, "recovered": True}
        self.assertEqual(monitor.observations(observation, overload), 12)
        overload["recovered"] = 1
        with self.assertRaises(Rejected):
            monitor.observations(observation, overload)

    def test_snapshot_scheduling_and_wait_failure_cancel_without_coroutine_leak(self):
        runtime = Mock()
        session = monitor.Session(runtime, reference(), proof()["binding"])
        future = Mock()
        future.result.side_effect = TimeoutError()
        for error in (RuntimeError("closed-loop"), None):

            def schedule(operation, loop):
                operation.close()
                if error:
                    raise error
                return future

            with patch.object(asyncio, "run_coroutine_threadsafe", side_effect=schedule):
                with self.assertRaises((RuntimeError, TimeoutError)):
                    session.capture()
        future.cancel.assert_called_once()

    def test_pending_work_must_drain_before_snapshot_is_admitted(self):
        good = proof()
        pending = copy.deepcopy(good)
        pending["state"]["pending_windows"] = 1
        session = monitor.Session(Mock(), reference(), good["binding"])
        with (
            patch.object(session, "capture", side_effect=[pending, good]),
            patch.object(monitor.time, "sleep") as sleep,
        ):
            result, summary = session.finish(1010)
            self.assertEqual(result, good)
            self.assertEqual(summary["status"], "pass")
            sleep.assert_called_once_with(0.05)
        with (
            patch.object(session, "capture", return_value=pending),
            patch.object(monitor.time, "monotonic", side_effect=[0, 10]),
            self.assertRaisesRegex(Rejected, "load_monitor_pending"),
        ):
            session.finish(1010)

    def test_context_never_accepts_unfinished_or_faulted_monitor_shutdown(self):
        for state in ("unused", "closed", "running", "faulted"):
            runtime = Mock()
            runtime.task = None if state == "unused" else Mock()
            if runtime.task:
                runtime.task.done.return_value = state != "running"
            runtime.snapshot.return_value = {"faults": ["shutdown"] if state == "faulted" else []}
            with (
                tempfile.TemporaryDirectory() as temporary,
                patch.object(monitor.monitoring_state, "initialize", return_value="e" * 64),
                patch.object(monitor.monitoring_config, "producer", return_value=runtime),
            ):

                def execute():
                    with monitor.session(
                        Path(temporary) / "owned",
                        expected(),
                        "a" * 32,
                        lambda app: nullcontext(1234),
                    ) as session:
                        self.assertIs(session.runtime, runtime)
                        monitor.binding(session.binding, reference(), "a" * 32)

                if state in ("running", "faulted"):
                    with self.assertRaisesRegex(Rejected, "load_monitor_shutdown"):
                        execute()
                else:
                    execute()

    @unittest.skipUnless(os.name == "posix", "one-use durable epochs require POSIX")
    def test_real_configured_runtime_sink_receipt_and_lifespan_close(self):
        from fastapi import FastAPI

        from mlsecops.load_probe import listen

        with tempfile.TemporaryDirectory() as temporary:
            with monitor.session(
                Path(temporary) / "owned", expected(), "a" * 32, listen
            ) as session:

                @asynccontextmanager
                async def lifecycle(app):
                    session.runtime.start()
                    try:
                        for index in range(1001):
                            session.runtime.observe(
                                context(), [[0.55] * 6], decisions(1), f"{index:032x}"
                            )
                        await session.runtime.cycle()
                        yield
                    finally:
                        await session.runtime.close()

                with listen(FastAPI(lifespan=lifecycle)) as port:
                    packet, summary = session.finish(1001)
                    self.assertEqual(summary["observations"], 1001)
                    self.assertGreater(summary["alerts_delivered"], 0)
                    self.assertEqual(packet["state"]["pending_alerts"], 0)
                self.assertTrue(session.runtime.task.done())
                self.assertEqual(session.runtime.snapshot()["state"], "stopped")
                with self.assertRaises(OSError):
                    import socket

                    socket.create_connection(("127.0.0.1", port), timeout=0.2)


if __name__ == "__main__":
    unittest.main()
