import copy
import io
import json
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, read_json
from mlsecops.datasets import FEATURES
from scripts import serving_core_qualification as core
from scripts import serving_pause_native as pause
from scripts.serving_native import site


class ServingPauseContracts(unittest.TestCase):
    def test_fault_selection_wraps_actual_http_prediction_dispatch(self):
        fixture = core.ServingCoreContracts()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        with tempfile.TemporaryDirectory() as directory:
            probe = pause.PausedQuery(Path(directory) / "client", {"container_id": "owned"})
            selected = []
            fixture.reader.check.side_effect = lambda loaded: selected.append(
                getattr(probe.local, "selected", False)
            )
            fixture.reader.trust.observation.return_value = {
                "version": 1,
                "document_sha256": "a" * 64,
                "sequence": 1,
                "wall": time.time(),
                "monotonic": time.monotonic(),
                "deadline": time.monotonic() + 60,
            }

            @contextmanager
            def injection(*arguments):
                yield probe

            def confirmed(name, condition):
                if not condition:
                    raise Rejected(name)

            with (
                site(fixture.engine) as request,
                patch.object(pause, "injection", injection),
                patch.object(pause, "command") as command,
                patch.object(probe, "run", wraps=probe.run) as run,
                redirect_stdout(io.StringIO()),
            ):
                with self.assertRaisesRegex(Rejected, "paused-established-query"):
                    pause.exercise(
                        fixture.engine,
                        request,
                        {"schema_version": 1, "instances": [dict.fromkeys(FEATURES, 0.5)]},
                        authority="unused",
                        port=15449,
                        client="unused",
                        expected=[0.75],
                        output=Path(directory) / "trace.json",
                        confirmed=confirmed,
                    )
                run.assert_called_once()
                self.assertIs(run.call_args.args[0].__func__, core.serving.Engine.predict_result)
                self.assertTrue(any(selected))
                command.assert_not_called()
            trace = read_json(Path(directory) / "trace.json")
            self.assertEqual(trace["status"], "inconclusive")
            self.assertFalse(trace["denial"]["connected_read_entered"])
            self.assertEqual(trace["denial"]["http_status"], 200)

    def setUp(self):
        self.owned = {"container_id": "a" * 64, "port": 15449}
        self.connection = Mock()
        self.connection.__enter__ = Mock(return_value=self.connection)
        self.connection.__exit__ = Mock(return_value=False)

    def test_expiry_window_requires_actual_short_signed_policy_binding(self):
        anchor = {
            "version": 2,
            "document_sha256": "a" * 64,
            "sequence": 9,
            "wall": 1000,
            "monotonic": 100,
            "deadline": 106,
        }
        receipt = {"version": 2, "document_sha256": "a" * 64, "reused": False}
        self.assertEqual(pause.expiry_window(anchor, 1008, receipt, 100.2), 108)
        for target, field, value in (
            ("receipt", "version", 1),
            ("receipt", "document_sha256", "b" * 64),
            ("receipt", "reused", True),
            ("receipt", "version", True),
            ("receipt", "document_sha256", "invalid"),
            ("anchor", "deadline", 111),
            ("anchor", "deadline", 99),
            ("anchor", "wall", float("nan")),
            ("anchor", "monotonic", 102),
        ):
            with self.subTest(target=target, field=field, value=value):
                selected = {"anchor": copy.deepcopy(anchor), "receipt": copy.deepcopy(receipt)}
                selected[target][field] = value
                with self.assertRaises(Rejected):
                    pause.expiry_window(selected["anchor"], 1008, selected["receipt"], 100.2)
        for expiry in (True, 1008.0, 1005, 1020):
            with self.subTest(expiry=expiry), self.assertRaises(Rejected):
                pause.expiry_window(anchor, expiry, receipt, 100.2)

    def test_expiry_profile_rejects_missing_renewal_before_runtime_access(self):
        engine, request = Mock(), Mock()
        with self.assertRaisesRegex(Rejected, "pause_expiry_renewal_required"):
            pause.exercise(
                engine,
                request,
                {},
                authority="owned",
                port=15449,
                client="client",
                expected=[],
                output="unused",
                confirmed=Mock(),
                expiry_receipt={},
                renew=None,
            )
        engine.identity.assert_not_called()
        request.assert_not_called()

    def test_failed_baseline_preserves_profile_receipt_and_stdout_key(self):
        for near_expiry in (False, True):
            with self.subTest(near_expiry=near_expiry), tempfile.TemporaryDirectory() as directory:
                engine = Mock()
                engine.identity.return_value = {"model_sha256": "a" * 64, "bundle_sha256": "b" * 64}
                receipt = {"version": 2, "document_sha256": "c" * 64, "reused": False}
                output = Path(directory) / "trace.json"
                captured = io.StringIO()

                def confirmed(name, condition):
                    if not condition:
                        raise Rejected(name)

                with (
                    redirect_stdout(captured),
                    patch.object(pause, "response_valid", return_value=True),
                    patch.object(pause, "injection") as injection,
                    self.assertRaisesRegex(Rejected, "baseline-golden"),
                ):
                    pause.exercise(
                        engine,
                        Mock(return_value=(503, {})),
                        {},
                        authority="owned",
                        port=15449,
                        client="client",
                        expected=[],
                        output=output,
                        confirmed=confirmed,
                        expiry_receipt=receipt if near_expiry else None,
                        renew=Mock() if near_expiry else None,
                    )
                trace = read_json(output)
                self.assertEqual(trace["status"], "inconclusive")
                self.assertIs(trace["release_ready"], False)
                self.assertEqual(trace.get("expected_trust"), receipt if near_expiry else None)
                key = "http_expiring_query" if near_expiry else "http_paused_query"
                self.assertEqual(json.loads(captured.getvalue()), {key: trace})
                injection.assert_not_called()

    def test_expiry_profile_observes_expiry_and_renews_before_explicit_recovery(self):
        for fault in (
            "none",
            "stale-renewal",
            "late-active",
            "late-denial",
            "early-wake",
            "wrong-recovered-policy",
            "expiry-already-passed",
        ):
            with (
                self.subTest(fault=fault),
                tempfile.TemporaryDirectory() as directory,
            ):
                clock = SimpleNamespace(wall=1000.0, monotonic=100.0)
                anchor = {
                    "version": 2,
                    "document_sha256": "a" * 64,
                    "sequence": 9,
                    "wall": 1000,
                    "monotonic": 100,
                    "deadline": 106,
                }
                receipt = {"version": 2, "document_sha256": "a" * 64, "reused": False}
                renewal = {
                    "version": 2 if fault == "stale-renewal" else 3,
                    "document_sha256": "c" * 64,
                    "reused": False,
                }
                calls = []
                probe = Mock(entered=threading.Event(), finished=threading.Event())
                probe.entered.set()
                probe.active.return_value = True

                @contextmanager
                def injection(*arguments):
                    try:
                        yield probe
                    finally:
                        calls.append("unpause")
                        probe.finished.set()

                engine = Mock(lock=threading.Lock(), generation=threading.Event())
                engine.generation.set()
                engine.admission.deadline = 500
                engine.identity.return_value = {"model_sha256": "a" * 64, "bundle_sha256": "b" * 64}
                engine.worker.container = "old"
                engine.reader.trust.lock = threading.RLock()
                engine.reader.trust.payload = {"expires_at": 1008}
                engine.reader.trust.observation.side_effect = [
                    anchor,
                    {
                        **anchor,
                        "sequence": 12,
                        "version": 2 if fault == "wrong-recovered-policy" else 3,
                        "document_sha256": "c" * 64,
                        "monotonic": 109,
                    },
                ]

                def drain():
                    self.assertIn("unpause", calls)
                    calls.append("drain")
                    engine.worker = None

                def renew():
                    self.assertIn("drain", calls)
                    calls.append("renew")
                    return renewal

                def activate():
                    self.assertIn("renew", calls)
                    calls.append("activate")
                    engine.worker = Mock(container="new")

                def request(path, body=None):
                    if not calls:
                        calls.append("baseline")
                        return 200, {}
                    if "activate" in calls:
                        return 200, {}
                    if path == "/readyz" and fault == "expiry-already-passed":
                        clock.wall, clock.monotonic = 1008.1, 108.1
                    if "unpause" not in calls and path == "/v1/predict":
                        if clock.monotonic >= 108:
                            calls.append("post-expiry")
                        else:
                            probe.observed = {
                                "wall": 1006.1 if fault == "late-active" else 1000.1,
                                "monotonic": 106.1 if fault == "late-active" else 100.1,
                            }
                            elapsed = 6.1 if fault == "late-denial" else 5.8
                            clock.wall, clock.monotonic = 1000 + elapsed, 100 + elapsed
                    return 503, {}

                def sleep(seconds):
                    if fault != "early-wake":
                        clock.wall += seconds
                        clock.monotonic += seconds

                def confirmed(name, condition):
                    self.assertTrue(name.startswith("near-expiry-"))
                    if not condition:
                        raise Rejected(name)

                engine.drain.side_effect = drain
                engine.activate.side_effect = activate
                output = Path(directory) / "trace.json"
                with (
                    patch.object(
                        pause,
                        "time",
                        SimpleNamespace(
                            time=lambda: clock.wall, monotonic=lambda: clock.monotonic, sleep=sleep
                        ),
                    ),
                    patch.object(pause, "injection", injection),
                    patch.object(pause, "response_valid", return_value=True),
                    patch.object(pause, "command", return_value=""),
                    redirect_stdout(io.StringIO()),
                ):
                    arguments = dict(
                        authority="owned",
                        port=15449,
                        client="client",
                        expected=[],
                        output=output,
                        confirmed=confirmed,
                        expiry_receipt=receipt,
                        renew=renew,
                    )
                    succeeds = fault in ("none", "expiry-already-passed")
                    if not succeeds:
                        with self.assertRaises(Rejected):
                            pause.exercise(engine, request, {}, **arguments)
                    else:
                        result = pause.exercise(engine, request, {}, **arguments)
                        self.assertEqual(result["status"], "pass")
                        self.assertGreaterEqual(result["post_expiry"]["started_wall"], 1008)
                        self.assertEqual(result["renewal_receipt"], renewal)
                reached_recovery = fault not in ("late-active", "late-denial", "early-wake")
                self.assertEqual("post-expiry" in calls, reached_recovery)
                self.assertEqual("renew" in calls, reached_recovery)
                self.assertEqual("activate" in calls, reached_recovery and fault != "stale-renewal")
                self.assertEqual(
                    read_json(output)["status"], "pass" if succeeds else "inconclusive"
                )

    def test_foreign_port_is_rejected_before_connect_or_pause(self):
        with (
            patch.object(pause.storage_bootstrap, "validate", return_value=self.owned),
            patch.object(pause, "command") as command,
            self.assertRaises(Rejected),
        ):
            with pause.injection("owned", 15450, "client"):
                self.fail("foreign port accepted")
        command.assert_not_called()

    def test_connected_read_is_retained_until_unpause_even_on_exception(self):
        actions = []

        def command(arguments, **keywords):
            actions.append(arguments)
            return "true" if len(actions) == 2 else "false"

        with (
            patch.object(pause.storage_bootstrap, "validate", return_value=self.owned),
            patch.object(pause.storage, "connect", return_value=self.connection),
            patch.object(pause, "command", side_effect=command),
            self.assertRaisesRegex(RuntimeError, "test failure"),
        ):
            with pause.injection("owned", 15449, "client") as probe:

                def operation():
                    with pause.storage.connect("client") as connection:
                        self.assertFalse(probe.entered.is_set())
                        self.assertFalse(probe.finished.is_set())
                        connection.execute("SELECT fixture")
                        self.assertTrue(probe.entered.is_set())
                    return 7

                self.assertEqual(probe.run(operation), 7)
                self.assertTrue(probe.finished.is_set())
                raise RuntimeError("test failure")
        self.assertEqual([item[1] for item in actions], ["pause", "inspect", "unpause", "inspect"])
        self.assertTrue(all(item[-1] == self.owned["container_id"] for item in actions))
        self.connection.execute.assert_called_once_with("SELECT fixture")

    def test_unrelated_thread_and_client_are_not_paused(self):
        with (
            patch.object(pause.storage_bootstrap, "validate", return_value=self.owned),
            patch.object(pause.storage, "connect", return_value=self.connection),
            patch.object(pause, "command") as command,
        ):
            with pause.injection("owned", 15449, "client") as probe:
                with pause.storage.connect("client"):
                    pass
                probe.run(lambda: pause.storage.connect("other").__enter__())
                self.assertFalse(probe.entered.is_set())
        command.assert_not_called()

    def test_changed_owner_prevents_unpause_of_unverified_target(self):
        probe = pause.PausedQuery("client", self.owned)
        probe.attempted = True
        with (
            patch.object(pause.storage_bootstrap, "validate", return_value={}),
            patch.object(pause, "command") as command,
            self.assertRaisesRegex(Rejected, "pause_authority_identity_changed"),
        ):
            probe.restore("owned")
        command.assert_not_called()

    def test_connection_finishing_after_context_exit_cannot_pause_authority(self):
        entered, release = threading.Event(), threading.Event()
        failures = []

        def connect(client):
            entered.set()
            release.wait(3)
            return self.connection

        with (
            patch.object(pause.storage_bootstrap, "validate", return_value=self.owned),
            patch.object(pause.storage, "connect", side_effect=connect),
            patch.object(pause, "command", return_value="true") as command,
        ):
            with pause.injection("owned", 15449, "client") as probe:

                def operation():
                    try:
                        with pause.storage.connect("client") as connection:
                            connection.execute("SELECT fixture")
                    except Rejected as failure:
                        failures.append(str(failure))

                thread = threading.Thread(target=lambda: probe.run(operation))
                thread.start()
                self.assertTrue(entered.wait(1))
            release.set()
            thread.join(3)
            self.assertFalse(thread.is_alive())
            command.assert_not_called()
            self.assertEqual(failures, ["pause_injection_closed"])

    def test_query_activity_is_required_not_only_open_connection(self):
        probe = pause.PausedQuery("client", self.owned)
        self.assertFalse(probe.active())
        probe.connection = self.connection
        self.connection.info.transaction_status = pause.TransactionStatus.IDLE
        self.assertFalse(probe.active())
        self.connection.info.transaction_status = pause.TransactionStatus.ACTIVE
        self.assertTrue(probe.active())

    def test_active_observation_after_http_completion_is_not_evidence(self):
        self.assertTrue(pause.active_before_denial({"wall": 1001, "monotonic": 101}, 100, 102))
        for observation in (
            None,
            {"wall": 1003, "monotonic": 103},
            {"wall": 999, "monotonic": 99},
            {"wall": 1001, "monotonic": float("nan")},
        ):
            with self.subTest(observation=observation):
                self.assertFalse(pause.active_before_denial(observation, 100, 102))

    def test_observer_records_active_time_and_stops_on_error_or_cancellation(self):
        for state in ("active", "error", "stopped"):
            with self.subTest(state=state):
                probe = pause.PausedQuery("client", self.owned)
                if state == "stopped":
                    probe.stop_observer.set()
                with patch.object(
                    probe,
                    "active",
                    side_effect=Rejected("closed") if state == "error" else None,
                    return_value=True,
                ) as active:
                    started = time.monotonic()
                    probe.observe()
                    finished = time.monotonic()
                if state == "active":
                    self.assertTrue(pause.active_before_denial(probe.observed, started, finished))
                else:
                    self.assertIsNone(probe.observed)
                self.assertEqual(active.call_count, 0 if state == "stopped" else 1)

    def test_observer_start_failure_cannot_leave_paused_resources(self):
        with (
            patch.object(pause.storage_bootstrap, "validate", return_value=self.owned),
            patch.object(pause, "command") as command,
            patch.object(pause.threading.Thread, "start", side_effect=RuntimeError("start failed")),
            self.assertRaisesRegex(RuntimeError, "start failed"),
        ):
            with pause.injection("owned", 15449, "client"):
                self.fail("unstarted observer accepted")
        command.assert_not_called()

    def test_trace_requires_unfinished_read_and_restores_before_drain(self):
        for early_finish, query_active, late_publication in (
            (False, True, False),
            (True, True, False),
            (False, False, False),
            (False, True, True),
        ):
            with (
                self.subTest(early_finish=early_finish),
                tempfile.TemporaryDirectory() as directory,
            ):
                probe = Mock(entered=threading.Event(), finished=threading.Event())
                probe.active.return_value = query_active
                probe.entered.set()
                if early_finish:
                    probe.finished.set()
                restored = []

                @contextmanager
                def injection(*arguments):
                    try:
                        yield probe
                    finally:
                        restored.append(True)
                        probe.finished.set()

                engine = Mock(lock=threading.Lock(), generation=threading.Event())
                engine.generation.set()
                engine.identity.return_value = {"model_sha256": "a" * 64, "bundle_sha256": "b" * 64}
                engine.worker.container = "old"
                engine.reader.trust.observation.side_effect = [
                    {
                        "sequence": 1,
                        "monotonic": time.monotonic(),
                        "deadline": time.monotonic() + 60,
                    },
                    {"sequence": 2},
                ]

                def drain():
                    self.assertTrue(restored)
                    engine.worker = None

                def activate():
                    engine.worker = Mock(container="new")

                def confirmed(name, condition):
                    if not condition:
                        raise Rejected(name)

                engine.drain.side_effect = drain
                engine.activate.side_effect = activate
                responses = iter([(200, {}), (503, {}), (503, {}), (503, {}), (200, {})])

                def request(*arguments):
                    probe.observed = (
                        None
                        if late_publication
                        else {"wall": time.time(), "monotonic": time.monotonic()}
                    )
                    return next(responses)

                original_write = pause.write_json

                def write_trace(path, trace):
                    original_write(path, trace)
                    if late_publication and "denial" in trace:
                        probe.observed = {
                            "wall": trace["denial"]["started_wall"],
                            "monotonic": trace["denial"]["started_monotonic"],
                        }

                output = Path(directory) / "trace.json"
                with (
                    patch.object(pause, "injection", injection),
                    patch.object(pause, "response_valid", return_value=True),
                    patch.object(pause, "command", return_value=""),
                    patch.object(pause, "write_json", side_effect=write_trace),
                    redirect_stdout(io.StringIO()),
                ):
                    arguments = dict(
                        authority="owned",
                        port=15449,
                        client="client",
                        expected=[],
                        output=output,
                        confirmed=confirmed,
                    )
                    if early_finish or not query_active or late_publication:
                        with self.assertRaisesRegex(Rejected, "HTTP-denial-before-completion"):
                            pause.exercise(engine, request, {}, **arguments)
                    else:
                        pause.exercise(engine, request, {}, **arguments)
                self.assertTrue(restored)
                self.assertEqual(
                    read_json(output)["status"],
                    "inconclusive"
                    if early_finish or not query_active or late_publication
                    else "pass",
                )


if __name__ == "__main__":
    unittest.main()
