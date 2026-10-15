import copy
import io
import tempfile
import threading
import unittest
from contextlib import ExitStack, contextmanager, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops import trust
from mlsecops.contracts import Rejected, read_json
from scripts import serving_outage_native as outage
from scripts import trust_qualification as fixtures


class ServingOutageContracts(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.TrustContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.lease = outage.ObservedLease(
            self.fixture.read,
            trusted_root=self.fixture.public,
            environment="local-cpu",
            minimum_version=1,
            wall_clock=lambda: self.fixture.wall,
            monotonic_clock=lambda: self.fixture.monotonic,
        )

    def test_observation_only_advances_after_verified_refresh(self):
        with self.assertRaises(Rejected):
            self.lease.observation()
        result = self.lease.refresh()
        original = self.lease.observation()
        self.assertEqual(original["sequence"], 1)
        self.assertEqual(original["document_sha256"], result["document_sha256"])
        self.assertEqual(original["deadline"], 160)
        self.fixture.advance(5)
        self.fixture.failure = trust.Unavailable("offline")
        with self.assertRaises(trust.Unavailable):
            self.lease.refresh()
        self.assertEqual(original, self.lease.observation())
        self.fixture.failure = None
        self.fixture.payload["environment"] = "foreign"
        with self.assertRaises(Rejected):
            self.lease.refresh()
        self.assertEqual(original, self.lease.observation())
        self.fixture.payload["environment"] = "local-cpu"
        self.lease.refresh()
        self.assertEqual(self.lease.observation()["sequence"], 2)
        original["deadline"] = 9999
        self.assertEqual(self.lease.observation()["deadline"], 165)

    def trace(self):
        self.lease.refresh()
        anchor = self.lease.observation()
        anchor["deadline"] -= 0.1
        records = []
        for started, ended, status in (
            (1, 1.01, 200),
            (59.8, 59.85, 200),
            (59.9, 59.99, 503),
            (60.1, 60.11, 503),
        ):
            records.append(
                {
                    "started_wall": anchor["wall"] + started,
                    "finished_wall": anchor["wall"] + ended,
                    "started_monotonic": anchor["monotonic"] + started,
                    "finished_monotonic": anchor["monotonic"] + ended,
                    "http_status": status,
                    "response_valid": True,
                    "trust_sequence": anchor["sequence"],
                    "lease_deadline": anchor["deadline"],
                }
            )
        return anchor, records

    def test_bounded_http_trace_accepts_only_timely_denial_and_unchanged_lease(self):
        anchor, records = self.trace()
        result = outage.assess(anchor, records)
        self.assertEqual(result["status"], "pass")
        self.assertAlmostEqual(result["first_503_seconds"], 59.99)
        self.assertEqual(result["observations"], 4)
        self.assertFalse(result["release_ready"])

    def test_late_denial_late_success_recovery_and_lease_extension_fail(self):
        anchor, records = self.trace()
        mutations = (
            (2, "finished_monotonic", anchor["monotonic"] + 60.001),
            (1, "finished_monotonic", anchor["deadline"]),
            (3, "http_status", 200),
            (0, "trust_sequence", 2),
            (0, "lease_deadline", anchor["deadline"] + 1),
            (0, "response_valid", False),
            (0, "http_status", 429),
        )
        for index, field, value in mutations:
            with self.subTest(field=field, index=index):
                changed = copy.deepcopy(records)
                changed[index][field] = value
                self.assertEqual(outage.assess(anchor, changed)["status"], "fail")
        for changed in (records[:2], records[2:], records[:3]):
            self.assertEqual(outage.assess(anchor, changed)["status"], "fail")

    def test_malformed_nonfinite_unordered_or_unbounded_trace_rejected(self):
        anchor, records = self.trace()
        for value in (True, float("nan"), float("inf"), -1, "100"):
            changed = copy.deepcopy(records)
            changed[0]["started_monotonic"] = value
            with self.subTest(value=value), self.assertRaises(Rejected):
                outage.assess(anchor, changed)
        for changed in ([], records * 129, list(reversed(records))):
            with self.assertRaises(Rejected):
                outage.assess(anchor, changed)
        records[0]["raw_token"] = "PRIVATE-CANARY"
        with self.assertRaises(Rejected):
            outage.assess(anchor, records)

    def test_only_owned_authority_restarted_even_after_body_or_stop_failure(self):
        marker = {
            "container_id": "a" * 64,
            "workspace_id": "b" * 32,
            "network_id": "c" * 64,
            "volume": "owned",
            "port": 15446,
        }
        for stop_fails in (False, True):
            with self.subTest(stop_fails=stop_fails), ExitStack() as stack:
                stack.enter_context(
                    patch.object(outage.storage_bootstrap, "validate", return_value=marker)
                )
                bootstrap = stack.enter_context(patch.object(outage.storage_bootstrap, "bootstrap"))
                stack.enter_context(
                    patch.object(outage.storage_bootstrap, "admin", return_value="1")
                )

                def execute(arguments, **keywords):
                    if arguments[1] == "stop" and stop_fails:
                        raise Rejected("controlled-stop")
                    return "false" if arguments[1] == "inspect" else ""

                command = stack.enter_context(patch.object(outage, "command", side_effect=execute))
                with self.assertRaises(Rejected):
                    with outage.stopped_authority("owned", 15446):
                        raise Rejected("controlled-body")
                bootstrap.assert_not_called()
                self.assertIn(
                    ["docker", "start", marker["container_id"]],
                    [entry.args[0] for entry in command.call_args_list],
                )
                self.assertEqual(command.call_args_list[0].args[0][-1], marker["container_id"])

    def test_replaced_authority_is_never_started(self):
        original = {"container_id": "a" * 64, "port": 15446}
        replacement = {"container_id": "b" * 64}
        with (
            patch.object(outage.storage_bootstrap, "validate", side_effect=[original, replacement]),
            patch.object(outage, "command", return_value="false"),
            patch.object(outage.storage_bootstrap, "bootstrap") as bootstrap,
        ):
            with self.assertRaisesRegex(Rejected, "outage_authority_identity_changed"):
                with outage.stopped_authority("owned", 15446):
                    pass
            bootstrap.assert_not_called()

    def test_restart_requires_sql_readiness_and_port_mismatch_never_stops(self):
        marker = {"container_id": "a" * 64, "port": 15446}
        with (
            patch.object(outage.storage_bootstrap, "validate", return_value=marker),
            patch.object(outage, "command", return_value="false") as command,
            patch.object(outage.storage_bootstrap, "admin", side_effect=Rejected("not-ready")),
            patch.object(outage, "time", SimpleNamespace(monotonic=Mock(side_effect=[0, 31]))),
        ):
            with self.assertRaisesRegex(Rejected, "outage_authority_port_changed"):
                with outage.stopped_authority("owned", 12345):
                    self.fail("wrong port")
            command.assert_not_called()
            with self.assertRaisesRegex(Rejected, "outage_authority_recovery_unconfirmed"):
                with outage.stopped_authority("owned", 15446):
                    pass
            self.assertEqual(command.call_args.args[0], ["docker", "start", marker["container_id"]])

    def test_outage_requires_a_new_verified_read_not_cached_fallback(self):
        self.lease.refresh()
        engine = SimpleNamespace(
            lock=threading.Lock(), reader=Mock(trust=self.lease), loaded=object()
        )
        with patch.object(outage, "stopped_authority") as stopped:
            with self.assertRaisesRegex(Rejected, "outage_fresh_read_required"):
                with outage.stopped_authority_after_read(engine, "owned", 15446):
                    self.fail("cached fallback accepted")
            stopped.assert_not_called()

    def test_anchor_and_stop_share_lock_but_http_and_restart_do_not(self):
        self.lease.refresh()
        engine = SimpleNamespace(
            lock=threading.Lock(), reader=Mock(trust=self.lease), loaded=object()
        )
        engine.reader.check.side_effect = lambda loaded: self.lease.refresh()
        restarted = []

        @contextmanager
        def stopped(*arguments):
            self.assertTrue(engine.lock.locked())
            try:
                yield
            finally:
                self.assertFalse(engine.lock.locked())
                restarted.append(True)

        with patch.object(outage, "stopped_authority", stopped):
            with self.assertRaisesRegex(Rejected, "controlled-body"):
                with outage.stopped_authority_after_read(engine, "owned", 15446) as anchor:
                    self.assertEqual(anchor["sequence"], 2)
                    self.assertFalse(engine.lock.locked())
                    raise Rejected("controlled-body")
        self.assertEqual(restarted, [True])

    def test_prediction_validation_checks_binding_count_scores_and_denial_body(self):
        expected = {"model_sha256": "a" * 64, "bundle_sha256": "b" * 64}
        prediction = {**expected, "predictions": [{"decision": "score", "score": 0.5}]}
        self.assertTrue(outage.response_valid(200, prediction, expected, [0.5]))
        for field, value in (
            ("model_sha256", "c" * 64),
            ("predictions", []),
            ("predictions", [{"decision": "score", "score": True}]),
        ):
            self.assertFalse(
                outage.response_valid(200, {**prediction, field: value}, expected, [0.5])
            )
        self.assertFalse(outage.response_valid(200, prediction, expected, [0.9]))
        self.assertTrue(
            outage.response_valid(
                503,
                {
                    "schema_version": 1,
                    "request_id": "a" * 32,
                    "error": {"code": "model_unavailable"},
                },
                expected,
                [0.5],
            )
        )
        self.assertFalse(outage.response_valid(503, prediction, expected, [0.5]))

    def test_exercise_preserves_failed_timing_and_recovers_with_fresh_read(self):
        for cleanup_delay, recovery_unavailable in ((0, False), (0.3, False), (0, True)):
            with (
                self.subTest(cleanup_delay=cleanup_delay),
                tempfile.TemporaryDirectory() as temporary,
            ):
                self.fixture.failure = None
                self.fixture.delay = 0.1
                self.lease.refresh()
                self.fixture.delay = 0
                identity = {"model_sha256": "a" * 64, "bundle_sha256": "b" * 64}
                engine = Mock()
                engine.identity.return_value = identity
                engine.reader.trust = self.lease
                engine.worker = SimpleNamespace(container="old-worker")
                error = {
                    "schema_version": 1,
                    "request_id": "c" * 32,
                    "error": {"code": "model_unavailable"},
                }
                result = {**identity, "predictions": [{"decision": "score", "score": 0.5}]}
                unavailable = False
                recovered = False

                def request(path, body=None):
                    nonlocal unavailable
                    self.fixture.advance(0.005)
                    if recovered and recovery_unavailable:
                        return 503, error
                    if unavailable:
                        return 503, error
                    try:
                        try:
                            self.lease.refresh()
                        except trust.Unavailable:
                            pass
                        self.lease.check(policy_sha256="a" * 64, artifacts=[], keys=[])
                    except Rejected:
                        unavailable = True
                        self.fixture.advance(cleanup_delay)
                        engine.worker = None
                        return 503, error
                    return 200, result

                def activate():
                    nonlocal unavailable, recovered
                    self.lease.refresh()
                    unavailable = False
                    recovered = True
                    engine.worker = SimpleNamespace(container="new-worker")

                @contextmanager
                def stopped(*arguments):
                    anchor = self.lease.observation()
                    self.fixture.failure = trust.Unavailable("offline")
                    try:
                        yield anchor
                    finally:
                        self.fixture.failure = None

                @contextmanager
                def cold_site(ignored):
                    yield lambda *arguments: (503, error)

                def confirmed(name, condition):
                    if not condition:
                        raise Rejected(name)

                engine.activate.side_effect = activate
                output = Path(temporary) / "trace.json"
                with (
                    patch.object(
                        outage,
                        "time",
                        SimpleNamespace(
                            time=lambda: self.fixture.wall,
                            monotonic=lambda: self.fixture.monotonic,
                            sleep=self.fixture.advance,
                        ),
                    ),
                    patch.object(outage, "stopped_authority_after_read", stopped),
                    patch.object(outage, "site", cold_site),
                    patch.object(outage, "command", return_value=""),
                    redirect_stdout(io.StringIO()) as stream,
                ):
                    arguments = dict(
                        authority="owned",
                        port=15446,
                        reader_factory=Mock(),
                        expected=[0.5],
                        output=output,
                        confirmed=confirmed,
                    )
                    if cleanup_delay or recovery_unavailable:
                        with self.assertRaises(Rejected):
                            outage.exercise(engine, request, {}, **arguments)
                    else:
                        self.assertEqual(
                            outage.exercise(engine, request, {}, **arguments)["status"], "pass"
                        )
                report = read_json(output)
                self.assertEqual(
                    report["status"],
                    "inconclusive" if recovery_unavailable else "fail" if cleanup_delay else "pass",
                )
                self.assertEqual("recovery_verified" in report, not recovery_unavailable)
                self.assertIn("http_trust_outage", stream.getvalue())
                engine.activate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
