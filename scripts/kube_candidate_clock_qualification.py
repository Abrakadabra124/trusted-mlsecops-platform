"""Real CandidateReader/Lease/Engine; transport and ONNX worker are local doubles."""

import copy
import unittest
from unittest.mock import Mock, patch

from mlsecops import kube_candidate_clock as probe
from mlsecops import serving
from mlsecops.contracts import Rejected, canonical
from mlsecops.datasets import FEATURES
from scripts import candidate_serving_reader_qualification as fixtures


class CandidateClockContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.CandidateReaderContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.CandidateReaderContracts.tearDownClass()

    def setUp(self):
        self.fixture = fixtures.CandidateReaderContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.reader = self.fixture.reader()
        self.worker = Mock(image=self.reader.image)
        self.worker.binding = {"model_sha256": self.fixture.permit["model_sha256"]}
        self.worker.predict.side_effect = lambda rows: [0.75] * len(rows)
        self.clock = patch.object(serving.time, "time", side_effect=lambda: self.fixture.wall)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.engine = serving.Engine(self.reader, worker_factory=lambda *args: self.worker)
        self.addCleanup(self.engine.close)
        self.engine.activate()
        self.expected = {
            "model": self.fixture.permit["model_sha256"],
            "bundle": self.fixture.permit["subject_sha256"],
            "scores": [0.75],
        }
        self.body = {"schema_version": 1, "instances": [dict.fromkeys(FEATURES, 0.5)]}
        self.original = (
            self.reader.trust.wall_clock,
            self.reader.trust.monotonic_clock,
            self.reader.trust.reader,
            self.reader.check,
            self.worker.predict,
        )
        self.checks = []

    def check(self, label, actual, expected):
        self.checks.append(label)
        if type(actual) is not type(expected) or actual != expected:
            raise Rejected(label)

    def request(self, path, body=None):
        try:
            if path == "/readyz":
                return 200, self.engine.check()
            rows = [[row[name] for name in FEATURES] for row in body["instances"]]
            return 200, self.engine.predict(rows)
        except Rejected:
            return 503, {"error": "service_unavailable"}

    def fresh(self):
        # A new lease with the genuine clocks, same policy/permit/package.
        old = self.fixture.lease
        self.fixture.lease = type(old)(
            self.fixture.read_trust,
            trusted_root=self.fixture.public,
            environment="local-cpu",
            minimum_version=1,
            wall_clock=self.original[0],
            monotonic_clock=self.original[1],
        )
        return self.fixture.reader()

    def exercise(self, fault, request=None, fresh=None):
        return probe.exercise(
            self.engine,
            request or self.request,
            self.body,
            self.expected,
            self.check,
            fault=fault,
            reader_factory=fresh or self.fresh,
        )

    def restored(self):
        self.assertEqual(
            (
                self.reader.trust.wall_clock,
                self.reader.trust.monotonic_clock,
                self.reader.trust.reader,
                self.reader.check,
                self.worker.predict,
            ),
            self.original,
        )

    def test_wall_rollback(self):
        self.verify_fault("wall-backward", "trust_clock_invalid")

    def test_monotonic_rollback(self):
        self.verify_fault("monotonic-backward", "trust_clock_invalid")

    def test_divergence(self):
        self.verify_fault("wall-jump", "trust_clock_invalid")

    def test_server_skew(self):
        self.verify_fault("server-skew", "trust_server_clock_skew")

    def test_invalid_signature_invalidates_cache(self):
        self.verify_fault("invalid-signature", "invalid_signature")

    def verify_fault(self, fault, cause):
        before = copy.deepcopy(self.fixture.package)
        report = self.exercise(fault)
        self.assertEqual(report["cause"], cause)
        self.assertEqual(report["fault"], fault)
        self.assertEqual(report["max_golden_error"], 0.0)
        self.assertEqual([row["status"] for row in report["trace"]], [503] * 5)
        self.assertTrue(self.engine.generation.is_set())
        self.assertIsNone(self.reader.current)
        self.assertIsNone(self.reader.trust.payload)
        self.assertEqual(self.worker.predict.call_count, 1)  # Only pre-fault golden call.
        self.assertEqual(self.fixture.package, before)
        self.assertEqual(len(self.checks), len(set(self.checks)))
        self.restored()

    def test_unknown_fault_has_no_mutations(self):
        with self.assertRaisesRegex(Rejected, "candidate_clock_fault"):
            self.exercise("host-clock-change")
        self.assertTrue(self.engine.check()["ready"])
        self.restored()

    def test_transport_failure_restores_dependencies(self):
        calls = 0

        def request(path, body=None):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("PRIVATE-TOKEN")
            return self.request(path, body)

        with self.assertRaises(OSError):
            self.exercise("server-skew", request=request)
        self.restored()

    def test_false_success_cannot_pass_and_restores_dependencies(self):
        with self.assertRaises(Rejected):
            self.exercise("wall-backward", request=lambda *args: (200, {}))
        self.restored()

    def test_wrong_recovered_candidate_rejects(self):
        fresh = Mock()
        fresh.load.return_value.model_sha256 = "0" * 64
        with self.assertRaises(Rejected):
            self.exercise("invalid-signature", fresh=lambda: fresh)
        self.restored()

    def test_late_worker_call_is_detected_even_when_http_returns_503(self):
        calls = 0

        def request(path, body=None):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.worker.predict([[0.5] * len(FEATURES)])
            return self.request(path, body)

        with self.assertRaisesRegex(Rejected, "no-worker-predictions-after-injection"):
            self.exercise("server-skew", request=request)
        self.restored()

    def test_unexpected_internal_error_is_finite_and_not_claimed_as_expected_cause(self):
        original = self.reader.check
        calls = 0

        def check(loaded):
            nonlocal calls
            calls += 1
            if calls > 2:
                raise Rejected("PRIVATE-TOKEN")
            return original(loaded)

        self.reader.check = check
        with self.assertRaises(Rejected) as caught:
            self.exercise("server-skew")
        self.assertNotIn("PRIVATE-TOKEN", str(caught.exception))
        self.assertNotIn("PRIVATE-TOKEN", canonical(self.checks).decode())


if __name__ == "__main__":
    unittest.main()
