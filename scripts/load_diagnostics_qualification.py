import copy
import threading
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import load_diagnostics as diagnostic
from mlsecops.contracts import Rejected


def fixture():
    @contextmanager
    def exclusive():
        yield

    engine = SimpleNamespace(
        exclusive=exclusive,
        reader=SimpleNamespace(check=lambda value: value, trust=SimpleNamespace(reader=lambda: 1)),
        worker=SimpleNamespace(ping=lambda: 2, predict=lambda value: value),
    )

    def predict(value):
        with engine.exclusive():
            engine.reader.check(value)
            engine.reader.trust.reader()
            engine.worker.ping()
            return engine.worker.predict(value)

    engine.predict_result = predict
    return engine


class DiagnosticContracts(unittest.TestCase):
    def test_wrapping_preserves_values_and_restores_every_method_after_failure(self):
        engine = fixture()
        originals = [getattr(obj, method) for obj, method, _ in diagnostic.targets(engine)]
        exclusive = engine.exclusive
        meter = diagnostic.Timings()
        with self.assertRaisesRegex(ValueError, "PRIVATE"), meter.instrument(engine):
            self.assertEqual(engine.predict_result("PRIVATE"), "PRIVATE")
            raise ValueError("PRIVATE")
        self.assertEqual(
            originals, [getattr(obj, method) for obj, method, _ in diagnostic.targets(engine)]
        )
        self.assertIs(engine.exclusive, exclusive)
        result = meter.snapshot()
        self.assertNotIn("PRIVATE", str(result))
        self.assertTrue(all(row["count"] == 1 and row["failed"] == 0 for row in result.values()))
        self.assertTrue(all(row["total_ns"] >= row["max_ns"] >= 0 for row in result.values()))

    def test_exact_timing_failure_propagation_and_refused_lock(self):
        meter = diagnostic.Timings()
        with patch.object(diagnostic.time, "monotonic_ns", side_effect=[10, 30]):
            with self.assertRaisesRegex(Rejected, "original"), meter.measure("reader_check"):
                raise Rejected("original")
        self.assertEqual(
            meter.snapshot()["reader_check"],
            {"count": 1, "failed": 1, "total_ns": 20, "max_ns": 20},
        )
        engine = fixture()

        @contextmanager
        def busy():
            raise Rejected("serving_busy")
            yield

        engine.exclusive = busy
        with meter.instrument(engine), self.assertRaisesRegex(Rejected, "serving_busy"):
            engine.predict_result(1)
        self.assertEqual(meter.snapshot()["engine_wait"]["failed"], 1)
        self.assertEqual(meter.snapshot()["engine_hold"]["count"], 0)

    def test_concurrent_updates_and_snapshot_are_detached(self):
        meter = diagnostic.Timings()
        threads = [
            threading.Thread(
                target=lambda: [meter.add("worker_ping", 2, False) for _ in range(100)]
            )
            for _ in range(4)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        snapshot = meter.snapshot()
        self.assertEqual(snapshot["worker_ping"]["count"], 400)
        self.assertEqual(snapshot["worker_ping"]["total_ns"], 800)
        snapshot["worker_ping"]["count"] = 0
        self.assertEqual(meter.snapshot()["worker_ping"]["count"], 400)

    def test_finite_reason_projection_and_summary_binding(self):
        for code in ("client_limited", "overloaded"):
            body = {"schema_version": 1, "request_id": "a" * 32, "error": {"code": code}}
            self.assertEqual(diagnostic.reason(body), code)
        for body in ({}, {"error": {"code": "PRIVATE"}}, None):
            self.assertEqual(diagnostic.reason(body), "unrecognized")
        value = diagnostic.result(diagnostic.Timings(), diagnostic.reasons())
        summary = {"warmup": {"outcomes": {"limited": 0}}, "measured": {"outcomes": {"limited": 0}}}
        overload = {"limited": 0}
        self.assertIs(diagnostic.checked(value, summary, overload), value)
        for section, key, bad in (
            ("timings", "worker_ping", {"count": True, "failed": 0, "total_ns": 0, "max_ns": 0}),
            ("limited", "normal", {"overloaded": 1, "client_limited": 0, "unrecognized": 0}),
            ("limited", "overload", {"overloaded": -1, "client_limited": 0, "unrecognized": 0}),
        ):
            altered = copy.deepcopy(value)
            altered[section][key] = bad
            with self.assertRaises(Rejected):
                diagnostic.checked(altered, summary, overload)
        with self.assertRaises(Rejected):
            diagnostic.checked({**value, "scope": "PRIVATE"}, summary, overload)


if __name__ == "__main__":
    unittest.main()
