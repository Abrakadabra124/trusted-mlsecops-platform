"""Trusted in-process aggregation; no service or model training is started."""

import dataclasses
import math
import unittest

from mlsecops import monitoring, monitoring_stream, serving_context
from mlsecops.audit_lineage import Lineage
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.datasets import FEATURES
from scripts.monitoring_qualification import reference


def context():
    lineage = Lineage(
        "f" * 40, "e" * 64, "f" * 64, "f" * 64, "c" * 64, "f" * 64, "f" * 64, "d" * 64
    )
    return serving_context.QualificationTrace("f" * 64, "f" * 64, "b" * 64, "a" * 64, lineage)


def decisions(count, *, score=0.5):
    return [{"decision": "score", "reason": None, "score": score} for _ in range(count)]


def accumulator():
    ref = reference()
    return monitoring_stream.Accumulator(ref, digest(canonical(ref)), started_at_ms=1000)


class StreamContracts(unittest.TestCase):
    def test_exact_bins_include_support_boundary_and_abstention_tails(self):
        stream = accumulator()
        features = [[value] * 6 for value in (-1, 0, 0.1, 0.9, 1, 2)]
        predictions = decisions(6)
        for index in (0, 5):
            predictions[index] = {"decision": "abstain", "reason": "outside-support", "score": None}
        stream.add(context(), features, predictions, "1" * 32)
        closed = stream.close(sequence=1, ended_at_ms=2000)
        document = closed.document()
        self.assertEqual(document["abstentions"], 2)
        self.assertEqual(document["observations"], 6)
        for key in FEATURES:
            self.assertEqual(document["histograms"][key], [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 2, 1])
        self.assertEqual(document["histograms"]["prediction"], [0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0])
        self.assertEqual(sum(positive for _, positive in closed.predictions), 4)
        self.assertEqual(closed.sha256, digest(canonical(document)))
        self.assertEqual(len(closed.predictions), 6)
        self.assertNotIn("11111111", canonical(document).decode())

    def test_real_thousand_observation_aggregate_is_accepted_by_evaluator(self):
        stream = accumulator()
        for index in range(10):
            rows = [[(row % 10 + 0.5) / 10] * 6 for row in range(100)]
            scores = [{"decision": "score", "reason": None, "score": row[0]} for row in rows]
            stream.add(context(), rows, scores, f"{index:032x}")
        closed = stream.close(sequence=1, ended_at_ms=2000)
        ref = reference()
        report = monitoring.Evaluator(ref, digest(canonical(ref))).evaluate(closed.document())
        self.assertEqual(report["status"], "observed")
        self.assertEqual(report["alerts"], [])
        self.assertTrue(all(value == 0 for value in report["psi"].values()))

    def test_model_bundle_lineage_and_context_type_must_match(self):
        original = context()
        alternatives = [
            None,
            dataclasses.asdict(original),
            serving_context.QualificationContext("f" * 64, "f" * 64, "b" * 64, "a" * 64),
            dataclasses.replace(original, model_sha256="f" * 64),
            dataclasses.replace(original, bundle_sha256="f" * 64),
        ]
        alternatives += [
            dataclasses.replace(
                original, lineage=dataclasses.replace(original.lineage, **{key: "f" * 64})
            )
            for key in ("dataset_sha256", "evaluation_sha256", "source_fingerprint")
        ]
        for value in alternatives:
            stream = accumulator()
            with self.subTest(value=type(value).__name__), self.assertRaises(Rejected):
                stream.add(value, [[0.5] * 6], decisions(1), "1" * 32)
            self.assertEqual(
                stream.close(sequence=1, ended_at_ms=2000).document()["observations"], 0
            )

    def test_release_trace_is_also_bound_without_claiming_promotion(self):
        original = context()
        trace = serving_context.ReleaseTrace(
            "f" * 64, "b" * 64, "a" * 64, original.lineage, "f" * 64, "f" * 64, "f" * 64
        )
        stream = accumulator()
        stream.add(trace, [[0.5] * 6], decisions(1), "1" * 32)
        self.assertEqual(stream.close(sequence=1, ended_at_ms=2000).document()["observations"], 1)

    def test_batch_is_validated_atomically_and_never_keeps_raw_features(self):
        for bad in (True, math.nan, math.inf, "private-canary", 10**1000):
            stream = accumulator()
            rows = [[0.5] * 6, [bad] * 6]
            with self.subTest(bad=type(bad).__name__), self.assertRaises(Rejected):
                stream.add(context(), rows, decisions(2), "1" * 32)
            self.assertEqual(
                stream.close(sequence=1, ended_at_ms=2000).document()["observations"], 0
            )
        for predicted in (
            [],
            {},
            decisions(2),
            [{"decision": "abstain", "reason": "outside-support", "score": None}],
            [{"decision": "score", "reason": "unexpected", "score": 0.5}],
            [{"decision": "score", "reason": None, "score": True}],
            [{"decision": "score", "reason": None, "score": math.nan}],
            [{"decision": "score", "reason": None, "score": 1.1}],
        ):
            with self.subTest(predicted=predicted), self.assertRaises(Rejected):
                accumulator().add(context(), [[0.5] * 6], predicted, "1" * 32)
        with self.assertRaises(Rejected):
            accumulator().add(context(), [[2] * 6], decisions(1), "1" * 32)

    def test_duplicate_request_cannot_inflate_window_or_cross_closed_boundary(self):
        stream = accumulator()
        stream.add(context(), [[0.5] * 6], decisions(1), "1" * 32)
        with self.assertRaisesRegex(Rejected, "monitor_request_duplicate"):
            stream.add(context(), [[0.5] * 6], decisions(1), "1" * 32)
        closed = stream.close(sequence=1, ended_at_ms=2000)
        self.assertIs(stream.close(sequence=1, ended_at_ms=2000), closed)
        with self.assertRaisesRegex(Rejected, "monitor_window_closed"):
            stream.add(context(), [[0.5] * 6], decisions(1), "2" * 32)
        with self.assertRaisesRegex(Rejected, "monitor_close_conflict"):
            stream.close(sequence=2, ended_at_ms=3000)
        document = closed.document()
        document["observations"] = 999
        self.assertEqual(closed.document()["observations"], 1)
        self.assertEqual(closed.predictions[0][0], monitoring_stream.observation_id("1" * 32, 0))

    def test_reference_time_capacity_and_id_validation(self):
        ref = reference()
        for expected, started in (("0" * 64, 1000), (digest(canonical(ref)), 999)):
            with self.assertRaises(Rejected):
                monitoring_stream.Accumulator(ref, expected, started_at_ms=started)
        for identifier, row in ((True, 0), ("bad", 0), ("1" * 32, True), ("1" * 32, 100)):
            with self.assertRaises(Rejected):
                monitoring_stream.observation_id(identifier, row)
        stream = accumulator()
        for index in range(200):
            stream.add(context(), [[0.5] * 6] * 100, decisions(100), f"{index:032x}")
        with self.assertRaisesRegex(Rejected, "monitor_capacity"):
            stream.add(context(), [[0.5] * 6], decisions(1), "f" * 32)
        self.assertEqual(
            stream.close(sequence=1, ended_at_ms=2000).document()["observations"], 20000
        )
        for ended in (1000, 61001, True):
            with self.assertRaises(Rejected):
                accumulator().close(sequence=1, ended_at_ms=ended)


if __name__ == "__main__":
    unittest.main()
