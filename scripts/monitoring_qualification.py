"""Fixed synthetic monitoring statistics; no HTTP, SQL or infrastructure."""

import copy
import math
import unittest
from unittest.mock import patch

from mlsecops import monitoring
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.datasets import FEATURES


def reference():
    return {
        "schema_version": 1,
        "profile": "synthetic-local-cpu-v1",
        "model_sha256": "a" * 64,
        "bundle_sha256": "b" * 64,
        "dataset_sha256": "c" * 64,
        "evaluation_sha256": "d" * 64,
        "source_fingerprint": "e" * 64,
        "frozen_at_ms": 1000,
        "observations": 1000,
        "abstentions": 0,
        "histograms": {key: [0] + [100] * 10 + [0] for key in (*FEATURES, "prediction")},
        "positive_labels": 200,
        "true_positives": 180,
    }


def window(ref, sequence=1, *, observations=1000, shifted=()):
    counts = [0] + [observations // 10] * 9 + [observations - 9 * (observations // 10)] + [0]
    histograms = {key: list(counts) for key in (*FEATURES, "prediction")}
    for key in shifted:
        histograms[key] = [0, observations] + [0] * 10
    return {
        "schema_version": 1,
        "reference_sha256": digest(canonical(ref)),
        "sequence": sequence,
        "started_at_ms": 1000 + (sequence - 1) * 1000,
        "ended_at_ms": 1000 + sequence * 1000,
        "observations": observations,
        "abstentions": 0,
        "histograms": histograms,
    }


class MonitoringContracts(unittest.TestCase):
    def setUp(self):
        self.reference = reference()
        self.engine = monitoring.Evaluator(self.reference, digest(canonical(self.reference)))

    def test_ten_clean_windows_do_not_alarm_or_authorize_release(self):
        for sequence in range(1, 11):
            result = self.engine.evaluate(window(self.reference, sequence))
            self.assertEqual(result["alerts"], [])
            self.assertEqual(result["status"], "observed")
            self.assertTrue(all(value == 0 for value in result["psi"].values()))
            self.assertIs(result["release_ready"], False)

    def test_shift_needs_two_consecutive_windows_for_same_feature(self):
        for sequence, changed, expected in (
            (1, (FEATURES[0],), []),
            (2, (FEATURES[1],), []),
            (3, (FEATURES[1], "prediction"), ["data_drift"]),
            (4, (FEATURES[1], "prediction"), ["data_drift", "prediction_drift"]),
            (5, (), []),
            (6, (FEATURES[1],), []),
        ):
            result = self.engine.evaluate(window(self.reference, sequence, shifted=changed))
            self.assertEqual(result["alerts"], expected)
        self.assertEqual(result["drift_features"], [])

    def test_exact_psi_threshold_is_inclusive(self):
        for value, expected in ((0.2, ["data_drift", "prediction_drift"]), (0.199999, [])):
            engine = monitoring.Evaluator(self.reference, digest(canonical(self.reference)))
            with patch.object(monitoring, "psi", return_value=value):
                engine.evaluate(window(self.reference))
                self.assertEqual(engine.evaluate(window(self.reference, 2))["alerts"], expected)

    def test_insufficient_windows_reset_streak_and_are_not_clean(self):
        self.engine.evaluate(window(self.reference, shifted=(FEATURES[0],)))
        for sequence, count in ((2, 999), (3, 0)):
            result = self.engine.evaluate(window(self.reference, sequence, observations=count))
            self.assertEqual(result["status"], "insufficient")
            self.assertEqual(result["alerts"], [])
            self.assertTrue(all(value is None for value in result["psi"].values()))
        result = self.engine.evaluate(window(self.reference, 4, shifted=(FEATURES[0],)))
        self.assertEqual(result["alerts"], [])

    def test_gap_is_visible_and_cannot_confirm_prior_drift(self):
        self.engine.evaluate(window(self.reference, shifted=(FEATURES[0],)))
        result = self.engine.evaluate(window(self.reference, 3, shifted=(FEATURES[0],)))
        self.assertEqual(result["alerts"], ["telemetry_gap"])
        result = self.engine.evaluate(window(self.reference, 4, shifted=(FEATURES[0],)))
        self.assertEqual(result["alerts"], ["data_drift"])

    def test_duplicate_is_idempotent_and_returns_unshared_result(self):
        first = window(self.reference, shifted=(FEATURES[0],))
        result = self.engine.evaluate(first)
        result["alerts"].append("forged")
        first["histograms"][FEATURES[0]][1] = 0
        original = window(self.reference, shifted=(FEATURES[0],))
        self.assertEqual(self.engine.evaluate(original)["alerts"], [])
        second = self.engine.evaluate(window(self.reference, 2, shifted=(FEATURES[0],)))
        self.assertEqual(second["alerts"], ["data_drift"])
        with self.assertRaisesRegex(Rejected, "monitor_window_replay"):
            self.engine.evaluate(original)

    def test_same_sequence_conflict_and_overlap_are_rejected_without_advancing(self):
        self.engine.evaluate(window(self.reference))
        with self.assertRaisesRegex(Rejected, "monitor_window_conflict"):
            self.engine.evaluate(window(self.reference, shifted=(FEATURES[0],)))
        second = window(self.reference, 2)
        second["started_at_ms"] -= 1
        with self.assertRaisesRegex(Rejected, "monitor_window_overlap"):
            self.engine.evaluate(second)
        self.assertEqual(self.engine.evaluate(window(self.reference, 2))["alerts"], [])

    def test_reference_is_pinned_copied_and_frozen_before_observation(self):
        self.reference["histograms"][FEATURES[0]][1] = 0
        self.assertEqual(self.engine.evaluate(window(reference()))["alerts"], [])
        for ref_hash in ("0" * 64, True, "bad"):
            with self.assertRaises(Rejected):
                monitoring.Evaluator(reference(), ref_hash)
        early = window(reference())
        early["started_at_ms"] = 999
        with self.assertRaisesRegex(Rejected, "monitor_window_before_reference"):
            self.engine.evaluate(early)

    def test_reference_shape_profile_counts_and_baseline_are_strict(self):
        mutations = (
            ("schema_version", True),
            ("schema_version", 2),
            ("profile", "other"),
            ("model_sha256", "bad"),
            ("bundle_sha256", False),
            ("dataset_sha256", None),
            ("evaluation_sha256", "F" * 64),
            ("source_fingerprint", []),
            ("frozen_at_ms", 0),
            ("observations", 999),
            ("observations", 20001),
            ("abstentions", 1),
            ("positive_labels", 199),
            ("positive_labels", True),
            ("true_positives", 201),
            ("true_positives", -1),
            ("positive_labels", 1001),
            ("unexpected", "private-canary"),
        )
        for key, value in mutations:
            candidate = reference()
            candidate[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(Rejected):
                monitoring.Evaluator(candidate, digest(canonical(candidate)))
        candidate = reference()
        del candidate["model_sha256"]
        with self.assertRaises(Rejected):
            monitoring.Evaluator(candidate, digest(canonical(candidate)))

    def test_reference_abstention_is_rejected_even_with_consistent_counts(self):
        candidate = reference()
        candidate["abstentions"] = 1000
        candidate["histograms"]["prediction"] = [0] * 12
        with self.assertRaisesRegex(Rejected, "monitor_reference_abstentions"):
            monitoring.Evaluator(candidate, digest(canonical(candidate)))

    def test_missing_time_interval_is_a_gap_even_without_sequence_jump(self):
        self.engine.evaluate(window(self.reference, shifted=(FEATURES[0],)))
        second = window(self.reference, 2, shifted=(FEATURES[0],))
        second["started_at_ms"] += 1
        self.assertEqual(self.engine.evaluate(second)["alerts"], ["telemetry_gap"])

    def test_invalid_window_fields_do_not_change_valid_sequence(self):
        mutations = (
            ("schema_version", True),
            ("reference_sha256", "0" * 64),
            ("sequence", True),
            ("sequence", 0),
            ("observations", -1),
            ("observations", 20001),
            ("observations", 1000.0),
            ("abstentions", 1001),
            ("started_at_ms", True),
            ("ended_at_ms", 1000),
            ("ended_at_ms", 61001),
            ("extra", "private-canary"),
        )
        for key, value in mutations:
            candidate = window(self.reference)
            candidate[key] = value
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.engine.evaluate(candidate)
        self.assertEqual(self.engine.evaluate(window(self.reference))["sequence"], 1)

    def test_histograms_are_bounded_exact_and_conserve_observations(self):
        for value in (True, -1, 20001, 1.0, math.nan, math.inf, "1", None):
            candidate = window(self.reference)
            candidate["histograms"][FEATURES[0]][1] = value
            with self.subTest(value=value), self.assertRaises(Rejected):
                self.engine.evaluate(candidate)
        for kind in ("missing", "extra", "short", "long", "mismatch", "not-list", "score-tail"):
            candidate = window(self.reference)
            histograms = candidate["histograms"]
            if kind == "missing":
                del histograms[FEATURES[0]]
            elif kind == "extra":
                histograms["private-canary"] = [0] * 12
            elif kind == "short":
                histograms[FEATURES[0]].pop()
            elif kind == "long":
                histograms[FEATURES[0]].append(0)
            elif kind == "mismatch":
                histograms[FEATURES[0]][1] -= 1
            elif kind == "not-list":
                histograms[FEATURES[0]] = {}
            else:
                histograms["prediction"][0] = 1
                histograms["prediction"][1] -= 1
            with self.subTest(kind=kind), self.assertRaises(Rejected):
                self.engine.evaluate(candidate)

    def test_abstentions_are_visible_and_not_synthetic_predictions(self):
        for sequence in (1, 2):
            candidate = window(self.reference, sequence)
            candidate["abstentions"] = 1000
            candidate["histograms"]["prediction"] = [0] * 12
            result = self.engine.evaluate(candidate)
            self.assertIsNone(result["psi"]["prediction"])
            self.assertEqual(result["prediction_status"], "insufficient")
            self.assertEqual(result["abstentions"], 1000)
            self.assertEqual(result["alerts"], [])

    def test_psi_zero_bins_smoothing_and_independent_formula(self):
        expected, observed = [0, 1000] + [0] * 10, [0, 0, 1000] + [0] * 9
        expected_psi = 2 * (1000 / 1006) * math.log(1000.5 / 0.5)
        self.assertAlmostEqual(monitoring.psi(expected, observed), expected_psi, places=12)
        self.assertEqual(monitoring.psi(expected, expected), 0)
        for invalid in ([0] * 12, [1] * 11, [True] * 12, [20001] * 12):
            with self.assertRaises(Rejected):
                monitoring.psi(invalid, observed)

    def test_delayed_quality_boundary_is_exact_and_distinct_from_drift(self):
        self.assertIsNone(monitoring.quality(180, 200, 0, 199))
        self.assertIsNone(monitoring.quality(180, 200, 0, 0))
        self.assertFalse(monitoring.quality(180, 200, 170, 200))
        self.assertTrue(monitoring.quality(180, 200, 169, 200))
        self.assertFalse(monitoring.quality(180, 200, 200, 200))
        for values in (
            (180, 199, 0, 200),
            (201, 200, 0, 200),
            (180, 200, 201, 200),
            (True, 200, 0, 200),
            (180, 200, -1, 200),
            (180, 200, 0, 20001),
        ):
            with self.subTest(values=values), self.assertRaises(Rejected):
                monitoring.quality(*values)

    def test_public_result_contains_no_raw_inputs_and_binds_exact_window(self):
        source = window(self.reference)
        result = self.engine.evaluate(source)
        self.assertEqual(result["window_sha256"], digest(canonical(source)))
        self.assertEqual(result["reference_sha256"], source["reference_sha256"])
        self.assertNotIn("histograms", result)
        self.assertNotIn("model_sha256", result)
        self.assertEqual(
            set(result),
            {
                "schema_version",
                "reference_sha256",
                "window_sha256",
                "sequence",
                "status",
                "prediction_status",
                "observations",
                "abstentions",
                "psi",
                "alerts",
                "drift_features",
                "release_ready",
            },
        )
        original = copy.deepcopy(source)
        self.engine.evaluate(source)
        self.assertEqual(source, original)


if __name__ == "__main__":
    unittest.main()
