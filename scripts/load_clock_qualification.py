import copy
import unittest
from unittest.mock import patch

from mlsecops import load_clock as clock
from mlsecops.contracts import Rejected


def anchors():
    return {
        "start": {
            "before_ns": 1_800_000_000_000_000_000,
            "after_ns": 1_800_000_000_000_000_002,
            "monotonic_ns": 10,
        },
        "end": {
            "before_ns": 1_800_000_130_000_000_000,
            "after_ns": 1_800_000_130_000_000_002,
            "monotonic_ns": 130_000_000_010,
        },
    }


class ClockContracts(unittest.TestCase):
    def test_origin_is_bracketed_without_float_precision_loss(self):
        with (
            patch.object(clock.time, "time_ns", side_effect=[100, 103]),
            patch.object(clock.time, "monotonic_ns", return_value=51),
        ):
            self.assertEqual(
                clock.sample(), {"before_ns": 100, "monotonic_ns": 51, "after_ns": 103}
            )
        result = clock.window(anchors(), 130_000_000_000)
        self.assertEqual(
            result,
            {
                "start_ns": 1_800_000_010_000_000_001,
                "end_ns": 1_800_000_130_000_000_001,
                "uncertainty_ns": 2,
            },
        )

    def test_clock_drift_reversal_and_invalid_elapsed_refuse(self):
        for phase, field, value in [
            ("start", "before_ns", True),
            ("start", "after_ns", 0),
            ("end", "after_ns", 1_800_000_130_100_000_003),
            ("end", "monotonic_ns", -1),
        ]:
            document = copy.deepcopy(anchors())
            document[phase][field] = value
            with self.assertRaises(Rejected):
                clock.window(document, 130_000_000_000)
        document = anchors()
        document["end"]["before_ns"] += 1_000_000_000
        document["end"]["after_ns"] += 1_000_000_000
        with self.assertRaisesRegex(Rejected, "load_clock_drift"):
            clock.window(document, 130_000_000_000)
        for elapsed in (True, -1, 1):
            with self.assertRaises(Rejected):
                clock.window(anchors(), elapsed)


if __name__ == "__main__":
    unittest.main()
