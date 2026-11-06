import copy
import unittest

from mlsecops.contracts import Rejected
from scripts import kube_privacy_probe as probe
from scripts.serving_output_probe import produce


def envelope():
    value = produce(
        lambda observe: (
            observe(tuple(bytes([i]) for i in range(1, 10))),
            {
                "status": "pass",
                "release_ready": False,
            },
        )[1],
        canary_count=9,
    )
    return {
        "schema_version": 1,
        "output": value,
        "diagnostics": {"bytes": 0, "gpu_discovery_warning": False, "raw_output_retained": False},
    }


class PrivacyProbeEnvelopeContracts(unittest.TestCase):
    def test_parent_accepts_only_complete_empty_diagnostic_lifecycle(self):
        result = probe.finish(envelope())
        self.assertEqual(result["output_observation"]["canary_count"], 9)
        self.assertTrue(result["output_observation"]["fd_lifecycle_complete"])
        self.assertFalse(result["release_ready"])

    def test_native_stderr_missing_canary_overflow_and_false_ready_are_refused(self):
        good = envelope()
        for mutate in (
            lambda v: v["diagnostics"].update(bytes=1),
            lambda v: v["output"]["observation"].update(canary_count=6),
            lambda v: v["output"]["observation"].update(stdout_characters=65537),
            lambda v: v["output"]["observation"].update(stderr_characters=True),
            lambda v: v["output"]["native"].update(release_ready=True),
            lambda v: v["output"].update(extra="private"),
        ):
            value = copy.deepcopy(good)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(Rejected):
                probe.finish(value)

    def test_capture_count_cannot_be_disabled_or_unbounded(self):
        for count in (0, 17, True, 1.5):
            with self.subTest(count=count), self.assertRaises(Rejected):
                produce(lambda observe: {}, canary_count=count)


if __name__ == "__main__":
    unittest.main()
