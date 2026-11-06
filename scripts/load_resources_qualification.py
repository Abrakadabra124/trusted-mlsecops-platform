"""Controlled Kubelet Summary fixtures; no Kubernetes connection is made."""

import copy
import unittest

from mlsecops.contracts import Rejected
from scripts import load_resources as resources

REFERENCE = {
    "node": "owned-node",
    "namespace": "ml-serve",
    "name": "worker-one",
    "uid": "11111111-1111-1111-1111-111111111111",
    "container": "worker",
}
ORIGIN = 1_800_000_000_000_000_000


def stamp(seconds):
    return f"2027-01-15T08:{seconds // 60:02d}:{seconds % 60:02d}Z"


def snapshot(seconds, *, cpu=None, memory=100):
    return {
        "node": {"nodeName": REFERENCE["node"]},
        "pods": [
            {
                "podRef": {key: REFERENCE[key] for key in ("name", "namespace", "uid")},
                "containers": [
                    {
                        "name": "worker",
                        "startTime": stamp(0),
                        "cpu": {
                            "time": stamp(seconds),
                            "usageCoreNanoSeconds": seconds * 100_000_000 if cpu is None else cpu,
                        },
                        "memory": {
                            "time": stamp(seconds),
                            "usageBytes": memory,
                            "workingSetBytes": memory - 10,
                            "rssBytes": memory - 20,
                        },
                    }
                ],
            }
        ],
    }


def sample(seconds, **kwargs):
    return resources.extract(
        snapshot(seconds, **kwargs), REFERENCE, observed_ns=ORIGIN + seconds * 1_000_000_000
    )


class ResourceContracts(unittest.TestCase):
    def test_exact_timestamps_and_counter_units(self):
        self.assertEqual(resources.timestamp(stamp(0)), ORIGIN)
        self.assertEqual(resources.timestamp(stamp(0)[:-1] + ".123456789Z"), ORIGIN + 123456789)
        value = sample(10)
        self.assertEqual(value["cpu_core_ns"], 1_000_000_000)
        self.assertEqual(value["working_set_bytes"], 90)
        self.assertEqual(value["rss_bytes"], 80)

    def test_unknown_duplicate_or_replaced_pod_and_container_are_rejected(self):
        values = []
        for field in ("uid", "name", "namespace"):
            document = snapshot(10)
            document["pods"][0]["podRef"][field] = "foreign"
            values.append(document)
        document = snapshot(10)
        document["pods"] *= 2
        values.append(document)
        document = snapshot(10)
        document["node"]["nodeName"] = "foreign"
        values.append(document)
        document = snapshot(10)
        document["pods"][0]["containers"] *= 2
        values.append(document)
        document = snapshot(10)
        document["pods"][0]["containers"][0]["name"] = "foreign"
        values.append(document)
        for document in values:
            with self.assertRaises(Rejected):
                resources.extract(document, REFERENCE, observed_ns=ORIGIN + 10_000_000_000)

    def test_missing_boolean_negative_and_stale_metrics_are_not_zero(self):
        for section, field, value in [
            ("cpu", "usageCoreNanoSeconds", None),
            ("cpu", "usageCoreNanoSeconds", True),
            ("cpu", "usageCoreNanoSeconds", -1),
            ("memory", "workingSetBytes", 101),
            ("memory", "rssBytes", -1),
            ("memory", "time", stamp(11)),
            ("cpu", "time", stamp(11)),
        ]:
            document = snapshot(10)
            document["pods"][0]["containers"][0][section][field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                resources.extract(document, REFERENCE, observed_ns=ORIGIN + 10_000_000_000)
        with self.assertRaises(Rejected):
            resources.extract(snapshot(10), REFERENCE, observed_ns=ORIGIN + 41_000_000_000)
        for value in (None, "2027-01-15", "2027-01-15T08:00:00+03:00", "2027-13-15T08:00:00Z"):
            with self.assertRaises(Rejected):
                resources.timestamp(value)

    def test_malformed_identity_missing_fields_and_out_of_range_clock_fail(self):
        for reference in ({**REFERENCE, "uid": ""}, {**REFERENCE, "container": True}):
            with self.assertRaises(Rejected):
                resources.extract(snapshot(10), reference, observed_ns=ORIGIN + 10_000_000_000)
        for document in ({}, {"node": None}, {**snapshot(10), "pods": []}):
            with self.assertRaises(Rejected):
                resources.extract(document, REFERENCE, observed_ns=ORIGIN + 10_000_000_000)
        document = snapshot(10)
        del document["pods"][0]["containers"][0]["memory"]["rssBytes"]
        with self.assertRaises(Rejected):
            resources.extract(document, REFERENCE, observed_ns=ORIGIN + 10_000_000_000)
        for stamp in ("1969-12-31T23:59:59Z", "9999-12-31T23:59:59Z"):
            with self.assertRaises(Rejected):
                resources.timestamp(stamp)

    def test_cached_timestamp_cannot_carry_new_counters_or_memory(self):
        for field, changed in (("cpu_core_ns", 1), ("usage_bytes", 101)):
            original = [sample(i) for i in range(0, 141, 10)]
            repeated = dict(original[5])
            repeated[field] += changed
            original.insert(6, repeated)
            with self.assertRaises(Rejected):
                resources.summarize(
                    original, start_ns=ORIGIN + 10_000_000_000, end_ns=ORIGIN + 130_000_000_000
                )
        for field, changed in (("identity_sha256", "foreign"), ("observed_ns", True)):
            value = sample(10)
            value[field] = changed
            with self.assertRaises(Rejected):
                resources.checked(value)

    def test_report_brackets_window_and_labels_sampled_ram_honestly(self):
        values = [sample(i, memory=100 + i) for i in range(0, 141, 10)]
        result = resources.summarize(
            values, start_ns=ORIGIN + 15_000_000_000, end_ns=ORIGIN + 135_000_000_000
        )
        self.assertEqual(result["cpu_observed_seconds"], 130)
        self.assertEqual(result["cpu_core_seconds"], 13)
        self.assertEqual(result["average_cpu_cores"], 0.1)
        self.assertEqual(result["max_sampled_working_set_bytes"], 230)
        self.assertEqual(result["max_sample_gap_seconds"], 10)
        self.assertFalse(result["true_peak_memory_measured"])

    def test_counter_reset_changed_start_time_and_reordered_samples_fail(self):
        original = [sample(i) for i in range(0, 141, 10)]
        for field, value in [
            ("cpu_core_ns", 0),
            ("started_ns", ORIGIN + 1),
            ("cpu_at_ns", ORIGIN),
            ("memory_at_ns", ORIGIN),
        ]:
            values = copy.deepcopy(original)
            values[5][field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                resources.summarize(
                    values, start_ns=ORIGIN + 10_000_000_000, end_ns=ORIGIN + 130_000_000_000
                )

    def test_missing_edges_long_gap_and_duplicate_only_do_not_prove_coverage(self):
        original = [sample(i) for i in range(0, 141, 10)]
        for values in (
            [],
            original[3:],
            original[:-3],
            original[:2] + original[-2:],
            [sample(0)] * 20,
            [sample(0)] * 257,
        ):
            with self.assertRaises(Rejected):
                resources.summarize(
                    values, start_ns=ORIGIN + 10_000_000_000, end_ns=ORIGIN + 130_000_000_000
                )
        # Repeated cached readings are retained, but cannot extend coverage.
        values = [row for row in original for _ in range(2)]
        self.assertEqual(
            resources.summarize(
                values, start_ns=ORIGIN + 10_000_000_000, end_ns=ORIGIN + 130_000_000_000
            )["average_cpu_cores"],
            0.1,
        )


if __name__ == "__main__":
    unittest.main()
