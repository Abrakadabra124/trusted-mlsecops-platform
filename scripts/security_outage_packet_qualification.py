"""Negative evidence checks for a healthy ML/monitoring outage observation."""

import copy
import dataclasses
import unittest

from mlsecops import monitoring, monitoring_stream
from mlsecops import security_outage_packet as packet
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.datasets import FEATURES
from mlsecops.load_golden import Golden
from scripts.monitoring_qualification import reference
from scripts.monitoring_stream_qualification import context


def fixture():
    ref, trace = reference(), context()
    golden = Golden.from_expected(
        {
            "features": [[0.05] * len(FEATURES)],
            "scores": [0.05],
            "model": trace.model_sha256,
            "bundle": trace.bundle_sha256,
        }
    )
    windows = []
    evaluator = monitoring.Evaluator(ref, digest(canonical(ref)))
    count = 0
    for index, phase in enumerate(packet.PHASES, 1):
        start, end = 1000 + (index - 1) * 1000, 1000 + index * 1000
        stream = monitoring_stream.Accumulator(ref, digest(canonical(ref)), started_at_ms=start)
        http = []
        for batch in range(10):
            rows = [[(n % 10 + 0.5) / 10] * len(FEATURES) for n in range(100)]
            response = {
                "schema_version": 1,
                "request_id": f"{index * 100 + batch:032x}",
                "model_sha256": trace.model_sha256,
                "bundle_sha256": trace.bundle_sha256,
                "predictions": [
                    {"decision": "score", "reason": None, "score": row[0]} for row in rows
                ],
            }
            stream.add(trace, rows, response["predictions"], response["request_id"])
            http.append({"features": rows, "response": response})
        closed = stream.close(sequence=index, ended_at_ms=end)
        report = evaluator.evaluate(closed.document())
        count += 1000
        state = {
            "healthy": True,
            "state": "observing",
            "faults": [],
            "epoch": "1" * 32,
            "reference_sha256": digest(canonical(ref)),
            "data_status": "observed",
            "observations": count,
            "windows_evaluated": index,
            "pending_windows": 0,
            "pending_alerts": 0,
            "alerts_delivered": 0,
            "unclosed_observations": 0,
            "release_ready": False,
            "reports": [report],
        }
        windows.append(
            {
                "phase": phase,
                "document": closed.document(),
                "predictions": closed.predictions,
                "http": http,
                "monitor": state,
                "observed_at_ms": end + 10,
                "observation_started_at_ms": start + 50,
            }
        )
    value = {
        "schema_version": 1,
        "campaign": "1" * 32,
        "context": dataclasses.asdict(trace),
        "windows": windows,
    }
    return value, ref, trace, golden


def timeline():
    values = {
        "ready": (500, 750),
        "outage": (2020, 2040),
        "attempt": (3020, 3040),
        "recover": (4020, 4040),
    }
    result = {
        phase: {
            "started_at_ms": start,
            "finished_at_ms": end,
            "started_ns": start * 1000000,
            "finished_ns": end * 1000000,
        }
        for phase, (start, end) in values.items()
    }
    result["finish"] = {"started_at_ms": 5020, "started_ns": 5020000000}
    return result


class PacketContracts(unittest.TestCase):
    def setUp(self):
        self.value, self.ref, self.trace, self.golden = fixture()

    def verify(self, value=None):
        return packet.verify(
            self.value if value is None else value,
            reference=self.ref,
            context=self.trace,
            golden=self.golden,
            campaign="1" * 32,
        )

    def test_four_fresh_green_phases_reconcile_primary_HTTP_and_windows(self):
        result = self.verify()
        self.assertEqual(result["observations"], 4000)
        self.assertEqual(result["phase_windows"], dict.fromkeys(packet.PHASES, 1))
        self.assertEqual(result["packet_sha256"], digest(canonical(self.value)))
        self.assertIs(result["release_ready"], False)
        packet.verify_timeline(self.value, timeline())

    def test_operator_clock_jump_and_missing_phase_coverage_reject(self):
        for phase, field, value in (
            ("outage", "finished_at_ms", 2060),
            ("attempt", "finished_at_ms", 3060),
            ("recover", "finished_at_ms", 4060),
            ("finish", "started_at_ms", 5005),
            ("finish", "started_ns", 8000000000),
            ("ready", "started_ns", True),
        ):
            bad = timeline()
            bad[phase][field] = value
            with self.subTest(phase=phase, field=field), self.assertRaises(Rejected):
                packet.verify_timeline(self.value, bad)

    def test_missing_reordered_or_foreign_phase_cannot_pass(self):
        for windows in (
            self.value["windows"][:-1],
            self.value["windows"][1:],
            list(reversed(self.value["windows"])),
            [],
            self.value["windows"] * 2,
        ):
            with self.subTest(size=len(windows)), self.assertRaises(Rejected):
                self.verify({**self.value, "windows": windows})
        self.value["windows"][0]["phase"] = "unknown"
        with self.assertRaises(Rejected):
            self.verify()

    def test_monitor_liveness_sufficient_data_and_freshness_are_mandatory(self):
        changes = {
            "healthy": False,
            "state": "stopped",
            "faults": ["clock"],
            "epoch": "2" * 32,
            "reference_sha256": "0" * 64,
            "data_status": "insufficient",
            "observations": 999,
            "windows_evaluated": 0,
            "pending_windows": 1,
            "pending_alerts": 1,
            "alerts_delivered": 1,
            "unclosed_observations": 1,
            "release_ready": True,
            "reports": [],
        }
        for field, value in changes.items():
            bad = copy.deepcopy(self.value)
            bad["windows"][0]["monitor"][field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.verify(bad)
        for observed in (1999, 12001, True):
            bad = copy.deepcopy(self.value)
            bad["windows"][0]["observed_at_ms"] = observed
            with self.assertRaises(Rejected):
                self.verify(bad)

    def test_changed_raw_HTTP_cannot_be_hidden_by_unchanged_green_summary(self):
        for field, value in (("score", 0.8), ("reason", "PRIVATE"), ("decision", "abstain")):
            bad = copy.deepcopy(self.value)
            bad["windows"][0]["http"][0]["response"]["predictions"][0][field] = value
            with self.assertRaises(Rejected):
                self.verify(bad)
        for field in ("model_sha256", "bundle_sha256"):
            bad = copy.deepcopy(self.value)
            bad["windows"][0]["http"][0]["response"][field] = "0" * 64
            with self.assertRaises(Rejected):
                self.verify(bad)

    def test_duplicate_request_rebound_context_and_window_hash_rejected(self):
        bad = copy.deepcopy(self.value)
        bad["windows"][1]["http"][0]["response"]["request_id"] = bad["windows"][0]["http"][0][
            "response"
        ]["request_id"]
        with self.assertRaises(Rejected):
            self.verify(bad)
        for field in ("campaign", "context"):
            bad = copy.deepcopy(self.value)
            bad[field] = "PRIVATE"
            with self.assertRaises(Rejected):
                self.verify(bad)
        self.value["windows"][0]["document"]["prediction_ledger_sha256"] = "0" * 64
        with self.assertRaises(Rejected):
            self.verify()

    def test_green_summary_and_golden_reference_are_independently_checked(self):
        self.value["windows"][0]["monitor"]["reports"][0]["psi"]["prediction"] = 0.0
        # Fixture PSI is zero; changing the actual expected golden still refuses.
        self.golden = dataclasses.replace(self.golden, score=0.9)
        with self.assertRaises(Rejected):
            self.verify()
        self.value, self.ref, self.trace, self.golden = fixture()
        self.value["windows"][0]["monitor"]["reports"][0]["alerts"] = ["data_drift"]
        with self.assertRaises(Rejected):
            self.verify()


if __name__ == "__main__":
    unittest.main()
