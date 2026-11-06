"""Reject forged success summaries using the underlying timestamped HTTP records."""

import copy
import unittest

from mlsecops import trust_trace
from mlsecops.contracts import Rejected


def outage():
    return {
        "anchor": "successful-request-start-lower-bound-on-last-trust-read",
        "fault": "outage",
        "first_503_seconds": 59.9,
        "observations": 3,
        "trace": [
            {"start_seconds": 0.1, "end_seconds": 0.2, "http_status": 200},
            {"start_seconds": 59.8, "end_seconds": 59.9, "http_status": 503},
            {"start_seconds": 60.1, "end_seconds": 60.2, "http_status": 503},
        ],
    }


def expiry():
    return {
        "expires_at": 100,
        "started_epoch": 90,
        "first_503_seconds_from_expiry": -0.2,
        "trace": [
            {"start_epoch": 90, "end_epoch": 90.5, "end_seconds": 0.5, "http_status": 200},
            {"start_epoch": 99.5, "end_epoch": 99.8, "end_seconds": 9.8, "http_status": 503},
            {"start_epoch": 101, "end_epoch": 101.1, "end_seconds": 11.1, "http_status": 503},
        ],
    }


def dependency(fault="wall-backward", cause="trust_clock_invalid"):
    return {
        "fault": fault,
        "cause": cause,
        "scope": "injected-reader-dependencies",
        "max_golden_error": 0.0,
        "trace": [
            {
                "phase": phase,
                "started_seconds": i / 10,
                "finished_seconds": i / 10 + 0.01,
                "wall_started": 100 + i / 10,
                "wall_finished": 100 + i / 10 + 0.01,
                "status": 503,
            }
            for i, phase in enumerate(
                (
                    "injected-predict",
                    "injected-ready",
                    "restored-predict-1",
                    "restored-predict-2",
                    "restored-ready",
                )
            )
        ],
    }


class TrustTraceContracts(unittest.TestCase):
    def test_refusal_is_recomputed_from_trace_and_outage_covers_the_deadline(self):
        self.assertEqual(trust_trace.refusal(outage(), "outage"), 59.9)
        for fault in (
            "blackhole",
            "policy-change",
            "revocation",
            "key-revocation",
            "root-rotation",
        ):
            value = {**outage(), "fault": fault}
            self.assertEqual(trust_trace.refusal(value, fault), 59.9)
        for path, wrong in (
            (("anchor",), "new-anchor-after-timeout"),
            (("fault",), "revocation"),
            (("observations",), 2),
            (("observations",), True),
            (("first_503_seconds",), 1),
            (("first_503_seconds",), float("nan")),
            (("trace", 0, "http_status"), 200.0),
            (("trace", 0, "http_status"), 429),
            (("trace", 0, "start_seconds"), True),
            (("trace", 0, "end_seconds"), float("inf")),
            (("trace", 1, "start_seconds"), 0),
            (("trace", 1, "end_seconds"), 60.01),
            (("trace", 2, "http_status"), 200),
            (("trace", 2, "end_seconds"), 66),
        ):
            value = outage()
            target = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = wrong
            with self.subTest(path=path, wrong=wrong), self.assertRaises(Rejected):
                trust_trace.refusal(value, "outage")

    def test_missing_early_or_shape_confused_traces_cannot_pass(self):
        for rows in ([], None, {}, [outage()["trace"][0]], outage()["trace"] * 2000):
            with self.subTest(rows=type(rows)), self.assertRaises(Rejected):
                trust_trace.refusal({**outage(), "trace": rows}, "outage")
        value = outage()
        value["trace"][-1] = {"start_seconds": 59.91, "end_seconds": 59.95, "http_status": 503}
        with self.assertRaises(Rejected):
            trust_trace.refusal(value, "outage")
        self.assertEqual(
            trust_trace.refusal({**value, "fault": "key-revocation"}, "key-revocation"), 59.9
        )
        for value in (None, [], {}, {**outage(), "extra": 1}, {**outage(), "trace": [None]}):
            with self.assertRaises(Rejected):
                trust_trace.refusal(value, "outage")
        with self.assertRaises(Rejected):
            trust_trace.refusal({**outage(), "fault": "unknown"}, "unknown")

    def test_expiry_requires_success_then_near_expiry_denial_and_persistent_refusal(self):
        self.assertAlmostEqual(trust_trace.approval_expiry(expiry()), -0.2)
        for path, wrong in (
            (("expires_at",), True),
            (("expires_at",), 100.0),
            (("expires_at",), 300),
            (("started_epoch",), 100),
            (("first_503_seconds_from_expiry",), -1),
            (("trace", 0, "http_status"), 503),
            (("trace", 0, "end_epoch"), 100),
            (("trace", 1, "end_epoch"), 97),
            (("trace", 1, "end_seconds"), 20),
            (("trace", 1, "http_status"), 200),
            (("trace", 2, "start_epoch"), 99),
            (("trace", 2, "http_status"), 200),
            (("trace", 2, "http_status"), 503.0),
            (("trace", 2, "end_seconds"), 1),
        ):
            value = expiry()
            target = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = wrong
            with self.subTest(path=path), self.assertRaises(Rejected):
                trust_trace.approval_expiry(value)
        with self.assertRaises(Rejected):
            trust_trace.approval_expiry({**expiry(), "trace": expiry()["trace"][:2]})

    def test_dependency_faults_require_each_cause_and_five_distinct_denial_phases(self):
        causes = {
            "wall-backward": "trust_clock_invalid",
            "monotonic-backward": "trust_clock_invalid",
            "wall-jump": "trust_clock_invalid",
            "server-skew": "trust_server_clock_skew",
            "invalid-signature": "invalid_signature",
        }
        values = [dependency(f, c) for f, c in causes.items()]
        self.assertEqual(trust_trace.dependency_faults(values), sorted(causes))
        for change in (
            lambda v: v.pop(),
            lambda v: v.append(v[0]),
            lambda v: v[0].update(scope="real-system-clock"),
            lambda v: v[0].update(cause="unrelated-error"),
            lambda v: v[0].update(max_golden_error=0.1),
            lambda v: v[0]["trace"].pop(),
            lambda v: v[0]["trace"][0].update(status=200),
            lambda v: v[0]["trace"][1].update(phase="injected-predict"),
            lambda v: v[0]["trace"][1].update(wall_started=90),
            lambda v: v[0]["trace"][1].update(started_seconds=-1),
        ):
            bad = copy.deepcopy(values)
            change(bad)
            with self.assertRaises(Rejected):
                trust_trace.dependency_faults(bad)
        for wrong in (None, {}, [None]):
            with self.assertRaises(Rejected):
                trust_trace.dependency_faults(wrong)

    def test_signed_version_replay_is_still_valid_and_recovers_only_explicitly(self):
        value = dependency("version-replay", "trust_version_replay")
        value.update(
            recovery_max_golden_error=0.0,
            replay={
                "checked_at_epoch": 100.25,
                "server_epoch": 100,
                "prior_expires_at_epoch": 200,
                "prior_valid_seconds": 99.75,
                "prior_version": 2,
                "current_version": 4,
                "prior_document_sha256": "a" * 64,
                "current_document_sha256": "b" * 64,
            },
        )
        self.assertEqual(
            trust_trace.version_replay(value), {"prior_version": 2, "current_version": 4}
        )
        for key, wrong in (
            ("prior_version", 4),
            ("prior_version", True),
            ("current_version", 2.5),
            ("prior_expires_at_epoch", 99),
            ("prior_valid_seconds", 100),
            ("server_epoch", 90),
            ("prior_document_sha256", "b" * 64),
            ("current_document_sha256", "not-a-hash"),
        ):
            bad = copy.deepcopy(value)
            bad["replay"][key] = wrong
            with self.subTest(key=key), self.assertRaises(Rejected):
                trust_trace.version_replay(bad)
        with self.assertRaises(Rejected):
            trust_trace.version_replay({**value, "recovery_max_golden_error": False})


if __name__ == "__main__":
    unittest.main()
