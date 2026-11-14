import copy
import unittest
from datetime import UTC, datetime, timedelta

from mlsecops.contracts import Rejected
from mlsecops.recovery_observation import measure


class Observation(unittest.TestCase):
    def setUp(self):
        self.wall = datetime(2026, 11, 14, tzinfo=UTC)
        stamp = int(self.wall.timestamp()) * 10**9
        self.clock = {
            "start": {"before_ns": stamp, "after_ns": stamp, "monotonic_ns": 5000},
            "end": {
                "before_ns": stamp + 900 * 10**9,
                "after_ns": stamp + 900 * 10**9,
                "monotonic_ns": 5000 + 900 * 10**9,
            },
        }
        subject = dict(
            candidate_reference="1" * 64, evaluation_reference="2" * 64, model_sha256="3" * 64
        )
        report = dict(
            model_sha256=subject["model_sha256"],
            subject_sha256="4" * 64,
            proposal_reference="5" * 64,
        )
        self.args = dict(
            primary=dict(
                start_ns=6000,
                finish_ns=7000,
                target=dict(workspace_id="a" * 32),
                source_stopped_at=self.wall.isoformat(),
            ),
            sql=subject,
            statement=dict(recovery_point_at=(self.wall - timedelta(days=1)).isoformat()),
            proposal={
                **subject,
                **report,
                "target_workspace": "a" * 32,
                "release_ready": False,
                "status": "verified-proposal-requires-assurance",
            },
            report=report,
            serving_verified_ns=self.clock["end"]["monotonic_ns"],
        )

    def test_limits_include_serving_time_and_snapshot_age(self):
        self.assertEqual(measure(self.clock, **self.args), dict(rto_seconds=900, rpo_seconds=86400))
        for key in self.clock["end"]:
            self.clock["end"][key] += 1
        with self.assertRaisesRegex(Rejected, "serving_timeline"):
            measure(self.clock, **self.args)

    def test_rejects_future_stale_unsynchronized_or_ambiguous_recovery_point(self):
        for point in (
            self.wall + timedelta(microseconds=1),
            self.wall - timedelta(days=1, microseconds=1),
            self.wall.replace(tzinfo=None),
        ):
            with self.subTest(point=point), self.assertRaises(Rejected):
                measure(
                    self.clock,
                    **{**self.args, "statement": dict(recovery_point_at=point.isoformat())},
                )
        self.clock["end"]["monotonic_ns"] -= 10**9
        with self.assertRaisesRegex(Rejected, "load_clock_drift"):
            measure(self.clock, **self.args)

    def test_early_replies_and_foreign_targets_do_not_establish_availability(self):
        for path, value in [
            (("serving_verified_ns",), 6999),
            (("primary", "start_ns"), 4999),
            (("primary", "source_stopped_at"), (self.wall + timedelta(seconds=901)).isoformat()),
            (("primary", "source_stopped_at"), self.wall.replace(tzinfo=None).isoformat()),
            (("primary", "source_stopped_at"), (self.wall + timedelta(microseconds=1)).isoformat()),
            (("proposal", "target_workspace"), "b" * 32),
            (("proposal", "release_ready"), True),
            (("proposal", "status"), "restored"),
            (("proposal", "subject_sha256"), "9" * 64),
            (("report", "proposal_reference"), "9" * 64),
            (("report", "model_sha256"), "9" * 64),
            (("sql", "evaluation_reference"), "9" * 64),
        ]:
            args = copy.deepcopy(self.args)
            dest = args if len(path) == 1 else args[path[0]]
            dest[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(Rejected):
                measure(self.clock, **args)
