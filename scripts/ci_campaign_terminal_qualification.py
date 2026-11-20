"""Terminal controller with public metadata and private storage represented only in memory."""

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import ci_campaign_terminal as terminal
from scripts import ci_private_assets as store
from scripts import ci_private_assets_qualification as assets

OWNER = {key: value for key, value in assets.EXPECTED.items() if key != "source_revision"}
SOURCE = dict(
    source_revision=assets.EXPECTED["source_revision"],
    source_fingerprint="f" * 64,
    image_id="sha256:" + "a" * 64,
)
TIP = dict(step=8, asset_id=9001, sha256="f" * 64)
JOBS = ("producer", "shared", "serving")
BASE = "repos/Abrakadabra124/trusted-mlsecops-platform"
RUN = BASE + "/actions/runs/123"
ATTEMPT = RUN + "/attempts/1"
JOB_LIST = ATTEMPT + "/jobs?per_page=100"


class TerminalTests(unittest.TestCase):
    def setUp(self):
        self.private = assets.StoreAPI()
        saved = []
        with patch("time.time", return_value=10000):
            receipt = store.publish(
                self.private,
                assets.EXPECTED,
                assets.PACKETS,
                lambda receipt: assets.CONTROL,
                checkpoint=saved.append,
            )
        self.private.mutations.clear()
        self.durable = assets.PACKETS | {"producer-control": assets.CONTROL}
        issuer = dict(
            public="YQ" * 21 + "E=",
            control_sha256=digest(assets.CONTROL),
            storage_sha256=digest(canonical(saved[-2])),
        )
        self.checkpoint = dict(storage=receipt, issuer=issuer)
        self.journal = dict(checkpoint=self.checkpoint, tip=TIP.copy(), complete=True)
        self.read_journal = Mock(side_effect=lambda **kw: deepcopy(self.journal))
        self.read_asset = Mock(side_effect=lambda stem, size: self.durable[stem])
        self.replay = Mock(side_effect=self.replay_result)
        identity = dict(id=1407811916, full_name=OWNER["repository"], fork=False, private=False)
        record = dict(
            id=123,
            run_attempt=1,
            workflow_id=45,
            path=".github/workflows/candidate-cross-job.yml",
            event="workflow_dispatch",
            head_branch="qualify/candidate-cross-job",
            head_sha=SOURCE["source_revision"],
            repository=identity.copy(),
            head_repository=identity.copy(),
            status="completed",
            conclusion="failure",
        )
        self.rows = {
            BASE: identity | {"visibility": "public", "owner": {"login": "Abrakadabra124"}},
            BASE + "/commits/" + SOURCE["source_revision"]: {"sha": SOURCE["source_revision"]},
            RUN: deepcopy(record),
            ATTEMPT: record,
            JOB_LIST: dict(
                total_count=3,
                jobs=[
                    dict(
                        id=index,
                        name=name,
                        run_id=123,
                        run_attempt=1,
                        head_sha=SOURCE["source_revision"],
                        status="completed",
                        conclusion=conclusion,
                    )
                    for index, (name, conclusion) in enumerate(
                        zip(JOBS, ("success", "failure", "skipped")), 10
                    )
                ],
            ),
        }
        self.requests = []

    def public_api(self, method, path):
        self.assertEqual(method, "GET")
        self.requests.append(path)
        return deepcopy(self.rows[path])

    def replay_result(self, *, run_owner, source, checkpoint, tip, terminal):
        self.assertEqual(run_owner, OWNER)
        self.assertEqual(source, SOURCE)
        self.assertEqual(checkpoint, self.checkpoint)
        self.assertEqual(tip, TIP)
        binding = dict(
            run_owner=run_owner, source=source, checkpoint=checkpoint, tip=tip, terminal=terminal
        )
        return dict(
            verified=True, binding_sha256=digest(canonical(binding)), read_asset=self.read_asset
        )

    def clean(self, **changes):
        args = dict(
            source_api=self.public_api,
            run_owner=deepcopy(OWNER),
            source=deepcopy(SOURCE),
            expected_tip=TIP.copy(),
            expected_jobs=JOBS,
            read_journal=self.read_journal,
            replay_retained=self.replay,
        )
        return terminal.cleanup(self.private, **(args | changes))

    def refused(self, **changes):
        with self.assertRaises(Rejected):
            self.clean(**changes)
        self.assertEqual(self.private.mutations, [])

    def test_nonterminal_or_unbound_public_observations_never_reach_private_readers(self):
        for row, field, bad in (
            (self.rows[BASE], "private", True),
            (self.rows[BASE], "fork", True),
            (self.rows[BASE], "id", "1407811916"),
            (self.rows[BASE], "owner", {"login": "foreign"}),
            (self.rows[BASE + "/commits/" + SOURCE["source_revision"]], "sha", "f" * 40),
            (self.rows[RUN], "run_attempt", 0),
            (self.rows[RUN], "run_attempt", True),
            (self.rows[RUN], "id", 456),
            (self.rows[RUN], "workflow_id", 46),
            (self.rows[RUN], "head_sha", "f" * 40),
            (self.rows[RUN], "status", "in_progress"),
            (self.rows[RUN], "conclusion", "success"),
            (self.rows[ATTEMPT], "run_attempt", 2),
            (self.rows[ATTEMPT], "id", "123"),
            (self.rows[ATTEMPT], "event", "push"),
            (self.rows[ATTEMPT], "path", "foreign.yml"),
            (self.rows[ATTEMPT], "head_branch", "main"),
            (self.rows[ATTEMPT], "status", "waiting"),
            (self.rows[ATTEMPT], "conclusion", None),
            (self.rows[ATTEMPT], "conclusion", "unknown"),
            (self.rows[ATTEMPT]["head_repository"], "fork", True),
            (self.rows[RUN]["repository"], "id", 123),
        ):
            with self.subTest(field=field, bad=bad), patch.dict(row, {field: bad}):
                self.refused()
        self.read_journal.assert_not_called()
        self.replay.assert_not_called()

    def test_incomplete_duplicate_foreign_or_nonterminal_job_list(self):
        page = self.rows[JOB_LIST]
        jobs = page["jobs"]
        for change in (
            {"total_count": 2},
            {"total_count": True},
            {"total_count": 101},
            {"jobs": jobs[:-1]},
            {"jobs": jobs + [jobs[0]]},
            {"jobs": []},
            {"jobs": [None, *jobs[1:]]},
        ):
            with self.subTest(fields=list(change)), patch.dict(page, change):
                self.refused()
        for field, bad in (
            ("id", True),
            ("id", jobs[1]["id"]),
            ("name", "other"),
            ("name", jobs[1]["name"]),
            ("run_attempt", 2),
            ("run_id", 456),
            ("head_sha", "f" * 40),
            ("status", "in_progress"),
            ("conclusion", None),
            ("conclusion", "unknown"),
        ):
            with self.subTest(field=field), patch.dict(jobs[0], {field: bad}):
                self.refused()
        self.read_journal.assert_not_called()

    def test_reject_invalid_operator_authority_before_public_io(self):
        for changes in (
            dict(run_owner=OWNER | {"run_attempt": True}),
            dict(run_owner=OWNER | {"producer_job": "other"}),
            dict(source=SOURCE | {"image_id": "latest"}),
            dict(expected_tip=None),
            dict(expected_tip=TIP | {"step": 7}),
            dict(expected_tip=TIP | {"asset_id": True}),
            dict(expected_tip=TIP | {"sha256": "?"}),
            dict(expected_jobs="producer"),
            dict(expected_jobs=("shared", "serving")),
            dict(expected_jobs=("producer", "producer")),
            dict(expected_jobs=("producer", "unsafe\nname")),
            dict(expected_jobs=("producer", None)),
            dict(expected_jobs=("producer",) + tuple(f"job-{i}" for i in range(100))),
        ):
            with self.subTest(fields=list(changes)):
                self.refused(**changes)
        self.assertEqual(self.requests, [])

    def test_future_attempt_is_never_looked_up_or_adopted(self):
        self.refused(run_owner=OWNER | {"run_attempt": 2})
        self.assertFalse(any("/attempts/" in path for path in self.requests))

    def test_complete_terminal_failure_retains_all_five_and_cleans_owned_store(self):
        with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            self.assertIsNone(self.clean())
        self.assertEqual(out.getvalue() + err.getvalue(), "")
        self.assertEqual(set(self.durable), set(store.LIMITS))
        self.assertEqual(
            {call.args for call in self.read_asset.call_args_list},
            {(stem, len(raw)) for stem, raw in self.durable.items()},
        )
        self.assertIsNone(self.private.release)
        self.assertIsNone(self.private.tag)
        self.assertFalse(self.private.assets)
        self.read_journal.assert_called_once_with(run_owner=OWNER, source=SOURCE, expected_tip=TIP)
        self.assertEqual(set(self.requests), set(self.rows))

    def test_private_replay_is_bound_to_specific_terminal_jobs_and_outcomes(self):
        self.clean()
        self.assertEqual(
            self.replay.call_args.kwargs.get("terminal"),
            dict(
                workflow_id=45,
                conclusion="failure",
                jobs={
                    "producer": {"id": 10, "conclusion": "success"},
                    "shared": {"id": 11, "conclusion": "failure"},
                    "serving": {"id": 12, "conclusion": "skipped"},
                },
            ),
        )

    def test_later_running_attempt_never_contributes_jobs_or_authority(self):
        self.rows[RUN].update(run_attempt=2, status="in_progress", conclusion=None)
        self.rows[ATTEMPT]["conclusion"] = "cancelled"
        self.clean()
        self.assertEqual(set(self.requests), set(self.rows))
        self.assertIsNone(self.private.release)
        self.assertEqual(self.read_asset.call_count, 5)

    def test_partial_stale_or_foreign_journal_never_deletes(self):
        for row, field, bad in (
            (self.journal, "complete", False),
            (self.journal, "complete", 1),
            (self.journal, "tip", TIP | {"sha256": "0" * 64}),
            (self.checkpoint, "issuer", None),
            (self.checkpoint["storage"]["expected"], "run_attempt", 2),
            (self.checkpoint["issuer"], "control_sha256", "0" * 64),
            (self.checkpoint["issuer"], "storage_sha256", "0" * 64),
        ):
            with self.subTest(field=field), patch.dict(row, {field: bad}):
                self.refused()
        partial = self.checkpoint["storage"]["assets"].copy()
        del partial["producer-control"]
        with patch.dict(self.checkpoint["storage"], assets=partial):
            self.refused()
        self.replay.assert_not_called()

    def test_replay_requires_bound_positive_result_and_independent_bytes_before_delete(self):
        for change in (
            lambda p: None,
            lambda p: True,
            lambda p: p | {"verified": False},
            lambda p: p | {"verified": 1},
            lambda p: p | {"binding_sha256": "0" * 64},
            lambda p: p | {"read_asset": None},
        ):
            self.refused(replay_retained=lambda **kw: change(self.replay_result(**kw)))

        def old_replay(**kw):
            kw["terminal"]["jobs"]["shared"]["conclusion"] = "success"
            return self.replay_result(**kw)

        self.refused(replay_retained=old_replay)
        self.read_asset.side_effect = lambda stem, limit: (
            b"short" if stem == "producer-control" else self.durable[stem]
        )
        self.refused()

    def test_unknown_asset_cannot_be_adopted_from_store(self):
        self.private.assets[333] = self.private.assets[100] | {"name": "unowned.bin", "id": 333}
        self.refused()

    def test_loss_of_public_or_private_proof_never_discloses_error_payload(self):
        def unavailable(*args, **kwargs):
            raise OSError("private-fixture-detail")

        for stage in ("source_api", "read_journal", "replay_retained"):
            with self.subTest(stage=stage), self.assertRaises(Rejected) as refusal:
                self.clean(**{stage: unavailable})
            self.assertNotIn("private-fixture-detail", str(refusal.exception))
            self.assertEqual(self.private.mutations, [])
        self.read_asset.side_effect = unavailable
        self.refused()

    def test_changed_completed_job_id_after_replay_blocks_all_deletes(self):
        def replay(**kwargs):
            self.rows[JOB_LIST]["jobs"][0]["id"] += 100
            return self.replay_result(**kwargs)

        self.refused(replay_retained=replay)

    def test_new_attempt_may_start_during_replay_without_retargeting_cleanup(self):
        def replay(**kwargs):
            self.rows[RUN].update(run_attempt=2, status="queued", conclusion=None)
            self.rows[JOB_LIST]["jobs"].reverse()
            return self.replay_result(**kwargs)

        self.clean(replay_retained=replay)
        self.assertEqual(self.private.mutations[-1], ("DELETE", "/git/refs/tags/" + assets.TAG))

    def test_latest_attempt_moving_backwards_blocks_deletion(self):
        self.rows[RUN].update(run_attempt=3, status="in_progress", conclusion=None)

        def replay(**kwargs):
            self.rows[RUN]["run_attempt"] = 2
            return self.replay_result(**kwargs)

        self.refused(replay_retained=replay)

    def test_ordinary_authorizer_is_bound_to_the_recovered_receipt(self):
        def changed_receipt(api, expected, receipt, *, authorize, retained_copy):
            authorize(receipt | {"release_id": 72})

        with patch.object(store, "cleanup", changed_receipt):
            self.refused()

    def test_lost_delete_acknowledgment_is_not_retried(self):
        def disconnected(method, path, result):
            if method == "DELETE":
                raise OSError("private-fixture-detail")
            return result

        self.private.hook = disconnected
        with self.assertRaises(Rejected):
            self.clean()
        self.assertEqual(len(self.private.mutations), 1)
        self.assertIsNotNone(self.private.release)


if __name__ == "__main__":
    unittest.main()
