"""Campaign admission with actual dispatcher inputs and an in-memory public metadata API."""

import platform
import unittest
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected
from scripts import ci_campaign_guard as guard


class SourceRun:
    """Install only host, checkout and network observations; keep the admission code real."""

    def __init__(self, case):
        repo = "Abrakadabra124/trusted-mlsecops-platform"
        branch = "qualify/candidate-cross-job"
        workflow = ".github/workflows/candidate-cross-job.yml"
        sha = "a" * 40
        self.owner = dict(repository=repo, run_id=3, run_attempt=1, producer_job="producer")
        self.source = dict(
            source_revision=sha, source_fingerprint="b" * 64, image_id="sha256:" + "c" * 64
        )
        self.env = dict(
            GITHUB_ACTIONS="true",
            RUNNER_ENVIRONMENT="github-hosted",
            RUNNER_OS="Linux",
            RUNNER_ARCH="X64",
            ImageOS="ubuntu24",
            GITHUB_REPOSITORY=repo,
            GITHUB_REPOSITORY_ID="1407811916",
            GITHUB_REF="refs/heads/" + branch,
            GITHUB_EVENT_NAME="workflow_dispatch",
            GITHUB_WORKFLOW_REF=f"{repo}/{workflow}@refs/heads/{branch}",
            GITHUB_WORKFLOW_SHA=sha,
            GITHUB_SHA=sha,
            GITHUB_RUN_ID="3",
            GITHUB_RUN_ATTEMPT="1",
            GITHUB_JOB="producer",
        )
        case.enterContext(patch.object(guard, "os", SimpleNamespace(environ=self.env)))
        self.platform = Mock(spec=platform)
        self.platform.system.return_value = "Linux"
        self.platform.machine.return_value = "x86_64"
        self.platform.freedesktop_os_release.return_value = {"ID": "ubuntu", "VERSION_ID": "24.04"}
        case.enterContext(patch.object(guard, "platform", self.platform))
        self.checkout = case.enterContext(
            patch.object(guard, "checkout_source", return_value=self.source.copy())
        )
        self.base = "repos/" + repo
        self.commit_path = self.base + "/commits/" + sha
        self.run_path = self.base + "/actions/runs/3"
        identity = dict(id=1407811916, full_name=repo, private=False, fork=False)
        self.rows = {
            self.base: identity | {"visibility": "public", "owner": {"login": "Abrakadabra124"}},
            self.commit_path: {"sha": sha},
            self.run_path: dict(
                id=3,
                run_attempt=1,
                head_sha=sha,
                head_branch=branch,
                path=workflow,
                event="workflow_dispatch",
                status="in_progress",
                repository=identity.copy(),
                head_repository=identity.copy(),
            ),
        }
        self.requests = []

    def api(self, method, path):
        self.requests.append((method, path))
        return deepcopy(self.rows[path])

    def authorize(self, **changes):
        args = dict(job="producer", source_api=self.api, run_owner=self.owner, source=self.source)
        return guard.authorize("root", **(args | changes))


class CampaignGuardTests(unittest.TestCase):
    def setUp(self):
        self.run = SourceRun(self)

    def test_metadata_is_read_from_only_the_three_fixed_public_endpoints(self):
        for job in ("producer", "shared", "serving"):
            with self.subTest(job=job), patch.dict(self.run.env, GITHUB_JOB=job):
                self.run.requests.clear()
                self.assertIsNone(self.run.authorize(job=job))
                self.assertEqual(
                    self.run.requests,
                    [
                        ("GET", self.run.base),
                        ("GET", self.run.commit_path),
                        ("GET", self.run.run_path),
                    ],
                )

    def test_wrong_job_event_ref_sha_or_runner_refuses_before_public_request(self):
        for field, value in {
            "GITHUB_ACTIONS": "false",
            "RUNNER_ENVIRONMENT": "self-hosted",
            "RUNNER_OS": "Windows",
            "RUNNER_ARCH": "ARM64",
            "ImageOS": "ubuntu22",
            "GITHUB_REPOSITORY": "other/repo",
            "GITHUB_REPOSITORY_ID": "1",
            "GITHUB_REF": "refs/tags/qualify/candidate-cross-job",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_WORKFLOW_REF": "foreign.yml@main",
            "GITHUB_WORKFLOW_SHA": "d" * 40,
            "GITHUB_SHA": "e" * 40,
            "GITHUB_RUN_ID": "03",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_JOB": "shared",
        }.items():
            with self.subTest(field=field), patch.dict(self.run.env, {field: value}):
                with self.assertRaises(Rejected):
                    self.run.authorize()
        with patch.dict(self.run.env, GITHUB_JOB="unrelated"), self.assertRaises(Rejected):
            self.run.authorize(job="unrelated")
        self.assertEqual(self.run.requests, [])

    def test_host_observations_must_agree_with_hosted_runner_labels(self):
        for name, value in (
            ("system", "Windows"),
            ("machine", "aarch64"),
            ("freedesktop_os_release", {"ID": "debian", "VERSION_ID": "24.04"}),
            ("freedesktop_os_release", {"ID": "ubuntu", "VERSION_ID": "22.04"}),
        ):
            with self.subTest(name=name), patch.object(self.run.platform, name, return_value=value):
                with self.assertRaises(Rejected):
                    self.run.authorize()
        self.run.platform.freedesktop_os_release.side_effect = OSError("fixture")
        with self.assertRaises(Rejected):
            self.run.authorize()
        self.assertEqual(self.run.requests, [])

    def test_refuse_dirty_or_different_local_source_and_image(self):
        for field, value in (
            ("source_revision", "f" * 40),
            ("source_fingerprint", "a" * 64),
            ("image_id", "sha256:" + "0" * 64),
        ):
            with self.subTest(field=field):
                self.run.checkout.return_value = self.run.source | {field: value}
                with self.assertRaises(Rejected):
                    self.run.authorize()
        self.run.checkout.side_effect = Rejected("serving_output_source_dirty")
        with self.assertRaises(Rejected):
            self.run.authorize()

    def test_foreign_source_owner_and_noncanonical_run_ids(self):
        for field, value in (
            ("run_id", True),
            ("run_attempt", "1"),
            ("producer_job", "shared"),
            ("repository", "another/repo"),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.run.authorize(run_owner=self.run.owner | {field: value})
        self.assertEqual(self.run.requests, [])

    def test_live_metadata_drift_refuses_even_when_local_observations_agree(self):
        identity = self.run.rows[self.run.base]
        record = self.run.rows[self.run.run_path]
        for row, field, value in (
            (identity, "private", True),
            (identity, "fork", True),
            (identity, "id", "1407811916"),
            (identity, "visibility", "private"),
            (identity, "full_name", "another/repo"),
            (identity, "owner", {"login": "another"}),
            (self.run.rows[self.run.commit_path], "sha", "d" * 40),
            (record, "id", "3"),
            (record, "run_attempt", 2),
            (record, "head_sha", "c" * 40),
            (record, "head_branch", "main"),
            (record, "event", "push"),
            (record, "status", "completed"),
            (record, "path", "another.yml"),
            (record["repository"], "id", 1),
            (record["head_repository"], "fork", True),
            (record["head_repository"], "full_name", "other/repo"),
        ):
            with self.subTest(field=field), patch.dict(row, {field: value}):
                with self.assertRaises(Rejected):
                    self.run.authorize()

    def test_unavailable_metadata_never_grants_authority(self):
        for path in self.run.rows:

            def unavailable(method, requested):
                if requested == path:
                    raise OSError("synthetic transport failure")
                return self.run.api(method, requested)

            with self.subTest(path=path), self.assertRaises(Rejected):
                self.run.authorize(source_api=unavailable)
