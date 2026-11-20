"""Admission to privileged jobs of the public candidate campaign."""

import os
import platform

from mlsecops.contracts import Rejected
from scripts import ci_campaign_control as control
from scripts.ci_campaign_producer import IMAGE
from scripts.ci_source_image_native import REPOSITORY, REPOSITORY_ID, same
from scripts.serving_output_native import source as checkout_source

BRANCH = "qualify/candidate-cross-job"
WORKFLOW = ".github/workflows/candidate-cross-job.yml"
REF = "refs/heads/" + BRANCH


def authorize(root, *, source_api, job, run_owner, source):
    """Check actual host, checkout and source run. source_api reads only the public repo."""
    control.binding(run_owner, source)
    if job not in ("producer", "shared", "serving"):
        raise Rejected("campaign_job")
    sha = source["source_revision"]
    expected = dict(
        GITHUB_ACTIONS="true",
        RUNNER_ENVIRONMENT="github-hosted",
        RUNNER_OS="Linux",
        RUNNER_ARCH="X64",
        ImageOS="ubuntu24",
        GITHUB_REPOSITORY=REPOSITORY,
        GITHUB_REPOSITORY_ID=str(REPOSITORY_ID),
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF=REF,
        GITHUB_WORKFLOW_REF=f"{REPOSITORY}/{WORKFLOW}@{REF}",
        GITHUB_WORKFLOW_SHA=sha,
        GITHUB_SHA=sha,
        GITHUB_JOB=job,
        GITHUB_RUN_ID=str(run_owner["run_id"]),
        GITHUB_RUN_ATTEMPT=str(run_owner["run_attempt"]),
    )
    if any(os.environ.get(name) != value for name, value in expected.items()):
        raise Rejected("campaign_run_environment")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise Rejected("campaign_run_host")
    try:
        release = platform.freedesktop_os_release()
    except OSError:
        raise Rejected("campaign_run_host") from None
    same(release, {"ID": "ubuntu", "VERSION_ID": "24.04"})
    if checkout_source(root, IMAGE) != source:
        raise Rejected("campaign_run_checkout")

    def get(suffix):
        try:
            return source_api("GET", "repos/" + REPOSITORY + suffix)
        except Exception:
            raise Rejected("campaign_source_metadata_unavailable") from None

    identity = dict(id=REPOSITORY_ID, full_name=REPOSITORY, private=False, fork=False)
    repo = get("")
    same(repo, identity | {"visibility": "public"})
    same(repo.get("owner"), {"login": "Abrakadabra124"})
    same(get("/commits/" + sha), {"sha": sha})
    run = get("/actions/runs/" + expected["GITHUB_RUN_ID"])
    same(
        run,
        dict(
            id=run_owner["run_id"],
            run_attempt=run_owner["run_attempt"],
            head_sha=sha,
            head_branch=BRANCH,
            event="workflow_dispatch",
            path=WORKFLOW,
            status="in_progress",
        ),
    )
    for field in ("repository", "head_repository"):
        same(run.get(field), identity)
