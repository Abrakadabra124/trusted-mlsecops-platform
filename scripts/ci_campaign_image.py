"""Exact public source-image transport for the manual candidate campaign."""

import os
import platform
import sys

from scripts import ci_source_image_native as native

WORKFLOW = native.Workflow(
    branch="qualify/candidate-cross-job",
    path=".github/workflows/candidate-cross-job.yml",
    events=("workflow_dispatch",),
    active_only=True,
    scope="campaign-source-image",
)
READERS = ("producer", "shared", "serving")
ROLES = {
    "build": ("image",),
    "precheck": READERS,
    "receive": READERS,
    "local-cleanup": ("image", *READERS),
    "cleanup": ("image_cleanup",),
}


def execute(action):
    environment = dict(os.environ)
    native.need(environment.get("GITHUB_JOB") in ROLES.get(action, ()))
    native.need(platform.system() == "Linux" and platform.machine() == "x86_64")
    native.same(platform.freedesktop_os_release(), {"ID": "ubuntu", "VERSION_ID": "24.04"})
    return native.transfer(action, environment, WORKFLOW)


def main(arguments=None):
    return native.cli(arguments, execute, WORKFLOW.scope)


if __name__ == "__main__":
    sys.exit(main())
