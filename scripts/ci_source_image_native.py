"""Bounded public source-image transfer between fresh hosted jobs; no ML release."""

import importlib
import os
import re
import secrets
import stat
import sys
from pathlib import Path

from mlsecops.contracts import Rejected, bounded_read, canonical, decode, safe_child
from mlsecops.inventory import command
from scripts.ci_private_channel import request

REPOSITORY = "Abrakadabra124/trusted-mlsecops-platform"
REPOSITORY_ID = 1407811916
BRANCH = "qualify/source-image-transfer"
WORKFLOW = ".github/workflows/source-image-transfer.yml"
DIRECTORY = ".runtime/source-image"
ARCHIVE_LIMIT = 384 * 1024**2
TAR_LIMIT = 2 * 1024**3
ZIP_LIMIT = ARCHIVE_LIMIT + 1024**2
SCOPE = "source-image-transfer"


def need(value):
    if not value:
        raise Rejected("ci_source_image_native_rejected")


def number(value):
    need(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,15}", value) is not None)
    result = int(value)
    need(result <= 2**53 - 1)
    return result


def same(record, fields):
    need(type(record) is dict)
    for key, value in fields.items():
        need(type(record.get(key)) is type(value) and record[key] == value)


def guard(api, environment, *, head, dirty, platform):
    need(platform == "linux" and dirty is False)
    expected = dict(
        GITHUB_ACTIONS="true",
        RUNNER_ENVIRONMENT="github-hosted",
        RUNNER_OS="Linux",
        RUNNER_ARCH="X64",
        ImageOS="ubuntu24",
        GITHUB_REPOSITORY=REPOSITORY,
        GITHUB_REPOSITORY_ID=str(REPOSITORY_ID),
        GITHUB_REF="refs/heads/" + BRANCH,
        GITHUB_WORKFLOW_REF=f"{REPOSITORY}/{WORKFLOW}@refs/heads/{BRANCH}",
    )
    same(environment, expected)
    need(environment.get("GITHUB_EVENT_NAME") in ("push", "workflow_dispatch"))
    need(type(head) is str and re.fullmatch(r"[a-f0-9]{40}", head) is not None)
    need(environment.get("GITHUB_SHA") == head and environment.get("GITHUB_WORKFLOW_SHA") == head)
    run, attempt = (
        number(environment.get("GITHUB_RUN_ID")),
        number(environment.get("GITHUB_RUN_ATTEMPT")),
    )
    identity = dict(id=REPOSITORY_ID, full_name=REPOSITORY, private=False, fork=False)
    repo = api("GET", "repos/" + REPOSITORY)
    same(repo, identity | {"visibility": "public"})
    same(repo.get("owner"), {"login": "Abrakadabra124"})
    same(api("GET", f"repos/{REPOSITORY}/commits/{head}"), {"sha": head})
    record = api("GET", f"repos/{REPOSITORY}/actions/runs/{run}")
    same(
        record,
        dict(
            id=run,
            run_attempt=attempt,
            head_sha=head,
            head_branch=BRANCH,
            event=environment["GITHUB_EVENT_NAME"],
            path=WORKFLOW,
        ),
    )
    for field in ("repository", "head_repository"):
        same(record.get(field), identity)
    return run, attempt


def authorize(api, environment, root):
    head = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    dirty = bool(
        command(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"])
    )
    return guard(api, environment, head=head, dirty=dirty, platform=sys.platform)


def receipt(value, environment):
    fields = {
        "schema_version",
        "source_revision",
        "source_fingerprint",
        "image_id",
        "archive_sha256",
        "archive_bytes",
        "tar_sha256",
        "tar_bytes",
    }
    need(type(value) is dict and set(value) == fields)
    same(value, dict(schema_version=1, source_revision=environment["GITHUB_SHA"]))
    for field, pattern in (
        ("source_revision", r"[a-f0-9]{40}"),
        ("source_fingerprint", r"[a-f0-9]{64}"),
        ("image_id", r"sha256:[a-f0-9]{64}"),
        ("archive_sha256", r"[a-f0-9]{64}"),
        ("tar_sha256", r"[a-f0-9]{64}"),
    ):
        need(type(value[field]) is str and re.fullmatch(pattern, value[field]) is not None)
    for field, limit in (("archive_bytes", ARCHIVE_LIMIT), ("tar_bytes", TAR_LIMIT)):
        need(type(value[field]) is int and 0 < value[field] <= limit)
    return value


def artifact_path(identifier):
    need(type(identifier) is int and 0 < identifier <= 2**53 - 1)
    return f"repos/{REPOSITORY}/actions/artifacts/{identifier}"


def artifact_valid(item, environment):
    need(type(item) is dict)
    artifact_path(item.get("id"))
    run, attempt = number(environment["GITHUB_RUN_ID"]), number(environment["GITHUB_RUN_ATTEMPT"])
    same(item, dict(name=f"source-image-{run}-{attempt}", expired=False))
    need(type(item.get("size_in_bytes")) is int and 0 < item["size_in_bytes"] <= ZIP_LIMIT)
    same(
        item.get("workflow_run"),
        dict(
            id=run,
            repository_id=REPOSITORY_ID,
            head_repository_id=REPOSITORY_ID,
            head_sha=environment["GITHUB_SHA"],
            head_branch=BRANCH,
        ),
    )
    return item


def artifact_check(api, environment, identifier):
    item = artifact_valid(api("GET", artifact_path(identifier)), environment)
    need(item["id"] == identifier)
    return item


def cleanup(api, environment, reauthorize):
    run = number(environment["GITHUB_RUN_ID"])
    path = f"repos/{REPOSITORY}/actions/runs/{run}/artifacts?per_page=100"
    listing = api("GET", path)
    need(type(listing) is dict and type(listing.get("artifacts")) is list)
    rows = listing["artifacts"]
    need(type(listing.get("total_count")) is int and listing["total_count"] == len(rows) <= 1)
    # No DELETE until every identity in the complete, bounded run list is checked.
    for item in rows:
        artifact_valid(item, environment)
        need(artifact_check(api, environment, item["id"]) == item)
    for item in rows:
        reauthorize()
        need(artifact_check(api, environment, item["id"]) == item)
        owned = artifact_path(item["id"])
        api("DELETE", owned)
        need(api("GET", owned, absent=True) is None)
    reauthorize()
    after = api("GET", path)
    same(after, dict(total_count=0, artifacts=[]))
    return len(rows)


def image_core():
    return importlib.import_module("scripts.ci_source_image")


def owner_path(root, environment):
    temporary = Path(environment["RUNNER_TEMP"])
    need(temporary.is_absolute() and temporary.is_dir() and not temporary.is_symlink())
    need(not temporary.resolve().is_relative_to(root))
    return safe_child(temporary, "source-image-owner.json")


def owner_record(root, environment, *, create):
    path = owner_path(root, environment)
    identity = dict(
        schema_version=1,
        repository_id=REPOSITORY_ID,
        run_id=number(environment["GITHUB_RUN_ID"]),
        run_attempt=number(environment["GITHUB_RUN_ATTEMPT"]),
        job=environment["GITHUB_JOB"],
        source_revision=environment["GITHUB_SHA"],
    )
    if create:
        owner = secrets.token_hex(32)
        # Exclusive creation: a retry cannot replace the authority of an existing workspace.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(identity | {"owner": owner}))
    need(path.exists())
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    record = decode(bounded_read(path, 4096), limit=4096)
    same(record, identity)
    need(set(record) == set(identity) | {"owner"})
    owner = record["owner"]
    need(type(owner) is str and re.fullmatch(r"[a-f0-9]{64}", owner) is not None)
    return owner


def execute(action):
    environment = dict(os.environ)
    jobs = {
        "producer": "producer",
        "receiver": "receiver",
        "precheck": "receiver",
        "cleanup": "cleanup",
        "producer-cleanup": "producer",
        "receiver-cleanup": "receiver",
    }
    # Check the actual job before git, imports that can execute work, or API calls.
    need(action in jobs and environment.get("GITHUB_JOB") == jobs[action])
    root = Path.cwd().resolve()

    def reauthorize():
        return authorize(request, environment, root)

    reauthorize()
    result = dict(status="pass", scope=SCOPE, release_ready=False)
    if action == "cleanup":
        return result | {"artifacts_deleted": cleanup(request, environment, reauthorize)}
    directory = safe_child(root, DIRECTORY)
    if action in ("precheck", "receiver"):
        artifact_check(request, environment, number(environment["SOURCE_IMAGE_ARTIFACT_ID"]))
        if action == "precheck":
            receipt(decode(environment["SOURCE_IMAGE_RECEIPT"].encode(), limit=4096), environment)
            owner = owner_record(root, environment, create=True)
            image_core().workspace_create(directory, owner)
            return result | {"artifact_checked": True}
    core = image_core()
    if action in ("producer-cleanup", "receiver-cleanup"):
        if not owner_path(root, environment).exists():
            need(not directory.exists())
            return result | {"files_removed": 0}
        owner = owner_record(root, environment, create=False)
        return result | {"files_removed": core.cleanup(directory, owner=owner)}
    if action == "producer":
        owner = owner_record(root, environment, create=True)
        prepared = receipt(core.prepare(root, directory, owner=owner), environment)
        reauthorize()
        with Path(environment["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write("receipt=" + canonical(prepared).decode() + "\n")
        return result | {"image_prepared": True}
    owner = owner_record(root, environment, create=False)
    try:
        expected = receipt(
            decode(environment["SOURCE_IMAGE_RECEIPT"].encode(), limit=4096), environment
        )
        received = receipt(core.receive(root, directory, expected, owner=owner), environment)
        need(received == expected)
        reauthorize()
        return result | {"image_received": True}
    finally:
        core.cleanup(directory, owner=owner)


def main(arguments=None):
    try:
        args = sys.argv[1:] if arguments is None else arguments
        need(len(args) == 1)
        result = execute(args[0])
        print(canonical(result).decode())
        return 0
    except (Exception, KeyboardInterrupt):
        print(canonical(dict(status="inconclusive", scope=SCOPE, release_ready=False)).decode())
        return 1


if __name__ == "__main__":
    sys.exit(main())
