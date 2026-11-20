"""Private cross-job transport canary; no candidate, image or release acceptance."""

import base64
import binascii
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from mlsecops import ci_transfer
from mlsecops.contracts import (
    Rejected,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    digest,
    safe_child,
)
from mlsecops.inventory import command, source_fingerprint

REPOSITORY = "Abrakadabra124/trusted-mlsecops-ci-private"
REPOSITORY_ID = 1465012664
SOURCE = "Abrakadabra124/trusted-mlsecops-platform"
BRANCH = "qualify/private-channel-native"
WORKFLOW = ".github/workflows/private-channel.yml"
FILE = ".runtime/private-channel/envelope.bin"
LIMIT = 65536
PAYLOAD = b"MLSecOps private cross-job transport canary v1\n" + bytes(range(256)) * 4
FIXTURE = digest(b"private-channel-fixture-not-a-model-or-release")


def need(value):
    if not value:
        raise Rejected("ci_private_channel_rejected")


def number(value):
    need(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,15}", value) is not None)
    result = int(value)
    need(result <= 2**53 - 1)
    return result


def key(value):
    try:
        need(type(value) is str and len(value) == 44)
        result = base64.b64decode(value, validate=True)
        need(len(result) == 32 and base64.b64encode(result).decode("ascii") == value)
        return result
    except (ValueError, binascii.Error):
        raise Rejected("ci_private_channel_rejected") from None


def guard(api, environment, *, head, dirty, platform):
    need(platform == "linux" and dirty is False)
    expected = dict(
        GITHUB_ACTIONS="true",
        RUNNER_ENVIRONMENT="github-hosted",
        GITHUB_REPOSITORY=REPOSITORY,
        GITHUB_REPOSITORY_ID=str(REPOSITORY_ID),
        GITHUB_REF="refs/heads/" + BRANCH,
        GITHUB_EVENT_NAME="workflow_dispatch",
    )
    need(all(environment.get(k) == v for k, v in expected.items()))
    need(type(head) is str and re.fullmatch(r"[a-f0-9]{40}", head) is not None)
    need(environment.get("GITHUB_SHA") == head)
    run, attempt = (
        number(environment.get("GITHUB_RUN_ID")),
        number(environment.get("GITHUB_RUN_ATTEMPT")),
    )
    repo = api("GET", "repos/" + REPOSITORY)
    need(type(repo) is dict)
    need(repo.get("id") == REPOSITORY_ID and repo.get("full_name") == REPOSITORY)
    need(
        repo.get("private") is True
        and repo.get("fork") is False
        and repo.get("visibility") == "private"
    )
    need(type(repo.get("owner")) is dict and repo["owner"].get("login") == "Abrakadabra124")
    published = api("GET", "repos/" + SOURCE + "/commits/" + head)
    need(type(published) is dict and published.get("sha") == head)
    record = api("GET", "repos/" + REPOSITORY + "/actions/runs/" + str(run))
    need(type(record) is dict)
    for name, value in dict(
        id=run,
        run_attempt=attempt,
        head_sha=head,
        head_branch=BRANCH,
        event="workflow_dispatch",
        path=WORKFLOW,
    ).items():
        need(type(record.get(name)) is type(value) and record[name] == value)
    for field in ("repository", "head_repository"):
        need(type(record.get(field)) is dict and record[field].get("id") == REPOSITORY_ID)
    return run, attempt


def build_context(environment, fingerprint):
    now = time.time_ns() // 1_000_000_000
    return dict(
        repository=REPOSITORY,
        run_id=number(environment["GITHUB_RUN_ID"]),
        run_attempt=number(environment["GITHUB_RUN_ATTEMPT"]),
        source_revision=environment["GITHUB_SHA"],
        source_fingerprint=fingerprint,
        image_id="sha256:" + FIXTURE,
        candidate_sha256=FIXTURE,
        proposal_sha256=FIXTURE,
        payload_sha256=digest(PAYLOAD),
        phase="private-channel-canary",
        purpose="candidate",
        issued_at=now,
        expires_at=now + 1800,
    )


def produce(secret, environment, fingerprint):
    ctx = build_context(environment, fingerprint)
    envelope = ci_transfer.seal(PAYLOAD, key=secret, context=ctx)
    return dict(envelope=envelope, context=ctx, pin=digest(envelope))


def consume(envelope, *, key, context, pin, environment, fingerprint):
    need(type(envelope) is bytes and 0 < len(envelope) <= LIMIT)
    expected = build_context(environment, fingerprint)
    need(type(context) is dict and context.keys() == expected.keys())
    need(all(context[k] == v for k, v in expected.items() if k not in ("issued_at", "expires_at")))

    def read(raw=envelope, ctx=context, secret=key, expected_pin=pin):
        return ci_transfer.open(
            raw, key=secret, expected_context=ctx, expected_ciphertext_sha256=expected_pin
        )

    need(read() == PAYLOAD)
    corrupted = envelope[:-1] + bytes([envelope[-1] ^ 1])
    cases = [
        dict(raw=corrupted, expected_pin=digest(corrupted)),
        dict(secret=bytes([key[0] ^ 1]) + key[1:]),
        dict(expected_pin="0" * 64),
        dict(ctx=context | {"run_id": context["run_id"] + 1}),
        dict(ctx=context | {"run_attempt": context["run_attempt"] + 1}),
        dict(ctx=context | {"phase": "different-phase"}),
        dict(ctx=context | {"repository": SOURCE}),
    ]
    for mutation in cases:
        try:
            read(**mutation)
        except Rejected:
            continue
        raise Rejected("ci_private_channel_negative_accepted")
    return dict(
        scope="private-cross-job-canary",
        status="pass",
        negative_checks=len(cases),
        release_ready=False,
    )


def artifact_path(identifier):
    need(type(identifier) is int and 0 < identifier <= 2**53 - 1)
    return "repos/" + REPOSITORY + "/actions/artifacts/" + str(identifier)


def artifact_valid(item, environment):
    need(type(item) is dict)
    artifact_path(item.get("id"))
    run, attempt = number(environment["GITHUB_RUN_ID"]), number(environment["GITHUB_RUN_ATTEMPT"])
    need(item.get("name") == f"private-channel-{run}-{attempt}")
    need(type(item.get("size_in_bytes")) is int and 0 < item["size_in_bytes"] <= LIMIT)
    need(item.get("expired") is False)
    owner = item.get("workflow_run")
    need(type(owner) is dict)
    for name, value in dict(
        id=run,
        repository_id=REPOSITORY_ID,
        head_repository_id=REPOSITORY_ID,
        head_sha=environment["GITHUB_SHA"],
        head_branch=BRANCH,
    ).items():
        need(type(owner.get(name)) is type(value) and owner[name] == value)
    return item


def artifact_check(api, environment, identifier):
    item = artifact_valid(api("GET", artifact_path(identifier)), environment)
    need(item["id"] == identifier)
    return item


def cleanup(api, environment):
    run = number(environment["GITHUB_RUN_ID"])
    path = f"repos/{REPOSITORY}/actions/runs/{run}/artifacts?per_page=100"
    listing = api("GET", path)
    need(type(listing) is dict and type(listing.get("artifacts")) is list)
    rows = listing["artifacts"]
    need(type(listing.get("total_count")) is int and listing["total_count"] == len(rows) <= 1)
    # Validate every candidate before any destructive request, never delete by name alone.
    for item in rows:
        artifact_valid(item, environment)
        need(artifact_check(api, environment, item["id"]) == item)
    for item in rows:
        owned = artifact_path(item["id"])
        api("DELETE", owned)
        need(api("GET", owned, absent=True) is None)
    after = api("GET", path)
    need(type(after) is dict and after.get("total_count") == 0 and after.get("artifacts") == [])
    return len(rows)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Rejected("ci_private_channel_api_redirect")


def request(method, path, *, absent=False):
    token = os.environ["GH_TOKEN"]
    need(type(token) is str and 1 <= len(token) <= 1024 and not any(c.isspace() for c in token))
    need(method in ("GET", "DELETE") and path.startswith("repos/"))
    need(re.fullmatch(r"[A-Za-z0-9_./?=&-]+", path) is not None and ".." not in path)
    req = urllib.request.Request(
        "https://api.github.com/" + path,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "mlsecops-private-channel",
        },
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=30) as response:
            raw = response.read(1024 * 1024 + 1)
            need(len(raw) <= 1024 * 1024)
            need(response.status == (204 if method == "DELETE" else 200))
            return decode(raw) if raw else {}
    except urllib.error.HTTPError as error:
        error.close()
        if absent and method == "GET" and error.code == 404:
            return None
        raise Rejected("ci_private_channel_api_rejected") from None


def execute(action):
    root = Path.cwd().resolve()
    environment = dict(os.environ)
    jobs = {
        "producer": "producer",
        "receiver": "receiver",
        "precheck": "receiver",
        "cleanup": "cleanup",
    }
    need(action in jobs and environment.get("GITHUB_JOB") == jobs[action])
    head = command(["git", "-C", str(root), "rev-parse", "HEAD"])
    dirty = bool(command(["git", "-C", str(root), "status", "--porcelain"]))
    guard(request, environment, head=head, dirty=dirty, platform=sys.platform)
    if action == "cleanup":
        return dict(
            status="pass", artifacts_deleted=cleanup(request, environment), release_ready=False
        )
    if action == "precheck":
        artifact_check(request, environment, number(environment["CHANNEL_ARTIFACT_ID"]))
        return dict(status="pass", artifact_checked=True, release_ready=False)
    secret = key(environment.pop("CHANNEL_AES_KEY"))
    fingerprint = source_fingerprint(root)
    target = safe_child(root, FILE)
    if action == "producer":
        sealed = produce(secret, environment, fingerprint)
        atomic_write(target, sealed["envelope"])
        need(bounded_read(target, LIMIT) == sealed["envelope"])
        with Path(environment["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write("context=" + canonical(sealed["context"]).decode() + "\n")
            output.write("pin=" + sealed["pin"] + "\n")
        return dict(status="pass", ciphertext_prepared=True, release_ready=False)
    try:
        return consume(
            bounded_read(target, LIMIT),
            key=secret,
            context=decode(environment["CHANNEL_CONTEXT"].encode()),
            pin=environment["CHANNEL_PIN"],
            environment=environment,
            fingerprint=fingerprint,
        )
    finally:
        target.unlink(missing_ok=True)


def main(arguments=None):
    try:
        args = sys.argv[1:] if arguments is None else arguments
        need(len(args) == 1)
        result = execute(args[0])
        print(canonical(result).decode())
        return 0
    except (Exception, KeyboardInterrupt):
        print('{"status":"inconclusive","scope":"private-cross-job-canary","release_ready":false}')
        return 1
    finally:
        os.environ.pop("CHANNEL_AES_KEY", None)


if __name__ == "__main__":
    sys.exit(main())
