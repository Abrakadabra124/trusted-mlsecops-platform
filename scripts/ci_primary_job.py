"""Hosted receiver capture/publish CLI and private operator replay of retained evidence."""

import os
import platform
import re
import stat
import sys
from importlib import import_module
from pathlib import Path
from tempfile import TemporaryDirectory

from mlsecops import key_files, signing
from mlsecops.ci_transfer import MAX_ENVELOPE_BYTES
from mlsecops.contracts import (
    Rejected,
    _parent,
    _stamp,
    atomic_write,
    bounded_read,
    canonical,
    decode,
    require_fields,
    safe_child,
)
from scripts import ci_campaign_guard as guard
from scripts import ci_campaign_image
from scripts import ci_serving_job as serving
from scripts import ci_shared_job as shared
from scripts import ci_source_image_native as native
from scripts.ci_asset_http import Client as PrivateClient
from scripts.ci_campaign_journal import _public
from scripts.ci_campaign_source import Client as PublicClient

CONTEXT_LIMIT = 64 * 1024
OWNER_FIELDS = ("freeze_pin", "freeze", "expected", "run_owner")


def _need(ok):
    if not ok:
        raise Rejected("primary_job_refused")


def _admit(role, source_api):
    env = os.environ
    _need(platform.system() == "Linux" and platform.machine() == "x86_64")
    native.same(platform.freedesktop_os_release(), {"ID": "ubuntu", "VERSION_ID": "24.04"})
    sha = env["GITHUB_SHA"]
    expected = dict(
        GITHUB_ACTIONS="true",
        RUNNER_ENVIRONMENT="github-hosted",
        RUNNER_OS="Linux",
        RUNNER_ARCH="X64",
        ImageOS="ubuntu24",
        GITHUB_REPOSITORY=guard.REPOSITORY,
        GITHUB_REPOSITORY_ID=str(guard.REPOSITORY_ID),
        GITHUB_JOB=role,
        GITHUB_REF=guard.REF,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_WORKFLOW_SHA=sha,
        GITHUB_WORKFLOW_REF=f"{guard.REPOSITORY}/{guard.WORKFLOW}@{guard.REF}",
    )
    _need(all(env.get(k) == v for k, v in expected.items()))
    _need(re.fullmatch(r"[0-9a-f]{40}", sha))
    run, attempt = native.number(env["GITHUB_RUN_ID"]), native.number(env["GITHUB_RUN_ATTEMPT"])
    root = Path.cwd()
    _need(root == Path(env["GITHUB_WORKSPACE"]) and root == root.resolve(strict=True))
    _directory(root)
    # Check the clean checkout and live public run before source() inspects the image.
    observed = native.authorize(source_api, dict(env), root, ci_campaign_image.WORKFLOW)
    _need(observed == (run, attempt))
    owner = dict(
        repository=guard.REPOSITORY, run_id=run, run_attempt=attempt, producer_job="producer"
    )
    source = guard.checkout_source(root, guard.IMAGE)
    guard.control.binding(owner, source)
    _need(source["source_revision"] == sha)
    return root, owner, source


def _directory(path, *, private=False):
    info = path.lstat()
    _need(stat.S_ISDIR(info.st_mode))
    if os.name == "posix":
        _need(info.st_uid == os.geteuid() and not info.st_mode & (0o077 if private else 0o022))


def _capture(root, folder, binding, clients, key, producer_public, trust_file):
    _need(not os.path.lexists(folder))
    trust = Path(trust_file)
    _need(
        trust.is_absolute()
        and trust.resolve(strict=True) == trust
        and not trust.is_relative_to(root)
    )
    key_files.validate(trust.lstat())
    handoff = import_module("scripts.ci_primary_handoff")
    run = shared.run if binding["role"] == "shared" else serving.run
    result = run(
        root,
        **clients,
        key=key,
        trusted_public=producer_public,
        trust_key_path=trust,
        run_owner=binding["run_owner"],
        source=binding["source"],
    )
    packet, public = handoff.seal(root, result, key=key, **binding)
    _public(public)
    _need(type(packet) is bytes and 0 < len(packet) <= MAX_ENVELOPE_BYTES)
    owner = {k: result["arguments"][k] for k in OWNER_FIELDS}
    origin = result["origin"]
    require_fields(origin, ("workspace_id", "container_id", "offline_pin"))
    context = canonical(dict(owner=owner, origin=origin, receiver_public=public))
    _need(len(context) <= CONTEXT_LIMIT)
    # Only a populated, read-only pair ever appears under the final name. Concurrent
    # captures cannot rename a directory over a winner's non-empty directory.
    _directory(folder.parent)
    with (
        _parent(folder) as (name, options),
        TemporaryDirectory(dir=folder.parent, prefix=".primary-") as staging,
    ):
        ready = Path(staging) / "ready"
        ready.mkdir(mode=0o700)
        atomic_write(ready / "packet.bin", packet, mode=0o400)
        atomic_write(ready / "context.json", context, mode=0o400)
        os.rename(ready, name, dst_dir_fd=options.get("dir_fd"))
        if options:
            os.fsync(options["dir_fd"])
    return public


def _publish(root, folder, binding, clients, key, trusted_public, release):
    _directory(folder, private=True)
    ctx = safe_child(folder, "context.json")
    blob = safe_child(folder, "packet.bin")
    for file in (ctx, blob):
        key_files.validate(file.lstat())
    context = decode(bounded_read(ctx, CONTEXT_LIMIT), CONTEXT_LIMIT)
    require_fields(context, ("owner", "origin", "receiver_public"))
    _need(context["receiver_public"] == trusted_public)
    packet = bounded_read(blob, MAX_ENVELOPE_BYTES)
    import_module("scripts.ci_primary_handoff").replay(
        root,
        packet,
        **binding,
        key=key,
        trusted_public=trusted_public,
        owner=context["owner"],
        origin=context["origin"],
    )
    guard.authorize(
        root,
        source_api=clients["source_api"],
        job=binding["role"],
        run_owner=binding["run_owner"],
        source=binding["source"],
    )
    import_module("scripts.ci_primary_store").put(
        clients["api"], packet, **binding, release=release
    )


def replay_remote(
    root, *, api, release, role, run_owner, source, key, trusted_public, owner, origin
):
    """Replay store bytes against authority supplied independently by the private operator."""
    _need(role in ("shared", "serving"))
    binding = dict(role=role, run_owner=run_owner, source=source)
    with serving.private_process():
        packet = import_module("scripts.ci_primary_store").get_unverified(
            api, **binding, release=release
        )
        return import_module("scripts.ci_primary_handoff").replay(
            root,
            packet,
            **binding,
            key=key,
            trusted_public=trusted_public,
            owner=owner,
            origin=origin,
        )


def _operator_replay(role):
    """Reopen one independent primary from a private receipt without publisher credentials."""
    _need(role in ("shared", "serving") and not os.environ.get("GITHUB_ACTIONS"))
    _need("CANDIDATE_STORE_WRITE" not in os.environ)
    root = Path.cwd()
    _need(root == Path(__file__).resolve().parents[1])
    path = Path(os.environ.pop("CANDIDATE_REPLAY_RECEIPT"))
    _need(
        path.is_absolute() and path == path.resolve(strict=True) and not path.is_relative_to(root)
    )
    with key_files.opened(path) as stream:
        before = os.fstat(stream.fileno())
        _need(0 < before.st_size <= CONTEXT_LIMIT)
        raw = stream.read(CONTEXT_LIMIT + 1)
        after = os.fstat(stream.fileno())
        key_files.validate(after)
        _need(len(raw) == before.st_size and _stamp(before) == _stamp(after))
    record = decode(raw, CONTEXT_LIMIT)
    require_fields(
        record, ("role", "release", "run_owner", "source", "trusted_public", "owner", "origin")
    )
    _need(record["role"] == role)
    guard.control.binding(record["run_owner"], record["source"])
    _public(record["trusted_public"])
    key = signing.decode64(_public(os.environ.pop("CANDIDATE_TRANSFER_KEY")))
    token = os.environ.pop("CANDIDATE_STORE_READ")
    _need(token)
    with serving.private_process():
        git = ["git", "-C", str(root)]
        _need(native.command([*git, "rev-parse", "HEAD"]) == record["source"]["source_revision"])
        _need(not native.command([*git, "status", "--porcelain", "--untracked-files=all"]))
        result = replay_remote(root, api=PrivateClient(token, write=False), key=key, **record)
        native.same(result, {"release_ready": False})


def _execute(command):
    role = os.environ.get("GITHUB_JOB")
    _need(role in ("shared", "serving"))
    publishing = command == "publish"
    reader, writer = "CANDIDATE_STORE_READ", "CANDIDATE_STORE_WRITE"
    _need((reader if publishing else writer) not in os.environ)
    public_token = os.environ.pop("CANDIDATE_PUBLIC_TOKEN")
    private_token = os.environ.pop(writer if publishing else reader)
    _need(public_token and private_token and public_token != private_token)
    clients = dict(
        source_api=PublicClient(public_token), api=PrivateClient(private_token, write=publishing)
    )
    del public_token, private_token
    key = signing.decode64(_public(os.environ.pop("CANDIDATE_TRANSFER_KEY")))
    public = _public(
        os.environ.pop("CANDIDATE_RECEIVER_PUBLIC" if publishing else "CANDIDATE_PRODUCER_PUBLIC")
    )
    value = os.environ.pop("CANDIDATE_PRIMARY_RELEASE" if publishing else "CANDIDATE_TRUST_FILE")
    # Both Python output and inherited file descriptors are private for all internal work.
    with serving.private_process():
        root, owner, source = _admit(role, clients["source_api"])
        binding = dict(role=role, run_owner=owner, source=source)
        runtime = safe_child(root, ".runtime")
        if not publishing:
            runtime.mkdir(mode=0o700, exist_ok=True)
        _directory(runtime)
        folder = safe_child(runtime, "ci-primary-" + role)
        if publishing:
            release = decode(value.encode(), limit=CONTEXT_LIMIT)
            _need(type(release) is dict and release)
            return _publish(root, folder, binding, clients, key, public, release)
        return _capture(root, folder, binding, clients, key, public, value)


def main(arguments=None):
    try:
        args = sys.argv[1:] if arguments is None else arguments
        if len(args) == 2 and args[0] == "replay":
            _operator_replay(args[1])
            print("primary_replay=pass")
            return 0
        _need(len(args) == 1 and args[0] in ("capture", "publish"))
        public = _execute(args[0])
    except (Exception, KeyboardInterrupt):
        print("primary_job=refused")
        return 1
    print("primary_" + args[0] + "=pass")
    if args[0] == "capture":
        print("receiver_public=" + public)
    return 0


if __name__ == "__main__":
    sys.exit(main())
