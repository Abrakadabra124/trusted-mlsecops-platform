"""Capture the independently signed terminal journal tip in operator-owned storage."""

import os
import sys
from itertools import islice
from pathlib import Path
from tempfile import TemporaryDirectory

from mlsecops import key_files, signing
from mlsecops.contracts import Rejected, _parent, _stamp, atomic_write, decode, require_fields
from scripts import ci_campaign_journal as journal
from scripts import ci_origin_backup as backup
from scripts import ci_source_image_native as native
from scripts import ci_tip_witness as witness
from scripts.ci_asset_http import Client
from scripts.ci_primary_job import _directory
from scripts.ci_serving_job import private_process

ROOT = Path(__file__).resolve().parents[1]
FILE = "journal-tip.bin"
FIELDS = ("journal_release", "origin_release", "run_owner", "source", "trusted_public")


def _need(value):
    if not value:
        raise Rejected("operator_tip_refused")


def _outside(path):
    _need(path.is_absolute() and not path.is_relative_to(ROOT) and path == path.resolve())
    _need(not any(os.path.lexists(parent / ".git") for parent in path.parents))


def _local(folder):
    _outside(folder)
    _directory(folder.parent, private=True)
    _directory(folder, private=True)
    path = folder / FILE
    _need(list(islice(folder.iterdir(), 2)) == [path])
    with key_files.opened(path) as stream:
        before = os.fstat(stream.fileno())
        _need(0 < before.st_size <= witness.LIMIT)
        raw = stream.read(witness.LIMIT + 1)
        after = os.fstat(stream.fileno())
        key_files.validate(after)
        _need(len(raw) == before.st_size and _stamp(before) == _stamp(after))
    return raw


def read_pin(folder, *, key, **context):
    """Read the operator's authenticated tip offline for terminal replay."""
    return witness.open_witness(_local(Path(folder)), key=key, **context)


def capture(
    folder, *, api, journal_release, origin_release, run_owner, source, trusted_public, key
):
    """Retain exact bytes only after independent signature and complete journal verification."""
    folder = Path(folder)
    _outside(folder)
    _directory(folder.parent, private=True)
    raw = backup.get_witness(api, release=origin_release, run_owner=run_owner, source=source)
    common = dict(run_owner=run_owner, source=source, trusted_public=trusted_public, key=key)
    tip = witness.open_witness(
        raw, journal_release=journal_release, origin_release=origin_release, **common
    )
    recovered = journal.recover(api, journal=journal_release, expected_tip=tip.copy(), **common)
    _need(recovered["complete"] is True and recovered["tip"] == tip)
    _need(
        recovered["checkpoint"]["storage"]["release_id"]
        not in (origin_release["release_id"], journal_release["release_id"])
    )
    with _parent(folder) as (name, options):
        if not os.path.lexists(folder):
            with TemporaryDirectory(dir=folder.parent, prefix=".tip-") as staging:
                ready = Path(staging) / "ready"
                ready.mkdir(mode=0o700)
                atomic_write(ready / FILE, raw, mode=0o600)
                try:
                    os.rename(ready, name, dst_dir_fd=options.get("dir_fd"))
                except OSError:
                    if not os.path.lexists(folder):
                        raise
        _need(_local(folder) == raw)
        if options:
            os.fsync(options["dir_fd"])
    return tip


def _execute():
    env = os.environ
    _need(not env.get("GITHUB_ACTIONS") and "CANDIDATE_STORE_WRITE" not in env)
    _need(Path.cwd() == ROOT)
    config = Path(env.pop("CANDIDATE_TIP_CONFIG"))
    _outside(config)
    record = decode(key_files.read(config), 4096)
    require_fields(record, FIELDS)
    folder = Path(env.pop("CANDIDATE_TIP_DIRECTORY"))
    token = env.pop("CANDIDATE_STORE_READ")
    key = signing.decode64(journal._public(env.pop("CANDIDATE_TRANSFER_KEY")))
    _need(token)
    with private_process():
        git = ["git", "-C", str(ROOT)]
        _need(native.command([*git, "rev-parse", "HEAD"]) == record["source"]["source_revision"])
        _need(not native.command([*git, "status", "--porcelain", "--untracked-files=all"]))
        capture(folder, api=Client(token, write=False), key=key, **record)


def main(arguments=None):
    try:
        _need((sys.argv[1:] if arguments is None else arguments) == ["pin"])
        _execute()
    except (Exception, KeyboardInterrupt):
        print("operator_tip=refused")
        return 1
    print("operator_tip=pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
