"""Local T19 fallback for an authenticated prediction on the caller's loopback listener."""

import asyncio
import os
import re
import sys
from pathlib import Path

from mlsecops import advisory, key_files, load_measurement
from mlsecops.contracts import Rejected, _parent, bounded_read, canonical, decode, require_fields
from mlsecops.datasets import FEATURES
from mlsecops.private_cli import Arguments

QUEUE = "manual-review"
PENDING = "pending human review"
CASE = re.compile(r"[0-9a-f]{64}")
MAX_BODY = 65536


def _check_case(case):
    if type(case) is not str or CASE.fullmatch(case) is None:
        raise Rejected("manual_review_case_digest")


def _private_queue(options):
    if options:
        metadata = os.fstat(options["dir_fd"])
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise Rejected("manual_review_queue_permissions")


def _validate_marker(metadata):
    key_files.validate(metadata)
    if metadata.st_size != 0:
        raise Rejected("manual_review_marker")


def _read_marker(path):
    _check_case(path.name)
    _validate_marker(path.lstat())
    bounded_read(path, 0)
    return {"case_sha256": path.name, "status": PENDING}


def _enqueue(state, case):
    path = Path(state) / QUEUE / case
    with _parent(path, create=True) as (name, options):
        _private_queue(options)
        # The complete record is the name in this queue. O_EXCL publishes it atomically,
        # including if the process dies immediately after open; there is no partial JSON.
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, **options)
        except FileExistsError:
            descriptor = os.open(name, flags, **options)
        try:
            _validate_marker(os.fstat(descriptor))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if options:
            os.fsync(options["dir_fd"])
            # The private queue itself may have been created by this or an interrupted call.
            with _parent(path.parent) as (_, state_options):
                os.fsync(state_options["dir_fd"])
    return _read_marker(path)


def pending(state):
    """Read the local operator queue, including when serving is offline."""
    directory = Path(state) / QUEUE
    try:
        directory.lstat()
    except FileNotFoundError:
        return []
    # The parent helper opens the queue itself without following symlinks on POSIX.
    with _parent(directory / ".list") as (_, options):
        _private_queue(options)
        names = sorted(os.listdir(options.get("dir_fd", directory)))
    return [_read_marker(directory / name) for name in names]


async def submit(state, *, case_sha256, port, token, body):
    """Issue one prediction. Only a well-formed model_unavailable response opens a case."""
    _check_case(case_sha256)
    if case_sha256 == token:
        raise Rejected("manual_review_credential_as_case")
    if type(body) is not bytes:
        raise Rejected("manual_review_prediction")
    request = decode(body, MAX_BODY)
    require_fields(request, ("schema_version", "instances"))
    instances = request["instances"]
    if (
        type(request["schema_version"]) is not int
        or request["schema_version"] != 1
        or type(instances) is not list
        or not 1 <= len(instances) <= 100
    ):
        raise Rejected("manual_review_prediction")
    rows = []
    for row in instances:
        require_fields(row, FEATURES)
        rows.append([row[name] for name in FEATURES])
    advisory.validate(rows)

    status, reply = await load_measurement.request(port, token, body)
    if status != 503:
        raise Rejected("manual_review_status")
    require_fields(reply, ("schema_version", "request_id", "error"))
    if (
        type(reply["schema_version"]) is not int
        or reply["schema_version"] != 1
        or type(reply["request_id"]) is not str
        or re.fullmatch("[0-9a-f]{32}", reply["request_id"]) is None
        or reply["error"] != {"code": "model_unavailable"}
    ):
        raise Rejected("manual_review_response")
    return _enqueue(state, case_sha256)


def main(argv=None):
    parser = Arguments(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path(".runtime"))
    commands = parser.add_subparsers(dest="action", required=True)
    submit_args = commands.add_parser("submit", help="Read one prediction request from stdin")
    submit_args.add_argument("--case-sha256", required=True)
    submit_args.add_argument("--port", required=True, type=int)
    submit_args.add_argument("--token-file", required=True, type=Path)
    commands.add_parser("list", help="Show pending cases in this local session")
    try:
        args = parser.parse_args(argv)
        if args.action == "list":
            result = pending(args.state)
        else:
            result = asyncio.run(
                submit(
                    args.state,
                    case_sha256=args.case_sha256,
                    port=args.port,
                    token=key_files.read(args.token_file).decode("ascii").strip(),
                    body=sys.stdin.buffer.read(MAX_BODY + 1),
                )
            )
        print(canonical(result).decode("ascii"))
        return 0
    except (OSError, ValueError, EOFError):
        print("manual_review_rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
