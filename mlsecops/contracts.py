import hashlib
import json
import os
import secrets
import stat
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from pathlib import Path


class Rejected(ValueError):
    pass


def canonical(value):
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise Rejected("invalid_json_value") from error


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("duplicate_json_key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise Rejected("nonfinite_json")


def decode(content, limit=16 * 1024 * 1024):
    if len(content) > limit:
        raise Rejected("document_too_large")
    try:
        return json.loads(content, object_pairs_hook=_unique, parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Rejected("invalid_json") from error


def digest(content):
    return hashlib.sha256(content).hexdigest()


def now():
    return datetime.now(UTC).isoformat()


@contextmanager
def _parent(path, *, create=False):
    """Pin every POSIX parent component without following links.

    Windows is a compatibility path with static reparse checks, not a claim of
    race-safe Win32 handles or ACL enforcement. Write directories must be trusted.
    """
    path = Path(path).absolute()
    if ".." in path.parts or "\x00" in str(path) or not path.name:
        raise Rejected("invalid_artifact_path")
    try:
        if os.name != "posix":
            if any(p.is_symlink() or p.is_junction() for p in (path, *path.parents)):
                raise Rejected("symlink_rejected")
            if create:
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            yield path, {}
            return
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
        directory = os.open(path.anchor, flags)
        try:
            for component in path.parts[1:-1]:
                if create:
                    try:
                        os.mkdir(component, 0o700, dir_fd=directory)
                    except FileExistsError:
                        pass
                child = os.open(component, flags, dir_fd=directory)
                os.close(directory)
                directory = child
            yield path.name, {"dir_fd": directory}
        finally:
            os.close(directory)
    except OSError:
        raise Rejected("artifact_unavailable") from None


def _regular(metadata):
    if not stat.S_ISREG(metadata.st_mode):
        raise Rejected("artifact_file_type")


def _stamp(metadata):
    return tuple(
        getattr(metadata, field)
        for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    )


def bounded_read(path, limit=16 * 1024 * 1024):
    if type(limit) is not int or limit < 0:
        raise Rejected("artifact_read_limit")
    with _parent(path) as (name, options), ExitStack() as cleanup:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(name, flags | getattr(os, "O_BINARY", 0), **options)
        cleanup.callback(os.close, descriptor)
        before = os.fstat(descriptor)
        _regular(before)
        if before.st_size > limit:
            raise Rejected("artifact_too_large")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            content = source.read(limit + 1)
        after = os.fstat(descriptor)
        _regular(after)
        if len(content) > limit:
            raise Rejected("artifact_too_large")
        if len(content) != before.st_size or _stamp(before) != _stamp(after):
            raise Rejected("artifact_changed")
        return content


def read_json(path):
    return decode(bounded_read(path))


def atomic_write(path, content, mode=0o600):
    with _parent(path, create=True) as (name, options):
        try:
            target = os.stat(name, follow_symlinks=False, **options)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(target.st_mode):
                raise Rejected("symlink_rejected")
            _regular(target)
        temporary = ".pending-" + secrets.token_hex(16)
        if not options:
            temporary = Path(name).parent / temporary
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags | getattr(os, "O_BINARY", 0), 0o600, **options)
        try:
            with ExitStack() as cleanup:
                cleanup.callback(os.close, descriptor)
                with os.fdopen(descriptor, "wb", closefd=False) as output:
                    output.write(content)
                    output.flush()
                if os.name == "posix":
                    os.fchmod(descriptor, mode)
                else:
                    os.chmod(temporary, mode)
                os.fsync(descriptor)
            directory = options.get("dir_fd")
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            if directory is not None:
                os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, **options)
            except FileNotFoundError:
                pass


def write_json(path, value):
    atomic_write(path, canonical(value) + b"\n")


def require_fields(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise Rejected("unexpected_fields")


def safe_child(root, name):
    if Path(root).is_symlink():
        raise Rejected("symlink_rejected")
    root = Path(root).resolve()
    if not isinstance(name, str) or not name or "\\" in name:
        raise Rejected("invalid_artifact_path")
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts or ":" in name:
        raise Rejected("invalid_artifact_path")
    candidate = root / relative
    if not candidate.resolve().is_relative_to(root):
        raise Rejected("artifact_path_escape")
    current = candidate
    while current != root:
        if current.is_symlink():
            raise Rejected("symlink_rejected")
        current = current.parent
    return candidate
