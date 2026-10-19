import hashlib
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path

from mlsecops import audit_retention
from mlsecops.contracts import Rejected, canonical, decode, require_fields


def _private(metadata, *, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not kind(metadata.st_mode)
        or metadata.st_mode & 0o077
        or metadata.st_uid != os.geteuid()
        or not directory
        and metadata.st_nlink != 1
    ):
        raise Rejected("audit_snapshot_identity")


def _identity(metadata):
    return [metadata.st_dev, metadata.st_ino]


def _read(directory, name, limit):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        _private(before)
        if not 0 <= before.st_size <= limit:
            raise Rejected("audit_snapshot_size")
        content = bytearray()
        while len(content) <= limit:
            block = os.read(descriptor, min(65536, limit + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        _private(after)
        if len(content) != before.st_size or any(
            getattr(before, field) != getattr(after, field)
            for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        ):
            raise Rejected("audit_snapshot_changed")
        return bytes(content), _identity(before)
    finally:
        os.close(descriptor)


def _names(directory):
    duplicate = os.open(".", os.O_RDONLY | os.O_DIRECTORY, dir_fd=directory)
    try:
        names = set()
        with os.scandir(duplicate) as entries:
            for entry in entries:
                names.add(entry.name)
                if len(names) > 66:
                    raise Rejected("audit_snapshot_inventory")
        return names
    finally:
        os.close(duplicate)


@contextmanager
def _leased(path):
    if os.name != "posix" or not path.is_absolute() or path.resolve() != path:
        raise Rejected("audit_snapshot_platform_or_path")
    nonce = os.urandom(32)
    identity = None
    descriptor = None
    offset = 0
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _private(os.fstat(directory), directory=True)
        descriptor = os.open(
            ".lease", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
        )
        metadata = os.fstat(descriptor)
        _private(metadata)
        identity = _identity(metadata)
        while offset < len(nonce):
            written = os.write(descriptor, nonce[offset:])
            if type(written) is not int or not 0 < written <= len(nonce) - offset:
                raise Rejected("audit_snapshot_lease_write")
            offset += written
        os.fsync(descriptor)
        os.fsync(directory)
        yield directory
    finally:
        try:
            if identity is not None:
                if _read(directory, ".lease", 32) != (nonce[:offset], identity):
                    raise Rejected("audit_snapshot_lease_changed")
                os.unlink(".lease", dir_fd=directory)
                os.fsync(directory)
        finally:
            try:
                if descriptor is not None:
                    os.close(descriptor)
            finally:
                os.close(directory)


def _integer(value, maximum=2**63 - 1, *, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise Rejected("audit_snapshot_manifest")
    return value


def manifest(content):
    saved = decode(content, audit_retention.MAX_MANIFEST)
    require_fields(
        saved, ("schema_version", "policy", "budget", "clock", "sequence", "next_index", "segments")
    )
    if (
        canonical(saved) != content
        or type(saved["schema_version"]) is not int
        or saved["schema_version"] != 1
    ):
        raise Rejected("audit_snapshot_manifest")
    require_fields(
        saved["policy"], ("segment_bytes", "max_segments", "rotate_seconds", "retain_seconds")
    )
    policy = audit_retention.Policy(**saved["policy"]).validate(saved["budget"])
    _integer(saved["sequence"])
    _integer(saved["next_index"])
    require_fields(saved["clock"], ("boot", "wall", "mono"))
    if (
        type(saved["clock"]["boot"]) is not str
        or re.fullmatch(r"[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}", saved["clock"]["boot"])
        is None
    ):
        raise Rejected("audit_snapshot_manifest")
    _integer(saved["clock"]["wall"], minimum=1)
    _integer(saved["clock"]["mono"], minimum=1)
    segments = saved["segments"]
    if type(segments) is not list or not 1 <= len(segments) <= policy.max_segments:
        raise Rejected("audit_snapshot_empty_or_capacity")
    names = set()
    for segment in segments:
        require_fields(segment, ("name", "size", "first", "last", "sha256", "identity"))
        if (
            type(segment["name"]) is not str
            or re.fullmatch(r"[a-f0-9]{16}\.jsonl", segment["name"]) is None
            or segment["name"] in names
            or not 0 < int(segment["name"][:16], 16) <= saved["next_index"]
            or not 0 < _integer(segment["size"], policy.segment_bytes)
            or _integer(segment["first"], minimum=1) > _integer(segment["last"], minimum=1)
            or segment["last"] > saved["clock"]["mono"]
            or type(segment["sha256"]) is not str
            or re.fullmatch(r"[a-f0-9]{64}", segment["sha256"]) is None
            or type(segment["identity"]) is not list
            or len(segment["identity"]) != 2
            or any(type(value) is not int or value < 0 for value in segment["identity"])
        ):
            raise Rejected("audit_snapshot_manifest")
        names.add(segment["name"])
    if sum(segment["size"] for segment in segments) > saved["budget"]:
        raise Rejected("audit_snapshot_capacity")
    return saved


def read_closed(path):
    try:
        with _leased(Path(path)) as directory:
            source, identity = _read(directory, "manifest.json", audit_retention.MAX_MANIFEST)
            saved = manifest(source)
            expected = {".lease", "manifest.json", *(item["name"] for item in saved["segments"])}
            if _names(directory) != expected:
                raise Rejected("audit_snapshot_inventory")
            chunks, previous = [], None
            for segment in saved["segments"]:
                content, actual = _read(directory, segment["name"], segment["size"])
                if (
                    actual != segment["identity"]
                    or len(content) != segment["size"]
                    or hashlib.sha256(content).hexdigest() != segment["sha256"]
                ):
                    raise Rejected("audit_snapshot_segment_changed")
                first, last = audit_retention.sequences(content)
                if previous is not None and first != previous + 1:
                    raise Rejected("audit_snapshot_sequence")
                previous = last
                chunks.append(content)
            if (
                previous != saved["sequence"]
                or _names(directory) != expected
                or _read(directory, "manifest.json", audit_retention.MAX_MANIFEST)
                != (source, identity)
            ):
                raise Rejected("audit_snapshot_changed")
        return chunks
    except Exception:
        raise Rejected("audit_snapshot_unavailable") from None
