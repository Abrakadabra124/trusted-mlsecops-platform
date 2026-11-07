"""Private Linux event journal: exclusive lock, atomic snapshot, fail-closed recovery.

No database, background process, key generation, or automatic initialization.
Durability assumes a persistent filesystem honoring fsync; host-admin rollback
and lost volumes require an external recovery authority and are not solved here.
"""

import os
import secrets
import stat
import sys
from contextlib import contextmanager
from pathlib import Path

from mlsecops import security_event_ledger as ledger
from mlsecops import security_events as events
from mlsecops.contracts import Rejected, _parent, _stamp, canonical, decode, digest

MAX_BYTES = 16 * 1024 * 1024


def platform():
    if sys.platform != "linux":
        raise Rejected("security_store_platform")


def path(value):
    if type(value) is not str or not Path(value).is_absolute():
        raise Rejected("security_store_path")
    return value


def private(metadata, *, directory=False):
    regular = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if (
        not regular
        or metadata.st_mode & 0o077
        or metadata.st_uid != os.geteuid()
        or not directory
        and metadata.st_nlink != 1
    ):
        raise Rejected("security_store_identity")


@contextmanager
def locked(root):
    platform()
    try:
        with _parent(path(root)) as (name, options):
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, **options)
            try:
                private(os.fstat(descriptor), directory=True)
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield descriptor
            finally:
                os.close(descriptor)
    except OSError:
        raise Rejected("security_store_unavailable") from None


def read(descriptor, name, limit=MAX_BYTES):
    target = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
    try:
        before = os.fstat(target)
        private(before)
        if before.st_size > limit:
            raise Rejected("security_store_size")
        chunks, size = [], 0
        while True:
            chunk = os.read(target, min(65536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                raise Rejected("security_store_size")
        after = os.fstat(target)
        if size != before.st_size or _stamp(before) != _stamp(after):
            raise Rejected("security_store_changed")
        return b"".join(chunks)
    finally:
        os.close(target)


def create(descriptor, name, content):
    target = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor
    )
    try:
        private(os.fstat(target))
        offset = 0
        while offset < len(content):
            written = os.write(target, content[offset:])
            if written <= 0:
                raise Rejected("security_store_write")
            offset += written
        os.fsync(target)
    finally:
        os.close(target)


def replace(descriptor, document):
    content = canonical(document) + b"\n"
    if len(content) > MAX_BYTES:
        raise Rejected("security_store_size")
    create(descriptor, ".pending", content)
    os.replace(".pending", "state", src_dir_fd=descriptor, dst_dir_fd=descriptor)
    os.fsync(descriptor)
    if read(descriptor, "state") != content:
        raise Rejected("security_store_readback")


def initialize(root, registry, *, clock_ms):
    platform()
    document = ledger.Ledger.empty(registry, clock_ms=clock_ms).document()
    identity = (
        canonical(
            {"schema_version": 1, "config_sha256": registry.sha256, "nonce": secrets.token_hex(32)}
        )
        + b"\n"
    )
    with _parent(path(root)) as (name, options):
        try:
            os.mkdir(name, 0o700, **options)
            with locked(root) as descriptor:
                create(descriptor, "identity", identity)
                replace(descriptor, document)
            os.fsync(options["dir_fd"])
        except OSError:
            raise Rejected("security_store_initialization") from None
    return digest(identity)


class Store:
    def __init__(self, root, identity_sha256, registry):
        platform()
        self.root = path(root)
        self.pin = events.hexadecimal(identity_sha256)
        self.registry = registry

    def _load(self, descriptor):
        names = set()
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if entry.name not in ("identity", "state", ".pending"):
                    raise Rejected("security_store_inventory")
                private(entry.stat(follow_symlinks=False))
                names.add(entry.name)
        if not {"identity", "state"} <= names:
            raise Rejected("security_store_missing")
        identity = read(descriptor, "identity", 512)
        value = decode(identity, 512)
        events.shape(value, ("schema_version", "config_sha256", "nonce"))
        events.version(value["schema_version"])
        events.hexadecimal(value["nonce"])
        if (
            digest(identity) != self.pin
            or value["config_sha256"] != self.registry.sha256
            or canonical(value) + b"\n" != identity
        ):
            raise Rejected("security_store_pin")
        content = read(descriptor, "state")
        document = decode(content, MAX_BYTES)
        if canonical(document) + b"\n" != content:
            raise Rejected("security_store_canonical")
        result = ledger.Ledger(self.registry, document)
        if ".pending" in names:
            # Only after the committed state has been fully revalidated.
            # This file was never an acknowledged commit; an unknown outcome
            # after rename is instead recovered from the new valid state.
            read(descriptor, ".pending")
            os.unlink(".pending", dir_fd=descriptor)
            os.fsync(descriptor)
        return result

    def snapshot(self):
        with locked(self.root) as descriptor:
            return self._load(descriptor).document()

    def _update(self, operation, envelope, clock_ms):
        with locked(self.root) as descriptor:
            book = self._load(descriptor)
            before = book.document()
            result = (
                book.poll(clock_ms=clock_ms)
                if operation == "poll"
                else getattr(book, operation)(envelope, clock_ms=clock_ms)
            )
            after = book.document()
            if before != after:
                replace(descriptor, after)
            return result

    def ingest(self, envelope, *, clock_ms):
        return self._update("ingest", envelope, clock_ms)

    def acknowledge(self, envelope, *, clock_ms):
        return self._update("acknowledge", envelope, clock_ms)

    def heartbeat(self, envelope, *, clock_ms):
        return self._update("heartbeat", envelope, clock_ms)

    def poll(self, *, clock_ms):
        return self._update("poll", None, clock_ms)
