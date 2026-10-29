"""Bounded private signing files. POSIX permissions are checked on open descriptors."""

import os
import stat
from contextlib import ExitStack, contextmanager
from pathlib import Path

from mlsecops.contracts import Rejected


def validate(metadata):
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise Rejected("signing_key_file_identity")
    if os.name == "posix" and (metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077):
        raise Rejected("signing_key_file_permissions")


@contextmanager
def opened(path, *, create=False):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise Rejected("symlink_key")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL if create else os.O_RDONLY
    flags |= (
        getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    )
    try:
        with ExitStack() as cleanup:
            options = {}
            selected = path
            if os.name == "posix":
                directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                cleanup.callback(os.close, directory)
                options["dir_fd"] = directory
                selected = path.name
            descriptor = os.open(selected, flags, 0o600, **options)
            cleanup.callback(os.close, descriptor)
            validate(os.fstat(descriptor))
            stream = cleanup.enter_context(
                os.fdopen(descriptor, "wb" if create else "rb", closefd=False)
            )
            yield stream
            if create:
                stream.flush()
                os.fsync(descriptor)
    except OSError:
        raise Rejected("signing_key_file_unavailable") from None


def read(path):
    with opened(path) as source:
        before = os.fstat(source.fileno())
        content = source.read(4097)
        after = os.fstat(source.fileno())
        validate(after)
        if len(content) > 4096:
            raise Rejected("signing_key_file_size")
        if len(content) != before.st_size or any(
            getattr(before, field) != getattr(after, field)
            for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        ):
            raise Rejected("signing_key_file_changed")
        return content
