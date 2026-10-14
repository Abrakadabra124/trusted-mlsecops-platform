import os
import sys
from contextlib import contextmanager
from pathlib import Path

from mlsecops.contracts import Rejected, safe_child


def set_lock(descriptor, acquire):
    if sys.platform == "win32":
        import msvcrt

        msvcrt.locking(descriptor, msvcrt.LK_NBLCK if acquire else msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB if acquire else fcntl.LOCK_UN)


@contextmanager
def target_lock(target):
    target = Path(target).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    path = safe_child(target.parent, f".{target.name}.recovery.lock")
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(descriptor, "r+b") as handle:
        if os.fstat(descriptor).st_size == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        try:
            set_lock(descriptor, True)
        except OSError:
            raise Rejected("restore_target_busy") from None
        try:
            yield
        finally:
            set_lock(descriptor, False)
