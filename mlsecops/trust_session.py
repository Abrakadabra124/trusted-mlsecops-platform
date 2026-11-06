"""One engine-owned SQL connection; never cache trust documents or decisions."""

import threading
import time
from contextlib import contextmanager
from pathlib import Path

from mlsecops import storage
from mlsecops.contracts import Rejected, bounded_read, canonical, digest, safe_child

MAX_REUSE_SECONDS = 5


def credentials(directory, options):
    parameters = storage.connection_parameters(directory, **options)
    if parameters["user"] not in {"ml_serving", "ml_promoter"}:
        raise Rejected("trust_client_identity")
    files = {
        name: digest(bounded_read(safe_child(Path(directory), name), limit))
        for name, limit in (
            ("connection.json", 65536),
            ("ca.crt", 4096),
            ("client.crt", 4096),
            ("client.key", 4096),
        )
    }
    return digest(canonical({"parameters": parameters, "files": files}))


class Session:
    def __init__(self):
        self.lock = threading.Lock()
        self.current = None
        self.identity = None
        self.expires = 0
        self.closed = False

    def drop(self):
        if self.current is not None:
            self.current.close()
            if not self.current.closed:
                raise Rejected("trust_session_cleanup_unconfirmed")
            self.current = None

    @contextmanager
    def connection(self, directory, *, expected_host=None):
        if not self.lock.acquire(timeout=1):
            raise Rejected("trust_session_busy")
        try:
            if self.closed:
                raise Rejected("trust_session_closed")
            options = {} if expected_host is None else {"expected_host": expected_host}
            identity = credentials(directory, options)
            if self.current is not None and (
                self.current.closed or self.identity != identity or time.monotonic() >= self.expires
            ):
                self.drop()
            if self.current is None:
                self.current = storage.connect(directory, **options)
                self.current.autocommit = True
                if credentials(directory, options) != identity:
                    raise Rejected("trust_session_credentials_changed")
                self.identity = identity
                self.expires = time.monotonic() + MAX_REUSE_SECONDS
            yield self.current
        except BaseException:
            self.drop()
            raise
        finally:
            self.lock.release()

    def close(self):
        with self.lock:
            self.closed = True
            self.drop()
