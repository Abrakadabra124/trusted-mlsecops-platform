import os
import queue
import re
import threading
import time
from pathlib import Path

from mlsecops.contracts import Rejected, canonical

MAX_RECORD = 2048
MAX_BYTES = 16 * 1024 * 1024
FIELDS = {"request_id", "principal_id", "route", "stage", "status", "release"}
REFERENCES = {"selection_sha256", "bundle_sha256", "model_sha256"}
REJECTIONS = {
    "audit_event_invalid",
    "audit_clock_invalid",
    "audit_sequence_exhausted",
    "audit_record_too_large",
    "audit_queue_full",
    "audit_capacity_exhausted",
}


def hexadecimal(value, length):
    return type(value) is str and len(value) == length and re.fullmatch("[a-f0-9]+", value)


def checked(value):
    if type(value) is not dict or len(value) != len(FIELDS) or value.keys() != FIELDS:
        raise Rejected("audit_event_invalid")
    result = {key: value[key] for key in FIELDS}
    if (
        not hexadecimal(result["request_id"], 32)
        or result["principal_id"] is not None
        and not hexadecimal(result["principal_id"], 32)
        or type(result["route"]) is not str
        or result["route"] not in {"predict", "ready", "live", "other"}
        or type(result["stage"]) is not str
        or result["stage"]
        not in {"request_started", "response_started", "response_completed", "aborted"}
    ):
        raise Rejected("audit_event_invalid")
    status = result["status"]
    if status is not None and (type(status) is not int or not 200 <= status <= 599):
        raise Rejected("audit_event_invalid")
    if result["stage"] == "request_started":
        if status is not None or result["release"] is not None:
            raise Rejected("audit_event_invalid")
    elif result["stage"] != "aborted" and status is None:
        raise Rejected("audit_event_invalid")
    release = result["release"]
    if release is not None:
        if type(release) is not dict or len(release) != 3 or release.keys() != REFERENCES:
            raise Rejected("audit_event_invalid")
        release = {key: release[key] for key in REFERENCES}
        if result["route"] not in {"predict", "ready"} or not all(
            hexadecimal(reference, 64) for reference in release.values()
        ):
            raise Rejected("audit_event_invalid")
        result["release"] = release
    if status == 200 and result["route"] in {"predict", "ready"}:
        if release is None or result["principal_id"] is None:
            raise Rejected("audit_event_invalid")
    return result


class Journal:
    def __init__(self, path, *, capacity=64, max_bytes=MAX_BYTES):
        if (
            type(capacity) is not int
            or not 1 <= capacity <= 64
            or type(max_bytes) is not int
            or not MAX_RECORD <= max_bytes <= MAX_BYTES
        ):
            raise Rejected("audit_limits_invalid")
        self.lock = threading.Lock()
        self.thread = None
        self._queue = queue.Queue(maxsize=capacity)
        self._capacity, self._max_bytes = capacity, max_bytes
        self._accepted = self._durable = self._pending = 0
        self._reserved = self._durable_bytes = self._clock = 0
        self._failure = None
        self._closing = self._closed = False
        self._descriptor = None
        try:
            path = Path(path)
            if not path.is_absolute():
                raise OSError("private_parent_required")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            if os.name == "posix":
                directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    parent = os.fstat(directory)
                    if parent.st_mode & 0o077 or parent.st_uid != os.geteuid():
                        raise OSError("private_parent_required")
                    self._descriptor = os.open(path.name, flags, 0o600, dir_fd=directory)
                    os.fsync(directory)
                finally:
                    os.close(directory)
            else:
                if path.parent.is_symlink():
                    raise OSError("private_parent_required")
                self._descriptor = os.open(path, flags, 0o600)
        except (OSError, TypeError, ValueError):
            self._finish()
            raise Rejected("audit_path_rejected") from None

    def start(self):
        with self.lock:
            if self.thread is not None or self._closing or self._closed or self._failure:
                raise Rejected("audit_start_rejected")
            try:
                self.thread = threading.Thread(target=self._run, daemon=True)
                self.thread.start()
            except Exception:
                self._failure = "thread_start"
                self._closing = True
        if self._failure == "thread_start":
            if self.thread is None or self.thread.ident is None:
                self._finish()
            raise Rejected("audit_thread_start") from None

    def emit(self, value):
        with self.lock:
            if self._closing or self._closed or self._failure or self.thread is None:
                raise Rejected("audit_unavailable")
            try:
                entry = checked(value)
                observed = time.time_ns()
                if type(observed) is not int or not self._clock <= observed < 2**63:
                    raise Rejected("audit_clock_invalid")
                if self._accepted >= 2**63 - 1:
                    raise Rejected("audit_sequence_exhausted")
                sequence = self._accepted + 1
                content = (
                    canonical(
                        {
                            "schema_version": 1,
                            "sequence": sequence,
                            "recorded_at_ns": observed,
                            "event": entry,
                        }
                    )
                    + b"\n"
                )
                if len(content) > MAX_RECORD:
                    raise Rejected("audit_record_too_large")
                if self._pending >= self._capacity:
                    raise Rejected("audit_queue_full")
                if self._reserved + len(content) > self._max_bytes:
                    raise Rejected("audit_capacity_exhausted")
                self._queue.put_nowait(content)
                self._accepted = sequence
                self._pending += 1
                self._reserved += len(content)
                self._clock = observed
                return sequence
            except Rejected as error:
                code = str(error) if str(error) in REJECTIONS else "audit_producer_failed"
                self._failure = code
                raise Rejected(code) from None
            except Exception:
                self._failure = "producer_failed"
                raise Rejected("audit_producer_failed") from None

    def _write(self, content):
        offset = 0
        while offset < len(content):
            written = os.write(self._descriptor, content[offset:])
            if type(written) is not int or not 1 <= written <= len(content) - offset:
                raise OSError("audit_write_no_progress")
            offset += written
        os.fsync(self._descriptor)

    def _run(self):
        try:
            while True:
                try:
                    content = self._queue.get(timeout=0.05)
                except queue.Empty:
                    with self.lock:
                        if (self._closing or self._failure) and self._pending == 0:
                            break
                    continue
                self._write(content)
                with self.lock:
                    self._durable += 1
                    self._durable_bytes += len(content)
                    self._pending -= 1
        except BaseException:
            with self.lock:
                self._failure = self._failure or "sink_failed"
        finally:
            while True:
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    break
            with self.lock:
                self._pending = 0
            self._finish()

    def _finish(self):
        with self.lock:
            descriptor, self._descriptor = self._descriptor, None
        if descriptor is None:
            return
        try:
            os.close(descriptor)
        except OSError:
            with self.lock:
                self._failure = self._failure or "close_failed"
        finally:
            with self.lock:
                self._closed = True

    def close(self, timeout=1):
        if type(timeout) not in (int, float) or not 0 <= timeout <= 5:
            with self.lock:
                self._failure = self._failure or "close_timeout_invalid"
            raise Rejected("audit_close_timeout_invalid")
        with self.lock:
            self._closing = True
            thread = self.thread
        if thread is not None and thread.ident is not None:
            thread.join(timeout)
            if thread.is_alive():
                raise Rejected("audit_shutdown_pending")
        else:
            self._finish()
        if not self.status()["closed"]:
            raise Rejected("audit_shutdown_pending")
        with self.lock:
            if self._accepted != self._durable:
                self._failure = self._failure or "unconfirmed"
        if self.status()["failure"]:
            raise Rejected("audit_failed")

    def status(self):
        with self.lock:
            return {
                "healthy": not (self._failure or self._closing or self._closed)
                and self.thread is not None
                and self.thread.is_alive(),
                "closed": self._closed,
                "failure": self._failure,
                "accepted": self._accepted,
                "durable": self._durable,
                "pending": self._pending,
                "unconfirmed": self._accepted - self._durable - self._pending,
                "durable_bytes": self._durable_bytes,
            }
