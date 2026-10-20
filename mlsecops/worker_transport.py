import os
import signal
import subprocess
import sys
import threading
import time

from mlsecops.contracts import Rejected, canonical, decode, require_fields
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce as enforce_privacy

MAX_OUTPUT = 16 * 1024 * 1024
MAX_DIAGNOSTIC = 64 * 1024


class CleanupIncomplete(Rejected):
    def __init__(self):
        super().__init__("worker_cleanup_incomplete")


def capture(arguments, timeout=570, *, canonical_output=False):
    if type(canonical_output) is not bool:
        raise Rejected("worker_capture_mode")
    captured = {}
    excessive = threading.Event()
    failed = threading.Event()
    readers = []

    def read_stream(name, stream, limit, completed):
        try:
            content = stream.read(limit + 1)
            captured[name] = content
            if len(content) > limit:
                excessive.set()
        except BaseException:
            failed.set()
        finally:
            completed.set()

    process = subprocess.Popen(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name == "posix",
    )
    try:
        for name, stream, limit in (
            ("output", process.stdout, MAX_OUTPUT),
            ("diagnostic", process.stderr, MAX_DIAGNOSTIC),
        ):
            completed = threading.Event()
            reader = threading.Thread(
                target=read_stream, args=(name, stream, limit, completed), daemon=True
            )
            readers.append((reader, stream, completed))
            reader.start()
        started = time.monotonic()
        while process.poll() is None:
            if failed.is_set():
                raise Rejected("worker_stream_incomplete")
            if excessive.is_set():
                raise Rejected("worker_stream_limit")
            if time.monotonic() - started > timeout:
                raise Rejected("worker_transport_deadline")
            time.sleep(0.02)
        for reader, _stream, _completed in readers:
            reader.join(timeout=2)
        if (
            failed.is_set()
            or excessive.is_set()
            or any(reader.is_alive() for reader, _stream, _completed in readers)
        ):
            raise Rejected("worker_stream_incomplete")
        if process.returncode:
            raise Rejected("worker_process_failed")
        diagnostic = captured["diagnostic"]
        output = decode(captured["output"], MAX_OUTPUT)
        if canonical_output and captured["output"] != canonical(output) + b"\n":
            raise Rejected("worker_output_noncanonical")
        return {
            "schema_version": 1,
            "output": output,
            "diagnostics": {
                "bytes": len(diagnostic),
                "gpu_discovery_warning": b"GPU device discovery failed" in diagnostic,
                "raw_output_retained": False,
            },
        }
    finally:
        interrupted = isinstance(sys.exception(), KeyboardInterrupt)
        try:
            cleanup(process, readers)
        except Rejected:
            if interrupted:
                raise KeyboardInterrupt from None
            raise


def cleanup(process, readers):
    incomplete = False
    cancelled = False
    blocked = set()

    def record(error):
        nonlocal incomplete, cancelled
        incomplete = True
        cancelled = cancelled or isinstance(error, KeyboardInterrupt)

    try:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.kill()
    except BaseException as error:
        record(error)
        try:
            process.kill()
        except BaseException as error:
            record(error)
    try:
        process.wait(timeout=5)
    except BaseException as error:
        record(error)
    for reader, stream, completed in readers:
        try:
            if completed.wait(timeout=2) and reader.ident is not None:
                reader.join(timeout=2)
                if not reader.is_alive():
                    continue
        except BaseException as error:
            record(error)
        incomplete = True
        blocked.add(id(stream))
    for stream in (process.stdout, process.stderr):
        if id(stream) not in blocked:
            try:
                stream.close()
            except BaseException as error:
                record(error)
    if cancelled:
        raise KeyboardInterrupt from None
    if incomplete:
        raise CleanupIncomplete() from None


def unwrap(value):
    require_fields(value, ("schema_version", "output", "diagnostics"))
    detail = value["diagnostics"]
    require_fields(detail, ("bytes", "gpu_discovery_warning", "raw_output_retained"))
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or type(detail["bytes"]) is not int
        or not 0 <= detail["bytes"] <= MAX_DIAGNOSTIC
        or type(detail["gpu_discovery_warning"]) is not bool
        or detail["raw_output_retained"] is not False
        or not isinstance(value["output"], dict)
    ):
        raise Rejected("invalid_worker_transport")
    return value["output"], detail


def main():
    try:
        enforce_privacy()
        parser = Arguments(
            prog="worker-transport", description="Separate bounded worker output and diagnostics"
        )
        parser.add_argument("--request-file", required=True)
        arguments = parser.parse_args()
        result = capture(
            [sys.executable, "-m", "mlsecops.worker", "--request-file", arguments.request_file]
        )
        unwrap(result)
        payload = canonical(result) + b"\n"
        if len(payload) > MAX_OUTPUT:
            raise Rejected("worker_envelope_limit")
        sys.stdout.buffer.write(payload)
        return 0
    except KeyboardInterrupt:
        print("worker_transport_cancelled", file=sys.stderr)
        return 130
    except Exception:
        print("worker_transport_rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
