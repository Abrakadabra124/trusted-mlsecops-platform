import argparse
import os
import signal
import subprocess
import sys
import threading
import time

from mlsecops.contracts import Rejected, canonical, decode, require_fields

MAX_OUTPUT = 16 * 1024 * 1024
MAX_DIAGNOSTIC = 64 * 1024


def capture(arguments, timeout=570):
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name == "posix",
    )
    captured = {}
    excessive = threading.Event()

    def read_stream(name, stream, limit):
        content = stream.read(limit + 1)
        captured[name] = content
        if len(content) > limit:
            excessive.set()

    readers = [
        threading.Thread(target=read_stream, args=(name, stream, limit), daemon=True)
        for name, stream, limit in (
            ("output", process.stdout, MAX_OUTPUT),
            ("diagnostic", process.stderr, MAX_DIAGNOSTIC),
        )
    ]
    for reader in readers:
        reader.start()
    started = time.monotonic()
    try:
        while process.poll() is None:
            if excessive.is_set():
                raise Rejected("worker_stream_limit")
            if time.monotonic() - started > timeout:
                raise Rejected("worker_transport_deadline")
            time.sleep(0.02)
        for reader in readers:
            reader.join(timeout=2)
        if excessive.is_set() or any(reader.is_alive() for reader in readers):
            raise Rejected("worker_stream_incomplete")
        if process.returncode:
            raise Rejected("worker_process_failed")
        diagnostic = captured["diagnostic"]
        return {
            "schema_version": 1,
            "output": decode(captured["output"], MAX_OUTPUT),
            "diagnostics": {
                "bytes": len(diagnostic),
                "gpu_discovery_warning": b"GPU device discovery failed" in diagnostic,
                "raw_output_retained": False,
            },
        }
    finally:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=2)
        if not any(reader.is_alive() for reader in readers):
            for stream in (process.stdout, process.stderr):
                stream.close()


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
    parser = argparse.ArgumentParser(description="Separate bounded worker output and diagnostics")
    parser.add_argument("--request-file", required=True)
    arguments = parser.parse_args()
    try:
        result = capture(
            [sys.executable, "-m", "mlsecops.worker", "--request-file", arguments.request_file]
        )
        unwrap(result)
        payload = canonical(result) + b"\n"
        if len(payload) > MAX_OUTPUT:
            raise Rejected("worker_envelope_limit")
        sys.stdout.buffer.write(payload)
        return 0
    except (Rejected, OSError) as error:
        print(f"Worker transport rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
