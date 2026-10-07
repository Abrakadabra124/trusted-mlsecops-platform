import subprocess
import threading
import time
import uuid
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, decode
from mlsecops.inventory import command, source_fingerprint

MAX_PROTOCOL = 16 * 1024 * 1024


def resolve_image(image):
    inspected = decode(command(["docker", "image", "inspect", image]).encode())[0]
    identifier = inspected["Id"]
    if not identifier.startswith("sha256:") or len(identifier) != 71:
        raise Rejected("invalid_image_digest")
    if inspected["Os"] != "linux" or inspected["Architecture"] != "amd64":
        raise Rejected("incompatible_image_profile")
    labels = inspected["Config"].get("Labels") or {}
    if labels.get("org.trusted-mlsecops.source-fingerprint") != source_fingerprint(
        Path(__file__).resolve().parents[1]
    ):
        raise Rejected("image_source_fingerprint_mismatch_rebuild_required")
    return identifier


def run_worker(image, request, timeout=600):
    payload = canonical(request)
    if len(payload) > MAX_PROTOCOL or not 1 <= timeout <= 600:
        raise Rejected("worker_request_limit")
    image = resolve_image(image)
    name = f"trusted-ml-worker-{uuid.uuid4().hex}"
    arguments = [
        "docker",
        "run",
        "--rm",
        "--interactive",
        "--name",
        name,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "65532:65532",
        "--pids-limit",
        "64",
        "--cpus",
        "2",
        "--memory",
        "4g",
        "--memory-swap",
        "4g",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--log-driver",
        "none",
        image,
        "python",
        "-m",
        "mlsecops.worker",
    ]
    process = subprocess.Popen(
        arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    captured = []
    oversized = threading.Event()

    def collect_output():
        content = process.stdout.read(MAX_PROTOCOL + 1)
        if len(content) > MAX_PROTOCOL:
            oversized.set()
        captured.append(content)

    def provide_input():
        try:
            process.stdin.write(payload)
            process.stdin.close()
        except (OSError, BrokenPipeError):
            pass

    reader = threading.Thread(target=collect_output, daemon=True)
    writer = threading.Thread(target=provide_input, daemon=True)
    reader.start()
    writer.start()
    started = time.monotonic()
    try:
        while process.poll() is None:
            if oversized.is_set():
                raise Rejected("worker_output_limit")
            if time.monotonic() - started > timeout:
                raise Rejected("worker_deadline")
            time.sleep(0.05)
        reader.join(timeout=5)
        writer.join(timeout=5)
        if reader.is_alive() or writer.is_alive() or oversized.is_set():
            raise Rejected("worker_protocol_incomplete")
        if process.returncode:
            raise Rejected("worker_failed")
        if not captured:
            raise Rejected("worker_empty_output")
        return decode(captured[0]), {
            "image_id": image,
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "network": "none",
            "memory_limit_bytes": 4 * 1024**3,
            "cpu_limit": 2,
            "deadline_seconds": timeout,
        }
    finally:
        subprocess.run(
            ["docker", "rm", "--force", name], capture_output=True, timeout=30, check=False
        )
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)
        reader.join(timeout=5)
        writer.join(timeout=5)
