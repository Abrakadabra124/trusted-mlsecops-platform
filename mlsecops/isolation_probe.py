import argparse
import ipaddress
import os
import socket
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from mlsecops.contracts import Rejected, canonical


def environment():
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    try:
        Path("/app/forbidden-write").write_text("probe")
        readonly = False
    except OSError:
        readonly = True
    scratch = Path("/tmp/probe-write")
    scratch.write_text("probe")
    scratch.unlink()
    return {
        "uid": os.getuid(),
        "read_only_root": readonly,
        "capabilities": status["CapEff"].strip(),
        "no_new_privileges": status["NoNewPrivs"].strip(),
        "memory_max": Path("/sys/fs/cgroup/memory.max").read_text().strip(),
        "pids_max": Path("/sys/fs/cgroup/pids.max").read_text().strip(),
        "cpu_max": Path("/sys/fs/cgroup/cpu.max").read_text().strip(),
        "absent": {
            name: not Path(name).exists()
            for name in (
                "/var/run/secrets/kubernetes.io/serviceaccount/token",
                "/var/run/docker.sock",
                "/etc/kubernetes/admin.conf",
                "/app/.runtime/keys",
                "/app/.runtime/approved",
            )
        },
        "pid1_is_probe": b"mlsecops.isolation_probe" in Path("/proc/1/cmdline").read_bytes(),
        "onnx_telemetry_disabled": os.environ.get("ORT_DISABLE_TELEMETRY") == "1",
    }


def connect(address, port):
    if ipaddress.ip_address(address) not in ipaddress.ip_network("10.78.0.0/16") or port != 8080:
        raise Rejected("probe_target_outside_owned_lab")
    try:
        with socket.create_connection((address, port), timeout=2):
            return {"reachable": True}
    except OSError:
        return {"reachable": False}


class Health(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"healthy")

    def log_message(self, format, *arguments):
        pass


def pid_limit():
    processes = []
    failure = None
    try:
        for iteration in range(80):
            try:
                processes.append(subprocess.Popen(["/bin/sleep", "30"]))
            except OSError as error:
                failure = error.errno
                break
        return {"started": len(processes), "failure_errno": failure, "attempt_limit": 80}
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description="Bounded probes for the owned Kubernetes lab")
    parser.add_argument(
        "action", choices=["environment", "connect", "serve", "deadline", "oom", "pids"]
    )
    parser.add_argument("--address")
    arguments = parser.parse_args()
    if arguments.action == "serve":
        HTTPServer(("0.0.0.0", 8080), Health).serve_forever()
    elif arguments.action == "environment":
        print(canonical(environment()).decode())
    elif arguments.action == "connect":
        print(canonical(connect(arguments.address, 8080)).decode())
    elif arguments.action == "deadline":
        time.sleep(120)
    elif arguments.action == "pids":
        print(canonical(pid_limit()).decode())
    else:
        limit = Path("/sys/fs/cgroup/memory.max").read_text().strip()
        if limit == "max" or int(limit) > 256 * 1024**2:
            raise Rejected("oom_probe_requires_256Mi_or_less_cgroup")
        allocations = []
        for iteration in range(40):
            allocations.append(bytearray(16 * 1024**2))
        raise Rejected("oom_limit_did_not_terminate_probe")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
