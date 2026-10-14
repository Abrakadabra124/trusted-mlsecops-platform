import math
import os
import queue
import re
import signal
import subprocess
import threading
import time
from contextlib import suppress

from mlsecops import serving_protocol as protocol
from mlsecops.contracts import Rejected, canonical, decode
from mlsecops.inventory import command
from mlsecops.sandbox import resolve_image


class Channel:
    def __init__(self, process):
        self.process = process
        self.requests = queue.Queue(maxsize=1)
        self.responses = queue.Queue(maxsize=1)
        self.lock = threading.Lock()
        self.closed = False
        self.reader = threading.Thread(target=self.exchange_loop, daemon=True)

    def start(self):
        if self.closed or self.reader.ident is not None:
            raise Rejected("serving_transport_closed")
        try:
            self.reader.start()
        except Exception:
            self.close()
            raise Rejected("serving_transport_failed") from None

    def exchange_loop(self):
        while not self.closed and (content := self.requests.get()) is not None:
            try:
                self.process.stdin.write(content)
                self.process.stdin.flush()
                reply = protocol.frame(self.process.stdout, protocol.MAX_FRAME)
                if reply is None:
                    raise Rejected("serving_worker_eof")
                result = True, reply
            except Exception:
                result = False, None
            with suppress(queue.Full):
                self.responses.put_nowait(result)

    def exchange(self, request, *, timeout):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise Rejected("serving_timeout_invalid")
        content = canonical(request) + b"\n"
        if len(content) > protocol.MAX_LOAD:
            raise Rejected("serving_request_limit")
        deadline = time.monotonic() + timeout
        acquired = self.lock.acquire(timeout=timeout)
        try:
            if not acquired or self.closed or self.process.poll() is not None:
                raise Rejected("serving_transport_closed")
            self.requests.put_nowait(content)
            success, result = self.responses.get(timeout=max(0, deadline - time.monotonic()))
            if not success or time.monotonic() >= deadline:
                raise Rejected("serving_transport_invalid")
            return result
        except Exception:
            self.close()
            raise Rejected("serving_transport_failed") from None
        finally:
            if acquired:
                self.lock.release()

    def close(self):
        self.closed = True
        try:
            with suppress(queue.Full):
                self.requests.put_nowait(None)
            if self.process.poll() is None:
                with suppress(ProcessLookupError):
                    if os.name == "posix" and os.getpgid(self.process.pid) == self.process.pid:
                        os.killpg(self.process.pid, signal.SIGKILL)
                    else:
                        self.process.kill()
            self.process.wait(timeout=3)
            if self.reader.ident is not None:
                self.reader.join(timeout=1)
            if self.reader.is_alive():
                raise Rejected("serving_cleanup_unconfirmed")
            for stream in (self.process.stdin, self.process.stdout):
                with suppress(OSError, ValueError):
                    stream.close()
        except Exception:
            raise Rejected("serving_cleanup_unconfirmed") from None


def create_arguments(image, session):
    return [
        "docker",
        "create",
        "--rm",
        "--interactive",
        "--name",
        f"trusted-ml-serving-{session}",
        "--label",
        f"org.trusted-mlsecops.session={session}",
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
        "1",
        "--memory",
        "1g",
        "--memory-swap",
        "1g",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=32m",
        "--log-driver",
        "none",
        image,
        "python",
        "-m",
        "mlsecops.serving_worker",
    ]


def verify_container(value, image, session):
    host, config = value["HostConfig"], value["Config"]
    if (
        value["Image"] != image
        or config["User"] != "65532:65532"
        or config.get("Labels", {}).get("org.trusted-mlsecops.session") != session
        or config["Cmd"] != ["python", "-m", "mlsecops.serving_worker"]
        or config.get("Entrypoint")
        or host["NetworkMode"] != "none"
        or host["ReadonlyRootfs"] is not True
        or host["Privileged"] is not False
        or host["AutoRemove"] is not True
        or host["Memory"] != 1024**3
        or host["MemorySwap"] != 1024**3
        or host["NanoCpus"] != 10**9
        or host["PidsLimit"] != 64
        or host.get("Binds")
        or host.get("PortBindings")
        or host.get("Devices")
        or "ALL" not in host["CapDrop"]
        or "no-new-privileges" not in host["SecurityOpt"]
        or host["LogConfig"]["Type"] != "none"
        or host["Tmpfs"] != {"/tmp": "rw,noexec,nosuid,size=32m"}
        or any(
            mount["Type"] != "tmpfs" or mount["Destination"] != "/tmp" for mount in value["Mounts"]
        )
    ):
        raise Rejected("serving_container_contract")


class Worker:
    def __init__(self, model, image):
        initial = protocol.load_request(model)
        self.image = resolve_image(image)
        if self.image != image:
            raise Rejected("serving_image_pin")
        self.container = None
        self.channel = None
        self.binding = {name: initial[name] for name in ("session_id", "model_sha256")}
        self.closed = False
        self.initial = initial

    def start(self):
        if self.closed or self.initial is None:
            raise Rejected("serving_worker_start_state")
        initial, self.initial = self.initial, None
        try:
            identifier = command(create_arguments(self.image, initial["session_id"]), timeout=30)
            if re.fullmatch(r"[a-f0-9]{64}", identifier) is None:
                raise Rejected("serving_container_identity")
            self.container = identifier
            inspected = decode(command(["docker", "inspect", identifier], timeout=10).encode())[0]
            verify_container(inspected, self.image, initial["session_id"])
            process = subprocess.Popen(
                ["docker", "start", "--attach", "--interactive", identifier],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=os.name == "posix",
            )
            self.channel = Channel(process)
            self.channel.start()
            self.send(initial, timeout=30)
            return self
        except Exception:
            self.close()
            raise Rejected("serving_load_failed") from None

    def send(self, request, *, timeout=2):
        if self.closed or self.channel is None:
            raise Rejected("serving_worker_closed")
        request = decode(canonical(request))
        protocol.validate(request)
        try:
            reply = self.channel.exchange(request, timeout=timeout)
            return protocol.verify_reply(request, reply)
        except Exception:
            self.close()
            raise Rejected("serving_exchange_rejected") from None

    def predict(self, features):
        return self.send(protocol.request(self.binding, "predict", features))

    def ping(self):
        self.send(protocol.request(self.binding, "ping"))

    def close(self):
        self.closed = True
        try:
            if self.channel is not None:
                self.channel.close()
        finally:
            if self.container is not None:
                identifier = self.container
                query = [
                    "docker",
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--no-trunc",
                    "--filter",
                    f"id={identifier}",
                ]
                if command(query, timeout=10):
                    with suppress(Rejected):
                        command(["docker", "rm", "--force", identifier], timeout=15)
                if command(query, timeout=10):
                    raise Rejected("serving_cleanup_unconfirmed")
                self.container = None
