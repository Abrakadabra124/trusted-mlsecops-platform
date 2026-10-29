"""Bounded stdio bridge to an existing network-denied serving worker.

Runs as an owned child of serving_runtime.Channel. That parent enforces the
whole exchange deadline, including DNS, TLS, writes and fragmented reads.
"""

import io
import logging
import socket
import sys
import time
from contextlib import contextmanager
from urllib.parse import urlencode

from websockets.sync.client import connect

from mlsecops import serving_protocol as protocol
from mlsecops import serving_startup
from mlsecops.contracts import Rejected, canonical
from mlsecops.controller_api import HOST, Client, identifier
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce

SUBPROTOCOL = "v5.channel.k8s.io"


@contextmanager
def open_connection(pod):
    name = identifier(pod)
    token, context = Client("serving").authorization()
    query = urlencode(
        {"container": "worker", "stdin": "true", "stdout": "true", "stderr": "true", "tty": "false"}
    )
    uri = f"wss://{HOST}/api/v1/namespaces/ml-serve/pods/{name}/attach?{query}"
    # A private logger never emits request headers, model bytes or features.
    logger = logging.Logger("private-kubernetes-attach")
    logger.addHandler(logging.NullHandler())
    logger.propagate = False
    sock = socket.create_connection((HOST, 443), timeout=10)
    connection = None
    try:
        # A preexisting socket makes websockets reject every redirect.
        connection = connect(
            uri,
            sock=sock,
            ssl=context,
            proxy=None,
            compression=None,
            subprotocols=[SUBPROTOCOL],
            additional_headers={"Authorization": "Bearer " + token},
            user_agent_header=None,
            open_timeout=10,
            close_timeout=1,
            ping_interval=None,
            max_size=protocol.MAX_FRAME + 1,
            max_queue=2,
            logger=logger,
            legacy=True,
        )
        if connection.subprotocol != SUBPROTOCOL:
            raise Rejected("serving_attach_protocol")
        yield connection
    finally:
        try:
            if connection is not None:
                connection.close()
        finally:
            sock.close()


def stderr_code(connection, frame, deadline):
    if len(frame) == 1:
        return "serving_attach_empty_stderr"
    content = bytearray(frame[1:4097])
    end = min(deadline, time.monotonic() + 0.5)
    for _ in range(8):
        remaining = end - time.monotonic()
        if b"\n" in content or len(content) >= 4096 or remaining <= 0:
            break
        try:
            following = connection.recv(timeout=remaining)
        except Exception:
            break
        if following == b"\x01":
            # Empty stdout can interleave stderr fragments. The exchange is already
            # rejected; only bounded classification continues.
            continue
        if not isinstance(following, bytes) or not following or following[0] != 2:
            break
        content.extend(following[1 : 4097 - len(content)])
    if content == b"serving_worker_rejected\n":
        return "serving_attach_worker_rejected"
    if b"[W:onnxruntime:" in content:
        if b"device_discovery.cc" in content and any(
            text in content
            for text in (
                b"GPU device discovery failed",
                b"NPU device discovery failed",
                b"Failed to detect devices under",
                b"Skipping pci_bus_id for PCI path at",
            )
        ):
            return "serving_attach_ort_device_warning"
        return "serving_attach_ort_other_warning"
    return "serving_attach_stderr"


def exchange(connection, request):
    protocol.validate(request)
    content = canonical(request) + b"\n"
    deadline = time.monotonic() + 30
    for start in range(0, len(content), 16384):
        connection.send(b"\x00" + content[start : start + 16384])
    result = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Rejected("serving_attach_deadline")
        frame = connection.recv(timeout=remaining)
        if not isinstance(frame, bytes) or not frame:
            raise Rejected("serving_attach_frame")
        if frame[0] == 2:
            # Stderr remains a failure. Only bounded diagnostics are assembled;
            # fragmented/color-prefixed messages must never be emitted raw.
            raise Rejected(stderr_code(connection, frame, deadline))
        if frame[0] != 1:
            raise Rejected(
                "serving_attach_" + {3: "status", 255: "closed"}.get(frame[0], "channel")
            )
        result.extend(frame[1:])
        if len(result) > protocol.MAX_FRAME:
            raise Rejected("serving_attach_output_limit")
        if b"\n" in result:
            source = io.BytesIO(result)
            reply = protocol.frame(source, protocol.MAX_FRAME)
            if source.read(1):
                raise Rejected("serving_attach_extra_output")
            protocol.verify_reply(request, reply)
            return bytes(result)


def serve(connection, source, destination):
    initial = protocol.frame(source, protocol.MAX_LOAD)
    protocol.validate(initial)
    if initial["action"] != "load":
        raise Rejected("serving_initial_load_required")
    request = initial
    while True:
        destination.write(exchange(connection, request))
        destination.flush()
        request = protocol.frame(source, protocol.MAX_FRAME)
        if request is None:
            connection.send(b"\xff\x00")
            return
        protocol.validate(request)
        if request["action"] == "load" or any(
            request[name] != initial[name] for name in ("session_id", "model_sha256")
        ):
            raise Rejected("serving_session_mismatch")


def main():
    phase = "preflight"
    try:
        enforce()
        parser = Arguments(prog="kube-attach")
        parser.add_argument("--pod", required=True)
        options = parser.parse_args()
        phase = "connect"
        with open_connection(options.pod) as connection:
            phase = "exchange"
            serve(connection, sys.stdin.buffer, sys.stdout.buffer)
        return 0
    except Exception as error:
        code = str(error)
        if code not in serving_startup.ATTACH_CODES and phase != "preflight":
            status = getattr(getattr(error, "response", None), "status_code", None)
            code = "serving_attach_http_" + str(status) if type(status) is int else ""
            if code not in serving_startup.ATTACH_CODES:
                code = "serving_attach_" + phase + "_failed"
        suffix = ":" + code if code in serving_startup.ATTACH_CODES else ""
        sys.stderr.write("serving_attach_rejected" + suffix + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
