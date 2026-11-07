"""Bounded signed-alert transport for the lab's loopback operator sink.

No remote URL, proxy, redirect, token or unsigned acknowledgement is accepted.
Signatures authenticate both directions; this is not a TLS confidentiality claim.
"""

import asyncio
import re
import time

from mlsecops import monitoring, monitoring_alerts, monitoring_state, signing
from mlsecops.contracts import Rejected, canonical, decode

MAX_PACKET = 16384
TIMEOUT = 2


def port_number(value):
    return monitoring.integer(value, 1, 65535)


async def exchange(port, envelope):
    port_number(port)
    if type(envelope) is not dict:
        raise Rejected("monitor_alert_packet")
    content = canonical(envelope)
    if len(content) > MAX_PACKET:
        raise Rejected("monitor_alert_packet")
    writer = None
    try:
        async with asyncio.timeout(TIMEOUT):
            reader, writer = await asyncio.open_connection("127.0.0.1", port, limit=8192)
            writer.write(
                b"POST /v1/alerts HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\nConnection: close\r\nContent-Length: "
                + str(len(content)).encode("ascii")
                + b"\r\n\r\n"
                + content
            )
            await writer.drain()
            try:
                header = await reader.readuntil(b"\r\n\r\n")
            except asyncio.LimitOverrunError:
                raise Rejected("monitor_alert_response") from None
            lines = header[:-4].split(b"\r\n")
            if len(header) > 8192 or re.fullmatch(rb"HTTP/1\.[01] 200 [^\r\n]*", lines[0]) is None:
                raise Rejected("monitor_alert_response")
            lengths = []
            for line in lines[1:]:
                name, separator, value = line.partition(b":")
                if not separator or re.fullmatch(rb"[A-Za-z0-9-]+", name) is None:
                    raise Rejected("monitor_alert_response")
                if name.lower() in (b"transfer-encoding", b"content-encoding"):
                    raise Rejected("monitor_alert_response")
                if name.lower() == b"content-length":
                    lengths.append(value.strip())
            if len(lengths) != 1 or re.fullmatch(rb"[0-9]{1,5}", lengths[0]) is None:
                raise Rejected("monitor_alert_response")
            length = int(lengths[0])
            if not 0 < length <= MAX_PACKET:
                raise Rejected("monitor_alert_response")
            return decode(await reader.readexactly(length), MAX_PACKET)
    except TimeoutError:
        raise
    except (OSError, asyncio.IncompleteReadError):
        raise Rejected("monitor_alert_transport") from None
    finally:
        if writer is not None:
            writer.close()


class Client:
    def __init__(self, producer_key, sink_public, *, port, reference_sha256, epoch):
        self.port = port_number(port)
        self.sink_public = monitoring_alerts.public_key(sink_public)
        producer = signing.encode64(signing.load_key(producer_key).public_key().public_bytes_raw())
        self.producer_public = producer
        if producer == sink_public:
            raise Rejected("monitor_alert_roles_not_separated")
        self._key = producer_key
        self.reference_sha256 = monitoring.sha256(reference_sha256)
        self.epoch = monitoring_alerts.epoch_id(epoch)

    async def send(self, event):
        monitoring_alerts.validate_event(event)
        if (event["reference_sha256"], event["epoch"]) != (self.reference_sha256, self.epoch):
            raise Rejected("monitor_alert_binding")
        signed = signing.sign(event, "monitor-alert", self._key)
        acknowledgement = await exchange(self.port, signed)
        monitoring_alerts.receipt(acknowledgement, event, self.sink_public)
        return acknowledgement


class App:
    def __init__(self, sink, *, clock=lambda: time.time_ns() // 1000000, epoch_guard=None):
        if type(sink) is not monitoring_alerts.Sink or not callable(clock):
            raise Rejected("monitor_sink_configuration")
        self.sink, self.clock = sink, clock
        if epoch_guard is not None and (
            type(epoch_guard) is not monitoring_state.Guard
            or (epoch_guard.role, epoch_guard.epoch, epoch_guard.reference)
            != ("sink", sink._epoch, sink._reference)
        ):
            raise Rejected("monitor_epoch_guard")
        self._epoch_guard = epoch_guard
        self._admitted = epoch_guard is None
        self.startup_failed = False

    async def read(self, scope, receive):
        if (scope["method"], scope["path"], scope.get("query_string", b"")) != (
            "POST",
            "/v1/alerts",
            b"",
        ):
            raise Rejected("monitor_alert_request")
        headers = [(name.lower(), value) for name, value in scope["headers"]]
        lengths = [value for name, value in headers if name == b"content-length"]
        types = [value for name, value in headers if name == b"content-type"]
        if (
            types != [b"application/json"]
            or len(lengths) != 1
            or re.fullmatch(rb"[0-9]{1,5}", lengths[0]) is None
            or not 0 < int(lengths[0]) <= MAX_PACKET
            or any(name in (b"transfer-encoding", b"content-encoding") for name, _ in headers)
        ):
            raise Rejected("monitor_alert_request")
        body = bytearray()
        async with asyncio.timeout(TIMEOUT):
            while True:
                await asyncio.sleep(0)
                message = await receive()
                if message["type"] != "http.request" or type(message.get("body")) is not bytes:
                    raise Rejected("monitor_alert_request")
                if len(body) + len(message["body"]) > int(lengths[0]):
                    raise Rejected("monitor_alert_request")
                body.extend(message["body"])
                if not message.get("more_body", False):
                    break
        if len(body) != int(lengths[0]):
            raise Rejected("monitor_alert_request")
        return decode(bytes(body), MAX_PACKET)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    self._admitted = False
                    try:
                        if self._epoch_guard is not None:
                            self._epoch_guard.claim()
                    except Exception:
                        self.startup_failed = True
                        await send(
                            {"type": "lifespan.startup.failed", "message": "monitor_epoch_rejected"}
                        )
                        return
                    self._admitted = True
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    self._admitted = False
                    await send({"type": "lifespan.shutdown.complete"})
                    return
                else:
                    raise Rejected("monitor_sink_lifespan")
        if scope["type"] != "http":
            raise Rejected("monitor_sink_protocol")
        try:
            if not self._admitted:
                raise Rejected("monitor_epoch_inactive")
            envelope = await self.read(scope, receive)
            body = canonical(self.sink.accept(envelope, clock_ms=self.clock()))
            status = 200
        except (Rejected, OSError, TimeoutError):
            status, body = 400, b'{"status":"rejected"}'
        async with asyncio.timeout(TIMEOUT):
            await send(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                        (b"cache-control", b"no-store"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body, "more_body": False})
