"""Authenticated, bounded ASGI ingress and read-only incident inspection."""

import asyncio
import re

from mlsecops import security_events as events
from mlsecops.contracts import Rejected, canonical, decode
from mlsecops.serving_access import Access, Limited

TIMEOUT_SECONDS = 2
MAX_RESPONSE = 65536


class App:
    def __init__(self, collector, ingress_token, operator_token):
        if ingress_token == operator_token:
            raise Rejected("security_http_roles")
        self.collector = collector
        self.ingress = Access.single(ingress_token)
        self.operator = Access.single(operator_token)
        self.startup_failed = False

    async def read(self, scope, receive):
        headers = [(name.lower(), value) for name, value in scope["headers"]]
        lengths = [value for name, value in headers if name == b"content-length"]
        types = [value for name, value in headers if name == b"content-type"]
        if (
            types != [b"application/json"]
            or len(lengths) != 1
            or re.fullmatch(rb"[0-9]{1,4}", lengths[0]) is None
            or not 0 < int(lengths[0]) <= events.MAX_ENVELOPE
            or any(name in (b"transfer-encoding", b"content-encoding") for name, _ in headers)
        ):
            raise Rejected("security_http_request")
        body = bytearray()
        async with asyncio.timeout(TIMEOUT_SECONDS):
            while True:
                await asyncio.sleep(0)
                message = await receive()
                if message["type"] != "http.request" or type(message.get("body")) is not bytes:
                    raise Rejected("security_http_request")
                if len(body) + len(message["body"]) > int(lengths[0]):
                    raise Rejected("security_http_request")
                body.extend(message["body"])
                if not message.get("more_body", False):
                    break
        if len(body) != int(lengths[0]):
            raise Rejected("security_http_request")
        return decode(bytes(body), events.MAX_ENVELOPE)

    async def lifespan(self, receive, send):
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                try:
                    await self.collector.start()
                except Exception:
                    self.startup_failed = True
                    await self.collector.close()
                    await send(
                        {"type": "lifespan.startup.failed", "message": "security_start_failed"}
                    )
                    return
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await self.collector.close()
                await send({"type": "lifespan.shutdown.complete"})
                return
            else:
                raise Rejected("security_http_lifespan")

    async def request(self, scope, receive):
        method, path = scope["method"], scope["path"]
        access = self.ingress if method == "POST" else self.operator
        credentials = [
            value.decode("latin-1")
            for name, value in scope["headers"]
            if name.lower() == b"authorization"
        ]
        principal = access.authenticate(credentials)
        if principal is None:
            return 401, {"status": "unauthorized"}
        ticket = access.acquire(principal)
        try:
            if scope.get("query_string", b""):
                return 400, {"status": "rejected"}
            if method == "POST" and path in ("/events", "/heartbeat"):
                try:
                    envelope = await self.read(scope, receive)
                except (Rejected, TimeoutError):
                    return 400, {"status": "rejected"}
                if path == "/events":
                    return 200, self.collector.ingest(envelope)
                record = self.collector.heartbeat(envelope)
                return 200, {"heartbeat": record, "release_ready": False}
            if method == "GET":
                if any(
                    name.lower() in (b"transfer-encoding", b"content-encoding")
                    or name.lower() == b"content-length"
                    and value != b"0"
                    for name, value in scope["headers"]
                ):
                    return 400, {"status": "rejected"}
                if path == "/health":
                    report = self.collector.health()
                    return (200 if report["healthy"] else 503), report
                match = re.fullmatch(r"/incidents/(0|[1-9][0-9]{0,3})", path)
                if match:
                    return 200, self.collector.incidents(int(match[1]))
            return 404, {"status": "not_found"}
        finally:
            ticket.release()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self.lifespan(receive, send)
            return
        if scope["type"] != "http":
            raise Rejected("security_http_protocol")
        try:
            status, result = await self.request(scope, receive)
            body = canonical(result)
            if len(body) > MAX_RESPONSE:
                raise Rejected("security_http_response_size")
        except Limited:
            status, body = 429, b'{"status":"limited"}'
        except Exception:
            # Runtime refusal and unavailable state never expose paths or input.
            status, body = 503, b'{"status":"unavailable"}'
        async with asyncio.timeout(TIMEOUT_SECONDS):
            await send(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                        (b"cache-control", b"no-store"),
                        (b"connection", b"close"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body, "more_body": False})
