import asyncio
from contextlib import suppress
from dataclasses import asdict

from mlsecops.contracts import Rejected

SCOPE_KEY = "mlsecops.audit_delivery"


class Delivery:
    def __init__(self, journal, request_id, principal, route, remaining, denial, release):
        self.journal = journal
        self.request_id, self.principal, self.route = request_id, principal, route
        self.remaining, self.denial = remaining, denial
        self.context = None
        self.status = None
        self.completed = False
        self.worker_pending = self.http_done = False
        self.release_callback = release
        self.ticket = None

    def start(self):
        if self.journal is None or self.ticket is not None:
            raise Rejected("audit_unavailable")
        self.ticket = self.journal.reserve()
        try:
            self.emit("request_started")
        except BaseException:
            self.journal.release(self.ticket)
            self.ticket = None
            raise

    def emit(self, stage, status=None):
        if self.ticket is None:
            raise Rejected("audit_unavailable")
        return self.journal.emit(
            {
                "schema_version": 2,
                "request_id": self.request_id,
                "principal_id": self.principal,
                "route": self.route,
                "stage": stage,
                "status": status,
                "context": asdict(self.context)
                if status == 200 and self.context is not None
                else None,
            },
            ticket=self.ticket,
        )

    def observe(self, stage, status):
        with suppress(Rejected):
            self.emit(stage, status)

    async def intended(self, status):
        if status != 200:
            self.context = None
            self.observe("response_intended", status)
            return
        sequence = self.emit("response_intended", status)
        while True:
            remaining = self.remaining()
            if self.journal.confirmed(self.ticket, sequence):
                self.remaining()
                return
            await asyncio.sleep(min(0.01, remaining))

    def finish(self):
        try:
            if not self.completed:
                self.observe("aborted", self.status)
        finally:
            if self.ticket is not None:
                self.journal.release(self.ticket)
            self.http_done = True
            self.release_resources()

    def release_resources(self):
        if self.http_done and not self.worker_pending and self.release_callback is not None:
            callback, self.release_callback = self.release_callback, None
            callback()


class Middleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        replacement = None
        start_attempted = False

        async def observed_send(message):
            nonlocal replacement, start_attempted
            delivery = scope.get(SCOPE_KEY)
            if delivery is None:
                await send(message)
                return
            if message["type"] == "http.response.start":
                if start_attempted or message.get("trailers", False):
                    raise Rejected("audit_http_message_invalid")
                start_attempted = True
                try:
                    await delivery.intended(message["status"])
                except Exception:
                    delivery.context = None
                    replacement = delivery.denial()
                    message = {
                        "type": "http.response.start",
                        "status": replacement.status_code,
                        "headers": replacement.raw_headers,
                    }
                await send(message)
                delivery.status = message["status"]
                delivery.observe("response_started", delivery.status)
            elif message["type"] == "http.response.body":
                if delivery.status is None:
                    raise Rejected("audit_http_message_invalid")
                if delivery.completed:
                    return
                if replacement is not None:
                    message = {
                        "type": "http.response.body",
                        "body": replacement.body,
                        "more_body": False,
                    }
                await send(message)
                if not message.get("more_body", False):
                    delivery.completed = True
                    delivery.observe("response_completed", delivery.status)
            else:
                raise Rejected("audit_http_message_invalid")

        try:
            await self.app(scope, receive, observed_send)
        finally:
            delivery = scope.get(SCOPE_KEY)
            if delivery is not None:
                delivery.finish()
