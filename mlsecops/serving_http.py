import argparse
import asyncio
import os
import re
import secrets
import sys
import time
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from mlsecops import (
    advisory,
    release_reader,
    serving,
    serving_access,
    serving_context,
    trust,
    trust_authority,
)
from mlsecops.contracts import Rejected, bounded_read, decode, require_fields
from mlsecops.datasets import FEATURES

MAX_BODY = 65536


class BodyLimit(Rejected):
    pass


async def read_body(request):
    lengths = request.headers.getlist("content-length")
    if len(lengths) > 1 or lengths and re.fullmatch(r"[0-9]{1,9}", lengths[0]) is None:
        raise Rejected("http_length_invalid")
    expected = int(lengths[0]) if lengths else None
    if expected is not None and expected > MAX_BODY:
        raise BodyLimit("http_body_limit")
    if (
        request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json"
        or request.headers.get("content-encoding", "identity") != "identity"
        or request.url.query
    ):
        raise Rejected("http_content_type")
    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > MAX_BODY:
            raise BodyLimit("http_body_limit")
        content.extend(chunk)
    if expected is not None and expected != len(content):
        raise Rejected("http_length_mismatch")
    payload = decode(bytes(content), MAX_BODY)
    require_fields(payload, ("schema_version", "instances"))
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise Rejected("http_schema_version")
    instances = payload["instances"]
    if not isinstance(instances, list) or not 1 <= len(instances) <= 100:
        raise Rejected("http_batch_limit")
    features = []
    for instance in instances:
        require_fields(instance, FEATURES)
        features.append([instance[name] for name in FEATURES])
    advisory.validate(features)
    return features


def create_app(engine, token=None, *, clients=None):
    if clients is None:
        clients = serving_access.Access.single(token)
    elif token is not None or not isinstance(clients, serving_access.Access):
        raise Rejected("http_clients_conflict")

    @asynccontextmanager
    async def lifespan(app):
        try:
            try:
                await asyncio.to_thread(engine.activate)
            except Rejected:
                pass
            yield
        finally:
            await asyncio.to_thread(engine.close)

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.slots = asyncio.Semaphore(8)
    app.state.pending = set()

    def remaining(budget):
        try:
            original = budget.remaining()
            current = engine.response_budget()
            if current.generation is not budget.generation:
                raise Rejected("serving_generation_changed")
            return min(original, current.remaining())
        except Rejected:
            engine.expire(budget.generation)
            raise

    async def await_result(task, budget, body_deadline=None):
        while True:
            timeout = remaining(budget)
            if body_deadline is not None:
                body_remaining = body_deadline - time.monotonic()
                if body_remaining <= 0:
                    raise TimeoutError("http_body_deadline")
                timeout = min(timeout, body_remaining)
            completed, _ = await asyncio.wait((task,), timeout=min(0.05, timeout))
            if completed:
                remaining(budget)
                return task.result()

    async def execute(operation, deferred, budget, ticket, *arguments):
        remaining(budget)
        task = asyncio.create_task(
            asyncio.to_thread(operation, *arguments, generation=budget.generation)
        )
        app.state.pending.add(task)
        deferred[0] = True

        def finished(future):
            app.state.pending.discard(future)
            with suppress(Exception, asyncio.CancelledError):
                future.result()
            if budget.generation.is_set():
                with suppress(Exception):
                    engine.expire(budget.generation)
            app.state.slots.release()
            ticket.release()

        task.add_done_callback(finished)
        return await await_result(task, budget)

    def error(status, code, request_id):
        return JSONResponse(
            {"schema_version": 1, "request_id": request_id, "error": {"code": code}},
            status_code=status,
            headers={"Cache-Control": "no-store"},
        )

    class VerifiedResponse(JSONResponse):
        def __init__(self, result, budget, code, request_id):
            if (
                type(result) is not serving.ServingResult
                or result.generation is not budget.generation
            ):
                raise Rejected("http_result_binding")
            self.audit_context = serving_context.bind(
                result.audit_context,
                bundle_sha256=result.payload["bundle_sha256"],
                model_sha256=result.payload["model_sha256"],
            )
            self.budget, self.code, self.request_id = budget, code, request_id
            super().__init__(
                {**result.payload, "request_id": request_id}, headers={"Cache-Control": "no-store"}
            )

        async def __call__(self, scope, receive, send):
            try:
                remaining(self.budget)
            except Exception:
                self.audit_context = None
                await error(503, self.code, self.request_id)(scope, receive, send)
                return
            await super().__call__(scope, receive, send)

    @app.get("/livez")
    async def live():
        return {"status": "alive"}

    @app.get("/readyz")
    async def ready(request: Request):
        request_id = secrets.token_hex(16)
        principal = clients.authenticate(request.headers.getlist("authorization"))
        if principal is None:
            return error(401, "unauthorized", request_id)
        try:
            budget = engine.response_budget()
            remaining(budget)
        except Exception:
            return error(503, "not_ready", request_id)
        try:
            ticket = clients.acquire(principal)
        except serving_access.Limited:
            return error(429, "client_limited", request_id)
        except Rejected:
            return error(503, "not_ready", request_id)
        deferred = [False]
        acquired = False
        try:
            if app.state.slots.locked():
                return error(503, "not_ready", request_id)
            await app.state.slots.acquire()
            acquired = True
            result = await execute(engine.check_result, deferred, budget, ticket)
            if result.payload.get("ready") is not True:
                raise Rejected("http_not_ready")
            return VerifiedResponse(result, budget, "not_ready", request_id)
        except Exception:
            return error(503, "not_ready", request_id)
        finally:
            if not deferred[0]:
                ticket.release()
                if acquired:
                    app.state.slots.release()

    @app.post("/v1/predict")
    async def predict(request: Request):
        request_id = secrets.token_hex(16)
        principal = clients.authenticate(request.headers.getlist("authorization"))
        if principal is None:
            return error(401, "unauthorized", request_id)
        try:
            budget = engine.response_budget()
            remaining(budget)
        except Exception:
            return error(503, "model_unavailable", request_id)
        try:
            ticket = clients.acquire(principal)
        except serving_access.Limited:
            return error(429, "client_limited", request_id)
        except Rejected:
            return error(503, "model_unavailable", request_id)
        deferred = [False]
        acquired = False
        try:
            if app.state.slots.locked():
                return error(429, "overloaded", request_id)
            await app.state.slots.acquire()
            acquired = True
            try:
                remaining(budget)
                body_task = asyncio.create_task(read_body(request))
                try:
                    features = await await_result(body_task, budget, time.monotonic() + 5)
                finally:
                    if not body_task.done():
                        body_task.cancel()
                    with suppress(Exception, asyncio.CancelledError):
                        await body_task
            except BodyLimit:
                remaining(budget)
                return error(413, "body_too_large", request_id)
            except TimeoutError:
                remaining(budget)
                return error(422, "invalid_request", request_id)
            except Rejected:
                remaining(budget)
                return error(422, "invalid_request", request_id)
            result = await execute(engine.predict_result, deferred, budget, ticket, features)
            return VerifiedResponse(result, budget, "model_unavailable", request_id)
        except Rejected as failure:
            if str(failure) == "serving_busy":
                return error(429, "overloaded", request_id)
            return error(503, "model_unavailable", request_id)
        except Exception:
            return error(503, "model_unavailable", request_id)
        finally:
            if not deferred[0]:
                ticket.release()
                if acquired:
                    app.state.slots.release()

    return app


def configured(path):
    config = decode(bounded_read(path, 1024 * 1024))
    credential_field = "principals_file" if "principals_file" in config else "token_file"
    require_fields(
        config,
        (
            "storage_client",
            "trust_client",
            "context",
            "trusted_root",
            "expected_policy",
            "expected_serving_image",
            "minimum_sequence",
            "trust_root",
            "minimum_trust_version",
            credential_field,
        ),
    )
    secret = Path(config[credential_field])
    if not secret.is_absolute() or os.name == "posix" and secret.stat().st_mode & 0o077:
        raise Rejected("http_token_permissions")
    clients = (
        serving_access.Access(decode(bounded_read(secret, MAX_BODY), MAX_BODY))
        if credential_field == "principals_file"
        else serving_access.Access.single(bounded_read(secret, 65).decode("ascii").strip())
    )
    lease = trust.Lease(
        lambda: trust_authority.read(
            config["trust_client"], config["context"]["policy"]["environment"], config["trust_root"]
        ),
        trusted_root=config["trust_root"],
        environment=config["context"]["policy"]["environment"],
        minimum_version=config["minimum_trust_version"],
    )
    reader = release_reader.Reader(
        config["storage_client"],
        **{
            key: config[key]
            for key in (
                "context",
                "trusted_root",
                "expected_policy",
                "expected_serving_image",
                "minimum_sequence",
            )
        },
        trust_lease=lease,
    )
    return create_app(serving.Engine(reader), clients=clients)


def main():
    parser = argparse.ArgumentParser(description="Loopback-only verified Release Risk Advisor")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8080)
    options = parser.parse_args()
    try:
        if not 1024 <= options.port <= 65535:
            raise Rejected("http_port_invalid")
        app = configured(options.config)
    except (Rejected, OSError, KeyError, TypeError, ValueError):
        print("serving_configuration_rejected", file=sys.stderr)
        return 1
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=options.port,
        access_log=False,
        proxy_headers=False,
        server_header=False,
        timeout_keep_alive=5,
        limit_concurrency=16,
        log_level="warning",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
