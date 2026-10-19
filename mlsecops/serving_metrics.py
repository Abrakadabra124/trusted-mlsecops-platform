import asyncio
import math
import re
import threading
import time
from contextlib import suppress

from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.core import CounterMetricFamily, HistogramMetricFamily
from starlette.responses import Response

from mlsecops import serving_access
from mlsecops.contracts import Rejected

ROUTES = ("predict", "ready", "live", "other")
OUTCOMES = ("2xx", "3xx", "4xx", "5xx", "aborted")
BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1.0, 5.0, 10.0, math.inf)
MAX_COUNT = 2**53 - 1
MAX_BYTES = 16384
SCRAPE_TIMEOUT = 2


class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self._responses = {(route, outcome): 0 for route in ROUTES for outcome in OUTCOMES}
        self._buckets = {route: [0] * len(BUCKETS) for route in ROUTES}
        self._sums = dict.fromkeys(ROUTES, 0.0)
        self._errors = 0
        self._registry = CollectorRegistry()
        self._registry.register(self)

    def describe(self):
        return [
            CounterMetricFamily(
                "mlsecops_http_responses",
                "Observed ASGI response outcomes",
                labels=["route", "outcome"],
            ),
            HistogramMetricFamily(
                "mlsecops_http_duration_seconds",
                "Time to final ASGI send or abort",
                labels=["route"],
            ),
            CounterMetricFamily(
                "mlsecops_http_metrics_errors", "Discarded metric observations or failed scrapes"
            ),
        ]

    def observe(self, route, outcome, duration):
        if (
            type(route) is not str
            or route not in ROUTES
            or type(outcome) is not str
            or outcome not in OUTCOMES
            or type(duration) not in (int, float)
            or not math.isfinite(duration)
            or duration < 0
        ):
            raise Rejected("metrics_observation_invalid")
        with self._lock:
            total = self._sums[route] + duration
            if self._buckets[route][-1] >= MAX_COUNT or not math.isfinite(total):
                raise Rejected("metrics_capacity_exhausted")
            self._responses[route, outcome] += 1
            self._sums[route] = total
            for index, boundary in enumerate(BUCKETS):
                if duration <= boundary:
                    self._buckets[route][index] += 1

    def failed(self):
        with self._lock:
            self._errors = min(MAX_COUNT, self._errors + 1)

    def collect(self):
        with self._lock:
            responses, sums = dict(self._responses), dict(self._sums)
            buckets = {route: list(values) for route, values in self._buckets.items()}
            errors = self._errors
        counters, durations, failures = self.describe()
        for route in ROUTES:
            for outcome in OUTCOMES:
                counters.add_metric([route, outcome], responses[route, outcome])
            durations.add_metric(
                [route],
                [
                    ("+Inf" if math.isinf(boundary) else str(boundary), count)
                    for boundary, count in zip(BUCKETS, buckets[route], strict=True)
                ],
                sums[route],
            )
        failures.add_metric([], errors)
        return [counters, durations, failures]

    def render(self):
        content = generate_latest(self._registry)
        if len(content) > MAX_BYTES:
            raise Rejected("metrics_output_limit")
        return content


def operator_access(token, clients):
    if (
        type(token) is not str
        or re.fullmatch("[a-f0-9]{64}", token) is None
        or clients.authenticate(["Bearer " + token]) is not None
    ):
        raise Rejected("metrics_credential_invalid")
    return serving_access.Access(
        {
            "schema_version": 1,
            "clients": [
                {
                    "principal_id": "0" * 32,
                    "token": token,
                    "requests_per_second": 4,
                    "burst": 8,
                    "max_in_flight": 2,
                }
            ],
        }
    )


class ScrapeResponse(Response):
    def __init__(self, response, ticket=None):
        super().__init__(
            response.body, status_code=response.status_code, headers=dict(response.headers)
        )
        self.ticket = ticket

    async def __call__(self, scope, receive, send):
        try:
            async with asyncio.timeout(SCRAPE_TIMEOUT):
                await super().__call__(scope, receive, send)
        finally:
            if self.ticket is not None:
                self.ticket.release()


class Middleware:
    def __init__(self, app, metrics, *, clock=time.monotonic):
        self.app, self.metrics, self.clock = app, metrics, clock

    def __getattr__(self, name):
        return getattr(self.app, name)

    def sample(self):
        try:
            return self.clock()
        except Exception:
            return math.nan

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or (scope.get("method"), scope.get("path")) == (
            "GET",
            "/metrics",
        ):
            await self.app(scope, receive, send)
            return
        route = {
            ("POST", "/v1/predict"): "predict",
            ("GET", "/readyz"): "ready",
            ("GET", "/livez"): "live",
        }.get((scope.get("method"), scope.get("path")), "other")
        started, completed, status = self.sample(), False, None
        disconnected = False

        def record(outcome):
            try:
                self.metrics.observe(route, outcome, self.sample() - started)
            except Exception:
                with suppress(Exception):
                    self.metrics.failed()

        async def observed_send(message):
            nonlocal completed, status
            await send(message)
            if message["type"] == "http.response.start" and status is None:
                candidate = message.get("status")
                if type(candidate) is int and 200 <= candidate <= 599:
                    status = candidate
            elif (
                message["type"] == "http.response.body"
                and not message.get("more_body", False)
                and status is not None
                and not completed
                and not disconnected
            ):
                completed = True
                record(f"{status // 100}xx")

        async def observed_receive():
            nonlocal disconnected
            message = await receive()
            if message["type"] == "http.disconnect":
                disconnected = True
            return message

        try:
            await self.app(scope, observed_receive, observed_send)
        finally:
            if not completed:
                record("aborted")
