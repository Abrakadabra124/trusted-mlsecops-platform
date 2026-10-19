import asyncio
import math
import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from prometheus_client import REGISTRY, Gauge
from prometheus_client.parser import text_string_to_metric_families

from mlsecops import serving_http, serving_metrics
from mlsecops.contracts import Rejected
from scripts.serving_privacy_qualification import invoke


def samples(metrics):
    return [
        sample
        for family in text_string_to_metric_families(metrics.render().decode())
        for sample in family.samples
    ]


def value(metrics, name, **labels):
    return next(
        sample.value
        for sample in samples(metrics)
        if sample.name == name and sample.labels == labels
    )


class MetricsContracts(unittest.TestCase):
    def test_zero_series_are_fixed_and_registry_is_private(self):
        foreign = Gauge("synthetic_private_metric", "canary", ["private_identity"])
        try:
            foreign.labels("synthetic_privacy_marker").set(1)
            metrics = serving_metrics.Metrics()
            output = metrics.render()
            self.assertEqual(len(samples(metrics)), 69)
            expected = {
                ("mlsecops_http_responses_total", (("outcome", outcome), ("route", route)))
                for route in ("predict", "ready", "live", "other")
                for outcome in ("2xx", "3xx", "4xx", "5xx", "aborted")
            }
            for route in ("predict", "ready", "live", "other"):
                expected.update(
                    ("mlsecops_http_duration_seconds_bucket", (("le", boundary), ("route", route)))
                    for boundary in (
                        "0.01",
                        "0.025",
                        "0.05",
                        "0.1",
                        "0.2",
                        "0.5",
                        "1.0",
                        "5.0",
                        "10.0",
                        "+Inf",
                    )
                )
                expected.update(
                    ("mlsecops_http_duration_seconds_" + suffix, (("route", route),))
                    for suffix in ("sum", "count")
                )
            expected.add(("mlsecops_http_metrics_errors_total", ()))
            self.assertEqual(
                {
                    (sample.name, tuple(sorted(sample.labels.items())))
                    for sample in samples(metrics)
                },
                expected,
            )
            self.assertTrue(all(sample.value == 0 for sample in samples(metrics)))
            self.assertNotIn(b"synthetic_privacy_marker", output)
            self.assertNotIn(b"python_", output)
            self.assertNotIn(b"process_", output)
            self.assertNotIn(b"_created", output)
            self.assertLessEqual(len(output), 16384)
        finally:
            REGISTRY.unregister(foreign)

    def test_counts_histograms_and_app_instances_are_independent(self):
        metrics, other = serving_metrics.Metrics(), serving_metrics.Metrics()
        metrics.observe("predict", "2xx", 0.2)
        metrics.observe("predict", "aborted", 20)
        self.assertEqual(
            value(metrics, "mlsecops_http_responses_total", route="predict", outcome="2xx"), 1
        )
        self.assertEqual(
            value(metrics, "mlsecops_http_duration_seconds_bucket", route="predict", le="0.2"), 1
        )
        self.assertEqual(
            value(metrics, "mlsecops_http_duration_seconds_bucket", route="predict", le="+Inf"), 2
        )
        self.assertEqual(
            value(metrics, "mlsecops_http_duration_seconds_sum", route="predict"), 20.2
        )
        self.assertEqual(value(metrics, "mlsecops_http_duration_seconds_count", route="predict"), 2)
        self.assertTrue(all(sample.value == 0 for sample in samples(other)))

    def test_invalid_measurements_do_not_change_series_or_values(self):
        metrics = serving_metrics.Metrics()
        original = metrics.render()
        for route, outcome, duration in (
            ("/private/path", "2xx", 1),
            ([], "2xx", 1),
            ("predict", "secret", 1),
            ("predict", [], 1),
            ("predict", "2xx", True),
            ("predict", "2xx", -1),
            ("predict", "2xx", math.nan),
            ("predict", "2xx", math.inf),
            ("predict", "2xx", "private"),
        ):
            with self.subTest(route=route, outcome=outcome, duration=duration):
                with self.assertRaisesRegex(Rejected, "metrics_observation_invalid"):
                    metrics.observe(route, outcome, duration)
                self.assertEqual(metrics.render(), original)

    def test_environment_does_not_create_multiprocess_files(self):
        for variable in ("PROMETHEUS_MULTIPROC_DIR", "prometheus_multiproc_dir"):
            for control in (True, False):
                with self.subTest(variable=variable, control=control):
                    with tempfile.TemporaryDirectory() as temporary:
                        environment = dict(os.environ)
                        for name in ("PROMETHEUS_MULTIPROC_DIR", "prometheus_multiproc_dir"):
                            environment.pop(name, None)
                        environment[variable] = temporary
                        source = (
                            "from prometheus_client import Counter; Counter('control', 'control').inc()"
                            if control
                            else "from mlsecops.serving_metrics import Metrics; "
                            "metrics = Metrics(); metrics.observe('live', '2xx', .01); metrics.render()"
                        )
                        result = subprocess.run(
                            [sys.executable, "-c", source],
                            env=environment,
                            capture_output=True,
                            timeout=15,
                            check=False,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr.decode())
                        self.assertEqual(bool(list(Path(temporary).iterdir())), control)

    def test_parallel_updates_are_counted_once(self):
        metrics = serving_metrics.Metrics()
        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(lambda _: metrics.observe("other", "4xx", 0.25), range(1000)))
        self.assertEqual(
            value(metrics, "mlsecops_http_responses_total", route="other", outcome="4xx"), 1000
        )
        self.assertEqual(
            value(metrics, "mlsecops_http_duration_seconds_count", route="other"), 1000
        )
        self.assertEqual(len(samples(metrics)), 69)

    def test_capacity_and_output_limits_fail_without_partial_updates(self):
        metrics = serving_metrics.Metrics()
        metrics.observe("live", "2xx", 1)
        original = metrics.render()
        with patch.object(serving_metrics, "MAX_COUNT", 1):
            with self.assertRaisesRegex(Rejected, "metrics_capacity_exhausted"):
                metrics.observe("live", "2xx", 1)
            self.assertEqual(metrics.render(), original)
            metrics.failed()
            metrics.failed()
            self.assertEqual(value(metrics, "mlsecops_http_metrics_errors_total"), 1)
        metrics = serving_metrics.Metrics()
        metrics.observe("live", "2xx", sys.float_info.max)
        original = metrics.render()
        with self.assertRaisesRegex(Rejected, "metrics_capacity_exhausted"):
            metrics.observe("live", "2xx", sys.float_info.max)
        self.assertEqual(metrics.render(), original)
        with patch.object(serving_metrics, "generate_latest", return_value=b" " * 16385):
            with self.assertRaisesRegex(Rejected, "metrics_output_limit"):
                metrics.render()


class MetricsMiddlewareContracts(unittest.IsolatedAsyncioTestCase):
    async def test_observed_disconnect_before_send_is_aborted(self):
        for early in (True, False):
            metrics = serving_metrics.Metrics()

            async def app(scope, receive, send):
                if early:
                    await receive()
                await send({"type": "http.response.start", "status": 503})
                await send({"type": "http.response.body"})
                if not early:
                    await receive()

            receive = AsyncMock(return_value={"type": "http.disconnect"})
            await serving_metrics.Middleware(app, metrics)(
                {"type": "http", "method": "POST", "path": "/v1/predict"}, receive, AsyncMock()
            )
            receive.assert_awaited_once()
            self.assertEqual(
                value(metrics, "mlsecops_http_responses_total", route="predict", outcome="aborted"),
                int(early),
            )
            self.assertEqual(
                value(metrics, "mlsecops_http_responses_total", route="predict", outcome="5xx"),
                int(not early),
            )

    async def exercise(self, messages, *, failure=None, send_failure=False, clock=None):
        metrics = serving_metrics.Metrics()

        async def app(scope, receive, send):
            for message in messages:
                await send(message)
            if failure is not None:
                raise failure

        async def send(message):
            if send_failure and message["type"] == "http.response.body":
                raise OSError("private_transport_detail")

        middleware = serving_metrics.Middleware(
            app, metrics, clock=clock or Mock(side_effect=[10, 10.2])
        )
        caught = None
        try:
            await middleware(
                {"type": "http", "method": "POST", "path": "/v1/predict"}, Mock(), send
            )
        except (OSError, asyncio.CancelledError) as error:
            caught = type(error)
        self.assertIs(
            caught, type(failure) if failure is not None else OSError if send_failure else None
        )
        return metrics

    async def test_completed_response_visible_before_app_finishes(self):
        metrics = serving_metrics.Metrics()
        sent, resume = asyncio.Event(), asyncio.Event()

        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200})
            await send({"type": "http.response.body"})
            sent.set()
            await resume.wait()

        async def send(message):
            pass

        middleware = serving_metrics.Middleware(app, metrics, clock=Mock(side_effect=[10, 10.2]))
        task = asyncio.create_task(
            middleware({"type": "http", "method": "GET", "path": "/livez"}, Mock(), send)
        )
        try:
            await asyncio.wait_for(sent.wait(), 1)
            self.assertEqual(
                value(metrics, "mlsecops_http_responses_total", route="live", outcome="2xx"), 1
            )
        finally:
            resume.set()
            await task
        self.assertAlmostEqual(
            value(metrics, "mlsecops_http_duration_seconds_sum", route="live"), 0.2
        )

    async def test_final_body_status_and_duration(self):
        for status, outcome in ((200, "2xx"), (307, "3xx"), (429, "4xx"), (503, "5xx")):
            metrics = await self.exercise(
                [
                    {"type": "http.response.start", "status": status},
                    {"type": "http.response.body", "body": b"private", "more_body": False},
                ]
            )
            self.assertEqual(
                value(metrics, "mlsecops_http_responses_total", route="predict", outcome=outcome), 1
            )
            self.assertAlmostEqual(
                value(metrics, "mlsecops_http_duration_seconds_sum", route="predict"), 0.2
            )
            self.assertNotIn(b"private", metrics.render())

    async def test_aborted_send_cancel_and_incomplete_body(self):
        for failure, send_failure, messages in (
            (OSError("private"), False, []),
            (asyncio.CancelledError(), False, []),
            (
                None,
                True,
                [{"type": "http.response.start", "status": 200}, {"type": "http.response.body"}],
            ),
            (
                None,
                False,
                [
                    {"type": "http.response.start", "status": 200},
                    {"type": "http.response.body", "more_body": True},
                ],
            ),
            (None, False, [{"type": "http.response.body"}]),
            (
                None,
                False,
                [{"type": "http.response.start", "status": True}, {"type": "http.response.body"}],
            ),
            (
                None,
                False,
                [{"type": "http.response.start", "status": 600}, {"type": "http.response.body"}],
            ),
        ):
            metrics = await self.exercise(messages, failure=failure, send_failure=send_failure)
            self.assertEqual(
                value(metrics, "mlsecops_http_responses_total", route="predict", outcome="aborted"),
                1,
            )

    async def test_exception_after_completed_send_is_not_fake_abort(self):
        metrics = await self.exercise(
            [
                {"type": "http.response.start", "status": 200},
                {"type": "http.response.body"},
            ],
            failure=OSError("private"),
        )
        self.assertEqual(
            value(metrics, "mlsecops_http_responses_total", route="predict", outcome="2xx"), 1
        )
        self.assertEqual(
            value(metrics, "mlsecops_http_responses_total", route="predict", outcome="aborted"), 0
        )

    async def test_clock_failure_does_not_break_http(self):
        metrics = await self.exercise(
            [
                {"type": "http.response.start", "status": 200},
                {"type": "http.response.body"},
            ],
            clock=Mock(side_effect=OSError("private_clock")),
        )
        self.assertEqual(value(metrics, "mlsecops_http_metrics_errors_total"), 1)


class MetricsEndpointContracts(unittest.IsolatedAsyncioTestCase):
    async def test_scrape_input_failure_and_render_failure_are_bounded(self):
        engine = Mock()
        app = serving_http.create_app(engine, "a" * 64, metrics_token="b" * 64)
        authorization = [(b"authorization", b"Bearer " + b"b" * 64)]
        for query, headers in (
            (b"private=value", []),
            (b"", [(b"content-length", b"1")]),
            (b"", [(b"content-length", b"0")] * 2),
            (b"", [(b"transfer-encoding", b"chunked")]),
        ):
            self.assertEqual(
                (await invoke(app, path="/metrics", query=query, headers=authorization + headers))[
                    0
                ],
                400,
            )
        with patch.object(app.state.metrics, "render", side_effect=RuntimeError("private_failure")):
            status, content = await invoke(app, path="/metrics", headers=authorization)
            self.assertEqual(status, 503)
            self.assertNotIn(b"private_failure", content)
        self.assertEqual(value(app.state.metrics, "mlsecops_http_metrics_errors_total"), 1)
        self.assertEqual((await invoke(app, path="/metrics", headers=authorization))[0], 200)
        engine.response_budget.assert_not_called()

    async def test_admission_failure_is_503_and_response_construction_releases_ticket(self):
        operator = serving_metrics.operator_access(
            "b" * 64, serving_http.serving_access.Access.single("a" * 64)
        )
        with patch.object(serving_metrics, "operator_access", return_value=operator):
            app = serving_http.create_app(Mock(), "a" * 64, metrics_token="b" * 64)
        headers = [(b"authorization", b"Bearer " + b"b" * 64)]
        with patch.object(operator, "acquire", side_effect=Rejected("private_admission")):
            self.assertEqual((await invoke(app, path="/metrics", headers=headers))[0], 503)
        with patch.object(
            serving_metrics, "ScrapeResponse", side_effect=RuntimeError("construction")
        ):
            with self.assertRaisesRegex(RuntimeError, "construction"):
                await invoke(app, path="/metrics", headers=headers)
        tickets = [operator.acquire("0" * 32), operator.acquire("0" * 32)]
        for ticket in tickets:
            ticket.release()

    async def test_unauthorized_and_limited_scrapes_have_send_deadline(self):
        for authorized in (False, True):
            app = serving_http.create_app(Mock(), "a" * 64, metrics_token="b" * 64)
            headers = [(b"authorization", b"Bearer " + b"b" * 64)] if authorized else []
            if authorized:
                for _ in range(8):
                    self.assertEqual((await invoke(app, path="/metrics", headers=headers))[0], 200)
            observed = []

            async def block(message):
                if message["type"] == "http.response.start":
                    observed.append(message["status"])
                if message["type"] == "http.response.body":
                    await asyncio.Event().wait()

            with patch.object(serving_metrics, "SCRAPE_TIMEOUT", 0.02):
                task = asyncio.create_task(
                    invoke(app, path="/metrics", headers=headers, send_hook=block)
                )
                done, pending = await asyncio.wait([task], timeout=0.15)
                try:
                    self.assertFalse(pending, "scrape rejection bypasses send deadline")
                    self.assertIsInstance(task.exception(), TimeoutError)
                    self.assertEqual(observed, [429 if authorized else 401])
                finally:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)

    async def test_outer_server_error_response_is_counted_as_5xx(self):
        app = serving_http.create_app(Mock(), "a" * 64, metrics_token="b" * 64)

        @app.get("/synthetic-failure")
        async def failure():
            raise RuntimeError("private_failure")

        with self.assertRaises(RuntimeError):
            await invoke(app, path="/synthetic-failure")
        self.assertEqual(
            value(app.state.metrics, "mlsecops_http_responses_total", route="other", outcome="5xx"),
            1,
        )
        self.assertEqual(
            value(
                app.state.metrics, "mlsecops_http_responses_total", route="other", outcome="aborted"
            ),
            0,
        )

    async def test_operator_slots_live_until_send_cancel_or_deadline(self):
        for cancel in (True, False):
            app = serving_http.create_app(Mock(), "a" * 64, metrics_token="b" * 64)
            headers = [(b"authorization", b"Bearer " + b"b" * 64)]
            entered = [asyncio.Event(), asyncio.Event()]

            async def block(message, index):
                if message["type"] == "http.response.body":
                    entered[index].set()
                    await asyncio.Event().wait()

            with patch.object(serving_metrics, "SCRAPE_TIMEOUT", 0.1):
                tasks = [
                    asyncio.create_task(
                        invoke(
                            app,
                            path="/metrics",
                            headers=headers,
                            send_hook=lambda message, index=index: block(message, index),
                        )
                    )
                    for index in range(2)
                ]
                try:
                    await asyncio.wait_for(asyncio.gather(*(event.wait() for event in entered)), 1)
                    self.assertEqual((await invoke(app, path="/metrics", headers=headers))[0], 429)
                    if cancel:
                        for task in tasks:
                            task.cancel()
                    results = await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True), 1
                    )
                    self.assertTrue(
                        all(
                            isinstance(result, asyncio.CancelledError if cancel else TimeoutError)
                            for result in results
                        )
                    )
                    self.assertEqual((await invoke(app, path="/metrics", headers=headers))[0], 200)
                finally:
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)

    async def test_metrics_are_opt_in_and_operator_only(self):
        disabled = serving_http.create_app(Mock(), "a" * 64)
        self.assertEqual((await invoke(disabled, path="/metrics"))[0], 404)
        engine = Mock()
        app = serving_http.create_app(engine, "a" * 64, metrics_token="b" * 64)
        for headers in (
            [],
            [(b"authorization", b"Bearer " + b"a" * 64)],
            [(b"authorization", b"Bearer " + b"b" * 64)] * 2,
        ):
            self.assertEqual((await invoke(app, path="/metrics", headers=headers))[0], 401)
        status, output = await invoke(
            app, path="/metrics", headers=[(b"authorization", b"Bearer " + b"b" * 64)]
        )
        self.assertEqual(status, 200)
        self.assertIn(b"mlsecops_http_responses_total", output)
        self.assertNotIn(b"b" * 64, output)
        engine.response_budget.assert_not_called()
        self.assertEqual(
            (
                await invoke(
                    app, path="/readyz", headers=[(b"authorization", b"Bearer " + b"b" * 64)]
                )
            )[0],
            401,
        )

    async def test_operator_token_cannot_equal_data_token(self):
        for token in ("a" * 64, True, "", "g" * 64, "b" * 63):
            with self.assertRaisesRegex(Rejected, "metrics_credential_invalid"):
                serving_http.create_app(Mock(), "a" * 64, metrics_token=token)

    async def test_many_private_urls_keep_same_metric_series(self):
        app = serving_http.create_app(Mock(), "a" * 64, metrics_token="b" * 64)
        before = {
            (sample.name, tuple(sorted(sample.labels.items())))
            for sample in samples(app.state.metrics)
        }
        for index in range(200):
            await invoke(
                app,
                path=f"/private-{index}",
                query=f"secret={index}".encode(),
                headers=[(b"x-user", str(index).encode())],
            )
        after = {
            (sample.name, tuple(sorted(sample.labels.items())))
            for sample in samples(app.state.metrics)
        }
        self.assertEqual(before, after)
        self.assertEqual(len(after), 69)
        self.assertEqual(
            value(app.state.metrics, "mlsecops_http_responses_total", route="other", outcome="4xx"),
            200,
        )
        self.assertNotIn(b"private-", app.state.metrics.render())


if __name__ == "__main__":
    unittest.main()
