"""Static operator UI must not expose credentials or change the API boundary."""

import json
import re
import shutil
import subprocess
import unittest
from unittest.mock import Mock

from starlette.requests import Request

from mlsecops import monitoring
from mlsecops import monitoring_dashboard as dashboard
from mlsecops.contracts import Rejected, canonical, digest
from scripts import monitoring_dashboard_probe as probe
from scripts import monitoring_http_qualification as fixtures
from scripts import monitoring_labels_qualification as label_fixtures
from scripts import monitoring_privacy_qualification as privacy_fixtures
from scripts import monitoring_stream_qualification as stream_fixtures
from scripts.audit_http_observation import Ledger
from scripts.monitoring_dashboard_harness import SCRIPT as HARNESS
from scripts.monitoring_qualification import reference


class DashboardAssetsContracts(unittest.IsolatedAsyncioTestCase):
    async def test_public_shell_is_constant_bounded_and_has_no_credentials(self):
        for path, media in dashboard.MEDIA.items():
            scope = {
                "type": "http",
                "method": "GET",
                "path": path,
                "query_string": b"",
                "headers": [],
            }
            response = await dashboard.asset(Request(scope))
            self.assertEqual(response.status_code, 200)
            self.assertIn(media, response.headers["content-type"])
            self.assertLess(len(response.body), 65536)
            self.assertEqual(response.headers["cache-control"], "no-store")
            self.assertEqual(response.headers["x-content-type-options"], "nosniff")
            self.assertIn("default-src 'none'", response.headers["content-security-policy"])
            self.assertIn("form-action 'none'", response.headers["content-security-policy"])
            self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
            for headers, query in (
                ([(b"authorization", b"Bearer PRIVATE-CANARY")], b""),
                ([(b"x-private", b"PRIVATE-CANARY")], b""),
            ):
                altered = await dashboard.asset(
                    Request({**scope, "headers": headers, "query_string": query})
                )
                self.assertEqual(response.body, altered.body)

    async def test_queries_bodies_and_unknown_assets_never_reflect_input(self):
        for path, query, headers in (
            ("/monitoring/ui", b"PRIVATE-CANARY", []),
            ("/monitoring/ui", b"", [(b"content-length", b"1")]),
            ("/monitoring/ui", b"", [(b"transfer-encoding", b"chunked")]),
            ("/PRIVATE-CANARY", b"", []),
        ):
            receive = Mock(side_effect=AssertionError("body must not be read"))
            result = await dashboard.asset(
                Request(
                    {
                        "type": "http",
                        "method": "GET",
                        "path": path,
                        "query_string": query,
                        "headers": headers,
                    },
                    receive,
                )
            )
            self.assertIn(result.status_code, (400, 404))
            self.assertNotIn(b"PRIVATE-CANARY", result.body)
            receive.assert_not_called()


class DashboardIngressContracts(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = fixtures.MonitoringHttpContracts.asyncSetUp
    cleanup = fixtures.MonitoringHttpContracts.cleanup
    invoke = fixtures.MonitoringHttpContracts.invoke

    async def test_ui_is_not_installed_when_monitoring_is_disabled(self):
        self.app = fixtures.serving_http.create_app(self.engine, self.token, audit=self.journal)
        for path in dashboard.ASSETS:
            self.assertEqual((await self.invoke(path=path, method="GET", headers=[]))[0], 404)

    async def test_shell_does_not_allow_unauthenticated_status_or_write(self):
        status, _, _ = await self.invoke(path="/monitoring", method="GET", headers=[])
        self.assertEqual(status, 401)
        status, _, _ = await self.invoke(
            path="/monitoring",
            method="GET",
            headers=[(b"authorization", ("Bearer " + self.token).encode())],
        )
        self.assertEqual(status, 401)
        status, _, _ = await self.invoke(path="/monitoring/ui", method="POST", headers=[])
        self.assertEqual(status, 405)

    async def test_real_asgi_shell_assets_are_public_without_observing_or_predicting(self):
        for path, content in dashboard.ASSETS.items():
            messages = []

            async def receive():
                self.fail("static asset must not consume a request body")

            async def send(message):
                messages.append(message)

            await self.app(
                {
                    "type": "http",
                    "asgi": {"version": "3.0"},
                    "http_version": "1.1",
                    "method": "GET",
                    "scheme": "http",
                    "path": path,
                    "raw_path": path.encode(),
                    "query_string": b"",
                    "headers": [],
                    "client": ("127.0.0.1", 12345),
                    "server": ("127.0.0.1", 8080),
                },
                receive,
                send,
            )
            self.assertEqual(messages[0]["status"], 200)
            self.assertEqual(b"".join(m.get("body", b"") for m in messages), content.encode())
        self.engine.predict_result.assert_not_called()
        self.assertEqual(self.runtime.snapshot()["observations"], 0)


class DashboardBrowserContracts(unittest.IsolatedAsyncioTestCase):
    """Execute shipped JavaScript against real evaluator/runtime JSON contracts."""

    asyncSetUp = fixtures.MonitoringHttpContracts.asyncSetUp
    cleanup = fixtures.MonitoringHttpContracts.cleanup

    async def browser(self, scenario):
        # Fixed controlled aggregates are produced by the real evaluator, including null PSI.
        ref = reference()
        pin = digest(canonical(ref))

        def report(count, abstain=False):
            stream = stream_fixtures.accumulator()
            for index in range(count // 100):
                rows = [[(row % 10 + 0.5) / 10] * 6 for row in range(100)]
                if abstain:
                    for row in rows:
                        row[-1] = -1
                predictions = [
                    {"decision": "abstain", "reason": "outside-support", "score": None}
                    if abstain
                    else {"decision": "score", "reason": None, "score": row[0]}
                    for row in rows
                ]
                stream.add(stream_fixtures.context(), rows, predictions, f"{index:032x}")
            closed = stream.close(sequence=1, ended_at_ms=2000)
            return monitoring.Evaluator(ref, pin).evaluate(closed.document())

        labelled = label_fixtures.LabelsContracts()
        labelled.setUp()
        try:
            label_report = labelled.submit()
        finally:
            labelled.doCleanups()
        state = self.runtime.snapshot()
        state.update(
            healthy=True,
            state="observing",
            data_status="observed",
            observations=1000,
            windows_evaluated=1,
            reports=[report(1000)],
            label_reports=[label_report],
            receipts=[
                {"kind": "quality_degradation", "delivery_seconds": 0.1, "received_at_ms": 1000}
            ],
        )
        payload = {
            "script": dashboard.SCRIPT,
            "ids": re.findall(r'id="([^"]+)"', dashboard.HTML),
            "state": state,
            "partial": report(100),
            "abstained": report(1000, True),
            "scenario": scenario,
        }
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node.js is required for dashboard qualification; no skips")
        result = subprocess.run(
            [node, "--input-type=module", "-e", HARNESS],
            input=canonical(payload),
            capture_output=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(json.loads(result.stdout)["status"], "pass")

    async def test_success_refresh_and_disconnect(self):
        await self.browser("success")

    async def test_partial_window_null_psi_is_insufficient_not_failure_or_zero(self):
        await self.browser("insufficient")

    async def test_prediction_abstentions_do_not_hide_valid_feature_psi(self):
        await self.browser("prediction-abstentions")

    async def test_unhealthy_503_snapshot_is_visible_and_distinct(self):
        await self.browser("unhealthy")

    async def test_invalid_key_and_401_clear_session_and_data(self):
        await self.browser("authentication")

    async def test_rate_limit_clears_stale_values_and_recovers_after_backoff(self):
        await self.browser("rate-limit")

    async def test_invalid_contract_is_never_rendered_or_reflected(self):
        await self.browser("bad-data")

    async def test_malformed_oversize_wrong_media_and_network_errors_clear_data(self):
        await self.browser("body-errors")

    async def test_timeout_aborts_owned_request_and_allows_recovery(self):
        await self.browser("timeout")

    async def test_body_timeout_is_bounded_and_recovers(self):
        await self.browser("body-timeout")

    async def test_disconnect_reconnect_ignores_late_response_and_pagehide_clears_key(self):
        await self.browser("late-response")


class DashboardWireContracts(unittest.TestCase):
    def test_all_assets_are_checked_without_credentials_or_canary_reflection(self):
        request, _ = privacy_fixtures.replay()
        self.assertEqual(probe.exercise(request, (b"PRIVATE-CANARY",)), 9)

    def test_wrong_status_changed_content_and_query_reflection_reject(self):
        request, _ = privacy_fixtures.replay()
        for path in dashboard.ASSETS:
            status, headers, content = request(path)
            for changed in ((401, headers, content), (status, headers, content + b"x")):
                with self.subTest(path=path), self.assertRaises(Rejected):
                    probe.checked(path, changed, (b"PRIVATE-CANARY",))
            with self.assertRaises(Rejected):
                probe.checked(path + "?private=x", (400, headers, content), (b"x",))

    def test_missing_duplicate_unbounded_or_unsafe_headers_reject(self):
        request, _ = privacy_fixtures.replay()
        status, headers, content = request("/monitoring/ui")
        for changed in (
            [],
            headers * 2,
            headers + [headers[0]],
            headers + [("x-private", "x" * 2049)],
            headers + [("x-private", "canary")],
            [(key, "wrong" if key.lower() == "cache-control" else value) for key, value in headers],
            [(key, value) for key, value in headers if key.lower() != "date"],
            headers + [("connection", "keep-alive")],
        ):
            with self.subTest(header_count=len(changed)), self.assertRaises(Rejected):
                probe.checked("/monitoring/ui", (status, changed, content), (b"canary",))

    def test_canary_in_otherwise_valid_constant_content_is_detected(self):
        request, _ = privacy_fixtures.replay()
        with self.assertRaisesRegex(Rejected, "canary"):
            probe.checked("/monitoring/ui", request("/monitoring/ui"), (b"Trusted MLSecOps",))

    def test_ledger_exemption_requires_exact_static_bytes_and_never_hides_unknown_route(self):
        ledger = Ledger(operator_routes=True)
        for path, content in dashboard.ASSETS.items():
            ledger.response(path, 200, content.encode())
            ledger.response(path + "?private=x", 400, b"")
        self.assertEqual(ledger.snapshot(), [])
        for path, status, content in (
            ("/monitoring/ui", 200, b"private"),
            ("/monitoring/ui", 400, b""),
            ("/monitoring/ui?private=x", 200, b""),
            ("/monitoring/ui/private", 200, b""),
        ):
            with self.subTest(path=path), self.assertRaises(Rejected):
                Ledger(operator_routes=True).response(path, status, content)
        with self.assertRaises(Rejected):
            Ledger().response("/monitoring/ui", 200, dashboard.HTML.encode())


if __name__ == "__main__":
    unittest.main()
