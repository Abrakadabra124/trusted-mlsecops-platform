"""Actual ASGI completion/audit boundary with the owned monitoring runtime."""

import asyncio
import dataclasses
import unittest
from unittest.mock import patch

from mlsecops import serving_http, serving_http_audit
from mlsecops.contracts import Rejected, canonical
from scripts import monitoring_runtime_qualification as runtime_fixtures
from scripts import serving_http_qualification as http_fixtures
from scripts.monitoring_stream_qualification import context


class MonitoringHttpContracts(unittest.IsolatedAsyncioTestCase):
    invoke = http_fixtures.ServingHttpContracts.invoke
    cleanup = runtime_fixtures.RuntimeContracts.cleanup

    async def asyncSetUp(self):
        await runtime_fixtures.RuntimeContracts.asyncSetUp(self)
        await http_fixtures.ServingHttpContracts.asyncSetUp(self)
        self.audit_context = context()
        self.engine.check.return_value.update(bundle_sha256="b" * 64, model_sha256="a" * 64)
        self.engine.predict.return_value.update(bundle_sha256="b" * 64, model_sha256="a" * 64)
        self.app = serving_http.create_app(
            self.engine,
            self.token,
            audit=self.journal,
            metrics_token="9" * 64,
            monitor=self.runtime,
        )

    async def test_only_successful_prediction_response_is_observed(self):
        status, response, _ = await self.invoke()
        self.assertEqual(status, 200)
        self.assertEqual(self.runtime.snapshot()["observations"], 1)
        self.assertNotIn("monitor", canonical(response).decode())
        self.assertEqual((await self.invoke(path="/readyz", method="GET"))[0], 200)
        self.assertEqual((await self.invoke(headers=[]))[0], 401)
        self.assertEqual((await self.invoke(body={}))[0], 422)
        self.assertEqual(self.runtime.snapshot()["observations"], 1)

    async def test_audit_substitution_abort_and_late_deadline_are_not_observations(self):
        with patch.object(
            serving_http_audit.Delivery, "intended", side_effect=Rejected("controlled")
        ):
            self.assertEqual((await self.invoke())[0], 503)
        with patch.object(
            serving_http.JSONResponse, "__call__", side_effect=asyncio.CancelledError
        ):
            with self.assertRaises(asyncio.CancelledError):
                await self.invoke()
        render = serving_http.JSONResponse.render

        def expire(response, content):
            if "predictions" in content:
                response.budget.generation.set()
            return render(response, content)

        with patch.object(serving_http.JSONResponse, "render", expire):
            self.assertEqual((await self.invoke())[0], 503)
        self.assertEqual(self.runtime.snapshot()["observations"], 0)

    async def test_completed_response_uses_immutable_result_context_and_clears_features(self):
        responses = []
        original = self.audit_context
        render = serving_http.JSONResponse.render

        def change_owner(response, content):
            if "predictions" in content:
                responses.append(response)
                self.audit_context = dataclasses.replace(original, model_sha256="f" * 64)
            return render(response, content)

        with patch.object(serving_http.JSONResponse, "render", change_owner):
            self.assertEqual((await self.invoke())[0], 200)
        self.assertEqual(self.runtime.snapshot()["observations"], 1)
        self.assertEqual(responses[0].audit_context, original)
        self.assertIsNone(responses[0].monitoring_features)
        self.assertIsNone(responses[0].monitoring_predictions)

    async def test_monitor_failure_is_visible_without_rewriting_already_sent_prediction(self):
        with patch.object(
            self.runtime, "observe", side_effect=RuntimeError("PRIVATE-MONITOR-CANARY")
        ):
            status, response, _ = await self.invoke()
        self.assertEqual(status, 200)
        self.assertEqual(self.runtime.snapshot()["faults"], ["observation"])
        self.assertNotIn("PRIVATE-MONITOR-CANARY", canonical(response).decode())
        self.assertNotIn("PRIVATE-MONITOR-CANARY", canonical(self.runtime.snapshot()).decode())

    async def test_operator_status_is_authenticated_bounded_and_does_not_count_as_prediction(self):
        self.assertEqual((await self.invoke(path="/monitoring", method="GET", headers=[]))[0], 401)
        headers = [(b"authorization", b"Bearer " + b"9" * 64)]
        status, response, _ = await self.invoke(path="/monitoring", method="GET", headers=headers)
        self.assertIn(status, (200, 503))
        self.assertEqual(response["reference_sha256"], self.reference_sha256)
        self.assertEqual(response["observations"], 0)
        self.assertEqual(response["data_status"], "insufficient")
        self.runtime.failed("scheduler")
        self.assertEqual(
            (await self.invoke(path="/monitoring", method="GET", headers=headers))[0], 503
        )

    async def test_runtime_lifespan_closes_partial_window_and_engine(self):
        async with self.app.router.lifespan_context(self.app):
            self.assertEqual((await self.invoke())[0], 200)
        state = self.runtime.snapshot()
        self.assertEqual(state["state"], "stopped")
        self.assertEqual(state["reports"][-1]["observations"], 1)
        self.assertEqual(state["reports"][-1]["status"], "insufficient")
        self.engine.close.assert_called()

    async def test_monitor_requires_operator_credential_and_known_runtime(self):
        for monitor, token in ((object(), "9" * 64), (self.runtime, None)):
            with self.assertRaisesRegex(Rejected, "http_monitor_configuration"):
                serving_http.create_app(
                    self.engine,
                    self.token,
                    audit=self.journal,
                    monitor=monitor,
                    metrics_token=token,
                )


if __name__ == "__main__":
    unittest.main()
