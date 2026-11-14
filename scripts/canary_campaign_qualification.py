"""A closed transport loop with the real HTTP handler and controlled model responses."""

import asyncio
import secrets
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import canary_campaign as campaign
from mlsecops import serving, serving_audit, serving_context, serving_http
from mlsecops.contracts import Rejected, canonical, digest, write_json
from mlsecops.load_golden import Golden
from mlsecops.load_probe import listen
from mlsecops.serving_access import Access
from scripts.load_golden_qualification import expected


def target(golden, token, journal):
    engine = Mock()
    generation = threading.Event()
    engine.response_budget.side_effect = lambda: serving.ResponseBudget(
        generation, time.monotonic() + 10
    )
    context = serving_context.QualificationContext("1" * 64, "2" * 64, golden.bundle, golden.model)
    payload = dict(
        schema_version=1,
        model_sha256=golden.model,
        bundle_sha256=golden.bundle,
        predictions=[dict(decision="score", reason=None, score=golden.score)],
    )
    engine.predict_result.side_effect = lambda features, *, generation: serving.ServingResult(
        payload, context, generation
    )
    access = Access(
        dict(
            schema_version=1,
            clients=[
                dict(
                    principal_id=secrets.token_hex(16),
                    token=token,
                    requests_per_second=1000,
                    burst=1000,
                    max_in_flight=4,
                )
            ],
        )
    )
    return serving_http.create_app(engine, clients=access, audit=journal), engine


class Campaign(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.state = Path(temp.name)
        ref = expected()
        self.references = dict(
            stable_golden=Golden.from_expected(ref),
            candidate_golden=Golden.from_expected(
                {**ref, "model": "3" * 64, "bundle": "4" * 64, "scores": [0.125, 0.25]}
            ),
        )

    def test_two_http_servers_replay_after_shutdown_and_exact_byte_pin(self):
        stable_token, next_token = secrets.token_hex(32), secrets.token_hex(32)
        journals = []
        for name in ("stable", "candidate"):
            journal = serving_audit.Journal(self.state / (name + ".jsonl"))
            self.addCleanup(journal.close, timeout=5)
            journal.start()
            journals.append(journal)
        stable, stable_engine = target(self.references["stable_golden"], stable_token, journals[0])
        candidate, next_engine = target(
            self.references["candidate_golden"], next_token, journals[1]
        )
        with listen(stable) as left, listen(candidate) as right:
            result = asyncio.run(
                campaign.run(
                    self.state,
                    stable=(left, stable_token),
                    candidate=(right, next_token),
                    requests=100,
                    **self.references,
                )
            )
        stable_engine.close.assert_called_once()
        next_engine.close.assert_called_once()
        self.assertEqual(result["decision"], "complete", result["stages"])
        self.assertEqual([r["candidate_attempts"] for r in result["stages"]], [0, 10, 50, 100])
        self.assertEqual(stable_engine.predict_result.call_count, 240)
        self.assertEqual(next_engine.predict_result.call_count, 160)
        path = self.state / "evidence" / ("canary-" + result["campaign"]) / "traffic.json"
        self.assertEqual(
            campaign.replay(path, result["primary_sha256"], **self.references)["stages"],
            result["stages"],
        )
        content = path.read_bytes()
        for private in (stable_token.encode(), next_token.encode(), b'"instances"'):
            self.assertNotIn(private, content)
        path.write_bytes(content + b" ")
        with self.assertRaisesRegex(Rejected, "canary_capture_changed"):
            campaign.replay(path, result["primary_sha256"], **self.references)

    def test_baseline_failure_stops_requests_before_advancing(self):
        with patch("mlsecops.load_measurement.request", return_value=(503, {})) as send:
            result = asyncio.run(
                campaign.run(
                    self.state,
                    stable=(8001, "1" * 64),
                    candidate=(8002, "2" * 64),
                    requests=100,
                    **self.references,
                )
            )
        self.assertEqual(result["decision"], "hold")
        self.assertEqual(send.await_count, 100)
        self.assertEqual([s["candidate_percent"] for s in result["stages"]], [0])

    def test_replay_requires_a_terminal_decision_and_unchanged_readback(self):
        path = self.state / "packet.json"
        write_json(path, [])
        with patch.object(
            campaign.canary_evaluation, "evaluate", return_value={"decision": "advance"}
        ):
            with self.assertRaisesRegex(Rejected, "canary_capture_incomplete"):
                campaign.replay(path, digest(canonical([]) + b"\n"), **self.references)
        with (
            patch.object(campaign.canary_probe, "run_stage", return_value={}),
            patch.object(
                campaign.canary_evaluation,
                "evaluate",
                side_effect=[{"decision": "hold"}, {"decision": "complete"}],
            ),
            self.assertRaisesRegex(Rejected, "canary_replay_changed"),
        ):
            asyncio.run(campaign.run(self.state, stable=(), candidate=(), **self.references))
