"""Replay real T19 sender packets against independent, fixed golden references."""

import math
import unittest
from dataclasses import replace
from unittest.mock import patch

from mlsecops import canary_probe
from mlsecops.canary_evaluation import evaluate
from mlsecops.contracts import Rejected, canonical
from mlsecops.datasets import FEATURES
from mlsecops.load_golden import Golden


class CanaryEvaluation(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        body = canonical({"schema_version": 1, "instances": [dict.fromkeys(FEATURES, 0.5)]})
        self.stable = Golden(body, "a" * 64, "b" * 64, 0.0)
        self.candidate = Golden(body, "c" * 64, "d" * 64, 0.75)
        self.request_id = 0
        self.clock_ns = 1_000_000_000

    async def stage(self, percent, attempts=100, *, errors=(), delay_ns=None, alter=None):
        """Only the HTTP exchange and its clock are synthetic; run_stage builds every row."""
        index = 0

        async def send(port, token, body):
            nonlocal index
            i = index
            index += 1
            self.request_id += 1
            self.clock_ns += 1_000_000 if delay_ns is None else delay_ns(i)
            if i in errors:
                if i % 3 == 1:
                    raise TimeoutError
                if i % 3 == 2:
                    raise ConnectionError
                return 503, {}
            model, bundle, score = {
                31001: ("a" * 64, "b" * 64, 0.0),
                31002: ("c" * 64, "d" * 64, 0.75),
            }[port]
            reply = dict(
                schema_version=1,
                model_sha256=model,
                bundle_sha256=bundle,
                predictions=[dict(decision="score", reason=None, score=score)],
                request_id=f"{self.request_id:032x}",
            )
            if alter is not None:
                alter(i, reply)
            return 200, reply

        with (
            patch.object(canary_probe.load_measurement, "request", new=send),
            patch.object(canary_probe.time, "monotonic_ns", new=lambda: self.clock_ns),
        ):
            packet = await canary_probe.run_stage(
                percent,
                stable=(31001, "1" * 64),
                candidate=(31002, "2" * 64),
                stable_golden=self.stable,
                candidate_golden=self.candidate,
                requests=attempts,
            )
        self.assertEqual(index, attempts)
        return packet

    def replay(self, *stages):
        return evaluate(list(stages), stable_golden=self.stable, candidate_golden=self.candidate)

    async def test_each_complete_prefix_reports_the_observed_attempts_and_decision(self):
        stages = []
        for percent, candidates in ((0, 0), (10, 10), (50, 50), (100, 100)):
            stages.append(await self.stage(percent))
            result = self.replay(*stages)
            with self.subTest(percent=percent):
                self.assertEqual(result["decision"], "complete" if percent == 100 else "advance")
                self.assertEqual(
                    [s["candidate_percent"] for s in result["stages"]],
                    [s["candidate_percent"] for s in stages],
                )
                last = result["stages"][-1]
                self.assertEqual((last["attempts"], last["valid"], last["errors"]), (100, 100, 0))
                self.assertEqual(last["candidate_attempts"], candidates)
                self.assertEqual((last["p95_ms"], last["p99_ms"]), (1, 1))
                self.assertTrue(last["checks"])
                self.assertTrue(all(last["checks"].values()))
                self.assertIs(last["passed"], True)

    async def test_nonzero_baseline_and_one_percentage_point_with_unequal_denominators(self):
        # HTTP failures, timeouts and transport errors all consume the original attempts.
        for n0, e0, n1, e1, decision in (
            (120, 6, 200, 12, "advance"),  # 5% to 6%, exactly +1 pp.
            (110, 6, 310, 20, "advance"),  # +0.99707 pp.
            (110, 2, 390, 11, "hold"),  # +1.00233 pp, rounds to +1.00.
        ):
            with self.subTest(baseline=(e0, n0), rollout=(e1, n1)):
                baseline = await self.stage(0, n0, errors=range(e0))
                stage = await self.stage(10, n1, errors=range(e1))
                result = self.replay(baseline, stage)
                self.assertIs(result["stages"][0]["passed"], True)
                self.assertEqual(result["decision"], decision)
                for report, n, errors in zip(result["stages"], (n0, n1), (e0, e1), strict=True):
                    self.assertEqual((report["errors"], report["valid"]), (errors, n - errors))
                self.assertEqual(result["stages"][1]["candidate_attempts"], n1 // 10)

    async def test_later_delta_uses_original_baseline_and_never_chains_stage_allowances(self):
        a = await self.stage(0, 200, errors=range(4))
        b = await self.stage(10, 200, errors=range(6))
        c = await self.stage(50, 200, errors=range(8))
        self.assertEqual(self.replay(a, b, c)["decision"], "hold")
        with self.assertRaises(Rejected):
            self.replay(a, b, c, await self.stage(100))

    async def test_hundred_valid_rows_required_even_with_acceptable_error_delta(self):
        a = await self.stage(0)
        b = await self.stage(10, errors=[0])
        result = self.replay(a, b)
        self.assertEqual(result["decision"], "hold")
        self.assertEqual(result["stages"][1]["valid"], 99)
        self.assertIs(result["stages"][1]["passed"], False)
        self.assertFalse(all(result["stages"][1]["checks"].values()))
        with self.assertRaises(Rejected):
            self.replay(a, b, await self.stage(50))

    async def test_latency_cutoffs_are_inclusive_and_use_all_and_successful_attempts(self):
        # Nearest ranks for 200 attempts are 190 and 198.
        edge = await self.stage(0, 200, delay_ns=lambda i: (200 if i < 190 else 500) * 1_000_000)
        report = self.replay(edge)
        self.assertEqual(report["decision"], "advance")
        self.assertEqual((report["stages"][0]["p95_ms"], report["stages"][0]["p99_ms"]), (200, 500))
        for slow, duration in ((11, 200_000_001), (3, 500_000_001)):
            with self.subTest(sample="all", slow=slow):
                packet = await self.stage(
                    0, 200, errors=range(slow), delay_ns=lambda i: duration if i < slow else 1
                )
                self.assertEqual(self.replay(packet)["decision"], "hold")
        for slow, duration in ((6, 200_000_001), (2, 500_000_001)):
            with self.subTest(sample="successful", slow=slow):
                packet = await self.stage(
                    0, 200, errors=range(100), delay_ns=lambda i: duration if i >= 200 - slow else 1
                )
                self.assertEqual(self.replay(packet)["decision"], "hold")

    async def test_score_tolerance_and_authentic_wrong_bundle_or_model_hold(self):
        def score(value):
            def alter(i, reply):
                if i == 0:
                    reply["predictions"][0]["score"] = value

            return alter

        for label, alter, decision in (
            ("score at tolerance", score(1e-6), "advance"),
            ("next float outside tolerance", score(math.nextafter(1e-6, math.inf)), "hold"),
            (
                "wrong model",
                lambda i, r: r.update(model_sha256="c" * 64) if i == 0 else None,
                "hold",
            ),
            (
                "wrong bundle",
                lambda i, r: r.update(bundle_sha256="d" * 64) if i == 0 else None,
                "hold",
            ),
        ):
            with self.subTest(case=label):
                packet = await self.stage(0, 110, alter=alter)
                self.assertEqual(self.replay(packet)["decision"], decision)

    async def test_forged_ok_response_cannot_pass_an_independent_golden_replay(self):
        a = await self.stage(0)
        b = await self.stage(10, 110)
        row = next(r for r in b["rows"] if r["target"] == "candidate")
        for field, wrong in (
            ("model_sha256", self.stable.model),
            ("bundle_sha256", self.stable.bundle),
            ("risk_score", self.stable.score),
        ):
            with self.subTest(field=field), patch.dict(row["response"], {field: wrong}):
                with self.assertRaises(Rejected):
                    self.replay(a, b)
        for bad in (replace(self.candidate, score=0.5), self.stable):
            with self.subTest(golden=bad.model):
                with self.assertRaises(Rejected):
                    evaluate([a, b], stable_golden=self.stable, candidate_golden=bad)

    async def test_duplicate_request_ids_reject_within_and_across_stages(self):
        a = await self.stage(0)
        b = await self.stage(10)
        for response in (a["rows"][0]["response"], b["rows"][1]["response"]):
            with patch.dict(b["rows"][0]["response"], {"request_id": response["request_id"]}):
                with self.assertRaises(Rejected):
                    self.replay(a, b)

    async def test_wrong_response_at_full_traffic_holds_even_with_enough_valid_predictions(self):
        stages = [await self.stage(p) for p in (0, 10, 50)]

        def corrupt(i, reply):
            if i == 0:
                reply["predictions"] = []
            elif i == 1:
                reply["bundle_sha256"] = self.stable.bundle

        packet = await self.stage(100, 200, alter=corrupt)
        self.assertIsNone(packet["rows"][0]["response"])
        result = self.replay(*stages, packet)
        self.assertEqual(result["decision"], "hold")
        last = result["stages"][-1]
        self.assertEqual((last["attempts"], last["valid"], last["errors"]), (200, 198, 2))
        self.assertIs(last["passed"], False)

    async def test_retained_status_outcome_and_response_must_agree(self):
        baseline = await self.stage(0, 110, errors=range(3))
        for index, fields in (
            (0, {"outcome": "timeout"}),  # HTTP 503 came back.
            (1, {"status": 200}),  # The sender timed out without a response.
            (2, {"response": baseline["rows"][3]["response"]}),
            (3, {"response": None}),  # Claimed success without a prediction.
            (3, {"outcome": "mismatch"}),  # The retained golden prediction matches.
        ):
            with self.subTest(index=index, field=next(iter(fields))):
                with patch.dict(baseline["rows"][index], fields), self.assertRaises(Rejected):
                    self.replay(baseline)

    async def test_swapped_routes_reject_even_if_totals_goldens_and_order_still_match(self):
        a = await self.stage(0)
        b = await self.stage(10)
        first, tenth = b["rows"][0], b["rows"][9]
        for key in ("target", "response"):
            first[key], tenth[key] = tenth[key], first[key]
        with self.assertRaises(Rejected):
            self.replay(a, b)

    async def test_missing_reordered_partial_or_different_payload_stages_are_rejected(self):
        a, b, c = [await self.stage(p, 110) for p in (0, 10, 50)]
        for label, stages in (
            ("empty", []),
            ("missing baseline", [b]),
            ("skipped ten", [a, c]),
            ("repeated stage", [a, b, b]),
            ("short final block", [a, {**b, "rows": b["rows"][:-1]}]),
            ("foreign payload", [a, {**b, "payload_sha256": "f" * 64}]),
        ):
            with self.subTest(case=label), self.assertRaises(Rejected):
                self.replay(*stages)
        with patch.dict(b["rows"][9], {"index": 8}), self.assertRaises(Rejected):
            self.replay(a, b)

    async def test_rejects_negative_duration_and_overlap_inside_or_between_stages(self):
        a = await self.stage(0)
        b = await self.stage(10)
        for label, i, key, value in (
            ("negative duration", 2, "end_ns", b["rows"][2]["start_ns"] - 1),
            ("overlap within", 2, "start_ns", b["rows"][1]["end_ns"] - 1),
            ("overlap between", 0, "start_ns", a["rows"][-1]["end_ns"] - 1),
        ):
            with self.subTest(case=label), patch.dict(b["rows"][i], {key: value}):
                with self.assertRaises(Rejected):
                    self.replay(a, b)


if __name__ == "__main__":
    unittest.main()
