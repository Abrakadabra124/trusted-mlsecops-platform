"""Controlled T19 sender contracts. All HTTP exchanges stay in process."""

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from mlsecops import canary_probe as probe
from mlsecops import load_measurement
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.load_golden import Golden
from scripts.load_golden_qualification import expected


class CanaryProbe(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        reference = expected()
        self.stable = Golden.from_expected(reference)
        self.candidate = Golden.from_expected(
            {**reference, "model": "c" * 64, "bundle": "d" * 64, "scores": [0.125, 0.25]}
        )
        self.options = dict(
            stable=(31001, "1" * 64),
            candidate=(31002, "2" * 64),
            stable_golden=self.stable,
            candidate_golden=self.candidate,
        )

    def response(self, golden, index):
        return dict(
            schema_version=1,
            model_sha256=golden.model,
            bundle_sha256=golden.bundle,
            predictions=[dict(decision="score", reason=None, score=golden.score)],
            request_id=f"{index:032x}",
        )

    async def test_wrong_target_response_preserves_observed_digest_without_qualifying(self):
        # The endpoint is reachable but is serving the other release's whole bundle.
        reply = self.response(self.stable, 123)
        with patch.object(
            load_measurement, "request", AsyncMock(return_value=(200, reply))
        ) as send:
            result = await probe.run_stage(100, **self.options)
        row = result["rows"][0]
        self.assertEqual(
            (row["status"], row["outcome"], row["target"]), (200, "mismatch", "candidate")
        )
        self.assertEqual(
            row["response"],
            {
                "model_sha256": self.stable.model,
                "bundle_sha256": self.stable.bundle,
                "risk_score": self.stable.score,
                "request_id": reply["request_id"],
            },
        )
        self.assertEqual(send.await_count, 100)

    async def test_each_stage_sends_the_exact_mix_body_and_token_in_order(self):
        self.assertEqual(probe.STAGES, (0, 10, 50, 100))
        for percent, count in ((0, 100), (10, 110), (50, 100), (100, 100)):
            sent = []

            async def predict(port, token, body):
                target = "stable" if port == self.options["stable"][0] else "candidate"
                self.assertEqual((port, token), self.options[target])
                self.assertEqual(body, self.stable.body)
                sent.append(target)
                return 200, self.response(self.options[target + "_golden"], len(sent))

            with patch.object(load_measurement, "request", predict):
                result = await probe.run_stage(percent, **self.options, requests=count)
            self.assertEqual(
                set(result), {"schema_version", "candidate_percent", "payload_sha256", "rows"}
            )
            self.assertEqual(
                (result["schema_version"], result["candidate_percent"], result["payload_sha256"]),
                (1, percent, digest(self.stable.body)),
            )
            self.assertEqual(len(sent), count)
            rows = result["rows"]
            self.assertEqual([r["target"] for r in rows], sent)
            self.assertEqual(sent.count("candidate"), count * percent // 100)
            for i, row in enumerate(rows):
                self.assertEqual(
                    set(row),
                    {"index", "target", "start_ns", "end_ns", "status", "outcome", "response"},
                )
                self.assertEqual(row["index"], i)
                self.assertEqual(sent[: i + 1].count("candidate"), (i + 1) * percent // 100)
                self.assertEqual((row["status"], row["outcome"]), (200, "ok"))
                golden = self.options[row["target"] + "_golden"]
                self.assertEqual(
                    row["response"],
                    dict(
                        model_sha256=golden.model,
                        bundle_sha256=golden.bundle,
                        risk_score=golden.score,
                        request_id=f"{i + 1:032x}",
                    ),
                )
                self.assertLessEqual(row["start_ns"], row["end_ns"])
                if i:
                    self.assertLessEqual(rows[i - 1]["end_ns"], row["start_ns"])
            primary = canonical(result)
            for secret in (self.options["stable"][1], self.options["candidate"][1], "instances"):
                self.assertNotIn(secret.encode(), primary)

    async def test_http_errors_timeout_and_exception_remain_individual_attempts(self):
        responses = [
            (429, {"error": "PRIVATE"}),
            (503, {"error": "PRIVATE"}),
            TimeoutError("PRIVATE"),
            OSError("PRIVATE"),
            Rejected("PRIVATE"),
            (403, "PRIVATE"),
            (307, "PRIVATE"),
            (201, "PRIVATE"),
        ]
        send = AsyncMock(
            side_effect=[*responses, *[(200, self.response(self.stable, i)) for i in range(8, 100)]]
        )
        with patch.object(load_measurement, "request", send):
            result = await probe.run_stage(0, **self.options)
        self.assertEqual(
            [(r["status"], r["outcome"], r["response"]) for r in result["rows"][:8]],
            [
                (429, "http_error", None),
                (503, "http_error", None),
                (0, "timeout", None),
                (0, "transport", None),
                (0, "transport", None),
                (403, "http_error", None),
                (307, "http_error", None),
                (201, "http_error", None),
            ],
        )
        self.assertEqual(len(result["rows"]), 100)
        self.assertEqual(send.await_count, 100)
        self.assertEqual(result["rows"][8]["outcome"], "ok")
        self.assertNotIn(b"PRIVATE", canonical(result))

    async def test_malformed_responses_and_credential_echo_never_leave_the_sender(self):
        valid = self.response(self.stable, 1)
        bad = [
            {},
            None,
            {"raw": "PRIVATE"},
            {**valid, "extra": "PRIVATE"},
            {**valid, "request_id": "PRIVATE"},
            {**valid, "predictions": []},
            {**valid, "predictions": "PRIVATE"},
            {**valid, "predictions": [None]},
            {**valid, "model_sha256": self.options["candidate"][1]},
            {**valid, "bundle_sha256": self.options["stable"][1]},
            {**valid, "model_sha256": []},
            {**valid, "schema_version": True},
            {**valid, "predictions": [dict(score=1, reason="PRIVATE", decision="score")]},
            *[
                {**valid, "predictions": [dict(score=s, reason=None, decision="score")]}
                for s in (True, "PRIVATE", None, float("nan"), 10**400, -0.1)
            ],
        ]
        wrong_score = {**valid, "predictions": [dict(score=0.25, reason=None, decision="score")]}
        tolerance = {
            **valid,
            "predictions": [dict(score=self.stable.score - 5e-7, reason=None, decision="score")],
        }
        wrong_bundle = {**valid, "bundle_sha256": self.candidate.bundle}
        replies = bad + [wrong_score, tolerance, wrong_bundle] + [valid] * (97 - len(bad))
        with patch.object(
            load_measurement, "request", AsyncMock(side_effect=[(200, reply) for reply in replies])
        ):
            result = await probe.run_stage(0, **self.options)
        rows = result["rows"]
        self.assertEqual(
            [(r["status"], r["outcome"], r["response"]) for r in rows[: len(bad)]],
            [(200, "mismatch", None)] * len(bad),
        )
        self.assertEqual(
            [r["outcome"] for r in rows[len(bad) : len(bad) + 3]], ["mismatch", "ok", "mismatch"]
        )
        self.assertEqual(rows[len(bad)]["response"]["risk_score"], 0.25)
        self.assertEqual(
            rows[len(bad) + 1]["response"]["risk_score"], tolerance["predictions"][0]["score"]
        )
        self.assertEqual(rows[len(bad) + 2]["response"]["bundle_sha256"], self.candidate.bundle)
        for secret in (
            b"PRIVATE",
            b"instances",
            self.options["stable"][1].encode(),
            self.options["candidate"][1].encode(),
        ):
            self.assertNotIn(secret, canonical(result))

    async def test_invalid_profile_endpoints_or_different_golden_input_fail_before_send(self):
        other = expected()
        other["features"][0][0] = 0.5
        changes = [
            {"candidate_golden": Golden.from_expected(other)},
            {"stable_golden": {}},
            {"candidate_golden": None},
            {"candidate": self.options["stable"]},
            {"stable": [31001, "1" * 64]},
            {"candidate": ("https://remote", "1" * 64)},
            {"candidate": (0, "1" * 64)},
            {"stable": (True, "1" * 64)},
            {"candidate": (65536, "1" * 64)},
            {"candidate": (31002, "PRIVATE")},
            {"stable": (31001, None)},
            *[{"requests": count} for count in (True, 0, 99, 101, 1010, 100.0)],
        ]
        with patch.object(load_measurement, "request", AsyncMock()) as send:
            for change in changes:
                with self.subTest(keys=list(change)), self.assertRaises(Rejected):
                    await probe.run_stage(0, **{**self.options, **change})
            for percent in (False, -1, 25, 101, 10.0):
                with self.assertRaises(Rejected):
                    await probe.run_stage(percent, **self.options)
            send.assert_not_awaited()

    async def test_same_bundle_cannot_stand_for_two_rollout_targets(self):
        with patch.object(load_measurement, "request", AsyncMock()) as send:
            with self.assertRaisesRegex(Rejected, "canary_targets"):
                await probe.run_stage(0, **{**self.options, "candidate_golden": self.stable})
            send.assert_not_awaited()

    async def test_real_request_uses_loopback_and_closes_a_timed_out_stream(self):
        # Exercise the actual HTTP encoder, absolute two-second deadline and decoder.
        # Only open_connection is replaced; no sockets are created.
        writes, closes = [], []

        async def connect(host, port, *, limit):
            self.assertEqual((host, port, limit), ("127.0.0.1", self.options["stable"][0], 16384))
            index = len(writes)
            body = canonical(self.response(self.stable, index))
            reader = asyncio.StreamReader()
            reader.feed_data(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode())
            if index:
                reader.feed_data(body)
                reader.feed_eof()

            class Writer:
                def write(self, data):
                    writes.append(data)

                async def drain(self):
                    pass

                def close(self):
                    closes.append(index)

            return reader, Writer()

        with patch.object(asyncio, "open_connection", connect):
            result = await probe.run_stage(0, **self.options)
        rows = result["rows"]
        self.assertEqual((rows[0]["status"], rows[0]["outcome"]), (0, "timeout"))
        self.assertGreaterEqual(rows[0]["end_ns"] - rows[0]["start_ns"], 1_900_000_000)
        self.assertEqual(sum(row["outcome"] == "ok" for row in rows), 99)
        self.assertEqual(closes, list(range(100)))
        for message in writes:
            head, body = message.split(b"\r\n\r\n")
            self.assertTrue(head.startswith(b"POST /v1/predict HTTP/1.1\r\nHost: 127.0.0.1\r\n"))
            self.assertIn(b"Authorization: Bearer " + self.options["stable"][1].encode(), head)
            self.assertEqual(body, self.stable.body)

    async def test_cancellation_propagates_without_retry_or_later_requests(self):
        started = asyncio.Event()

        async def block(*args):
            started.set()
            await asyncio.Future()

        with patch.object(load_measurement, "request", AsyncMock(side_effect=block)) as send:
            stage = asyncio.create_task(probe.run_stage(10, **self.options))
            await started.wait()
            stage.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await stage
            self.assertEqual(send.await_count, 1)


if __name__ == "__main__":
    unittest.main()
