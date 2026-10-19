import io
import unittest
from unittest.mock import patch

from mlsecops import model, serving_worker
from mlsecops import serving_protocol as protocol
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.signing import encode64
from scripts import model_contract_qualification as fixtures


class ServingSessionContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.ModelContractTests.setUpClass()
        cls.model = fixtures.ModelContractTests.content
        cls.features = fixtures.ModelContractTests.features[:3]

    def setUp(self):
        self.load = protocol.load_request(self.model)

    def transcript(self, requests):
        output, diagnostic = io.BytesIO(), io.StringIO()
        status = serving_worker.serve(
            io.BytesIO(b"".join(canonical(request) + b"\n" for request in requests)),
            output,
            diagnostic,
        )
        return (
            status,
            [decode(line) for line in output.getvalue().splitlines()],
            diagnostic.getvalue(),
        )

    def test_real_session_loads_once_and_replies_bind_model_nonce_and_rows(self):
        first = protocol.request(self.load, "predict", self.features)
        second = protocol.request(self.load, "predict", self.features)
        ping = protocol.request(self.load, "ping")
        with patch.object(model, "session", wraps=model.session) as load:
            status, replies, diagnostic = self.transcript([self.load, first, second, ping])
        self.assertEqual((status, diagnostic, load.call_count), (0, "", 1))
        for request, reply in zip((self.load, first, second, ping), replies, strict=True):
            protocol.verify_reply(request, reply)
        self.assertEqual(
            replies[1]["predictions"],
            [
                {"row_id": f"{first['request_id']}:{index}", "score": score}
                for index, score in enumerate(protocol.verify_reply(first, replies[1]))
            ],
        )
        self.assertEqual(
            protocol.verify_reply(first, replies[1]), protocol.verify_reply(second, replies[2])
        )

    def test_mutated_signature_free_transport_cannot_change_expected_model(self):
        mutations = (
            {"model": encode64(b"PRIVATE-CANARY")},
            {"model_sha256": "a" * 64},
            {"session_id": "not-a-session"},
            {"schema_version": True},
            {"path": "https://untrusted.invalid/model"},
        )
        for changes in mutations:
            with (
                self.subTest(changes=tuple(changes)),
                patch.object(model, "session") as load,
            ):
                status, replies, diagnostic = self.transcript([{**self.load, **changes}])
                self.assertEqual((status, replies), (1, []))
                self.assertEqual(diagnostic, "serving_worker_rejected\n")
                load.assert_not_called()

    def test_malformed_onnx_never_acknowledges_ready(self):
        status, replies, diagnostic = self.transcript([protocol.load_request(b"not-onnx")])
        self.assertEqual((status, replies), (1, []))
        self.assertNotIn("not-onnx", diagnostic)

    def test_reload_foreign_session_or_model_and_invalid_feature_kill_session(self):
        valid = protocol.request(self.load, "predict", self.features)
        mutations = (
            self.load,
            {**valid, "session_id": "a" * 32},
            {**valid, "model_sha256": "a" * 64},
            {**valid, "features": [[True] * 6]},
            {**valid, "features": [[2] * 6]},
            {**valid, "features": self.features * 34},
            {**valid, "extra": "PRIVATE-CANARY"},
        )
        for request in mutations:
            with self.subTest(request=tuple(request)):
                status, replies, diagnostic = self.transcript([self.load, request, valid])
                self.assertEqual((status, len(replies)), (1, 1))
                self.assertEqual(diagnostic, "serving_worker_rejected\n")

    def test_replay_and_malformed_reply_are_rejected_by_parent(self):
        request = protocol.request(self.load, "predict", self.features)
        _, replies, _ = self.transcript([self.load, request])
        reply = replies[1]
        changes = (
            {"model_sha256": "a" * 64},
            {"session_id": "a" * 32},
            {"request_id": "a" * 32},
            {"request_sha256": "a" * 64},
            {"schema_version": True},
            {"predictions": []},
            {"predictions": list(reversed(reply["predictions"]))},
            {"predictions": [{**row, "score": True} for row in reply["predictions"]]},
            {"predictions": [{**row, "score": float("nan")} for row in reply["predictions"]]},
            {"extra": "unexpected"},
        )
        for mutation in changes:
            with self.subTest(mutation=tuple(mutation)), self.assertRaises(Rejected):
                protocol.verify_reply(request, {**reply, **mutation})
        with self.assertRaises(Rejected):
            protocol.verify_reply(protocol.request(self.load, "predict", self.features), reply)

    def test_load_ack_requires_scan_and_pinned_runtime_version(self):
        _, replies, _ = self.transcript([self.load])
        for mutation in (
            {"runtime_version": "foreign"},
            {"scan": {}},
            {"ready": False},
            {"ready": 1},
            {"request_sha256": digest(b"different bytes")},
        ):
            with self.subTest(mutation=tuple(mutation)), self.assertRaises(Rejected):
                protocol.verify_reply(self.load, {**replies[0], **mutation})

    def test_frames_require_newline_and_enforce_size_and_single_json(self):
        for content in (b"{}", b"{} {}\n", b"x" * 101 + b"\n", b'{"a":1,"a":2}\n'):
            with self.subTest(content=content[:20]), self.assertRaises(Rejected):
                protocol.frame(io.BytesIO(content), 100)
        self.assertIsNone(protocol.frame(io.BytesIO(b""), 100))

    def test_unsupported_action_and_missing_load_exit_without_input_disclosure(self):
        for request in ({"action": "PRIVATE-CANARY"}, protocol.request(self.load, "ping")):
            status, replies, diagnostic = self.transcript([request])
            self.assertEqual((status, replies, diagnostic), (1, [], "serving_worker_rejected\n"))
        status, replies, diagnostic = self.transcript([])
        self.assertEqual((status, replies), (1, []))


if __name__ == "__main__":
    unittest.main()
