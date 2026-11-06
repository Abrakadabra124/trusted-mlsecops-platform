import copy
import unittest

from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.datasets import FEATURES
from mlsecops.load_golden import Golden


def expected():
    return {
        "features": [[0.1] * len(FEATURES), [0.9] * len(FEATURES)],
        "scores": [0.75, 0.25],
        "model": "a" * 64,
        "bundle": "b" * 64,
    }


def response():
    return {
        "schema_version": 1,
        "model_sha256": "a" * 64,
        "bundle_sha256": "b" * 64,
        "request_id": "c" * 32,
        "predictions": [{"decision": "score", "reason": None, "score": 0.75}],
    }


class GoldenContracts(unittest.TestCase):
    def test_pins_one_independent_reference_row_and_exact_response(self):
        reference = expected()
        golden = Golden.from_expected(reference)
        self.assertEqual(decode(golden.body)["instances"], [{name: 0.1 for name in FEATURES}])
        self.assertEqual(golden.binding()["payload_sha256"], digest(golden.body))
        self.assertEqual(golden.binding()["rows_per_request"], 1)
        self.assertTrue(golden.valid(response()))
        reference["features"][0][0] = 0.9
        reference["scores"][0] = 0
        self.assertTrue(golden.valid(response()))

    def test_changed_identity_schema_and_unexpected_body_are_denied(self):
        golden = Golden.from_expected(expected())
        for field, value in [
            ("model_sha256", "d" * 64),
            ("bundle_sha256", "d" * 64),
            ("schema_version", True),
            ("schema_version", 2),
            ("request_id", None),
            ("request_id", "private"),
            ("predictions", []),
            ("predictions", {}),
            ("predictions", response()["predictions"] * 2),
        ]:
            with self.subTest(field=field):
                self.assertFalse(golden.valid({**response(), field: value}))
        for value in (None, [], {}, {**response(), "unexpected": "private"}):
            self.assertFalse(golden.valid(value))

    def test_unsafe_nonfinite_ood_wrong_and_boolean_scores_are_denied(self):
        golden = Golden.from_expected(expected())
        for field, value in [
            ("score", True),
            ("score", float("nan")),
            ("score", float("inf")),
            ("score", -0.1),
            ("score", 1.1),
            ("score", 0.750002),
            ("score", None),
            ("decision", "abstain"),
            ("reason", "outside-support"),
        ]:
            reply = response()
            reply["predictions"][0][field] = value
            self.assertFalse(golden.valid(reply))
        self.assertTrue(
            golden.valid(
                {
                    **response(),
                    "predictions": [{"score": 0.7500005, "decision": "score", "reason": None}],
                }
            )
        )

    def test_invalid_reference_rejected_before_any_http_request(self):
        for reference in (None, [], {}):
            with self.assertRaises(Rejected):
                Golden.from_expected(reference)
        for field, value in [
            ("features", []),
            ("features", {}),
            ("features", [[True] * len(FEATURES)]),
            ("features", [[1.1] * len(FEATURES)]),
            ("features", [[0.1]]),
            ("features", [[float("nan")] * len(FEATURES)]),
            ("scores", []),
            ("scores", [True, 0.25]),
            ("scores", [float("inf"), 0.25]),
            ("scores", [-0.1, 0.25]),
            ("model", "private"),
            ("bundle", 1),
        ]:
            reference = copy.deepcopy(expected())
            reference[field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                Golden.from_expected(reference)
        for body in (None, b"", b"x" * 65537):
            with self.assertRaises(Rejected):
                Golden(body, "a" * 64, "b" * 64, 0.5)

    def test_direct_construction_cannot_mislabel_multiple_or_unsupported_rows(self):
        body = decode(Golden.from_expected(expected()).body)
        for value in (
            {},
            {**body, "schema_version": True},
            {**body, "instances": body["instances"] * 2},
            {**body, "instances": [{name: -1 for name in FEATURES}]},
        ):
            with self.assertRaises(Rejected):
                Golden(canonical(value), "a" * 64, "b" * 64, 0.5)


if __name__ == "__main__":
    unittest.main()
