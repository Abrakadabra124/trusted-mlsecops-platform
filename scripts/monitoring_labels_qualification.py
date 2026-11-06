"""Real signatures and bounded joins; no external label service."""

import dataclasses
import tempfile
import unittest
from pathlib import Path

from mlsecops import monitoring_labels, signing
from mlsecops.contracts import Rejected, canonical, digest
from scripts.monitoring_qualification import reference
from scripts.monitoring_stream_qualification import accumulator, context


class LabelsContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.key = Path(temporary.name) / "labels.pem"
        self.public = signing.create_key(self.key)
        self.reference = reference()
        self.reference_sha256 = digest(canonical(self.reference))
        stream = accumulator()
        for batch in range(2):
            predictions = [
                {
                    "decision": "score",
                    "reason": None,
                    "score": 0.8 if batch * 100 + row < 169 else 0.2,
                }
                for row in range(100)
            ]
            stream.add(context(), [[0.5] * 6] * 100, predictions, f"{batch:032x}")
        self.closed = stream.close(sequence=1, ended_at_ms=2000)
        self.labels = self.consumer()

    def consumer(self, *, closed=None, public=None, expected=None):
        return monitoring_labels.Labels(
            self.reference,
            self.reference_sha256,
            closed or self.closed,
            self.closed.sha256 if expected is None else expected,
            public or self.public,
        )

    def payload(self, count=200):
        return {
            "schema_version": 1,
            "reference_sha256": self.reference_sha256,
            "window_sha256": self.closed.sha256,
            "issued_at_ms": 2000,
            "expires_at_ms": 12000,
            "labels": [
                {"observation_id": identifier, "label": 1}
                for identifier, _ in self.closed.predictions[:count]
            ],
        }

    def submit(self, document=None, *, clock=3000, kind="monitor-labels"):
        return self.labels.accept(
            signing.sign(document or self.payload(), kind, self.key), clock_ms=clock
        )

    def test_real_signature_partial_labels_retry_and_distinct_quality_alert(self):
        first = self.submit(self.payload(199))
        self.assertEqual(first["status"], "insufficient")
        self.assertIsNone(first["alert"])
        self.assertEqual(first["accepted_labels"], 199)
        second = self.submit()
        self.assertEqual(second["alert"], "quality_degradation")
        self.assertEqual(second["positives"], 200)
        self.assertEqual(second["true_positives"], 169)
        self.assertEqual(second["accepted_labels"], 1)
        self.assertFalse(second["release_ready"])
        self.assertEqual(self.submit()["accepted_labels"], 0)
        self.assertEqual(self.submit()["window_sha256"], self.closed.sha256)

    def test_conflicting_or_unmatched_labels_are_atomic(self):
        first = self.payload(1)
        self.submit(first)
        conflict = self.payload(2)
        conflict["labels"].reverse()
        conflict["labels"][-1]["label"] = 0
        with self.assertRaisesRegex(Rejected, "monitor_label_conflict"):
            self.submit(conflict)
        self.assertEqual(self.submit()["accepted_labels"], 199)
        unknown = self.payload(1)
        unknown["labels"][0]["observation_id"] = "f" * 64
        with self.assertRaisesRegex(Rejected, "monitor_label_unmatched"):
            self.submit(unknown)

    def test_untrusted_signer_wrong_kind_modified_signature_and_context_fail(self):
        other_key = self.key.with_name("other.pem")
        signing.create_key(other_key)
        with self.assertRaises(Rejected):
            self.labels.accept(
                signing.sign(self.payload(), "monitor-labels", other_key), clock_ms=3000
            )
        with self.assertRaises(Rejected):
            self.submit(kind="feedback")
        envelope = signing.sign(self.payload(), "monitor-labels", self.key)
        envelope["payload"] = signing.encode64(canonical({**self.payload(), "issued_at_ms": 2001}))
        with self.assertRaises(Rejected):
            self.labels.accept(envelope, clock_ms=3000)
        for key, value in (
            ("schema_version", True),
            ("reference_sha256", "f" * 64),
            ("window_sha256", "f" * 64),
            ("extra", "private-canary"),
        ):
            document = self.payload()
            document[key] = value
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.submit(document)

    def test_labels_must_follow_prediction_and_have_bounded_valid_lifetime(self):
        for issued, expires, clock in (
            (1999, 12000, 3000),
            (3001, 12000, 3000),
            (2000, 3000, 3000),
            (2000, 86402001, 3000),
            (True, 12000, 3000),
            (2000, 12000, True),
        ):
            document = {**self.payload(), "issued_at_ms": issued, "expires_at_ms": expires}
            with self.subTest(times=(issued, expires, clock)), self.assertRaises(Rejected):
                self.submit(document, clock=clock)

    def test_label_schema_count_duplicates_and_integer_type(self):
        for labels in (
            [],
            {},
            self.payload(1)["labels"] * 1001,
            [{"observation_id": "f" * 64, "label": True}],
            [{"observation_id": "f" * 64, "label": 2}],
            [{"observation_id": "bad", "label": 0}],
            [{"observation_id": "f" * 64, "label": 0, "extra": 0}],
            self.payload(1)["labels"] * 2,
        ):
            with self.subTest(size=len(labels)), self.assertRaises(Rejected):
                self.submit({**self.payload(), "labels": labels})

    def test_window_and_private_prediction_bits_are_bound_before_label_acceptance(self):
        changed = list(self.closed.predictions)
        changed[0] = (changed[0][0], False)
        for closed, expected in (
            (dataclasses.replace(self.closed, predictions=tuple(changed)), self.closed.sha256),
            (self.closed, "0" * 64),
            (dataclasses.replace(self.closed, content=b"{}"), self.closed.sha256),
        ):
            with self.assertRaises(Rejected):
                self.consumer(closed=closed, expected=expected)
        with self.assertRaises(Rejected):
            self.consumer(public="bad")
        with self.assertRaises(Rejected):
            self.consumer(closed={"not": "a closed window"})

    def test_negative_labels_do_not_create_positive_denominator(self):
        document = self.payload()
        for label in document["labels"]:
            label["label"] = 0
        result = self.submit(document)
        self.assertEqual(result["positives"], 0)
        self.assertEqual(result["true_positives"], 0)
        self.assertIsNone(result["alert"])
        self.assertNotIn("labels", result)
        self.assertNotIn("observation_id", canonical(result).decode())

    def test_malformed_prediction_ledger_is_rejected_even_with_a_matching_window_pin(self):
        original = self.closed.predictions
        malformed = (
            list(original),
            original[:-1],
            ([original[0][0], original[0][1]], *original[1:]),
            ((original[0][0], original[0][1], "extra"), *original[1:]),
            ((original[0][0], 1), *original[1:]),
            (original[1], *original[1:]),
        )
        for predictions in malformed:
            closed = dataclasses.replace(self.closed, predictions=predictions)
            with (
                self.subTest(size=len(predictions)),
                self.assertRaisesRegex(Rejected, "monitor_prediction_ledger_shape"),
            ):
                self.consumer(closed=closed)
        changed = ((original[0][0], False), *original[1:])
        document = self.closed.document()
        document["prediction_ledger_sha256"] = digest(canonical(changed))
        closed = dataclasses.replace(self.closed, content=canonical(document), predictions=changed)
        with self.assertRaisesRegex(Rejected, "monitor_prediction_ledger_binding"):
            self.consumer(closed=closed, expected=closed.sha256)
        with self.assertRaisesRegex(Rejected, "monitor_label_key"):
            self.consumer(public=signing.encode64(b"short"))


if __name__ == "__main__":
    unittest.main()
