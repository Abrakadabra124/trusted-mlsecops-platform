import tempfile
import unittest
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.controller_intake import check_readback, pinned


class ControllerIntakeContracts(unittest.TestCase):
    def test_changed_bytes_and_foreign_digest_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "packet"
            raw = canonical({"synthetic": True})
            pin = digest(raw)
            path.write_bytes(raw)
            self.assertEqual(pinned(path, pin), {"synthetic": True})
            with self.assertRaisesRegex(Rejected, "M21_pin_mismatch"):
                pinned(path, digest(b"other"))
            path.write_bytes(raw + b" ")
            with self.assertRaisesRegex(Rejected, "M21_pin_mismatch"):
                pinned(path, pin)

    def test_original_evaluation_cannot_be_replaced_by_matrix_positive(self):
        original = {"candidate_reference": "a", "holdout_access": {"slot": 1}}
        other = original | {"holdout_access": {"slot": 2}}
        matrix = {
            "positive": {"evaluation_reference": "second", "evaluation": other},
            "candidate_reference": "a",
            "model_digest": "model",
            "denials": [{"payload": {"id": 1}}, {"payload": {"id": 2}}],
            "controller": {"pod_uid": "scorer"},
        }
        observed = {
            "positive": original,
            "candidate_reference": "a",
            "model_digest": "model",
            "denials": [{"id": 1}, {"id": 2}],
            "release_ready": False,
            "controller": {"pod_uid": "reader"},
        }
        check_readback(matrix, observed, "first", original)
        for wrong in (
            {"positive": other},
            {"model_digest": "foreign"},
            {"denials": []},
            {"controller": {"pod_uid": "scorer"}},
        ):
            with self.subTest(wrong=wrong), self.assertRaises(Rejected):
                check_readback(matrix, observed | wrong, "first", original)
        with self.assertRaises(Rejected):
            check_readback(matrix, observed, "second", original)
