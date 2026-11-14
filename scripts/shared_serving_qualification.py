"""Contracts for joint M11/M12 evidence selection."""

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops import inference_gate
from mlsecops.contracts import Rejected, canonical, decode, digest, write_json
from scripts import shared_serving_native as shared


class SharedServingTests(unittest.TestCase):
    def test_proposal_pin_pair_must_be_present_and_equal(self):
        for pins in (
            {},
            {"M11_PROPOSAL_SHA256": "a" * 64},
            {
                "M11_PROPOSAL_SHA256": "a" * 64,
                "M12_PROPOSAL_SHA256": "b" * 64,
                "M11_DEMO_SHA256": "d" * 64,
            },
        ):
            with self.subTest(pins=pins), self.assertRaises(Rejected):
                shared.pins(pins)

    def test_only_one_expected_proposal_and_demo(self):
        env = dict(
            M11_PROPOSAL_SHA256="1" * 64, M12_PROPOSAL_SHA256="1" * 64, M11_DEMO_SHA256="2" * 64
        )
        self.assertEqual(shared.pins(env), ("1" * 64, "2" * 64))
        for override in (
            dict(M12_EARLY_SHA256="1" * 64),
            dict(M11_DEMO_SHA256="../input"),
            dict(M11_PROPOSAL_SHA256="", M12_PROPOSAL_SHA256=""),
        ):
            with self.subTest(override=override), self.assertRaises(Rejected):
                shared.pins({**env, **override})

    def test_only_original_actual_bytes_and_same_attempt_are_selected(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(shared, "hosted"),
            patch.object(shared, "owner") as owner,
            patch.object(shared, "retained", return_value={}) as retained,
        ):
            state = Path(tmp)
            owner.return_value = {"runner": {"attempt": "1"}, "source": {"image_id": "image"}}
            early = dict(
                owner=owner.return_value,
                prepared={"actual": {"job_outcome": "rejected"}},
                binding={"model": "frozen"},
                actual={"native": "original"},
            )

            def pin(path, record):
                write_json(state / path, record)
                return digest((state / path).read_bytes())

            first = pin(shared.EARLY, early)
            controlled = dict(actual=early["prepared"]["actual"], image_id="image")
            full = dict(early_sha256=first, controlled=controlled)

            def select(second, early_pin=first):
                with patch.dict(
                    os.environ, {shared.PIN: second, "M11_M12_ACTUAL_SHA256": early_pin}
                ):
                    return shared.lookup(state, state, "image")

            second = pin(shared.FULL, full)
            self.assertEqual(select(second)[1]["actual_inference"], early["actual"])
            retained.assert_called_once_with(state, early)
            for second_pin, early_pin in (
                (second, "0" * 64),
                ("f" * 64, first),
                ("../escape", first),
            ):
                with self.assertRaises(Rejected):
                    select(second_pin, early_pin)
            for changed in (
                dict(actual_inference=early["actual"]),
                dict(actual={}),
                dict(image_id="changed"),
            ):
                with self.assertRaises(Rejected):
                    select(pin(shared.FULL, {**full, "controlled": {**controlled, **changed}}))
            second = pin(shared.FULL, full)
            owner.return_value = {**early["owner"], "runner": {"attempt": "2"}}
            with self.assertRaises(Rejected):
                select(second)
            owner.return_value = early["owner"]
            pin(shared.EARLY, {**early, "actual": {}})
            with self.assertRaises(Rejected):
                select(second)
            (state / shared.EARLY).unlink()
            with self.assertRaises((Rejected, OSError)):
                select(second)

    def test_handoff_rejects_live_authority_or_sql_drift_before_rotation(self):
        early = dict(
            owner={},
            actual={
                "independent_authorities": {
                    "states": {"after_key": {"primary": 1, "model-revocation": 2}}
                }
            },
            sql_snapshot={"count": 3},
        )
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(shared, "hosted"),
            patch.object(shared, "owner", return_value={}),
            patch.object(shared, "retained"),
            patch.object(shared.kube_serving_native, "qualify") as rotation,
        ):
            state = Path(tmp)
            write_json(state / shared.EARLY, early)
            for primary, peer, sql in ((0, 2, 3), (1, 4, 3), (1, 2, 4)):
                with (
                    patch.object(shared.kube_authority_pair, "read", side_effect=[primary, peer]),
                    patch.object(shared, "snapshot", return_value={"count": sql}),
                    self.assertRaises(Rejected),
                ):
                    shared.late(state, state, "image", digest((state / shared.EARLY).read_bytes()))
            rotation.assert_not_called()

    def test_matrix_rejects_missing_rows_and_changed_negatives(self):
        actual = dict(
            native={"cases": [], "authority_target": "primary", "max_golden_error": 0.0},
            model_sha256="a" * 64,
            subject_sha256="b" * 64,
            qualification_permit_sha256="c" * 64,
        )
        rows = [
            dict(id=name, status="pass", expected=True, actual=True)
            for name in inference_gate.NATIVE_CASES
        ]
        for cases in ([], rows, rows + [rows[0]]):
            actual["native"]["cases"] = cases
            with self.assertRaises(Rejected):
                inference_gate.joint_cases(actual, {})

    def test_diagnostic_is_bounded_and_excludes_error_arguments(self):
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["joint", "actual"]),
            patch.object(shared, "hosted"),
            patch.object(shared, "capture", side_effect=ValueError("private-needle")),
            redirect_stdout(output),
        ):
            self.assertEqual(shared.main(), 1)
        self.assertNotIn("private-needle", output.getvalue())
        report = decode(output.getvalue().encode())
        self.assertEqual(set(report), {"stage", "status", "site", "callers", "request"})
        self.assertLessEqual(len(report["callers"]), 12)
        self.assertLess(len(canonical(report)), 4096)
