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
    def test_offline_source_pin_detects_restart_or_container_replacement(self):
        from scripts import shared_serving_receipt as receipts

        marker = dict(container_id="owned")
        observed = dict(
            State=dict(Running=False, Status="exited", StartedAt="start", FinishedAt="stop"),
            RestartCount=0,
        )
        with (
            patch.object(receipts.storage_bootstrap, "validate", return_value=marker),
            patch.object(receipts.storage_bootstrap, "inspect", return_value=observed),
        ):
            original = receipts.offline_pin(Path(".runtime"))
            for field, value in (("StartedAt", "next start"), ("FinishedAt", "next stop")):
                with patch.dict(observed["State"], {field: value}):
                    self.assertNotEqual(original, receipts.offline_pin(Path(".runtime")))
            with patch.dict(marker, {"container_id": "other"}):
                self.assertNotEqual(original, receipts.offline_pin(Path(".runtime")))
            with patch.dict(observed["State"], {"Running": True}), self.assertRaises(Rejected):
                receipts.offline_pin(Path(".runtime"))

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

    def test_m12_replays_its_own_measurements_and_keeps_the_unfiltered_probe(self):
        from scripts.inference_gate_qualification import InferenceGateContracts

        fixture = InferenceGateContracts()
        fixture.setUp()
        native = fixture.native
        stamp = "1970-01-01T00:03:20+00:00"
        native["started_at"] = stamp
        actual = native["actual_inference"]
        actual.update(started_at=stamp, qualification_permit_sha256="c" * 64)
        baseline = actual["native"]
        baseline["authority_target"] = "primary"
        envelope = {"fixture": "permit"}
        grouped = {
            200: "verified-ready golden-status 64KiB-accepted 100-rows-status outside-support-status ready-after-invalid",
            401: "unauthorized-401",
            413: "413-over-64KiB",
            429: "429-busy",
            100: "100-rows-count",
            503: "stopped-worker-503 stopped-worker-not-ready",
            actual["subject_sha256"]: "golden-bundle ready-bundle",
            actual["model_sha256"]: "golden-model ready-model",
            "abstain": "outside-support-abstains",
            "candidate-qualification": "qualification-audit-context",
            "unexpected_fields": "unsigned-permit-signature-reason",
            "invalid_signature_count": "unsigned-proposal-signature-reason",
            actual["qualification_permit_sha256"]: "qualification-permit-payload",
            digest(canonical(envelope)): "qualification-permit-envelope",
            None: "outside-support-no-score",
        }
        observed = {name: value for value, names in grouped.items() for name in names.split()}
        observed.update(
            {
                "initial-worker-absence": 0,
                "final-worker-absence": 0,
                "one-persistent-worker": 1,
                "actual-candidate-not-release": False,
                "golden-parity-1e-6": True,
                "finite-bounded-scores": True,
            }
        )
        for name in inference_gate.NATIVE_CASES - observed.keys():
            if name.startswith("422-"):
                observed[name] = 422
            elif name.endswith("-503"):
                observed[name] = 503
            elif name.endswith("-worker-constructions") or name.endswith("-cleanup"):
                observed[name] = int(name == "malformed-model-worker-constructions")
        observed["primary-only-clock-row"] = True
        baseline["cases"] = [
            dict(id=k, status="pass", actual=v, expected=v) for k, v in observed.items()
        ]
        self.assertEqual(len(inference_gate.joint_cases(actual, envelope)), 62)
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(inference_gate, "hosted"),
            patch.object(
                inference_gate,
                "source_fingerprint",
                return_value=fixture.source["source_fingerprint"],
            ),
            patch.object(
                inference_gate,
                "command",
                side_effect=lambda cmd: (
                    "" if "status" in cmd else fixture.source["source_revision"]
                ),
            ),
            patch.object(inference_gate, "contracts", return_value={"cases": []}),
            patch.object(inference_gate.kube_serving_native, "prepare") as prepare,
            patch.dict(os.environ, {"M11_M12_ACTUAL_SHA256": "8" * 64}, clear=True),
        ):
            state = Path(tmp)
            root = Path(__file__).resolve().parents[1]
            with self.assertRaisesRegex(Rejected, "M12_joint_native_required"):
                inference_gate.qualify(root, state)
            frozen = {"input_files": {"evidence/release-native.json": "1" * 64}}
            with (
                patch.dict(os.environ, {shared.PIN: "7" * 64}),
                patch.object(
                    shared, "lookup", return_value=(frozen, native, {"permit_envelope": envelope})
                ),
            ):
                report = inference_gate.qualify(root, state)
                self.assertEqual(report["metrics"]["native_cases"], 62)
                self.assertEqual(report["artifact_hashes"]["pinned_actual"], "8" * 64)
                self.assertEqual(
                    decode((state / "evidence/inference-native.json").read_bytes())[
                        "actual_inference"
                    ]["native"],
                    baseline,
                )
                row = next(
                    row for row in baseline["cases"] if row["id"] == "actual-candidate-not-release"
                )
                row.update(actual=0, expected=0)
                with self.assertRaisesRegex(Rejected, "M12_joint_native_cases"):
                    inference_gate.qualify(root, state)
            prepare.assert_not_called()
