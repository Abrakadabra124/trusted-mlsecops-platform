import copy
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import inference_gate as gate
from mlsecops.contracts import Rejected, canonical, read_json


class InferenceGateContracts(unittest.TestCase):
    def test_contract_inventory_includes_async_methods_and_matches_loader(self):
        from scripts.evaluation_contracts import case_ids as loaded_ids

        loaded = loaded_ids(
            unittest.defaultTestLoader.loadTestsFromNames(gate.inference_contracts.MODULES)
        )
        self.assertEqual(gate.inference_contracts.case_ids(), loaded)
        self.assertIn(
            "scripts.serving_http_qualification.ServingHttpContracts.test_strict_schema_and_nonfinite_input_are_422",
            loaded,
        )

    def test_dispatcher_has_fail_closed_prerequisites_and_maps_gate_results(self):
        from mlsecops import acceptance

        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            self.assertEqual(acceptance.report("M12", "local-cpu", root, state)["exit_code"], 2)
            for name in ("workspace.json", "kubeconfig", "storage.json", "storage-demo.json"):
                (state / name).write_bytes(b"fixture")
            evidence = {
                "status": "pass",
                "source_dirty": False,
                "cases": [],
                "checks": 0,
                "metrics": {},
                "limitations": [],
                "artifact_hashes": {},
                "input_digests": {"model": "a" * 64},
            }
            with patch.object(gate, "qualify", return_value=evidence) as runner:
                result = acceptance.report("M12", "local-cpu", root, state)
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(result["input_digests"]["model"], "a" * 64)
                for error, code in (
                    (Rejected("trust_hosted_runner_required"), 2),
                    (OSError(), 2),
                    (Rejected("M12_native_binding"), 1),
                ):
                    runner.side_effect = error
                    self.assertEqual(
                        acceptance.report("M12", "local-cpu", root, state)["exit_code"], code
                    )

    def setUp(self):
        self.source = {
            "source_revision": "r" * 40,
            "source_fingerprint": "f" * 64,
            "image_id": "sha256:" + "a" * 64,
        }
        native = {
            "status": "pass",
            "release_ready": False,
            "source_dirty": False,
            **self.source,
            "actual": {"candidate": "c" * 64, "proposal": "d" * 64, "model": "e" * 64},
            "actual_inference": {
                "source": self.source,
                "source_dirty": False,
                "status": "pass",
                "release_ready": False,
                "candidate_reference": "c" * 64,
                "proposal_reference": "d" * 64,
                "model_sha256": "e" * 64,
                "subject_sha256": "b" * 64,
                "artifact_hashes": {},
                "native": {
                    "status": "pass",
                    "release_ready": False,
                    "model_sha256": "e" * 64,
                    "subject_sha256": "b" * 64,
                    "max_golden_error": 0.0,
                    "cases": [
                        {"id": n, "status": "pass", "expected": True, "actual": True}
                        for n in sorted(gate.NATIVE_CASES)
                    ],
                },
            },
        }
        for phase, cases in (
            (
                "before_approval",
                [
                    "unapproved-or-revoked-ready-503",
                    "unapproved-or-revoked-predict-503",
                    "refused-before-worker-start",
                ],
            ),
            (
                "approved",
                [
                    "ordinary-CLI-ready-after-verified-load",
                    "ONNX-golden-parity",
                    "response-model-and-bundle-binding",
                    "same-worker-UID-across-requests",
                    "stopped-worker-503",
                ],
            ),
            (
                "after_revocation",
                ["unapproved-or-revoked-ready-503", "refused-before-worker-start"],
            ),
        ):
            native[phase] = {
                "status": "pass",
                "release_ready": False,
                "cases": [*cases, "worker-cleanup-confirmed"],
            }
        self.native = native

    def test_missing_duplicate_failed_and_type_confused_native_cases_rejected(self):
        self.assertEqual(len(gate.reconcile(self.native, self.source)), 60)
        for fault in ("missing", "duplicate", "failed", "type", "different", "field"):
            value = copy.deepcopy(self.native)
            cases = value["actual_inference"]["native"]["cases"]
            if fault == "missing":
                cases.pop()
            elif fault == "duplicate":
                cases[-1] = cases[0]
            elif fault == "failed":
                cases[0]["status"] = "fail"
            elif fault == "type":
                cases[0]["actual"] = 1
            elif fault == "different":
                cases[0]["actual"] = False
            else:
                cases[0]["extra"] = True
            with self.subTest(fault=fault), self.assertRaises(Rejected):
                gate.reconcile(value, self.source)

    def test_source_subject_and_actual_candidate_cannot_be_swapped(self):
        for path in (
            ("source_revision",),
            ("source_dirty",),
            ("release_ready",),
            ("actual", "model"),
            ("actual", "proposal"),
            ("actual", "candidate"),
            ("actual_inference", "source"),
            ("actual_inference", "native", "subject_sha256"),
            ("actual_inference", "native", "model_sha256"),
        ):
            value = copy.deepcopy(self.native)
            target = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = "wrong"
            with self.subTest(path=path), self.assertRaises(Rejected):
                gate.reconcile(value, self.source)

    def test_normal_cli_proof_is_mandatory_and_shape_errors_are_rejections(self):
        for phase in ("before_approval", "approved", "after_revocation"):
            value = copy.deepcopy(self.native)
            value[phase]["cases"] = []
            with self.assertRaisesRegex(Rejected, "normal_CLI"):
                gate.reconcile(value, self.source)
        for value in ({}, None, {**self.native, "actual_inference": None}):
            with self.assertRaises(Rejected):
                gate.reconcile(value, self.source)

    def test_contracts_require_exact_executed_set_and_success(self):
        expected = {"test.a", "test.b"}
        report = {
            "scope": gate.inference_contracts.SCOPE,
            "status": "pass",
            "checks": 2,
            "cases": [
                {"id": n, "status": "pass", "expected": True, "actual": True}
                for n in sorted(expected)
            ],
        }
        with (
            patch.object(gate.inference_contracts, "case_ids", return_value=expected),
            patch.object(gate.subprocess, "run") as run,
        ):
            run.return_value = SimpleNamespace(returncode=0, stdout=canonical(report))
            self.assertEqual(gate.contracts(Path.cwd()), report)
            for changes in ({"checks": True}, {"cases": report["cases"][:1]}, {"status": "fail"}):
                run.return_value.stdout = canonical({**report, **changes})
                with self.assertRaises(Rejected):
                    gate.contracts(Path.cwd())
            run.return_value.returncode = 1
            with self.assertRaisesRegex(Rejected, "failed"):
                gate.contracts(Path.cwd())
            run.side_effect = subprocess.TimeoutExpired("controlled", 300)
            with self.assertRaises(subprocess.TimeoutExpired):
                gate.contracts(Path.cwd())

    def test_gate_executes_native_and_retains_binding_and_detects_material_change(self):
        controlled = {
            "cases": [{"id": "contract", "status": "pass", "expected": True, "actual": True}]
        }
        for changed in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state = root / "state"
                names = [m.replace(".", "/") + ".py" for m in gate.inference_contracts.MODULES]
                names += [
                    "scripts/inference_contracts.py",
                    "scripts/evaluation_contracts.py",
                    "scripts/kube_candidate_native.py",
                    "scripts/kube_serving_native.py",
                    "scripts/candidate_serving_reader.py",
                    "scripts/kube_promotion_native.py",
                    "data.lock",
                ]
                for name in names:
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"fixture")

                def native(*args, **kwargs):
                    self.assertTrue(kwargs["include_candidate"])
                    if changed:
                        (root / "data.lock").write_bytes(b"changed")
                    return self.native

                with (
                    patch.object(gate, "hosted"),
                    patch.object(gate, "contracts", return_value=controlled),
                    patch.object(gate.kube_serving_native, "qualify", side_effect=native),
                    patch.object(
                        gate, "source_fingerprint", return_value=self.source["source_fingerprint"]
                    ),
                    patch.object(
                        gate,
                        "command",
                        side_effect=lambda args: (
                            self.source["source_revision"] if "rev-parse" in args else ""
                        ),
                    ),
                ):
                    if changed:
                        with self.assertRaisesRegex(Rejected, "inputs_changed"):
                            gate.qualify(root, state)
                        self.assertEqual(
                            read_json(state / "evidence/inference-gate.json")["status"],
                            "inconclusive",
                        )
                    else:
                        result = gate.qualify(root, state)
                        self.assertEqual(result["checks"], 61)
                        self.assertEqual(result["input_digests"]["model"], "e" * 64)
                        self.assertFalse(result["release_ready"])
                        self.assertEqual(
                            read_json(state / "evidence/inference-native.json"), self.native
                        )


if __name__ == "__main__":
    unittest.main()
