import contextlib
import copy
import io
import runpy
import subprocess
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

from mlsecops import trust_acceptance
from mlsecops.contracts import Rejected, canonical, read_json
from scripts import trust_gate_qualification as gate_tests
from scripts.trust_gate_fixtures import fixture


class TrustAcceptanceContracts(unittest.TestCase):
    def test_acceptance_dispatches_M11_and_reports_missing_runtime_without_success(self):
        from mlsecops import acceptance

        root = Path(__file__).resolve().parents[1]
        evidence = {
            "status": "pass",
            "started_at": "2026-11-06T00:00:00+00:00",
            "source_dirty": False,
            "cases": [],
            "checks": 0,
            "metrics": {},
            "limitations": [],
            "artifact_hashes": {},
            "input_digests": {"model": "a" * 64},
        }
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            self.assertEqual(acceptance.report("M11", "local-cpu", root, state)["exit_code"], 2)
            for name in ("workspace.json", "kubeconfig", "storage.json", "storage-demo.json"):
                (state / name).write_bytes(b"owned fixture")
            with patch.object(trust_acceptance, "qualify", return_value=evidence) as runner:
                result = acceptance.report("M11", "local-cpu", root, state)
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(result["input_digests"]["model"], "a" * 64)
                for error, code in (
                    (Rejected("trust_hosted_runner_required"), 2),
                    (OSError("private"), 2),
                    (Rejected("M11_native_binding"), 1),
                    (ValueError("private"), 1),
                ):
                    runner.side_effect = error
                    failed = acceptance.report("M11", "local-cpu", root, state)
                    self.assertEqual(failed["exit_code"], code)
                    self.assertNotIn("private", canonical(failed).decode())

    def test_contract_cli_exit_code_distinguishes_pass_from_skip(self):
        class Sample(unittest.TestCase):
            def test_pass(self):
                self.assertTrue(True)

            @unittest.skip("unavailable")
            def test_skip(self):
                pass

        for method, expected in (("test_pass", 0), ("test_skip", 1)):
            with (
                patch.object(
                    unittest.defaultTestLoader,
                    "loadTestsFromNames",
                    return_value=unittest.TestSuite([Sample(method)]),
                ),
                contextlib.redirect_stdout(io.StringIO()),
                warnings.catch_warnings(),
                self.assertRaises(SystemExit) as stopped,
            ):
                warnings.simplefilter("ignore", RuntimeWarning)
                runpy.run_module("scripts.trust_contracts", run_name="__main__")
            self.assertEqual(stopped.exception.code, expected)

    def test_current_controlled_inventory_executes_and_rejects_skips(self):
        from scripts import trust_contracts

        report = trust_contracts.qualify()
        self.assertEqual(report["status"], "pass")
        self.assertEqual({c["id"] for c in report["cases"]}, trust_contracts.case_ids())

        class Skipped(unittest.TestCase):
            @unittest.skip("unavailable does not mean pass")
            def test_missing(self):
                pass

        with patch.object(
            trust_contracts.unittest.defaultTestLoader,
            "loadTestsFromNames",
            return_value=unittest.TestSuite([Skipped("test_missing")]),
        ):
            self.assertEqual(trust_contracts.qualify()["status"], "fail")

    def test_material_inventory_detects_host_code_and_policy_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (
                "mlsecops/core.py",
                "scripts/probe.py",
                "data.lock",
                "uv.lock",
                "pyproject.toml",
                ".python-version",
                "Dockerfile",
                "policies/local-cpu.json",
            ):
                p = root / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"initial")
            before = trust_acceptance.materials(root)
            self.assertEqual(len(before), 8)
            (root / "scripts/probe.py").write_bytes(b"changed")
            self.assertNotEqual(before, trust_acceptance.materials(root))

    def test_fresh_runner_uses_one_source_prepares_before_checks_and_never_grants_ready(self):
        native, source = fixture()
        native["actual_inference"]["started_at"] = "1970-01-01T00:03:20+00:00"
        native["actual_inference"]["artifact_hashes"] = {"probe.json": "d" * 64}
        signers, _ = gate_tests.TrustGateContracts().signer()
        rotation = {
            "status": "pass",
            "release_ready": False,
            **{k: source[k] for k in ("source_revision", "source_fingerprint")},
            "cases": [str(i) for i in range(37)],
            "rotations": ["a" * 64, "b" * 64, "c" * 64],
            "head_sequence": 4,
            "policy_version": 4,
        }
        contracts = {
            "status": "pass",
            "scope": "controlled-M11-contracts",
            "checks": 1,
            "cases": [
                {"id": "controlled-test", "status": "pass", "expected": True, "actual": True}
            ],
        }
        prepared = {**source, "profile": {"image_id": source["image_id"]}}
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            for failure in (None, "source", "descriptor", "native", "signer"):
                value = copy.deepcopy(native)
                if failure == "descriptor":
                    value["actual_inference"]["proposal_issued_at"] = 1000
                if failure == "native":
                    value["actual_inference"]["key_revocation"]["status"] = "fail"
                signature = copy.deepcopy(signers)
                if failure == "signer":
                    signature["workers_removed"] = 5
                events = []

                def prepared_source(*args):
                    events.append("prepare")
                    return prepared

                def controlled(*args):
                    events.append("contracts")
                    return contracts

                with (
                    patch.object(trust_acceptance, "hosted"),
                    patch.object(
                        trust_acceptance,
                        "materials",
                        side_effect=[
                            {"code": "a" * 64},
                            {"code": ("b" if failure == "source" else "a") * 64},
                        ],
                    ),
                    patch.object(
                        trust_acceptance,
                        "command",
                        side_effect=lambda args: (
                            "" if "status" in args else source["source_revision"]
                        ),
                    ),
                    patch.object(
                        trust_acceptance,
                        "source_fingerprint",
                        return_value=source["source_fingerprint"],
                    ),
                    patch.object(trust_acceptance, "now", return_value="1970-01-01T00:03:20+00:00"),
                    patch.object(
                        trust_acceptance.kube_serving_native, "prepare", side_effect=prepared_source
                    ),
                    patch.object(trust_acceptance, "controlled_contracts", side_effect=controlled),
                    patch.object(
                        trust_acceptance.kube_serving_native, "qualify", return_value=value
                    ) as runtime,
                    patch.object(
                        trust_acceptance.release_key_native, "qualify", return_value=rotation
                    ),
                    patch.object(
                        trust_acceptance.release_key_serving_native,
                        "qualify",
                        return_value=signature,
                    ),
                ):
                    if failure:
                        with self.assertRaises(Rejected):
                            trust_acceptance.qualify(state, state)
                        self.assertEqual(
                            read_json(state / "evidence/trust-gate.json")["status"], "inconclusive"
                        )
                    else:
                        report = trust_acceptance.qualify(state, state)
                        self.assertEqual(report["status"], "pass")
                        self.assertFalse(report["release_ready"])
                        self.assertEqual(
                            report["input_digests"]["candidate_reference"],
                            value["actual"]["candidate"],
                        )
                        self.assertEqual(report["checks"], len(report["cases"]))
                        self.assertEqual(report, read_json(state / "evidence/trust-gate.json"))
                    self.assertEqual(events, ["prepare", "contracts"])
                    self.assertTrue(runtime.call_args.kwargs["include_trust_lifecycle"])
                    self.assertTrue(runtime.call_args.kwargs["include_key_revocation"])

    def test_hosted_guard_precedes_any_mutation(self):
        with (
            patch.object(
                trust_acceptance, "hosted", side_effect=Rejected("trust_hosted_runner_required")
            ),
            patch.object(trust_acceptance, "write_json") as write,
        ):
            with self.assertRaises(Rejected):
                trust_acceptance.qualify(Path("root"), Path("state"))
        write.assert_not_called()

    def test_controlled_report_requires_complete_current_inventory(self):
        good = {
            "status": "pass",
            "scope": "controlled-M11-contracts",
            "checks": 1,
            "cases": [{"id": "test.case", "status": "pass", "expected": True, "actual": True}],
        }
        for change in ({}, {"checks": True}, {"cases": []}, {"status": "fail"}, {"scope": "other"}):
            payload = canonical({**good, **change})
            process = subprocess.CompletedProcess([], 0, payload, b"")
            with (
                patch.object(
                    trust_acceptance.trust_contracts, "case_ids", return_value={"test.case"}
                ),
                patch.object(trust_acceptance.subprocess, "run", return_value=process),
            ):
                if change:
                    with self.assertRaises(Rejected):
                        trust_acceptance.controlled_contracts(Path.cwd())
                else:
                    self.assertEqual(trust_acceptance.controlled_contracts(Path.cwd()), good)
        with patch.object(
            trust_acceptance.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, b"", b"private"),
        ):
            with self.assertRaisesRegex(Rejected, "M11_contracts_failed"):
                trust_acceptance.controlled_contracts(Path.cwd())


if __name__ == "__main__":
    unittest.main()
