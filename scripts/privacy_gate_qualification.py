import ast
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

from mlsecops import privacy_gate as gate
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from scripts.kube_privacy_native_qualification import report


def fixture():
    value = report()
    source = {
        "source_revision": "a" * 40,
        "source_fingerprint": "b" * 64,
        "image_id": "sha256:" + "c" * 64,
    }
    value.update(
        schema_version=1,
        scope="actual-candidate-kubernetes-inference",
        source=source,
        started_at="2026-11-06T12:00:01+00:00",
        finished_at="2026-11-06T12:00:03+00:00",
        proposal_issued_at=1793966400,
        privacy_campaign_id="d" * 32,
        candidate_reference="1" * 64,
        proposal_reference="2" * 64,
        evaluation_reference="3" * 64,
        qualification_permit_sha256="4" * 64,
        method_materials="5" * 64,
    )
    value["controlled_cli"].update(privacy_campaign_id="e" * 32, runtime_source=source)
    return value, source


class PrivacyGateContracts(unittest.TestCase):
    def test_failure_diagnostic_never_exports_child_values_or_unknown_identifiers(self):
        for stdout in (
            b"private exception token",
            canonical({"cases": [{"id": "private-token", "status": "pass"}]}),
            canonical({"cases": [{"id": "allowed", "status": "fail"}]}),
            canonical({"cases": []}),
            canonical({"cases": [{"id": {}, "status": "pass"}]}),
            b"null",
        ):
            process = subprocess.CompletedProcess([], 1, stdout, b"private stderr token")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                gate.contract_diagnostic(process, {"allowed"})
            value = output.getvalue()
            self.assertNotIn("private", value)
            self.assertIn('"missing_count":1', value)

    def test_contract_cli_emits_only_canonical_summary_and_uses_failure_exit(self):
        from scripts import privacy_contracts

        class Sample(unittest.TestCase):
            def test_case(self):
                if failed:
                    self.fail("private diagnostic")
                print("private diagnostic")

        tree = ast.parse("class Sample:\n    def test_case(self): pass\n")
        for failed in (False, True):
            cases = []
            for module in privacy_contracts.MODULES:
                case = Sample("test_case")
                case.id = lambda module=module: module + ".Sample.test_case"
                cases.append(case)
            with (
                patch.object(ast, "parse", return_value=tree),
                patch.object(
                    unittest.defaultTestLoader,
                    "loadTestsFromNames",
                    return_value=unittest.TestSuite(cases),
                ),
                contextlib.redirect_stdout(io.StringIO()) as output,
                warnings.catch_warnings(),
                self.assertRaises(SystemExit) as stopped,
            ):
                warnings.simplefilter("ignore", RuntimeWarning)
                runpy.run_module("scripts.privacy_contracts", run_name="__main__")
            self.assertEqual(stopped.exception.code, int(failed))
            self.assertNotIn("private diagnostic", output.getvalue())

    def test_retained_primary_and_exact_private_packets_are_read_after_native_cleanup(self):
        value, _ = fixture()
        value["actual_refusal"]["campaign_id"] = "f" * 32
        value["native"]["audit"].update(public={}, packet_sha256="7" * 64)
        value["artifact_hashes"] = {
            name: digest(name.encode())
            for name in ("reference.json", "config.json", "request.json", "probe.json")
        }
        cli = value["controlled_cli"]
        cli["native"]["privacy"].update(snapshot={}, http=[], audit={"accepted": True})
        for rows in (
            cli["service_windows"],
            value["native"]["operator_observation"]["service_observations"],
        ):
            for row in rows.values():
                row["sha256"] = digest(b"service packet")
        for fault in (None, "primary", "artifact", "context", "cli-bytes", "cli-audit", "service"):
            with tempfile.TemporaryDirectory() as directory:
                state = Path(directory)
                actual_path = state / "candidate-inference" / value["privacy_campaign_id"]
                actual_path.mkdir(parents=True)
                for name in value["artifact_hashes"]:
                    (actual_path / name).write_bytes(name.encode())
                if fault == "artifact":
                    (actual_path / "probe.json").write_bytes(b"changed")
                context = {
                    "model_sha256": cli["model_sha256"],
                    "bundle_sha256": cli["subject_sha256"],
                }
                if fault == "context":
                    context["model_sha256"] = "0" * 64
                write_json(
                    state / "evidence/cli-privacy" / cli["privacy_campaign_id"] / "context.json",
                    context,
                )

                def packet(path):
                    if path.name == "closed-window":
                        return (
                            b"changed"
                            if fault == "cli-bytes"
                            else canonical(cli["native"]["privacy"])
                        )
                    return b"changed" if fault == "service" else b"service packet"

                with (
                    patch.object(
                        gate,
                        "verify_packet",
                        return_value={} if fault == "primary" else value["native"]["audit"],
                    ) as primary,
                    patch.object(gate.audit_snapshot, "load_packet", side_effect=packet) as load,
                    patch.object(
                        gate,
                        "verify_snapshot",
                        return_value={} if fault == "cli-audit" else {"accepted": True},
                    ),
                ):
                    if fault:
                        with self.subTest(fault=fault), self.assertRaises(Rejected):
                            gate.retained(state, state, value)
                    else:
                        result = gate.retained(state, state, value)
                        self.assertEqual(len(result), 6)
                        self.assertEqual(load.call_count, 5)
                        self.assertEqual(primary.call_args.args[2], value["source"])
                        self.assertEqual(primary.call_args.args[3], value["privacy_campaign_id"])

    def test_fresh_runner_clears_old_success_and_rejects_mutation_without_publishing(self):
        for fault in (None, "native", "projection", "source", "methods", "private", "stale"):
            with tempfile.TemporaryDirectory() as directory:
                state = Path(directory)
                value, source = fixture()
                before = {"file": "hash"}
                value["method_materials"] = digest(canonical(before))
                write_json(state / "evidence/privacy-gate.json", {"status": "pass", "stale": True})
                write_json(
                    state / "evidence/kubernetes-privacy-private.json",
                    {"status": "pass", "stale": True},
                )

                def native(*args):
                    for name in ("privacy-gate", "kubernetes-privacy-private"):
                        self.assertEqual(
                            read_json(state / f"evidence/{name}.json"),
                            {"status": "inconclusive", "release_ready": False},
                        )
                    if fault == "native":
                        raise Rejected("private failure")
                    if fault == "stale":
                        value["started_at"] = "2026-11-06T11:59:59+00:00"
                    write_json(state / "evidence/kubernetes-privacy-private.json", value)
                    return (
                        {} if fault == "projection" else gate.kube_privacy_native.projection(value)
                    )

                def retained(*args):
                    if fault == "private":
                        write_json(
                            state / "evidence/kubernetes-privacy-private.json", {"changed": True}
                        )
                    return {"retained": "9" * 64}

                with (
                    patch.object(gate, "hosted"),
                    patch.object(
                        gate,
                        "now",
                        side_effect=[
                            "2026-11-06T12:00:00+00:00",
                            "2026-11-06T12:00:04+00:00",
                            "2026-11-06T12:00:05+00:00",
                        ],
                    ),
                    patch.object(
                        gate, "source", side_effect=[source, {} if fault == "source" else source]
                    ),
                    patch.object(
                        gate,
                        "materials",
                        side_effect=[before, {} if fault == "methods" else before],
                    ),
                    patch.object(
                        gate,
                        "contracts",
                        return_value={
                            "cases": [
                                {
                                    "id": "controlled",
                                    "status": "pass",
                                    "expected": True,
                                    "actual": True,
                                }
                            ]
                        },
                    ),
                    patch.object(gate.kube_privacy_native, "qualify", side_effect=native),
                    patch.object(gate, "retained", side_effect=retained),
                ):
                    if fault:
                        with self.subTest(fault=fault), self.assertRaises(Rejected):
                            gate.qualify(state, state)
                        self.assertEqual(
                            read_json(state / "evidence/privacy-gate.json")["status"],
                            "inconclusive",
                        )
                    else:
                        result = gate.qualify(state, state)
                        self.assertEqual(result["checks"], 9)
                        self.assertFalse(result["release_ready"])
                        self.assertEqual(
                            result["input_digests"]["model_sha256"], value["model_sha256"]
                        )
                        self.assertNotIn("private-canary", canonical(result).decode())
                        self.assertNotIn("private_observation", result["artifact_hashes"])
                        self.assertNotIn("retained", result["artifact_hashes"])
                        self.assertEqual(read_json(state / "evidence/privacy-gate.json"), result)

    def test_contract_runner_is_fail_closed_for_skip_expected_failure_and_wrong_inventory(self):
        from scripts import privacy_contracts

        class Cases(unittest.TestCase):
            def test_ok(self):
                self.assertTrue(True)

            @unittest.skip("platform unavailable")
            def test_skipped(self):
                pass

            @unittest.expectedFailure
            def test_expected_failure(self):
                self.fail()

            def test_failure(self):
                self.fail()

        for name in ("test_ok", "test_skipped", "test_expected_failure", "test_failure"):
            case = Cases(name)
            with (
                patch.object(privacy_contracts, "case_ids", return_value={case.id()}),
                patch.object(
                    unittest.defaultTestLoader,
                    "loadTestsFromNames",
                    return_value=unittest.TestSuite([case]),
                ),
            ):
                result = privacy_contracts.qualify()
            self.assertEqual(result["status"], "pass" if name == "test_ok" else "fail")
        expected = privacy_contracts.case_ids()
        loaded = unittest.defaultTestLoader.loadTestsFromNames(privacy_contracts.MODULES)
        from scripts.evaluation_contracts import case_ids

        self.assertEqual(expected, case_ids(loaded))
        self.assertGreater(len(expected), 250)

    def reconcile(self, value, source):
        return gate.reconcile(
            value,
            source,
            started="2026-11-06T12:00:00+00:00",
            finished="2026-11-06T12:00:04+00:00",
            methods="5" * 64,
        )

    def test_composition_keeps_subjects_distinct_and_exports_only_finite_metrics(self):
        value, source = fixture()
        result = self.reconcile(value, source)
        self.assertEqual(result["closed_service_windows"], 4)
        self.assertNotIn("private-canary", canonical(result).decode())
        self.assertNotIn("packet_sha256", canonical(result).decode())

    def test_stale_future_naive_unbound_dirty_and_incomplete_reports_refuse(self):
        mutations = (
            lambda v: v.update(started_at="2026-11-06T11:59:59+00:00"),
            lambda v: v.update(finished_at="2026-11-06T12:00:05+00:00"),
            lambda v: v.update(finished_at="2026-11-06T12:00:00+00:00"),
            lambda v: v.update(started_at="2026-11-06T12:00:01"),
            lambda v: v.update(started_at=1),
            lambda v: v.update(proposal_issued_at=True),
            lambda v: v.update(proposal_issued_at=10**300),
            lambda v: v.update(privacy_campaign_id="../foreign"),
            lambda v: v.update(candidate_reference="not-a-digest"),
            lambda v: v.update(method_materials="0" * 64),
            lambda v: v.update(source_dirty=True),
            lambda v: v.update(release_ready=True),
            lambda v: v.update(scope="other"),
            lambda v: v["source"].update(source_revision="0" * 40),
            lambda v: v["controlled_cli"].update(runtime_source={}),
            lambda v: v["controlled_cli"].update(privacy_campaign_id=v["privacy_campaign_id"]),
            lambda v: v["controlled_cli"].update(model_sha256=v["model_sha256"]),
            lambda v: v["native"]["operator_observation"].update(service_windows=1),
            lambda v: v["native"]["cases"].pop(),
            lambda v: v["native"].update(primary_reverification={}),
        )
        for mutate in mutations:
            value, source = fixture()
            source = copy.deepcopy(source)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(Rejected):
                self.reconcile(value, source)
        for value in (None, {}, [], {"source": None}):
            with self.assertRaises(Rejected):
                self.reconcile(value, fixture()[1])

    def test_source_schema_and_digest_types_refuse(self):
        for field, wrong in (
            ("source_revision", "a" * 64),
            ("source_fingerprint", True),
            ("image_id", "tag:mutable"),
            ("unknown", "private"),
        ):
            value, source = fixture()
            source[field] = wrong
            with self.assertRaises(Rejected):
                self.reconcile(value, source)

    def test_required_contract_inventory_rejects_skip_extra_duplicate_wrong_count_and_failure(self):
        valid = {
            "scope": "controlled-M13-privacy-contracts",
            "status": "pass",
            "checks": 1,
            "cases": [{"id": "test.one", "status": "pass", "expected": True, "actual": True}],
        }
        with patch.object(gate.privacy_contracts, "case_ids", return_value={"test.one"}):
            for fault in (None, "exit", "skip", "extra", "duplicate", "count", "empty", "stderr"):
                value = copy.deepcopy(valid)
                if fault == "skip":
                    value["cases"][0]["status"] = "skipped"
                if fault == "extra":
                    value["cases"][0]["id"] = "test.foreign"
                if fault == "duplicate":
                    value["cases"] *= 2
                if fault == "count":
                    value["checks"] = True
                if fault == "empty":
                    value["cases"] = []
                process = subprocess.CompletedProcess(
                    [],
                    int(fault == "exit"),
                    canonical(value),
                    b"private" if fault == "stderr" else b"",
                )
                with patch.object(gate.subprocess, "run", return_value=process):
                    if fault is None:
                        self.assertEqual(gate.contracts(Path(".")), valid)
                    else:
                        with self.subTest(fault=fault), self.assertRaises(Rejected):
                            gate.contracts(Path("."))

    def test_hosted_guard_prevents_source_inspection_and_state_writes(self):
        with (
            patch.object(gate, "hosted", side_effect=Rejected("hosted")),
            patch.object(gate, "source") as source,
        ):
            with self.assertRaises(Rejected):
                gate.qualify(Path("."), Path(".runtime"))
            source.assert_not_called()

    def test_acceptance_dispatch_and_constant_failure_output(self):
        from mlsecops import acceptance

        root = Path(__file__).resolve().parents[1]
        evidence = {
            "status": "pass",
            "started_at": "2026-11-06T12:00:00+00:00",
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
            self.assertEqual(acceptance.report("M13", "local-cpu", root, state)["exit_code"], 2)
            for name in ("workspace.json", "kubeconfig", "storage.json", "storage-demo.json"):
                (state / name).write_bytes(b"fixture")
            with patch.object(gate, "qualify", return_value=evidence) as run:
                self.assertEqual(acceptance.report("M13", "local-cpu", root, state)["exit_code"], 0)
                for error, code in (
                    (Rejected("trust_hosted_runner_required"), 2),
                    (OSError("private"), 2),
                    (Rejected("private"), 1),
                    (ValueError("private"), 1),
                ):
                    run.side_effect = error
                    result = acceptance.report("M13", "local-cpu", root, state)
                    self.assertEqual(result["exit_code"], code)
                    self.assertNotIn("private", canonical(result).decode())


if __name__ == "__main__":
    unittest.main()
