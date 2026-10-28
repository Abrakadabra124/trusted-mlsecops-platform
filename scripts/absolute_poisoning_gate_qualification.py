"""Controlled controller contracts. No container, ONNX parsing or model-quality claim."""

import copy
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from mlsecops import absolute_poisoning_gate as gate
from mlsecops import acceptance
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from mlsecops.prediction_protocol import response
from scripts import absolute_poisoning as protocol
from scripts.poisoning_evidence_qualification import IMAGE, ROOT, worker


class GateContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name)
        write_json(
            self.state / "workspace.json",
            {"product": "trusted-mlsecops", "schema_version": 1, "workspace_id": "a" * 32},
        )
        self.profile = read_json(ROOT / "policies/local-cpu.json")
        # The small controlled fixture exercises control flow. Locked native data is tested separately.
        self.train = [{"features": [0.2] * 6, "label": 1, "entity_id": 1}] * 14000
        self.validation = [{"features": [0.3] * 6, "label": 0, "entity_id": 2}]
        self.probes = [{"features": [0.4] * 6, "label": 1, "entity_id": 3}]
        self.triggered = [{"features": [0.5] * 6, "label": 1, "entity_id": 3}]
        self.materials = (self.profile, self.train, self.validation, self.probes, self.triggered)
        self.candidate = {
            "model": b"controlled-model",
            "metadata": {"input_digest": "a" * 64},
            "policy": {"training_seed": 17, "repeat_tolerance": 1e-6},
            "bindings": {"candidate_reference": "b" * 64, "evaluation_reference": "c" * 64},
        }
        self.scores = [0.9, 0.9]
        self.stack = self.enterContext(ExitStack())
        self.stack.enter_context(
            patch.object(gate.native, "materials", return_value=self.materials)
        )
        self.stack.enter_context(patch.object(gate, "source_fingerprint", return_value="d" * 64))
        self.stack.enter_context(
            patch.object(gate, "subject", side_effect=lambda *a: copy.deepcopy(self.candidate))
        )
        self.stack.enter_context(patch.object(gate, "resolve_image", return_value=IMAGE))
        self.stack.enter_context(
            patch.object(gate, "command", side_effect=lambda a: "" if "status" in a else "e" * 40)
        )
        self.stack.enter_context(patch.object(gate.native, "execute", side_effect=self.execute))
        self.stack.enter_context(
            patch.object(gate.evidence, "case_materials", side_effect=self.read_case)
        )
        self.stack.enter_context(patch.object(gate, "metrics", return_value={"status": "pass"}))
        self.stack.enter_context(patch.object(gate, "run_worker", side_effect=worker))

    def execute(self, root, directory, case, train, validation, views, profile, image, **kwargs):
        self.assertEqual(len(train), case["train_rows"])
        self.assertEqual(kwargs["experiment_policy"], protocol.policy())
        directory.mkdir()
        for name in gate.CASE_FILES:
            (directory / name).write_bytes(b"controlled primary")
        index = protocol.matrix().index(case)
        return {
            **case,
            "run_id": f"{index:032x}",
            "mutation_count": case["count"],
            "input_digest": "a" * 64,
        }, self.scores.copy()

    def read_case(
        self,
        directory,
        case,
        profile,
        train,
        validation,
        probes,
        triggered,
        inputs,
        revision,
        started,
        finished,
        **kwargs,
    ):
        self.assertEqual(kwargs["experiment_policy"], protocol.policy())
        return read_json(directory / "result.json"), self.scores.copy()

    def launch(self):
        self.report = gate.qualify(ROOT, self.state)
        self.campaign = self.state / "absolute-poisoning" / self.report["campaign_id"]
        self.manifest = read_json(self.campaign / "campaign.json")
        return self.report

    def reconcile(self, candidate=None):
        manifest = self.manifest
        return gate.reconcile(
            ROOT,
            self.campaign,
            candidate or self.candidate,
            manifest["inputs"],
            manifest["revision"],
            manifest["started_at"],
            self.report["finished_at"],
        )

    def test_42_green_cases_still_cannot_grant_independent_assurance(self):
        report = self.launch()
        self.assertEqual(report["status"], "inconclusive")
        self.assertEqual(report["component_status"], "pass")
        self.assertEqual(report["metrics"]["primary_files_verified"], 300)
        self.assertEqual(report["metrics"]["poisoned_runs"], 36)
        self.assertEqual(report["metrics"]["clean_controls"], 6)
        self.assertEqual(report["metrics"]["independent_challenges"], 0)
        self.assertEqual(report["checks"], 43)
        self.assertFalse(report["release_ready"])
        self.assertEqual(read_json(self.state / "evidence/absolute-poisoning-gate.json"), report)
        self.assertEqual(report["input_digests"]["model_digest"], digest(self.candidate["model"]))

    def test_failure_is_not_hidden_by_missing_challenges(self):
        with patch.object(gate, "metrics", return_value={"status": "fail"}):
            report = self.launch()
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["metrics"]["violating_scenarios"], 42)

    def test_rehashed_fraction_and_metrics_are_recomputed(self):
        self.launch()
        path = self.campaign / protocol.matrix()[0]["id"] / "result.json"
        original = read_json(path)
        for field, value in [
            ("fraction", 0.5),
            ("fraction", False),
            ("metrics", {"status": "fail"}),
        ]:
            with self.subTest(field=field, value=value):
                write_json(path, {**original, field: value})
                with self.assertRaises(Rejected):
                    self.reconcile()
        write_json(path, original)

    def test_missing_material_and_changed_manifest_or_locked_data_rejected(self):
        self.launch()
        for filename in [
            "campaign.json",
            "train.json",
            "validation.json",
            "probes.json",
            "triggered.json",
        ]:
            path = self.campaign / filename
            original = path.read_bytes()
            path.unlink()
            with self.assertRaises(Rejected):
                self.reconcile()
            path.write_bytes(canonical({}))
            with self.assertRaises(Rejected):
                self.reconcile()
            path.write_bytes(original)

    def test_candidate_model_features_response_and_execution_are_bound(self):
        self.launch()
        path = self.campaign / "candidate-binding.json"
        original = read_json(path)
        changes = [
            ("request", "model", "Zm9yZWlnbg=="),
            ("request", "features", [[0.1] * 6] * 2),
            ("response", "request_digest", "0" * 64),
            ("execution", "network", "host"),
        ]
        for section, field, value in changes:
            altered = copy.deepcopy(original)
            altered[section][field] = value
            write_json(path, altered)
            with self.subTest(section=section, field=field), self.assertRaises(Rejected):
                self.reconcile()
        write_json(path, original)

    def test_candidate_seed_training_and_actual_predictions_cannot_be_substituted(self):
        self.launch()
        for key, field, value in [
            ("policy", "training_seed", 99),
            ("metadata", "input_digest", "f" * 64),
        ]:
            candidate = copy.deepcopy(self.candidate)
            candidate[key][field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.reconcile(candidate)
        path = self.campaign / "candidate-binding.json"
        proof = read_json(path)
        proof["response"] = response(proof["request"], [0.1, 0.9], proof["response"]["scan"])
        write_json(path, proof)
        with self.assertRaisesRegex(Rejected, "prediction_binding"):
            self.reconcile()

    def test_malformed_prediction_proof_is_a_structured_refusal(self):
        self.launch()
        for value in [None, [], {}, {"request": None}]:
            write_json(self.campaign / "candidate-binding.json", value)
            with self.assertRaises(Rejected):
                self.reconcile()

    def test_primary_materials_and_revision_are_rechecked(self):
        self.launch()
        snapshot = gate.primary_hashes(self.campaign)
        with patch.object(
            gate, "primary_hashes", side_effect=[snapshot, {**snapshot, "extra": "f" * 64}]
        ):
            with self.assertRaisesRegex(Rejected, "primary_changed"):
                self.reconcile()
        with patch.object(gate, "command", return_value="f" * 40):
            with self.assertRaisesRegex(Rejected, "revision"):
                self.reconcile()

    def test_changed_subject_or_late_primary_materials_never_leave_a_green_report(self):
        def changed(*args):
            campaign = max(
                (self.state / "absolute-poisoning").iterdir(), key=lambda p: p.stat().st_mtime_ns
            )
            path = campaign / "train.json"
            path.write_bytes(path.read_bytes() + b" ")
            return copy.deepcopy(self.candidate)

        for side_effect in (
            [self.candidate, {**self.candidate, "model": b"changed"}],
            [self.candidate, self.candidate],
        ):
            with patch.object(gate, "subject", side_effect=side_effect):
                if side_effect[1] == self.candidate:
                    original = gate.subject
                    with patch.object(
                        gate,
                        "subject",
                        side_effect=lambda *a: (
                            original(*a) if original.call_count == 0 else changed(*a)
                        ),
                    ):
                        with self.assertRaises(Rejected):
                            gate.qualify(ROOT, self.state)
                else:
                    with self.assertRaises(Rejected):
                        gate.qualify(ROOT, self.state)
            report = read_json(self.state / "evidence/absolute-poisoning-gate.json")
            self.assertEqual(report["status"], "inconclusive")
            self.assertFalse(report["release_ready"])

    def test_bad_ownership_and_runtime_failures_leave_no_completed_evidence(self):
        with patch.object(gate, "resolve_image", side_effect=Rejected("required_tool_missing")):
            with self.assertRaisesRegex(Rejected, "required_tool_missing"):
                gate.qualify(ROOT, self.state)
        self.assertEqual(
            read_json(self.state / "evidence/absolute-poisoning-gate.json")["status"],
            "inconclusive",
        )
        write_json(self.state / "workspace.json", {})
        with self.assertRaises(Rejected):
            gate.qualify(ROOT, self.state)


class MetricContracts(unittest.TestCase):
    def test_clean_and_trigger_views_use_the_same_matched_control(self):
        with patch.object(gate.poisoning, "compare", return_value={"status": "pass"}) as compare:
            gate.metrics([{"label": 1}], [0.9, 0.8], [0.7, 0.6], "backdoor")
            self.assertEqual(compare.call_args.args[1:], ([0.9], [0.7], [0.8], [0.6]))
            gate.metrics([{"label": 1}], [0.9, 0.8], [0.7, 0.6], "label-flip")
            self.assertEqual(compare.call_args.args[1:], ([0.9], [0.7], [0.9], [0.7]))


class DispatchContracts(unittest.TestCase):
    def test_missing_state_incomplete_challenges_and_runtime_errors_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            self.assertEqual(
                acceptance.report("M22", "local-cpu", ROOT, state)["status"], "inconclusive"
            )
            for name in (
                "workspace.json",
                "storage.json",
                "storage-demo.json",
                "storage-trust.json",
                "trusted-keys.json",
            ):
                write_json(state / name, {})
            for status, code in [("inconclusive", 2), ("fail", 1)]:
                report = {
                    "status": status,
                    "source_dirty": False,
                    "cases": [{"id": "independent-reviewer-challenges", "status": "inconclusive"}],
                    "checks": 43,
                    "metrics": {"component_status": "pass", "independent_challenges": 0},
                    "limitations": ["Independent challenges absent"],
                    "artifact_hashes": {},
                    "input_digests": {"candidate_reference": "a" * 64},
                }
                write_json(state / "evidence/absolute-poisoning-gate.json", report)
                with patch.object(gate, "qualify", return_value=report):
                    actual = acceptance.report("M22", "local-cpu", ROOT, state)
                self.assertEqual((actual["status"], actual["exit_code"]), (status, code))
                self.assertEqual(actual["input_digests"]["candidate_reference"], "a" * 64)
                self.assertIn("absolute-poisoning_gate", actual["artifact_hashes"])
            for error, status in [
                (Rejected("M22_candidate_model_binding"), "fail"),
                (Rejected("required_tool_missing"), "inconclusive"),
                (OSError(), "inconclusive"),
            ]:
                with patch.object(gate, "qualify", side_effect=error):
                    self.assertEqual(
                        acceptance.report("M22", "local-cpu", ROOT, state)["status"], status
                    )
