import copy
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import acceptance
from mlsecops import robustness_gate as gate
from mlsecops.contracts import Rejected, canonical, digest, now, read_json, write_json
from mlsecops.prediction_protocol import response
from scripts import robustness, robustness_contracts
from scripts.poisoning_evidence_qualification import IMAGE, ROOT, worker


class CandidateParityContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.campaign = Path(self.temporary.name)
        self.rows = [{"entity_id": i, "features": [0.5] * 6, "label": i % 2} for i in range(3000)]
        self.clean = [0.9 if row["label"] else 0.1 for row in self.rows]
        self.corners = [self.clean.copy() for _ in range(4)]
        for scores in self.corners:
            for i in range(1, 401, 2):
                scores[i] = 0.1
        self.training = {
            "action": "train",
            "train": self.rows,
            "seed": 17,
            "features": [row["features"] for row in self.rows],
        }
        self.candidate = {
            "metadata": {"input_digest": digest(canonical(self.training))},
            "policy": {"parity_tolerance": 1e-5, "repeat_tolerance": 1e-6},
        }
        for name, value in {
            "validation.json": self.rows,
            "probes.json": self.rows,
            "request-0.json": self.training,
            "response-0.json": {
                "input_digest": digest(canonical(self.training)),
                "python_scores": self.clean,
            },
            "clean.json": self.clean,
            "attack.json": robustness.select(
                [r["features"] for r in self.rows], self.clean, self.corners
            ),
        }.items():
            write_json(self.campaign / name, value)
        self.scores = self.clean + self.clean + [v for scores in self.corners for v in scores]

    def test_actual_candidate_preserves_failing_evasion_and_records_golden_parity(self):
        result = gate.bind_candidate(self.campaign, self.candidate, self.scores)
        self.assertEqual(result["metrics"]["status"], "fail")
        self.assertEqual(result["parity"]["rows"], 3000)
        self.assertEqual(result["parity"]["max_error"], 0.0)
        self.assertEqual(result["reference_replay_error"], 0.0)

    def test_wrong_candidate_training_count_scores_or_policy_fail_closed(self):
        for mutate in (
            lambda c, s: c["metadata"].update(input_digest="a" * 64),
            lambda c, s: c["policy"].update(parity_tolerance=1e-4),
            lambda c, s: s.pop(),
            lambda c, s: s.__setitem__(0, float("nan")),
            lambda c, s: s.__setitem__(0, 0.2),
            lambda c, s: s.__setitem__(3000, 0.2),
        ):
            candidate, scores = copy.deepcopy(self.candidate), self.scores.copy()
            mutate(candidate, scores)
            with self.subTest(mutation=mutate), self.assertRaises(Rejected):
                gate.bind_candidate(self.campaign, candidate, scores)

    def test_threshold_label_mismatch_rejected_even_with_small_probability_error(self):
        values = self.clean.copy()
        values[0] = 0.5 + 1.1e-5
        write_json(
            self.campaign / "response-0.json",
            {"input_digest": digest(canonical(self.training)), "python_scores": values},
        )
        scores = self.scores.copy()
        scores[0] = 0.5 - 1e-8
        with self.assertRaises(Rejected):
            gate.bind_candidate(self.campaign, self.candidate, scores)


class GateFlowContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = CandidateParityContracts()
        cls.fixture.setUp()
        cls.addClassCleanup(cls.fixture.doCleanups)

    def flow(self, mode="fail"):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            campaign = state / "robustness" / ("a" * 32)
            shutil.copytree(self.fixture.campaign, campaign)
            write_json(campaign / "train.json", self.fixture.rows)
            candidate = {
                **self.fixture.candidate,
                "model": b"controlled-model",
                "bindings": {"candidate_reference": "b" * 64, "evaluation_reference": "c" * 64},
            }
            report = {
                "campaign_id": "a" * 32,
                "source_dirty": False,
                "source_revision": "d" * 40,
                "input_digests": {"model": "e" * 64},
                "artifact_hashes": {},
                "status": "fail",
                "protocol": robustness.policy(),
            }
            repeated = copy.deepcopy(candidate)
            if mode == "changed-subject":
                repeated["model"] = b"changed"
            if mode == "summary":
                report["status"] = "pass"
            if mode == "protocol":
                report["protocol"]["maximum_recall_drop"] = 1.0
            if mode == "shape":
                del report["input_digests"]
            if mode == "frozen":
                write_json(campaign / "train.json", [])
            if mode == "training":
                changed = copy.deepcopy(self.fixture.training)
                changed["seed"] = 18
                write_json(campaign / "request-0.json", changed)

            def native(*args):
                return {
                    **report,
                    "started_at": "2020-01-01T00:00:00+00:00" if mode == "stale" else now(),
                }

            def predict(image, request):
                output, execution = worker(image, request)
                scores = (
                    self.fixture.scores if len(request["features"]) > 1 else self.fixture.clean[:1]
                )
                if mode == "foreign-worker":
                    execution["image_id"] = "sha256:" + "f" * 64
                if mode == "mixed" and len(scores) == 1:
                    scores = [0.8]
                return response(request, scores, output["scan"]), execution

            original_decide = gate.advisory.decide

            def decide(rows, predictor):
                if mode == "ood":
                    return [{"decision": "score", "score": None}]
                return original_decide(rows, predictor)

            with (
                patch.object(gate.advisory, "decide", side_effect=decide),
                patch.object(gate, "run_contracts", return_value={"cases": []}),
                patch.object(gate, "resolve_image", return_value=IMAGE),
                patch.object(gate, "subject", side_effect=[candidate, repeated]),
                patch.object(gate.robustness_native, "qualify", side_effect=native),
                patch.object(
                    gate.robustness_native,
                    "materials",
                    return_value=(
                        {"training_seed": 17, "repeat_tolerance": 1e-6},
                        self.fixture.rows,
                        self.fixture.rows,
                        self.fixture.rows,
                    ),
                ),
                patch.object(
                    gate.robustness_native,
                    "reconcile",
                    side_effect=[
                        {"status": "fail"},
                        {"status": "pass"} if mode == "changed-primary" else {"status": "fail"},
                    ],
                ),
                patch.object(gate, "run_worker", side_effect=predict),
            ):
                if mode != "fail":
                    with self.assertRaises(Rejected):
                        gate.qualify(ROOT, state)
                    self.assertEqual(
                        read_json(state / "evidence/robustness-gate.json")["status"], "inconclusive"
                    )
                    return
                result = gate.qualify(ROOT, state)
            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["metrics"]["actual_candidate_predictions"], 18001)
            self.assertEqual(result["metrics"]["outside_support_abstentions"], 12)
            self.assertEqual(result["input_digests"]["model_digest"], digest(candidate["model"]))

    def test_fresh_actual_candidate_flow_preserves_evasion_failure(self):
        self.flow()

    def test_stale_forged_or_changed_materials_cannot_be_accepted(self):
        for mode in (
            "stale",
            "changed-subject",
            "changed-primary",
            "summary",
            "protocol",
            "shape",
            "frozen",
            "training",
            "foreign-worker",
            "mixed",
            "ood",
        ):
            with self.subTest(mode=mode):
                self.flow(mode)


class ContractsAndDispatch(unittest.TestCase):
    def test_empty_controlled_execution_cannot_report_success(self):
        with patch.object(
            robustness_contracts.unittest.defaultTestLoader,
            "loadTestsFromNames",
            return_value=unittest.TestSuite(),
        ):
            result = robustness_contracts.qualify()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["cases"], [])

    def test_failed_missing_duplicate_and_forged_contract_results_reject(self):
        expected = sorted(robustness_contracts.case_ids(ROOT))
        report = {
            "status": "pass",
            "scope": robustness_contracts.SCOPE,
            "checks": len(expected),
            "cases": [{"id": name, "status": "pass"} for name in expected],
        }
        with patch.object(
            gate.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=0, stdout=canonical(report)),
        ):
            self.assertEqual(gate.run_contracts(ROOT), report)
        for mutate in (
            lambda r: r.update(status="fail"),
            lambda r: r.update(scope="unrelated"),
            lambda r: r.update(checks=True),
            lambda r: r["cases"].pop(),
            lambda r: r["cases"].append(r["cases"][0]),
        ):
            forged = copy.deepcopy(report)
            mutate(forged)
            with (
                patch.object(
                    gate.subprocess,
                    "run",
                    return_value=SimpleNamespace(returncode=0, stdout=canonical(forged)),
                ),
                self.assertRaises(Rejected),
            ):
                gate.run_contracts(ROOT)
        with (
            patch.object(gate.subprocess, "run", return_value=SimpleNamespace(returncode=1)),
            self.assertRaises(Rejected),
        ):
            gate.run_contracts(ROOT)

    def test_missing_candidate_never_dispatches_runtime(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(gate, "qualify") as run:
            result = acceptance.report("M09", "local-cpu", ROOT, Path(temporary))
            self.assertEqual(result["status"], "inconclusive")
            run.assert_not_called()

    def test_dispatch_preserves_gate_result_and_runtime_unavailability(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            for name in (
                "workspace.json",
                "storage.json",
                "storage-demo.json",
                "storage-trust.json",
                "trusted-keys.json",
            ):
                write_json(state / name, {})
            for status, code in (("pass", 0), ("fail", 1), ("inconclusive", 2)):
                evidence = {
                    "status": status,
                    "source_dirty": False,
                    "cases": [],
                    "checks": 0,
                    "metrics": {},
                    "limitations": [],
                    "artifact_hashes": {},
                    "input_digests": {},
                }
                write_json(state / "evidence/robustness-gate.json", evidence)
                with patch.object(gate, "qualify", return_value=evidence):
                    result = acceptance.report("M09", "local-cpu", ROOT, state)
                self.assertEqual((result["status"], result["exit_code"]), (status, code))
            for error, status in (
                (Rejected("M09_bad_subject"), "fail"),
                (Rejected("required_tool_missing"), "inconclusive"),
                (OSError("private"), "inconclusive"),
                (subprocess.TimeoutExpired("worker", 3), "inconclusive"),
            ):
                with patch.object(gate, "qualify", side_effect=error):
                    result = acceptance.report("M09", "local-cpu", ROOT, state)
                self.assertEqual(result["status"], status)
                self.assertNotIn("private", canonical(result).decode())


if __name__ == "__main__":
    unittest.main()
