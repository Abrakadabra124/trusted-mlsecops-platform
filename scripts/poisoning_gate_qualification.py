import contextlib
import copy
import io
import runpy
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import acceptance, poisoning_gate
from mlsecops.contracts import Rejected, canonical, digest, now, read_json, write_json
from mlsecops.prediction_protocol import response
from scripts import poisoning, poisoning_contracts, poisoning_native
from scripts.poisoning_evidence_qualification import IMAGE, ROOT, worker


class CandidateBindingContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.campaign = Path(self.temporary.name)
        self.probes = [{"entity_id": i, "features": [0.5] * 6, "label": i % 2} for i in range(1200)]
        write_json(self.campaign / "probes.json", self.probes)
        self.scores = [0.9 if row["label"] else 0.1 for row in self.probes] * 2
        self.subject = {
            "metadata": {"input_digest": "a" * 64},
            "policy": {"training_seed": 17, "repeat_tolerance": 1e-6},
        }
        self.records = []
        for index, case in enumerate(poisoning.matrix()):
            scores = self.scores.copy()
            if case["family"] != "clean":
                scores = [0.1] * len(scores)
            metrics = poisoning.compare(
                self.probes, self.scores[:1200], scores[:1200], self.scores[:1200], scores[:1200]
            )
            write_json(self.campaign / case["id"] / "security-scores.json", scores)
            self.records.append(
                {
                    **case,
                    "run_id": f"{index:032x}",
                    "mutation_count": case["count"],
                    "input_digest": "a" * 64,
                    "metrics": metrics,
                    "artifacts": {"security-scores": digest(canonical(scores) + b"\n")},
                }
            )

    def bind(self, records=None, scores=None):
        return poisoning_gate.bind_candidate(
            self.campaign,
            self.records if records is None else records,
            self.subject,
            self.scores if scores is None else scores,
        )

    def test_candidate_binding_preserves_all_measured_failures(self):
        records, error = self.bind()
        self.assertEqual(poisoning_native.summarize(records)["violating_scenarios"], 30)
        self.assertEqual(error, 0.0)
        self.assertEqual(len(records), 35)

    def test_foreign_training_input_or_predictions_cannot_borrow_a_campaign(self):
        self.subject["metadata"]["input_digest"] = "b" * 64
        with self.assertRaisesRegex(Rejected, "candidate_training"):
            self.bind()
        self.subject["metadata"]["input_digest"] = "a" * 64
        changed = self.scores.copy()
        changed[0] = 0.2
        with self.assertRaisesRegex(Rejected, "candidate_prediction"):
            self.bind(scores=changed)

    def test_changed_primary_scores_and_wrong_seed_are_rejected(self):
        path = self.campaign / "clean-17/security-scores.json"
        write_json(path, [0.0] * len(self.scores))
        with self.assertRaisesRegex(Rejected, "candidate_scores_changed"):
            self.bind()
        self.subject["policy"]["training_seed"] = 19
        with self.assertRaisesRegex(Rejected, "candidate_seed"):
            self.bind()


class DispatchContracts(unittest.TestCase):
    def test_missing_candidate_prerequisites_do_not_run_workers(self):
        root = Path(__file__).resolve().parents[1]
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(poisoning_gate, "qualify") as run,
        ):
            result = acceptance.report("M08", "local-cpu", root, Path(temporary))
        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("candidate", " ".join(result["residual_risks"]))
        run.assert_not_called()

    def test_fail_and_inconclusive_campaigns_remain_nonzero(self):
        for status, code in (("pass", 0), ("fail", 1), ("inconclusive", 2)):
            with tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                for name in (
                    "workspace",
                    "storage",
                    "storage-demo",
                    "storage-trust",
                    "trusted-keys",
                ):
                    write_json(state / (name + ".json"), {})
                evidence = {
                    "status": status,
                    "source_dirty": False,
                    "cases": [],
                    "checks": 0,
                    "metrics": {},
                    "limitations": [],
                    "artifact_hashes": {},
                    "input_digests": {"candidate_reference": "a" * 64},
                }
                write_json(state / "evidence/poisoning-gate.json", evidence)
                with patch.object(poisoning_gate, "qualify", return_value=evidence):
                    actual = acceptance.report("M08", "local-cpu", ROOT, state)
                self.assertEqual((actual["status"], actual["exit_code"]), (status, code))
                self.assertEqual(actual["input_digests"]["candidate_reference"], "a" * 64)
                for error, expected in (
                    (Rejected("bad-binding"), "fail"),
                    (Rejected("required_tool_unavailable"), "inconclusive"),
                    (OSError(), "inconclusive"),
                    (subprocess.TimeoutExpired("worker", 1), "inconclusive"),
                ):
                    with patch.object(poisoning_gate, "qualify", side_effect=error):
                        self.assertEqual(
                            acceptance.report("M08", "local-cpu", ROOT, state)["status"], expected
                        )


class SubjectContracts(unittest.TestCase):
    def test_signed_lineage_and_second_candidate_read_must_agree(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            trust = {"curator": "curator", "evaluator": "evaluator"}
            write_json(state / "storage-trust.json", trust)
            write_json(state / "trusted-keys.json", trust)
            write_json(
                state / "storage-demo.json",
                {"candidate": {"candidate_reference": "a" * 64}, "evaluation_reference": "b" * 64},
            )
            expected = {
                "image_id": IMAGE,
                "source_revision": "c" * 40,
                "source_fingerprint": "d" * 64,
            }
            record = {"metadata_object": "e" * 64, "dataset_reference": "f" * 64}
            model = b"controlled-subject"
            projection = {
                "graph": {
                    "assets": [
                        {"kind": "model", "sha256": digest(model)},
                        {"kind": "run", "sha256": record["metadata_object"]},
                    ]
                },
                "bindings": {"dataset_reference": record["dataset_reference"]},
            }
            with (
                patch.object(poisoning_gate, "validate", return_value={}),
                patch.object(poisoning_gate, "command", return_value=expected["source_revision"]),
                patch.object(
                    poisoning_gate,
                    "source_fingerprint",
                    return_value=expected["source_fingerprint"],
                ),
                patch.object(poisoning_gate.candidate_lineage, "collect", return_value=projection),
                patch.object(
                    poisoning_gate.storage_pipeline,
                    "load_candidate",
                    return_value=(record, expected, model),
                ),
            ):
                self.assertEqual(poisoning_gate.subject(ROOT, state, IMAGE)["model"], model)
                projection["graph"]["assets"][0]["sha256"] = "0" * 64
                with self.assertRaisesRegex(Rejected, "readback_changed"):
                    poisoning_gate.subject(ROOT, state, IMAGE)
                write_json(state / "storage-trust.json", {**trust, "curator": "foreign"})
                with self.assertRaisesRegex(Rejected, "trust_changed"):
                    poisoning_gate.subject(ROOT, state, IMAGE)


class FlowContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = CandidateBindingContracts()
        cls.fixture.setUp()
        cls.addClassCleanup(cls.fixture.doCleanups)

    def run_flow(self, mode="fail"):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            campaign = state / "poisoning" / ("a" * 32)
            shutil.copytree(self.fixture.campaign, campaign)
            write_json(campaign / "triggered.json", self.fixture.probes)
            subject = {
                **self.fixture.subject,
                "model": b"controlled-model",
                "bindings": {"candidate_reference": "b" * 64, "evaluation_reference": "c" * 64},
            }
            report = {
                "campaign_id": "a" * 32,
                "cases": self.fixture.records,
                "source_dirty": False,
                "source_revision": "d" * 40,
                "input_digests": {},
                "status": "fail",
            }
            verified = {
                "evidence_integrity": "pass",
                "verified_cases": 35,
                "verified_files": 251,
                "status": "fail",
                "materials_digest": "e" * 64,
                "report_digest": "f" * 64,
            }
            if mode == "incomplete":
                verified["verified_cases"] = 34
            if mode == "shape":
                del verified["verified_files"]

            def campaign_run(*args):
                return {
                    **report,
                    "started_at": "2020-01-01T00:00:00+00:00" if mode == "stale" else now(),
                }

            def predict(image, request):
                output, execution = worker(image, request)
                scores = self.fixture.scores
                output = response(request, scores, output["scan"])
                return output, execution

            repeated = copy.deepcopy(subject)
            if mode == "changed-subject":
                repeated["model"] = b"changed"
            with (
                patch.object(poisoning_gate, "run_contracts", return_value={"cases": []}),
                patch.object(poisoning_gate, "resolve_image", return_value=IMAGE),
                patch.object(poisoning_gate, "subject", side_effect=[subject, repeated]),
                patch.object(poisoning_native, "qualify", side_effect=campaign_run),
                patch.object(
                    poisoning_gate.poisoning_evidence,
                    "reconcile",
                    side_effect=[
                        verified,
                        {
                            **verified,
                            "materials_digest": "0" * 64
                            if mode == "changed-primary"
                            else verified["materials_digest"],
                        },
                    ],
                ),
                patch.object(poisoning_gate, "run_worker", side_effect=predict),
            ):
                if mode != "fail":
                    with self.assertRaises(Rejected):
                        poisoning_gate.qualify(ROOT, state)
                    self.assertEqual(
                        read_json(state / "evidence/poisoning-gate.json")["status"], "inconclusive"
                    )
                    return
                result = poisoning_gate.qualify(ROOT, state)
            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["metrics"]["violating_scenarios"], 30)
            self.assertEqual(result["input_digests"]["model_digest"], digest(subject["model"]))
            self.assertFalse(result["release_ready"])
            self.assertEqual(result, read_json(state / "evidence/poisoning-gate.json"))

    def test_complete_matrix_and_candidate_replay_preserve_fail(self):
        self.run_flow()

    def test_stale_incomplete_changed_or_malformed_evidence_never_passes(self):
        for mode in ("incomplete", "stale", "changed-subject", "changed-primary", "shape"):
            with self.subTest(mode=mode):
                self.run_flow(mode)


class ContractRunnerChecks(unittest.TestCase):
    def test_real_unittest_skips_and_failures_cannot_count_as_complete(self):
        for mode in ("pass", "skip", "fail", "missing"):
            suite = unittest.TestSuite()
            for index in range(28 if mode == "missing" else 29):

                def check(index=index, mode=mode):
                    if index == 0 and mode == "skip":
                        raise unittest.SkipTest("controlled unavailable test")
                    if index == 0 and mode == "fail":
                        raise AssertionError("controlled failure")

                check.__name__ = f"contract_{index}"
                suite.addTest(unittest.FunctionTestCase(check))
            with patch.object(unittest.defaultTestLoader, "loadTestsFromNames", return_value=suite):
                actual = poisoning_contracts.qualify()
            self.assertEqual(actual["status"], "pass" if mode == "pass" else "fail")

    def test_contract_cli_refuses_an_empty_suite(self):
        with (
            patch.object(
                unittest.defaultTestLoader, "loadTestsFromNames", return_value=unittest.TestSuite()
            ),
            contextlib.redirect_stdout(io.StringIO()) as output,
            self.assertRaises(SystemExit) as stopped,
        ):
            runpy.run_module("scripts.poisoning_contracts", run_name="__main__")
        self.assertEqual(stopped.exception.code, 1)
        self.assertIn('"status":"fail"', output.getvalue())

    def test_missing_skipped_failed_and_foreign_contracts_rejected(self):
        expected = poisoning_gate.case_ids(
            unittest.defaultTestLoader.loadTestsFromNames(
                poisoning_gate.poisoning_contracts.MODULES
            )
        )
        good = {
            "status": "pass",
            "scope": poisoning_gate.poisoning_contracts.SCOPE,
            "checks": len(expected),
            "cases": [{"id": name, "status": "pass"} for name in sorted(expected)],
        }
        with patch.object(
            poisoning_gate.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=0, stdout=canonical(good)),
        ):
            self.assertEqual(poisoning_gate.run_contracts(ROOT), good)
        for status, body in (
            (1, good),
            (0, {**good, "cases": []}),
            (0, {**good, "scope": "foreign"}),
            (0, {**good, "checks": True}),
        ):
            with patch.object(
                poisoning_gate.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=status, stdout=canonical(body)),
            ):
                with self.assertRaises(Rejected):
                    poisoning_gate.run_contracts(ROOT)


if __name__ == "__main__":
    unittest.main()
