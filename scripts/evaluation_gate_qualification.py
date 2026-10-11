import copy
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from mlsecops import acceptance, evaluation_gate, evaluation_quality
from mlsecops.contracts import Rejected, canonical, digest, now, read_json, write_json
from mlsecops.inventory import command, source_fingerprint
from scripts.evaluation_contracts import SCOPE, case_ids
from scripts.evaluation_quality_qualification import examples

ROOT = Path(__file__).resolve().parents[1]


class EvaluationGateContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.started = now()
        cls.policy = {**read_json(ROOT / "policies/local-cpu.json"), "rows": 496}
        rows, scores = examples()
        cls.splits = {
            "train": copy.deepcopy(rows[:64]),
            "validation": copy.deepcopy(rows[:32]),
            "holdout": rows,
        }
        cls.summary = evaluation_quality.summarize(
            rows, scores, evaluation_quality.freeze(cls.policy)
        )
        cls.image = "sha256:" + "1" * 64
        cls.model = b"controlled-no-model-parser"
        cls.manifest = {
            "objects": {
                f"{name}.json": {"sha256": digest(canonical(split))}
                for name, split in cls.splits.items()
            }
        }
        cls.statement = {"dataset_id": "2" * 64, "lineage_id": "3" * 64}
        cls.record = {"dataset_reference": "4" * 64}
        cls.metadata = {
            **cls.statement,
            "created_at": now(),
            "image_id": cls.image,
            "source_fingerprint": source_fingerprint(ROOT),
            "source_revision": command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
            "input_digest": digest(
                canonical(
                    {
                        "action": "train",
                        "train": cls.splits["train"],
                        "seed": cls.policy["training_seed"],
                        "features": [row["features"] for row in cls.splits["validation"]],
                    }
                )
            ),
            "materials": cls.manifest["objects"],
        }
        cls.bound = {
            "dataset_reference": cls.record["dataset_reference"],
            "holdout_access": {"reservation": "5" * 64},
            "report": {
                **cls.summary,
                "created_at": now(),
                "holdout_digest": cls.manifest["objects"]["holdout.json"]["sha256"],
            },
        }
        cls.evidence = {
            "status": "pass",
            "scope": "native-frozen-evaluation-component-not-full-M07",
            "checks": len(evaluation_gate.QUALITY_CASES),
            "cases": [
                {"id": name, "status": "pass"} for name in sorted(evaluation_gate.QUALITY_CASES)
            ],
            "source_fingerprint": cls.metadata["source_fingerprint"],
            "observed_at": now(),
            "candidate_reference": "6" * 64,
            "evaluation_reference": "7" * 64,
            "dataset_reference": cls.record["dataset_reference"],
            "image_id": cls.image,
            "evaluation_policy_digest": cls.summary["evaluation_policy_digest"],
            "metrics": {
                name: cls.summary[name]
                for name in (
                    "rows",
                    "positives",
                    "auprc",
                    "dummy_auprc",
                    "auprc_gain",
                    "slices",
                    "confidence_intervals",
                )
            },
        }

    def reconcile(self, evidence=None, metadata=None, bound=None, splits=None):
        with ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    evaluation_gate,
                    "read_json",
                    side_effect=lambda path: (
                        self.policy
                        if path.name == "local-cpu.json"
                        else {"curator": "controlled", "source_approval_digest": "controlled"}
                    ),
                )
            )
            stack.enter_context(
                patch.object(
                    evaluation_gate.storage_pipeline,
                    "read_evaluation",
                    return_value=bound or self.bound,
                )
            )
            stack.enter_context(
                patch.object(
                    evaluation_gate.storage_pipeline,
                    "load_candidate",
                    return_value=(self.record, metadata or self.metadata, self.model),
                )
            )
            stack.enter_context(
                patch.object(
                    evaluation_gate.storage_dataset,
                    "read_dataset",
                    return_value=(splits or self.splits, self.manifest, self.statement),
                )
            )
            return evaluation_gate.reconcile(
                ROOT, Path("controlled"), evidence or self.evidence, self.image, self.started
            )

    def test_signed_materials_are_reconciled(self):
        result = self.reconcile()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["input_digests"]["model"], digest(self.model))

    def test_replayed_or_modified_evidence_rejected(self):
        for field, value in (
            ("scope", "other"),
            ("source_fingerprint", "0" * 64),
            ("dataset_reference", "0" * 64),
            ("image_id", "sha256:" + "0" * 64),
            ("evaluation_policy_digest", "0" * 64),
            ("observed_at", "2000-01-01T00:00:00+00:00"),
            ("observed_at", "2999-01-01T00:00:00+00:00"),
            ("observed_at", "2026-01-01T00:00:00"),
            ("observed_at", "bad"),
            ("metrics", {}),
            ("metrics", {"rows": 1}),
        ):
            evidence = {**copy.deepcopy(self.evidence), field: value}
            with self.subTest(field=field, value=value), self.assertRaises(Rejected):
                self.reconcile(evidence=evidence)

    def test_candidate_request_source_and_material_changes_rejected(self):
        for field, value in (
            ("source_fingerprint", "0" * 64),
            ("source_revision", "0" * 40),
            ("input_digest", "0" * 64),
            ("materials", {}),
            ("image_id", "sha256:" + "0" * 64),
            ("dataset_id", "0" * 64),
            ("lineage_id", "0" * 64),
            ("created_at", "2000-01-01T00:00:00+00:00"),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.reconcile(metadata={**self.metadata, field: value})

    def test_malformed_materials_fail_closed(self):
        for value in (None, [], {"status": "pass"}):
            with self.assertRaisesRegex(Rejected, "M07_material_shape_invalid"):
                self.reconcile(bound={**self.bound, "report": value})
        with self.assertRaisesRegex(Rejected, "M07_component_shape_invalid"):
            evaluation_gate.checked_cases(None)
        with self.assertRaisesRegex(Rejected, "M07_budget_shape_invalid"):
            evaluation_gate.check_budget({}, self.image, "a" * 64, "b" * 64, now())
        with self.assertRaisesRegex(Rejected, "M07_quality_state_invalid"):
            self.reconcile(
                bound={
                    **self.bound,
                    "report": {**self.bound["report"], "quality_component": "skipped"},
                }
            )

    def test_quality_inconclusive_and_failure_are_not_pass(self):
        for status in ("fail", "inconclusive"):
            bound = copy.deepcopy(self.bound)
            bound["report"]["quality_component"] = status
            self.assertEqual(self.reconcile(bound=bound)["status"], status)
        bound = copy.deepcopy(self.bound)
        bound["report"]["confidence_intervals"]["status"] = "inconclusive"
        evidence = copy.deepcopy(self.evidence)
        evidence["metrics"]["confidence_intervals"] = bound["report"]["confidence_intervals"]
        self.assertEqual(self.reconcile(bound=bound, evidence=evidence)["status"], "inconclusive")

    def test_contract_process_failure_empty_or_partial_is_not_accepted(self):
        good = {
            "status": "pass",
            "scope": SCOPE,
            "checks": 48,
            "cases": [{"id": name, "status": "pass"} for name in case_ids()],
        }
        for status, content, expected in (
            (1, b"secret failure", "M07_controlled_contracts_failed"),
            (0, b"", "invalid_json"),
            (
                0,
                canonical(
                    {"status": "pass", "checks": 1, "cases": [{"id": "only", "status": "pass"}]}
                ),
                "M07_controlled_contracts_incomplete",
            ),
        ):
            with patch.object(
                evaluation_gate.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], status, content, b""),
            ):
                with self.assertRaisesRegex(Rejected, expected):
                    evaluation_gate.run_contracts(ROOT)
        with patch.object(
            evaluation_gate.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, canonical(good), b""),
        ):
            self.assertEqual(evaluation_gate.run_contracts(ROOT), good)
        for mutate in (
            lambda evidence: evidence.update(scope="other"),
            lambda evidence: evidence["cases"][0].update(id="substituted-test"),
        ):
            altered = copy.deepcopy(good)
            mutate(altered)
            with patch.object(
                evaluation_gate.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, canonical(altered), b""),
            ):
                with self.assertRaises(Rejected):
                    evaluation_gate.run_contracts(ROOT)

    def run_campaign(
        self, state, *, budget_mutation=None, fingerprints=None, cleanup_changed=False
    ):
        result = self.reconcile()
        budget = {
            "scope": "native-persistent-holdout-budget-component-not-full-M07",
            "observed_at": now(),
            "status": "pass",
            "checks": len(evaluation_gate.BUDGET_CASES),
            "cases": sorted(evaluation_gate.BUDGET_CASES),
            "source_fingerprint": source_fingerprint(ROOT),
            "image_id": self.image,
            "holdout_digest": result["input_digests"]["holdout"],
            "budget_policy": evaluation_gate.holdout_budget.policy(),
            "budget_policy_digest": digest(canonical(evaluation_gate.holdout_budget.policy())),
            "consumed": 32,
        }
        if budget_mutation:
            budget.update(budget_mutation)
        contracts = {
            "status": "pass",
            "checks": 1,
            "cases": [{"id": "controlled-dispatch-fixture", "status": "pass"}],
        }
        with ExitStack() as stack:
            stack.enter_context(
                patch.object(evaluation_gate, "resolve_image", return_value=self.image)
            )
            stack.enter_context(
                patch.object(evaluation_gate, "run_contracts", return_value=contracts)
            )
            stack.enter_context(patch.object(evaluation_gate, "initialize"))
            stack.enter_context(patch.object(evaluation_gate, "bootstrap"))
            native = stack.enter_context(
                patch.object(evaluation_gate, "evaluate", return_value=self.evidence)
            )
            stack.enter_context(patch.object(evaluation_gate, "reconcile", return_value=result))
            run_budget = stack.enter_context(
                patch.object(
                    evaluation_gate,
                    "budget_campaign",
                    side_effect=lambda *args: {
                        **budget,
                        "observed_at": (budget_mutation or {}).get("observed_at", now()),
                    },
                )
            )
            stack.enter_context(
                patch.object(
                    evaluation_gate,
                    "validate",
                    side_effect=[
                        {"container_id": "owned"},
                        {"container_id": "other" if cleanup_changed else "owned"},
                    ],
                )
            )
            stopped = stack.enter_context(patch.object(evaluation_gate, "docker"))
            if fingerprints:
                stack.enter_context(
                    patch.object(evaluation_gate, "source_fingerprint", side_effect=fingerprints)
                )
            try:
                report = evaluation_gate.qualify(ROOT, state)
            except Rejected:
                if cleanup_changed:
                    stopped.assert_not_called()
                else:
                    stopped.assert_called_once_with(["stop", "owned"], timeout=60)
                raise
            native.assert_called_once()
            run_budget.assert_called_once()
            self.assertNotEqual(native.call_args.args[1], run_budget.call_args.args[1])
            stopped.assert_called_once_with(["stop", "owned"], timeout=60)
            self.assertEqual(read_json(state / "evidence/evaluation-gate.json"), report)
            return report

    def test_campaign_executes_fresh_components_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            first = self.run_campaign(state)
            second = self.run_campaign(state)
            self.assertNotEqual(first["campaign_id"], second["campaign_id"])
            self.assertEqual(first["status"], "pass")
            self.assertFalse(first["release_ready"])

    def test_campaign_rejects_budget_subject_and_source_mutations(self):
        for field, value in (
            ("source_fingerprint", "0" * 64),
            ("image_id", "sha256:" + "0" * 64),
            ("holdout_digest", "0" * 64),
            ("budget_policy", {}),
            ("budget_policy_digest", "0" * 64),
            ("consumed", True),
            ("consumed", 31),
            ("checks", 0),
            ("observed_at", "2000-01-01T00:00:00+00:00"),
            ("scope", "unrelated-campaign"),
        ):
            with tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                with self.subTest(field=field), self.assertRaises(Rejected):
                    self.run_campaign(state, budget_mutation={field: value})
                self.assertEqual(
                    read_json(state / "evidence/evaluation-gate.json")["status"], "inconclusive"
                )
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(Rejected, "M07_source_changed_during_campaign"),
        ):
            self.run_campaign(Path(temporary), fingerprints=[source_fingerprint(ROOT), "0" * 64])

    def test_cleanup_refuses_changed_resource_identity(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(Rejected, "M07_cleanup_identity_changed"),
        ):
            self.run_campaign(Path(temporary), cleanup_changed=True)

    def test_dispatch_propagates_status_and_classifies_unavailability(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            write_json(state / "workspace.json", {})
            result = self.run_campaign(state)
            for status, code in (("pass", 0), ("fail", 1), ("inconclusive", 2)):
                with patch.object(
                    evaluation_gate, "qualify", return_value={**result, "status": status}
                ):
                    report = acceptance.report("M07", "local-cpu", ROOT, state)
                    self.assertEqual((report["status"], report["exit_code"]), (status, code))
            for error, status in (
                (Rejected("M07_material_binding_invalid"), "fail"),
                (Rejected("evaluation_quality_inconclusive"), "inconclusive"),
                (Rejected("image_source_fingerprint_mismatch_rebuild_required"), "inconclusive"),
                (OSError("private material"), "inconclusive"),
                (subprocess.TimeoutExpired("private material", 1), "inconclusive"),
            ):
                with patch.object(evaluation_gate, "qualify", side_effect=error):
                    report = acceptance.report("M07", "local-cpu", ROOT, state)
                self.assertEqual(report["status"], status)
                self.assertNotIn("private material", canonical(report).decode())

    def test_missing_prerequisites_is_inconclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = acceptance.report("M07", "local-cpu", ROOT, Path(temporary))
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["exit_code"], 2)

    def test_partial_skipped_duplicate_and_boolean_cases_rejected(self):
        evidence = {
            "status": "pass",
            "checks": 2,
            "cases": [{"id": name, "status": "pass"} for name in ("first", "second")],
        }
        self.assertEqual(len(evaluation_gate.checked_cases(evidence, {"first", "second"})), 2)
        for field, value in (
            ("checks", True),
            ("checks", 1),
            ("status", "inconclusive"),
            ("cases", []),
            ("cases", [evidence["cases"][0]] * 2),
            ("cases", [{"id": "first", "status": "skipped"}, evidence["cases"][1]]),
            ("cases", [{"id": "other", "status": "pass"}, evidence["cases"][1]]),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(Rejected):
                evaluation_gate.checked_cases(
                    {**copy.deepcopy(evidence), field: value}, {"first", "second"}
                )

    def test_stale_output_replaced_and_stale_image_does_not_bootstrap(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            output = state / "evidence/evaluation-gate.json"
            write_json(output, {"status": "pass", "stale": True})
            with (
                patch.object(
                    evaluation_gate,
                    "resolve_image",
                    side_effect=Rejected("image_source_fingerprint_mismatch_rebuild_required"),
                ),
                patch.object(evaluation_gate, "bootstrap") as bootstrap,
                self.assertRaises(Rejected),
            ):
                evaluation_gate.qualify(ROOT, state)
            bootstrap.assert_not_called()
            self.assertEqual(read_json(output)["status"], "inconclusive")
            self.assertNotIn("stale", read_json(output))


if __name__ == "__main__":
    unittest.main()
