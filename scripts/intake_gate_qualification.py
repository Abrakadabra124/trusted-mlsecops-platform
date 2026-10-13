import copy
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from mlsecops import acceptance, artifact_intake, intake_gate, worker
from mlsecops.contracts import Rejected, canonical, digest, now, write_json
from mlsecops.datasets import generate
from mlsecops.inventory import command, source_fingerprint
from mlsecops.signing import decode64

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "sha256:" + "1" * 64


class IntakeGateContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = decode64(
            worker.train(
                {
                    "action": "train",
                    "train": generate(rows=1000),
                    "seed": 17,
                    "features": [[0.5] * 6],
                }
            )["model"]
        )

    def native(self):
        self.started = now()
        cases = []
        for name in intake_gate.NATIVE_CASES:
            content = b"\x80\x04N." if name == "renamed-pickle-rejected" else self.content

            def executor(image, request):
                if name in ("deadline", "crash"):
                    raise Rejected("worker_deadline" if name == "deadline" else "worker_failed")
                return worker.execute(request), {"image_id": IMAGE}

            try:
                report = artifact_intake.inspect_candidate(
                    content, digest(content), IMAGE, IMAGE, executor
                )
            except artifact_intake.IntakeFailure as error:
                report = error.report
            cases.append({"id": name, "status": "pass", "report": report})
            if name in ("deadline", "crash"):
                cases[-1]["owned_container_removed"] = True
        return {
            "schema_version": 1,
            "status": "pass",
            "scope": "native-docker-intake-component-not-full-M21",
            "observed_at": now(),
            "image_id": IMAGE,
            "source_fingerprint": "2" * 64,
            "cases": cases,
            "release_ready": False,
        }

    def check(self, value):
        return intake_gate.check_native(value, self.content, IMAGE, "2" * 64, self.started)

    def test_native_reports_reconcile_actual_bytes(self):
        value = self.native()
        self.assertEqual(len(self.check(value)), 5)
        self.assertEqual(value["cases"][0]["report"]["approved_outputs"], [digest(self.content)])

    def test_partial_duplicate_failed_or_skipped_cases_rejected(self):
        original = self.native()
        for cases in (
            [],
            original["cases"][:-1],
            original["cases"] + [original["cases"][0]],
            [{**case, "status": "skip"} for case in original["cases"]],
            [{**case, "id": "unexpected"} for case in original["cases"]],
            [None],
            [{} for _ in original["cases"]],
        ):
            with self.subTest(cases=len(cases)), self.assertRaises(Rejected):
                self.check({**original, "cases": cases})

    def test_stale_wrong_image_source_and_scope_rejected(self):
        original = self.native()
        for name, value in (
            ("scope", "historical"),
            ("image_id", "sha256:" + "0" * 64),
            ("source_fingerprint", "0" * 64),
            ("schema_version", True),
            ("status", "inconclusive"),
            ("release_ready", True),
            ("observed_at", "2000-01-01T00:00:00+00:00"),
            ("observed_at", "2999-01-01T00:00:00+00:00"),
            ("observed_at", "2026-01-01T00:00:00"),
            ("observed_at", None),
        ):
            with self.subTest(name=name), self.assertRaises(Rejected):
                self.check({**original, name: value})

    def test_unsafe_cannot_be_presented_as_clean_and_cleanup_is_required(self):
        original = self.native()
        for index, field, value in (
            (0, "report", None),
            (1, "report", original["cases"][0]["report"]),
            (2, "owned_container_removed", False),
            (2, "owned_container_removed", 1),
            (3, "report", original["cases"][2]["report"]),
            (4, "report", original["cases"][0]["report"]),
        ):
            altered = copy.deepcopy(original)
            altered["cases"][index][field] = value
            with self.subTest(index=index, field=field), self.assertRaises(Rejected):
                self.check(altered)

    def test_report_bytes_tool_counts_or_time_cannot_be_changed(self):
        original = self.native()
        for field, value in (
            ("bytes", 0),
            ("inspected", 0),
            ("unsupported", 1),
            ("model_digest", "0" * 64),
            ("request_digest", "0" * 64),
            ("tool", {}),
            ("finished_at", "2000-01-01T00:00:00+00:00"),
        ):
            altered = copy.deepcopy(original)
            altered["cases"][0]["report"][field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.check(altered)

    def test_contract_process_must_run_all_expected_cases(self):
        from scripts.intake_contracts import SCOPE, case_ids

        evidence = {
            "status": "pass",
            "scope": SCOPE,
            "checks": len(case_ids()),
            "cases": [{"id": name, "status": "pass"} for name in sorted(case_ids())],
        }
        with patch.object(
            intake_gate.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, canonical(evidence)),
        ):
            self.assertEqual(intake_gate.run_contracts(ROOT), evidence)
        for value in (
            {**evidence, "checks": True},
            {**evidence, "scope": "wrong"},
            {**evidence, "cases": evidence["cases"][:-1]},
        ):
            with patch.object(
                intake_gate.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, canonical(value)),
            ):
                with self.assertRaises(Rejected):
                    intake_gate.run_contracts(ROOT)
        with patch.object(
            intake_gate.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, b"private"),
        ):
            with self.assertRaisesRegex(Rejected, "M21_contracts_failed"):
                intake_gate.run_contracts(ROOT)

    def test_dispatcher_missing_prerequisites_and_errors_are_not_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            self.assertEqual(
                acceptance.report("M21", "local-cpu", ROOT, state)["status"], "inconclusive"
            )
            write_json(state / "workspace.json", {"fixture": True})
            for error, expected in (
                (Rejected("M21_native_binding"), "fail"),
                (Rejected("M21_linux_required"), "inconclusive"),
                (OSError("private-password"), "inconclusive"),
                (subprocess.TimeoutExpired("private-command", 1), "inconclusive"),
            ):
                with patch.object(intake_gate, "qualify", side_effect=error):
                    report = acceptance.report("M21", "local-cpu", ROOT, state)
                self.assertEqual(report["status"], expected)
                self.assertNotIn(b"private", canonical(report))

    def sql_fixture(self):
        from scripts.intake_denial_native import CHECK_IDS

        native = self.native()
        fingerprint = source_fingerprint(ROOT)
        native["source_fingerprint"] = fingerprint
        policy = intake_gate.read_json(ROOT / "policies/local-cpu.json")
        trust = {"evaluator": "controlled-reader-fixture"}
        metadata = {
            "image_id": IMAGE,
            "source_fingerprint": fingerprint,
            "source_revision": command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
            "created_at": now(),
            "materials": {},
        }
        bound = {
            "report": {
                "intake": native["cases"][0]["report"],
                "created_at": now(),
                "quality_component": "pass",
            }
        }
        demo = {
            "candidate": {"candidate_reference": "3" * 64},
            "evaluation_reference": "4" * 64,
            "evaluation": copy.deepcopy(bound),
        }
        entries = []
        for offset, case in enumerate((native["cases"][1], native["cases"][2], native["cases"][3])):
            report = copy.deepcopy(case["report"])
            report.update(
                status=("fail", "fail", "inconclusive")[offset],
                reason=("model_parse_rejected", "scanner_protocol_rejected", "scanner_timeout")[
                    offset
                ],
            )
            entries.append(
                {
                    "candidate_reference": "5" * 64 if offset == 0 else "3" * 64,
                    "denial_reference": str(offset + 6) * 64,
                    "payload": {
                        "intake": report,
                        "dataset_reference": "9" * 64,
                        "holdout_access": {"slot": offset + 2},
                    },
                }
            )
        denial = {
            "schema_version": 1,
            "scope": "durable-sql-intake-denial-not-full-M21",
            "status": "pass",
            "source_fingerprint": fingerprint,
            "source_revision": metadata["source_revision"],
            "image_id": IMAGE,
            "release_ready": False,
            "observed_at": now(),
            "input_digests": {
                "trust": digest(canonical(trust)),
                "policy": digest(canonical(policy)),
                "original_candidate": "3" * 64,
                "original_evaluation": "4" * 64,
            },
            "checks": len(CHECK_IDS),
            "cases": [{"id": name, "status": "pass"} for name in sorted(CHECK_IDS)],
            "denials": entries,
        }
        return demo, native, denial, metadata, bound, policy, trust

    def reconcile_fixture(self, fixture, unsafe=b"\x80\x04N.", served=None):
        demo, native, denials, metadata, bound, policy, trust = fixture
        expected = served or {
            entry["denial_reference"]: copy.deepcopy(entry["payload"])
            for entry in denials["denials"]
            if isinstance(entry, dict)
        }
        with ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    intake_gate,
                    "read_json",
                    side_effect=lambda path: policy if path.name == "local-cpu.json" else trust,
                )
            )
            stack.enter_context(
                patch.object(
                    intake_gate.storage_pipeline,
                    "load_candidate",
                    side_effect=lambda reader, candidate, rules: (
                        {"dataset_reference": "9" * 64},
                        metadata,
                        unsafe if candidate == "5" * 64 else self.content,
                    ),
                )
            )
            stack.enter_context(
                patch.object(intake_gate.storage_pipeline, "read_evaluation", return_value=bound)
            )
            stack.enter_context(
                patch.object(
                    intake_gate.intake_denial,
                    "read",
                    side_effect=lambda reader, reference, *args: expected[reference],
                )
            )
            return intake_gate.reconcile(
                ROOT, ROOT / ".runtime", demo, native, denials, IMAGE, self.started
            )

    def test_sql_reconciliation_uses_readers_and_actual_model(self):
        result = self.reconcile_fixture(self.sql_fixture())
        self.assertEqual(result["input_digests"]["model"], digest(self.content))
        self.assertEqual(
            result["metrics"], {"native_cases": 5, "sql_cases": 25, "quality_component": "pass"}
        )
        with self.assertRaisesRegex(Rejected, "M21_unsafe_fixture_binding"):
            self.reconcile_fixture(self.sql_fixture(), unsafe=b"another-object")

    def test_sql_stale_source_unbound_evidence_and_schema_rejected(self):
        for field, value in (
            ("image_id", "wrong"),
            ("source_revision", "0" * 40),
            ("source_fingerprint", "0" * 64),
            ("input_digests", {}),
            ("scope", "wrong"),
            ("schema_version", True),
            ("release_ready", True),
        ):
            fixture = self.sql_fixture()
            fixture[2][field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.reconcile_fixture(fixture)
        fixture = self.sql_fixture()
        fixture[0]["evaluation"]["report"]["quality_component"] = "fail"
        with self.assertRaisesRegex(Rejected, "M21_sql_material_binding"):
            self.reconcile_fixture(fixture)

    def test_sql_incomplete_foreign_duplicate_and_rewritten_denials_rejected(self):
        for mutate in (
            lambda entries: entries.pop(),
            lambda entries: entries.__setitem__(1, copy.deepcopy(entries[0])),
            lambda entries: entries[1].update(candidate_reference="5" * 64),
            lambda entries: entries[1]["payload"].update(dataset_reference="0" * 64),
            lambda entries: entries[1]["payload"]["intake"].update(reason="unexpected"),
            lambda entries: entries[1]["payload"]["holdout_access"].update(slot=2),
        ):
            fixture = self.sql_fixture()
            mutate(fixture[2]["denials"])
            with self.assertRaises(Rejected):
                self.reconcile_fixture(fixture)
        fixture = self.sql_fixture()
        served = {
            entry["denial_reference"]: copy.deepcopy(entry["payload"])
            for entry in fixture[2]["denials"]
        }
        fixture[2]["denials"][0]["payload"]["intake"]["reason"] = "edited-summary"
        with self.assertRaisesRegex(Rejected, "M21_denial_material_binding"):
            self.reconcile_fixture(fixture, served=served)
        fixture = self.sql_fixture()
        fixture[2]["denials"][0] = None
        with self.assertRaisesRegex(Rejected, "M21_sql_material_shape"):
            self.reconcile_fixture(fixture)

    def campaign_fixture(self, state, outcome=None, identity_changed=False, source_changed=False):
        demo, native, denials, metadata, bound, policy, trust = self.sql_fixture()
        contracts = {"status": "pass", "cases": [{"id": "controlled-fixture", "status": "pass"}]}
        result = {"input_digests": {}, "metrics": {"fixture": True}}
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(intake_gate.sys, "platform", "linux"))
        stack.enter_context(
            patch.object(
                intake_gate,
                "initialize",
                side_effect=lambda root, path: path.mkdir(parents=True, exist_ok=True),
            )
        )
        stack.enter_context(patch.object(intake_gate, "bootstrap"))
        stack.enter_context(
            patch.object(
                intake_gate,
                "validate",
                side_effect=[
                    {"container_id": "owned"},
                    {"container_id": "foreign" if identity_changed else "owned"},
                ],
            )
        )
        stack.enter_context(patch.object(intake_gate, "resolve_image", return_value=IMAGE))
        stack.enter_context(
            patch.object(
                intake_gate,
                "contract_source",
                side_effect=["before", "after" if source_changed else "before"],
            )
        )
        stack.enter_context(patch.object(intake_gate, "run_contracts", return_value=contracts))
        stack.enter_context(patch.object(intake_gate.storage_pipeline, "demo", return_value=demo))
        stack.enter_context(
            patch.object(
                intake_gate.storage_pipeline,
                "load_candidate",
                return_value=({}, metadata, self.content),
            )
        )
        stack.enter_context(patch("scripts.artifact_intake_native.qualify", return_value=native))
        stack.enter_context(patch("scripts.intake_denial_native.qualify", return_value=denials))
        stack.enter_context(
            patch.object(intake_gate, "reconcile", return_value=result, side_effect=outcome)
        )
        return stack.enter_context(patch.object(intake_gate, "docker"))

    def test_campaign_saves_evidence_stops_only_owned_db_and_stays_inconclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            stop = self.campaign_fixture(state)
            result = intake_gate.qualify(ROOT, state)
            stop.assert_called_once_with(["stop", "owned"], timeout=60)
            self.assertEqual(result["status"], "inconclusive")
            self.assertEqual(result["component_status"], "pass")
            self.assertFalse(result["release_ready"])
            self.assertEqual(result["cases"][-1]["actual"], "backend-not-available")
            self.assertEqual(result["checks"], len(result["cases"]))
            self.assertEqual(set(result["artifact_hashes"]), {"contracts", "native", "denials"})
            with patch.object(intake_gate, "qualify", return_value=result):
                write_json(state / "workspace.json", {"fixture": True})
                public = acceptance.report("M21", "local-cpu", ROOT, state)
            self.assertEqual(public["exit_code"], 2)
            self.assertIn("intake_gate", public["artifact_hashes"])

    def test_failed_campaign_preserves_inconclusive_file_and_cleans_owned_resource(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            stop = self.campaign_fixture(state, outcome=Rejected("M21_fixture"))
            with self.assertRaisesRegex(Rejected, "M21_fixture"):
                intake_gate.qualify(ROOT, state)
            stop.assert_called_once()
            self.assertEqual(
                intake_gate.read_json(state / "evidence/intake-gate.json")["status"], "inconclusive"
            )

    def test_full_gate_requires_fresh_scoped_component_and_propagates_failure(self):
        from mlsecops.intake_probe import CASE_IDS
        from mlsecops.kube_intake_qualification import HOST_CASES

        for rejected in (False, True):
            with self.subTest(rejected=rejected), tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                stop = self.campaign_fixture(state)
                write_json(state / "controllers/resources.json", {"controlled": True})
                native = {
                    "status": "pass",
                    "candidate_reference": "0" * 64,
                    "cases": [
                        {"id": name, "status": "pass"} for name in sorted(CASE_IDS | HOST_CASES)
                    ],
                }
                with patch(
                    "mlsecops.kube_intake_qualification.qualify",
                    return_value=native,
                    side_effect=Rejected("kube_intake_material_binding") if rejected else None,
                ):
                    if rejected:
                        with self.assertRaisesRegex(Rejected, "kube_intake_material_binding"):
                            intake_gate.qualify(ROOT, state)
                    else:
                        result = intake_gate.qualify(ROOT, state)
                        self.assertEqual(result["status"], "pass")
                        self.assertEqual(result["cases"][-1]["actual"], "pass")
                        self.assertIn("kubernetes", result["artifact_hashes"])
                        self.assertFalse(result["release_ready"])
                stop.assert_called_once()

    def test_foreign_cleanup_identity_is_never_stopped(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            stop = self.campaign_fixture(state, identity_changed=True)
            with self.assertRaisesRegex(Rejected, "M21_cleanup_identity_changed"):
                intake_gate.qualify(ROOT, state)
            stop.assert_not_called()

    def test_source_mutation_during_campaign_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            stop = self.campaign_fixture(state, source_changed=True)
            with self.assertRaisesRegex(Rejected, "M21_source_changed_during_campaign"):
                intake_gate.qualify(ROOT, state)
            stop.assert_called_once()

    def test_linux_requirement_preserves_nonpass_without_bootstrapping_sql(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            with (
                patch.object(intake_gate.sys, "platform", "win32"),
                patch.object(intake_gate, "initialize"),
                patch.object(intake_gate, "bootstrap") as sql,
            ):
                with self.assertRaisesRegex(Rejected, "M21_linux_required"):
                    intake_gate.qualify(ROOT, state)
            sql.assert_not_called()
        self.assertEqual(len(intake_gate.contract_source(ROOT)), 64)


if __name__ == "__main__":
    unittest.main()
