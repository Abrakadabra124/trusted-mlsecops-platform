import copy
import os
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, digest
from scripts import r1_walkthrough


class WalkthroughContracts(unittest.TestCase):
    def test_state_must_be_fresh_owned_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / ".runtime"
            runtime.mkdir()
            target = runtime / "walkthrough"
            self.assertEqual(r1_walkthrough.destination(root, target), target.resolve())
            target.mkdir()
            with self.assertRaisesRegex(Rejected, "walkthrough_requires_fresh_state"):
                r1_walkthrough.destination(root, target)
            for invalid in (root, runtime, root / "outside", runtime / ".." / "outside"):
                with self.subTest(path=invalid), self.assertRaises(Rejected):
                    r1_walkthrough.destination(root, invalid)

    def test_symlink_state_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(Path, "is_symlink", return_value=True):
                with self.assertRaises(Rejected):
                    r1_walkthrough.destination(root, root / ".runtime" / "new")

    def test_subject_chain_requires_actual_candidate_and_explicit_refusal(self):
        demo = {"candidate": {"candidate_reference": "candidate"}, "evaluation_reference": "eval"}
        proposal = {
            "status": "pass",
            "release_ready": False,
            "subject_sha256": "subject",
            "model_sha256": "model",
            "proposal_reference": "proposal",
            "cases": ["actual-promotion-admission-without-assurance-denied"],
        }
        serving = {
            "status": "pass",
            "scope": "actual-candidate-serving-qualification-not-release-approval",
            "release_ready": False,
            "subject_sha256": "subject",
            "model_sha256": "model",
            "proposal_reference": "proposal",
            "candidate_reference": "candidate",
            "evaluation_reference": "eval",
            "cases": [
                "actual-candidate-revocation-http-503",
                "actual-candidate-revocation-readiness-503",
            ],
        }
        r1_walkthrough.verify_subject(demo, proposal, serving)
        for field, value in (
            ("candidate_reference", "other"),
            ("evaluation_reference", "other"),
            ("subject_sha256", "other"),
            ("model_sha256", "other"),
            ("proposal_reference", "other"),
            ("release_ready", True),
            ("status", "inconclusive"),
            ("scope", "controlled-fixture"),
            ("cases", []),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                r1_walkthrough.verify_subject(demo, proposal, {**serving, field: value})
        invalid = copy.deepcopy(proposal)
        invalid["cases"] = []
        with self.assertRaises(Rejected):
            r1_walkthrough.verify_subject(demo, invalid, serving)

    def test_cleanup_checks_ownership_and_actual_stopped_state(self):
        marker = {"container_id": "owned"}
        with (
            patch.object(r1_walkthrough.storage_bootstrap, "validate", return_value=marker),
            patch.object(r1_walkthrough.storage_bootstrap, "docker") as command,
            patch.object(
                r1_walkthrough.storage_bootstrap,
                "inspect",
                return_value={"State": {"Running": False}},
            ),
        ):
            self.assertEqual(r1_walkthrough.stop_owned(Path("state")), "stopped-volumes-retained")
            command.assert_called_once_with(["stop", "owned"])
        with (
            patch.object(
                r1_walkthrough.storage_bootstrap, "validate", side_effect=Rejected("foreign")
            ),
            patch.object(r1_walkthrough.storage_bootstrap, "docker") as command,
        ):
            with self.assertRaises(Rejected):
                r1_walkthrough.stop_owned(Path("state"))
            command.assert_not_called()
        with (
            patch.object(r1_walkthrough.storage_bootstrap, "validate", return_value=marker),
            patch.object(r1_walkthrough.storage_bootstrap, "docker"),
            patch.object(
                r1_walkthrough.storage_bootstrap,
                "inspect",
                return_value={"State": {"Running": True}},
            ),
        ):
            with self.assertRaisesRegex(Rejected, "walkthrough_stop_unconfirmed"):
                r1_walkthrough.stop_owned(Path("state"))

    def test_missing_consent_stops_before_execution(self):
        with patch.object(r1_walkthrough, "run") as execute:
            with self.assertRaises(SystemExit):
                r1_walkthrough.main([])
            execute.assert_not_called()

    def test_non_linux_or_dirty_checkout_stops_before_infrastructure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for system, dirty in (("Windows", ""), ("Linux", " M tracked.py")):
                with (
                    self.subTest(system=system),
                    patch.dict(
                        os.environ,
                        {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"},
                    ),
                    patch.object(r1_walkthrough.platform, "system", return_value=system),
                    patch.object(r1_walkthrough.inventory, "command", return_value=dirty),
                    patch.object(r1_walkthrough.bootstrap, "initialize") as initialize,
                ):
                    with self.assertRaises(Rejected):
                        r1_walkthrough.run(root, root / ".runtime" / "fresh")
                    initialize.assert_not_called()

    def test_non_hosted_runner_stops_before_infrastructure(self):
        for environment in (
            {},
            {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"},
            {"GITHUB_ACTIONS": "false", "RUNNER_ENVIRONMENT": "github-hosted"},
        ):
            with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                root = Path(directory)
                stack.enter_context(patch.dict(os.environ, environment, clear=True))
                stack.enter_context(
                    patch.object(r1_walkthrough.platform, "system", return_value="Linux")
                )
                stack.enter_context(
                    patch.object(r1_walkthrough.inventory, "command", return_value="")
                )
                lock = stack.enter_context(
                    patch.object(r1_walkthrough.data_source, "validate_lock")
                )
                with self.assertRaisesRegex(Rejected, "walkthrough_requires_hosted_runner"):
                    r1_walkthrough.run(root, root / ".runtime" / "fresh")
                lock.assert_not_called()
                self.assertFalse((root / ".runtime").exists())

    def exercise_run(self, failure=None):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            stack.enter_context(
                patch.dict(
                    os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
                )
            )
            root = Path(directory)
            state = root / ".runtime" / "fresh"

            def initialize(root, path):
                path.mkdir(parents=True, exist_ok=True)
                return {"identity": "stable"}

            def database(path, port):
                (path / "storage.json").write_text("{}", encoding="utf-8")

            def recovery(*arguments):
                target = arguments[2]
                target.mkdir()
                (target / "storage.json").write_text("{}", encoding="utf-8")
                return {"status": "pass", "release_ready": False}

            demo = {
                "candidate": {"candidate_reference": "candidate"},
                "evaluation_reference": "eval",
            }
            proposal = {"model_sha256": "model", "subject_sha256": "subject"}
            operations = (
                (r1_walkthrough.platform, "system", {"return_value": "Linux"}),
                (r1_walkthrough.inventory, "command", {"return_value": ""}),
                (r1_walkthrough.inventory, "source_fingerprint", {"return_value": "source"}),
                (r1_walkthrough.data_source, "validate_lock", {"return_value": {}}),
                (r1_walkthrough.bootstrap, "initialize", {"side_effect": initialize}),
                (r1_walkthrough.inventory, "build_image", {"return_value": None}),
                (r1_walkthrough.sandbox, "resolve_image", {"return_value": "image"}),
                (r1_walkthrough.storage_bootstrap, "bootstrap", {"side_effect": database}),
                (r1_walkthrough.storage_pipeline, "demo", {"return_value": demo}),
                (r1_walkthrough.release_native, "qualify", {"return_value": proposal}),
                (
                    r1_walkthrough.serving_output_native,
                    "run",
                    {"return_value": {"cases": ["check"]}},
                ),
                (r1_walkthrough, "verify_subject", {"return_value": None}),
                (r1_walkthrough, "recover", {"side_effect": recovery}),
                (r1_walkthrough, "stop_owned", {"return_value": "stopped-volumes-retained"}),
            )
            mocks = {}
            for module, name, options in operations:
                if failure == name:
                    options = {"side_effect": Rejected("controlled_failure")}
                mocks[(module.__name__, name)] = stack.enter_context(
                    patch.object(module, name, **options)
                )
            if failure == "bootstrap-identity":
                mocks[(r1_walkthrough.bootstrap.__name__, "initialize")].side_effect = [
                    {"identity": "first"},
                    {"identity": "second"},
                ]
            report = r1_walkthrough.run(root, state)
            self.assertFalse(report["release_ready"])
            self.assertEqual(report["r1_status"], "incomplete")
            self.assertEqual(len(report["required_gates"]), 23)
            self.assertTrue((state / "report.json").is_file())
            return report

    def test_complete_orchestration_is_not_release_acceptance(self):
        report = self.exercise_run()
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["release_decision"], "refused")
        self.assertEqual(report["inference_mode"], "qualification-only-not-production")
        self.assertEqual(len(report["stages"]), 5)
        self.assertEqual(set(report["cleanup"].values()), {"stopped-volumes-retained"})

    def test_component_and_cleanup_failures_never_become_success(self):
        for failure in (
            "build_image",
            "bootstrap-identity",
            "demo",
            "qualify",
            "run",
            "verify_subject",
            "recover",
            "stop_owned",
        ):
            with self.subTest(failure=failure):
                self.assertEqual(self.exercise_run(failure)["status"], "fail")

    def test_cli_returns_nonzero_for_preflight_or_incomplete_execution(self):
        for result, expected in (({"status": "pass"}, 0), ({"status": "fail"}, 1)):
            with patch.object(r1_walkthrough, "run", return_value=result):
                self.assertEqual(r1_walkthrough.main(["--confirm-disposable"]), expected)
        with patch.object(r1_walkthrough, "run", side_effect=Rejected("private-canary")):
            self.assertEqual(r1_walkthrough.main(["--confirm-disposable"]), 1)

    def exercise_recovery(self, mutation=None):
        root, source, target = Path("root"), Path("source"), Path("target")
        original = ({"dataset_reference": "dataset"}, {"metadata": "original"}, b"model")
        model = digest(original[2])
        marker = {"workspace_id": "target", "volume": "target", "container_id": "target"}
        source_marker = {name: "source" for name in marker}
        public = {"trust": "source-key"}
        receipt = {"tables": {"ledger": "same"}, "release_ready": False}
        repeat = {"reused": True, "container_id": "target"}
        restored = original
        proof = {"rows": 1000, "model_digest": model}
        execution = {"image_id": "image"}
        target_keys = {"trust": "new-key"}
        recovered_keys = public
        running = False
        scores = [0.5] * 1000
        if mutation == "model":
            restored = (*original[:2], b"different")
        elif mutation == "ledger":
            receipt["tables"] = {}
        elif mutation == "release":
            receipt["release_ready"] = True
        elif mutation in marker:
            marker[mutation] = "source"
        elif mutation == "private-keys":
            target_keys = public
        elif mutation == "public-keys":
            recovered_keys = {}
        elif mutation == "rows":
            proof["rows"] = 999
        elif mutation == "proof-model":
            proof["model_digest"] = "other"
        elif mutation == "execution-image":
            execution["image_id"] = "other"
        elif mutation == "score":
            scores[0] = 0.6
        elif mutation == "source-running":
            running = True
        elif mutation == "repeat":
            repeat["reused"] = False
        elif mutation == "repeat-identity":
            repeat["container_id"] = "other"

        def read(path):
            if path.name == "local-cpu.json":
                return {"parity_tolerance": 1e-5}
            if path.name == "storage-trust.json":
                return {"curator": "curator", "source_approval_digest": "approval"}
            if path == source / "trusted-keys.json":
                return public
            if path == target / "trusted-keys.json":
                return target_keys
            if path.name == "recovered-public-keys.json":
                return recovered_keys
            raise AssertionError(path)

        batches = [Mock(), Mock()]
        batches[0].consume.return_value = ([0.5] * 1000, {}, {})
        batches[1].consume.return_value = (scores, {}, proof)
        order = []

        def restore(*arguments, **keywords):
            self.assertEqual(keywords["expected_backup_id"], "backup")
            self.assertIn("stop", order)
            order.append("restore")
            return receipt if order.count("restore") == 1 else repeat

        with (
            patch.object(r1_walkthrough, "read_json", side_effect=read),
            patch.object(r1_walkthrough, "write_json"),
            patch.object(
                r1_walkthrough.storage_pipeline, "load_candidate", side_effect=[original, restored]
            ),
            patch.object(
                r1_walkthrough.storage_dataset,
                "read_dataset",
                return_value=({"validation": [{"features": [0.5]}] * 1000}, {}, {}),
            ),
            patch.object(r1_walkthrough, "PredictionBatch", side_effect=batches),
            patch.object(r1_walkthrough.sandbox, "run_worker", return_value=({}, execution)),
            patch.object(
                r1_walkthrough.storage_backup,
                "create",
                return_value={
                    "backup_id": "backup",
                    "directory": "backup",
                    "tables": {"ledger": "same"},
                },
            ),
            patch.object(
                r1_walkthrough.storage_bootstrap, "validate", side_effect=[source_marker, marker]
            ),
            patch.object(
                r1_walkthrough, "stop_owned", side_effect=lambda owned: order.append("stop")
            ),
            patch.object(r1_walkthrough.storage_restore, "restore", side_effect=restore),
            patch.object(
                r1_walkthrough.storage_bootstrap,
                "inspect",
                return_value={"State": {"Running": running}},
            ),
        ):
            result = r1_walkthrough.recover(
                root,
                source,
                target,
                "image",
                {"candidate": {"candidate_reference": "candidate"}},
                {"model_sha256": model},
            )
        self.assertEqual(order, ["stop", "restore", "restore"])
        return result

    def test_same_candidate_recovery_and_repeat_are_required(self):
        result = self.exercise_recovery()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["golden_rows"], 1000)
        self.assertEqual(result["max_error"], 0.0)
        self.assertFalse(result["release_ready"])

    def test_recovery_integrity_ownership_parity_and_independence_fail_closed(self):
        for mutation in (
            "model",
            "ledger",
            "release",
            "workspace_id",
            "volume",
            "container_id",
            "private-keys",
            "public-keys",
            "rows",
            "proof-model",
            "execution-image",
            "score",
            "source-running",
            "repeat",
            "repeat-identity",
        ):
            with self.subTest(mutation=mutation), self.assertRaises(Rejected):
                self.exercise_recovery(mutation)


if __name__ == "__main__":
    unittest.main()
