import copy
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import acceptance, isolation_gates, kube_qualification, kube_worker
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from scripts import isolation_native


class AccessGateContracts(unittest.TestCase):
    def setUp(self):
        self.binding = {"source_fingerprint": "a" * 64, "image_id": "sha256:" + "b" * 64}
        self.components = {
            name: {
                **self.binding,
                "status": "pass",
                "cases": [{"id": identifier, "status": "pass"} for identifier in sorted(required)],
            }
            for name, required in isolation_gates.required_access_cases().items()
        }
        self.components["storage"]["worker_image"] = self.binding["image_id"]
        self.components["storage"]["count"] = len(self.components["storage"]["cases"])

    def test_complete_identity_and_operation_matrix_is_required(self):
        cases = isolation_gates.reconcile_access(self.components, self.binding)
        self.assertEqual(len(cases), sum(len(item["cases"]) for item in self.components.values()))
        for name in self.components:
            with self.subTest(name=name):
                incomplete = copy.deepcopy(self.components)
                incomplete[name]["cases"].pop()
                with self.assertRaises(Rejected):
                    isolation_gates.reconcile_access(incomplete, self.binding)

    def test_failed_duplicate_foreign_or_missing_component_cannot_pass(self):
        for mutation in ("failed", "duplicate", "source", "image", "missing"):
            components = copy.deepcopy(self.components)
            if mutation == "failed":
                components["access"]["cases"][0]["status"] = "fail"
            elif mutation == "duplicate":
                components["access"]["cases"].append(components["access"]["cases"][0])
            elif mutation == "source":
                components["controller"]["source_fingerprint"] = "changed"
            elif mutation == "image":
                components["storage"]["worker_image"] = "changed"
            else:
                components.pop("controller")
            with self.assertRaises(Rejected):
                isolation_gates.reconcile_access(components, self.binding)

    def state_fixture(self, state):
        self.components["isolation"]["cluster"] = {"namespace_uid": "namespace"}
        self.components["storage"]["volume_uid"] = "volume"
        for name in ("access", "controller"):
            self.components[name]["dataset_reference"] = "c" * 64
        hashes = {}
        for name, report in self.components.items():
            filename = "kubernetes-storage-qualification" if name == "storage" else f"M20-{name}"
            path = state / "evidence" / f"{filename}.json"
            write_json(path, report)
            hashes[name] = digest(path.read_bytes())
        self.authority = {
            **self.binding,
            "status": "pass",
            "artifact_hashes": hashes,
            "dataset_reference": "c" * 64,
        }
        write_json(state / "evidence/authority-qualification.json", self.authority)

    def context(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.temporary = stack.enter_context(tempfile.TemporaryDirectory())
        state = Path(self.temporary)
        self.state_fixture(state)
        stack.enter_context(
            patch.object(
                isolation_gates, "validate_cluster", return_value={"namespace_uid": "namespace"}
            )
        )
        stack.enter_context(
            patch.object(
                isolation_gates.kube_storage, "validate", return_value={"volume_uid": "volume"}
            )
        )
        stack.enter_context(
            patch.object(
                isolation_gates,
                "source_fingerprint",
                return_value=self.binding["source_fingerprint"],
            )
        )
        stack.enter_context(
            patch.object(isolation_gates, "resolve_image", return_value=self.binding["image_id"])
        )
        self.perform = stack.enter_context(patch.object(isolation_gates, "perform_access_checks"))
        return state

    def save_access(self, state, access):
        path = state / "evidence/access-qualification.json"
        write_json(path, access)
        write_json(
            state / "evidence/M04.json",
            {
                "status": "pass",
                "exit_code": 0,
                "artifact_hashes": {"isolation_qualification": digest(path.read_bytes())},
            },
        )

    def access_fixture(self, state):
        access = isolation_gates.qualify_access(state, state)
        self.save_access(state, access)
        return access

    def test_access_gate_binds_persisted_components_to_live_resource_identities(self):
        state = self.context()
        result = isolation_gates.qualify_access(state, state)
        self.assertEqual(read_json(state / "evidence/access-qualification.json"), result)
        self.assertEqual(result["cluster_namespace_uid"], "namespace")
        self.assertEqual(result["storage_volume_uid"], "volume")
        self.perform.assert_called_once_with(state.resolve(), state)
        for fault in ("authority", "hash", "cluster", "volume", "dataset"):
            self.state_fixture(state)
            if fault == "authority":
                self.authority["status"] = "fail"
            elif fault == "hash":
                self.authority["artifact_hashes"]["isolation"] = "changed"
            elif fault == "cluster":
                self.components["isolation"]["cluster"]["namespace_uid"] = "foreign"
            elif fault == "volume":
                self.components["storage"]["volume_uid"] = "foreign"
            else:
                self.components["access"]["dataset_reference"] = "foreign"
            for name, component in self.components.items():
                filename = (
                    "kubernetes-storage-qualification" if name == "storage" else f"M20-{name}"
                )
                path = state / "evidence" / f"{filename}.json"
                write_json(path, component)
                if fault != "hash":
                    self.authority["artifact_hashes"][name] = digest(path.read_bytes())
            write_json(state / "evidence/authority-qualification.json", self.authority)
            with self.assertRaises(Rejected):
                isolation_gates.qualify_access(state, state)

    def test_reconciliation_rejects_component_status_and_invalid_case_shape(self):
        for changed in (
            {"status": "fail"},
            {"cases": None},
            {"cases": [{"id": None, "status": "pass"}]},
        ):
            components = copy.deepcopy(self.components)
            components["storage"].update(changed)
            with self.assertRaises(Rejected):
                isolation_gates.reconcile_access(components, self.binding)
        tables = {**isolation_gates.TABLES, "train": ("curator", ("publisher", "serving"))}
        with patch.object(isolation_gates, "TABLES", tables):
            with self.assertRaisesRegex(Rejected, "policy_contract_changed"):
                isolation_gates.required_access_cases()
        components = copy.deepcopy(self.components)
        components["storage"]["count"] -= 1
        with self.assertRaisesRegex(Rejected, "count_mismatch"):
            isolation_gates.reconcile_access(components, self.binding)

    def test_training_native_composition_requires_current_access_and_real_candidate_hook(self):
        state = self.context()
        access = self.access_fixture(state)
        observed = {"status": "pass", "model_sha256": "d" * 64, "bundle_sha256": "e" * 64}
        serving = {
            "status": "pass",
            "release_ready": False,
            "model_sha256": "d" * 64,
            "subject_sha256": "e" * 64,
            "candidate_reference": "f" * 64,
        }

        def candidate(root, state, image, **options):
            options["during_serving"](None, None, None)
            return serving

        with (
            patch.object(
                isolation_native, "load_image", return_value=("tag", self.binding["image_id"])
            ),
            patch.object(
                isolation_native,
                "source_fingerprint",
                return_value=self.binding["source_fingerprint"],
            ),
            patch.object(
                isolation_native, "validate_cluster", return_value={"namespace_uid": "namespace"}
            ),
            patch.object(isolation_native.release_native, "qualify") as release,
            patch.object(isolation_native, "exercise", return_value=observed),
            patch.object(
                isolation_native.candidate_serving_native, "qualify", side_effect=candidate
            ),
        ):
            result = isolation_gates.qualify_training(state, state, "image")
            self.assertEqual(read_json(state / "evidence/training-isolation.json"), result)
            self.assertFalse(serving["release_ready"])
            release.assert_called_once()
            for fault in ("access", "resources", "candidate", "runtime"):
                changed = copy.deepcopy(access)
                if fault == "access":
                    changed["status"] = "fail"
                elif fault == "resources":
                    changed["cluster_namespace_uid"] = "foreign"
                elif fault == "candidate":
                    serving["model_sha256"] = "foreign"
                else:
                    serving["model_sha256"] = observed["model_sha256"]
                    self.components["isolation"]["cases"][0]["status"] = "fail"
                    path = state / "evidence/M20-isolation.json"
                    write_json(path, self.components["isolation"])
                    changed["artifact_hashes"]["isolation"] = digest(path.read_bytes())
                self.save_access(state, changed)
                with self.assertRaises(Rejected):
                    isolation_native.qualify(state, state, "image")

    def test_missing_or_repeated_serving_hook_refuses(self):
        state = self.context()
        self.access_fixture(state)
        with (
            patch.object(
                isolation_native, "load_image", return_value=("tag", self.binding["image_id"])
            ),
            patch.object(
                isolation_native,
                "source_fingerprint",
                return_value=self.binding["source_fingerprint"],
            ),
            patch.object(
                isolation_native, "validate_cluster", return_value={"namespace_uid": "namespace"}
            ),
            patch.object(isolation_native.release_native, "qualify"),
            patch.object(isolation_native, "exercise", return_value={"status": "pass"}),
        ):
            with patch.object(
                isolation_native.candidate_serving_native,
                "qualify",
                return_value={"status": "pass"},
            ):
                with self.assertRaises(Rejected):
                    isolation_native.qualify(state, state, "image")

            def repeated(root, state, image, **options):
                options["during_serving"](None, None, None)
                options["during_serving"](None, None, None)

            with patch.object(
                isolation_native.candidate_serving_native, "qualify", side_effect=repeated
            ):
                with self.assertRaisesRegex(Rejected, "repeated_observer"):
                    isolation_native.qualify(state, state, "image")

    def test_gate_dispatches_are_fail_closed_without_prerequisites(self):
        state = self.context()
        for filename in (
            "controllers/resources.json",
            "storage.json",
            "cluster.json",
            "evidence/M04.json",
        ):
            write_json(state / filename, {})
        root = Path(__file__).resolve().parents[1]
        with patch.object(acceptance, "command", return_value="a" * 40):
            for gate, qualifier, filename in (
                ("M04", "qualify_access", "access-qualification.json"),
                ("M05", "qualify_training", "training-isolation.json"),
            ):
                result = {
                    "status": "pass",
                    "cases": [],
                    "checks": 0,
                    "limitations": ["controlled"],
                    "artifact_hashes": {},
                    "image_id": self.binding["image_id"],
                }
                write_json(state / "evidence" / filename, result)

                def completed(root, state):
                    write_json(state / "evidence" / filename, result)
                    return result

                with patch.object(isolation_gates, qualifier, side_effect=completed):
                    self.assertEqual(
                        acceptance.report(gate, "local-cpu", root, state)["exit_code"], 0
                    )
                for error, status in (
                    (Rejected("controlled"), "fail"),
                    (Rejected("required_tool_missing:controlled"), "inconclusive"),
                    (OSError("controlled"), "inconclusive"),
                    (subprocess.TimeoutExpired("controlled", 1), "inconclusive"),
                ):
                    with patch.object(isolation_gates, qualifier, side_effect=error):
                        self.assertEqual(
                            acceptance.report(gate, "local-cpu", root, state)["status"], status
                        )
                self.assertEqual(
                    acceptance.report(gate, "local-cpu", root, state / "missing")["status"],
                    "inconclusive",
                )

    def test_failed_new_access_attempt_invalidates_old_pass_and_M05(self):
        state = self.context()
        previous = self.access_fixture(state)
        self.perform.side_effect = Rejected("live_sql_acl_violation")
        with self.assertRaisesRegex(Rejected, "live_sql_acl_violation"):
            isolation_gates.qualify_access(state, state)
        current = read_json(state / "evidence/access-qualification.json")
        self.assertEqual(current["status"], "inconclusive")
        self.assertNotEqual(current["attempt_id"], previous["attempt_id"])
        with patch.object(isolation_native, "load_image") as loader:
            with self.assertRaisesRegex(Rejected, "current_M04_not_pass"):
                isolation_native.qualify(state, state, "image")
        loader.assert_not_called()

    def test_new_M04_failure_or_changed_storage_blocks_M05_before_resources(self):
        state = self.context()
        access = self.access_fixture(state)
        for fault in ("gate", "storage"):
            self.save_access(state, access)
            if fault == "gate":
                write_json(state / "evidence/M04.json", {"status": "fail", "exit_code": 1})
            else:
                write_json(
                    state / "evidence/kubernetes-storage-qualification.json", {"status": "fail"}
                )
            with patch.object(isolation_native, "load_image") as loader:
                with self.assertRaises(Rejected):
                    isolation_native.qualify(state, state, "image")
            loader.assert_not_called()

    def test_fresh_native_campaigns_execute_once_and_publish_M20_and_storage(self):
        from mlsecops import kube_storage_qualification

        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            with (
                patch.object(acceptance, "report", return_value={"status": "pass"}) as authority,
                patch.object(
                    kube_storage_qualification, "qualify", return_value={"status": "pass"}
                ) as storage,
            ):
                isolation_gates.perform_access_checks(state, state)
                authority.assert_called_once_with("M20", "local-cpu", state, state)
                storage.assert_called_once()
                self.assertEqual(read_json(state / "evidence/M20.json")["status"], "pass")
                self.assertEqual(
                    read_json(state / "evidence/kubernetes-storage-qualification.json")["status"],
                    "pass",
                )
                authority.return_value = {"status": "fail"}
                with self.assertRaisesRegex(Rejected, "fresh_M20_not_pass"):
                    isolation_gates.perform_access_checks(state, state)
                self.assertEqual(read_json(state / "evidence/M20.json")["status"], "fail")
                self.assertEqual(storage.call_count, 1)


class FaultServingContracts(unittest.TestCase):
    def setUp(self):
        self.engine = SimpleNamespace(worker=SimpleNamespace(container="actual-worker"))
        self.response = {
            "model_sha256": "a" * 64,
            "bundle_sha256": "b" * 64,
            "predictions": [{"score": 0.2, "decision": "score"}],
        }
        self.body = {"schema_version": 1, "instances": [{"controlled": 0.2}]}
        self.calls = []

    def request(self, path, body=None):
        self.calls.append(path)
        return 200, copy.deepcopy(self.response)

    def probe(self, state, image, image_id, action, **options):
        sample = options["observe"](
            {
                "metadata": {"uid": f"{action}-pod"},
                "status": {
                    "containerStatuses": [
                        {"state": {"running": {"startedAt": "2026-10-20T00:00:00Z"}}}
                    ]
                },
            }
        )
        sample["running_after_response"] = True
        return {
            "condition": "Failed",
            "reason": "DeadlineExceeded" if action == "deadline" else "BackoffLimitExceeded",
            "termination": "Error" if action == "deadline" else "OOMKilled",
            "elapsed_seconds": 12,
            "pod_uid": f"{action}-pod",
            "observations": 1,
            "pod_spec_digest": "c" * 64,
        }

    def test_real_http_response_identity_and_worker_survive_both_faults(self):
        with patch.object(isolation_native, "probe", side_effect=self.probe):
            result = isolation_native.exercise(
                self.engine,
                self.request,
                self.body,
                state=Path("."),
                image="tag",
                image_id="digest",
            )
        self.assertEqual(result["status"], "pass")
        self.assertEqual(set(result["faults"]), {"deadline", "oom"})
        self.assertEqual(result["model_sha256"], self.response["model_sha256"])
        self.assertEqual(result["response_sha256"], digest(canonical(self.response)))

    def test_failed_http_or_wrong_predictions_and_restarted_worker_refuse(self):
        for mutation in (
            "http",
            "prediction",
            "worker",
            "no-overlap",
            "termination",
            "shape",
            "pod",
            "after",
        ):

            def fault(state, image, image_id, action, **options):
                if mutation == "http":

                    def response(path, body=None):
                        return 503, {}
                elif mutation == "prediction":
                    self.response["predictions"][0]["score"] = 0.3
                    response = self.request
                else:
                    response = self.request
                if mutation == "worker":
                    self.engine.worker.container = "restarted"
                if mutation == "shape":
                    self.response.pop("predictions")
                if mutation == "http":
                    original = self.request
                    self.request = response
                    try:
                        return self.probe(state, image, image_id, action, **options)
                    finally:
                        self.request = original
                if mutation == "no-overlap":
                    return {"condition": "Failed", "reason": "DeadlineExceeded", "observations": 0}
                result = self.probe(state, image, image_id, action, **options)
                if mutation == "termination":
                    result["condition"] = "Complete"
                elif mutation == "pod":
                    result["pod_uid"] = "another-pod"
                elif mutation == "after":
                    self.response["predictions"][0]["score"] = 0.7
                return result

            with self.subTest(mutation=mutation):
                self.setUp()
                with patch.object(isolation_native, "probe", side_effect=fault):
                    with self.assertRaises(Rejected):
                        isolation_native.exercise(
                            self.engine,
                            lambda path, body=None: self.request(path, body),
                            self.body,
                            state=Path("."),
                            image="tag",
                            image_id="digest",
                        )

    def test_producer_exception_is_not_suppressed(self):
        with patch.object(isolation_native, "probe", side_effect=Rejected("controlled")):
            with self.assertRaisesRegex(Rejected, "controlled"):
                isolation_native.exercise(
                    self.engine,
                    self.request,
                    self.body,
                    state=Path("."),
                    image="tag",
                    image_id="digest",
                )


class RunningObservationContracts(unittest.TestCase):
    def test_callback_runs_only_for_observed_running_nonterminal_pod(self):
        pod = {
            "metadata": {"uid": "owned"},
            "status": {"containerStatuses": [{"state": {"running": {"startedAt": "now"}}}]},
        }
        responses = iter(
            (
                {"status": {}},
                {"items": [pod]},
                {
                    "status": {
                        "conditions": [
                            {"type": "Failed", "status": "True", "reason": "DeadlineExceeded"}
                        ]
                    }
                },
                {"items": []},
            )
        )
        observed = []
        with (
            patch.object(
                kube_worker,
                "kubectl",
                side_effect=lambda *args, **kwargs: SimpleNamespace(
                    stdout=canonical(next(responses))
                ),
            ),
            patch.object(kube_worker.time, "sleep"),
        ):
            result, _, _ = kube_worker.wait_job(
                Path("."), "ml-train", "owned", 10, observe=observed.append
            )
        self.assertEqual(observed, [pod])
        self.assertEqual(result["reason"], "DeadlineExceeded")


class ProbeExecutionContracts(unittest.TestCase):
    def setUp(self):
        self.pod = {
            "metadata": {
                "uid": "pod",
                "name": "controlled",
                "ownerReferences": [{"uid": "job", "controller": True}],
            },
            "spec": kube_worker.pod_spec(
                "image", "trainer", ["mlsecops.isolation_probe", "deadline"], memory="256Mi"
            ),
            "status": {"containerStatuses": [{"state": {"running": {"startedAt": "controlled"}}}]},
        }
        self.commands = []
        self.post = self.pod
        self.condition = {"type": "Failed", "reason": "DeadlineExceeded"}
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.execute = stack.enter_context(
            patch.object(kube_qualification, "kubectl", side_effect=self.command)
        )
        self.wait = stack.enter_context(
            patch.object(kube_qualification, "wait_job", side_effect=self.wait_job)
        )
        stack.enter_context(patch.object(kube_qualification, "verify_running_image"))

    def command(self, state, arguments, value=None, **options):
        self.commands.append(arguments)
        if arguments[0] == "create":
            result = {"metadata": {"uid": "job"}}
        elif arguments[0] == "get":
            result = self.post
        else:
            result = {"controlled": True}
        return SimpleNamespace(returncode=0, stdout=canonical(result))

    def wait_job(self, state, namespace, name, deadline, *, observe=None):
        if observe is not None:
            observe(self.pod)
        return self.condition, self.pod, 11

    def test_fault_probe_binds_owner_spec_and_post_http_running_observation(self):
        result = kube_qualification.probe(
            Path("."), "image", "digest", "deadline", observe=lambda pod: {}
        )
        self.assertEqual(result["job_uid"], "job")
        self.assertEqual(result["pod_uid"], "pod")
        self.assertEqual(result["observations"], 1)
        self.assertEqual(result["pod_spec"], self.pod["spec"])
        self.assertEqual(self.commands[-1][0], "delete")
        self.post = {"metadata": {"uid": "foreign"}, "status": {}}
        result = kube_qualification.probe(
            Path("."), "image", "digest", "deadline", observe=lambda pod: {}
        )
        self.assertEqual(result["observations"], 0)

    def test_default_probe_and_complete_logs_remain_supported(self):
        self.condition = {"type": "Complete"}
        result = kube_qualification.probe(Path("."), "image", "digest", "deadline")
        self.assertEqual(result["output"], {"controlled": True})
        self.assertNotIn("pod_spec", result)

    def test_create_failure_does_not_delete_an_unowned_job(self):
        self.execute.side_effect = Rejected("create-refused")
        with self.assertRaisesRegex(Rejected, "create-refused"):
            kube_qualification.probe(Path("."), "image", "digest", "deadline")
        self.assertEqual(self.execute.call_count, 1)

    def test_foreign_owner_and_wait_failure_preserve_refusal_and_cleanup(self):
        self.pod["metadata"]["ownerReferences"] = []
        with self.assertRaisesRegex(Rejected, "spec_or_owner_changed"):
            kube_qualification.probe(Path("."), "image", "digest", "deadline")
        self.assertEqual(self.commands[-1][0], "delete")
        self.wait.side_effect = Rejected("controlled-wait-failure")
        with self.assertRaisesRegex(Rejected, "controlled-wait-failure"):
            kube_qualification.probe(Path("."), "image", "digest", "deadline")
        self.assertEqual(self.commands[-1][0], "delete")


if __name__ == "__main__":
    unittest.main()
