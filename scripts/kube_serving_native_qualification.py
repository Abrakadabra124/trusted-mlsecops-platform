import copy
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import controller_resources, kube_serving_probe, serving_http
from mlsecops.contracts import Rejected, canonical
from scripts import kube_serving_native as native
from scripts.kube_serving_runtime_qualification import PROFILE


class NativeContracts(unittest.TestCase):
    def test_owned_sigterm_is_accepted_only_after_process_wait(self):
        import signal
        from unittest.mock import Mock

        for code in [0, -signal.SIGTERM, 1, -9]:
            process = Mock(returncode=code)
            process.poll.return_value = None
            if code in (0, -signal.SIGTERM):
                kube_serving_probe.stop(process)
            else:
                with self.assertRaises(Rejected):
                    kube_serving_probe.stop(process)
            process.send_signal.assert_called_once_with(signal.SIGTERM)
            process.wait.assert_called_once_with(timeout=20)

    def test_serving_permissions_are_scoped_and_legacy_roles_stay_separate(self):
        documents = controller_resources.resources("test", PROFILE["image"], serving=True)
        role = next(x for x in documents if x["kind"] == "Role")
        self.assertEqual(role["metadata"]["namespace"], "ml-serve")
        self.assertEqual(
            {r for rule in role["rules"] for r in rule["resources"]},
            {"jobs", "pods", "pods/attach"},
        )
        binding = next(x for x in documents if x["kind"] == "RoleBinding")
        self.assertEqual(
            binding["subjects"],
            [{"kind": "ServiceAccount", "name": "serving", "namespace": "ml-serving"}],
        )
        policy = next(x for x in documents if x["kind"] == "ValidatingAdmissionPolicy")
        self.assertEqual(policy["spec"]["failurePolicy"], "Fail")
        self.assertIn("mlsecops.serving_worker", canonical(policy).decode())
        old = controller_resources.resources("test", PROFILE["image"])
        self.assertEqual(
            {x["metadata"]["namespace"] for x in old if x["kind"] == "Role"},
            {"ml-train", "ml-eval"},
        )

    def test_native_cli_is_hosted_only_and_redacts_errors(self):
        with (
            patch.object(native, "hosted", side_effect=Rejected("private")),
            patch.object(native, "qualify") as qualify,
            patch.object(native.sys, "stderr", io.StringIO()) as stderr,
        ):
            self.assertEqual(native.main(["--state", "elsewhere"]), 1)
            self.assertEqual(stderr.getvalue(), "kubernetes_serving_native_rejected\n")
            qualify.assert_not_called()

    def test_harness_uses_real_cli_profile_and_private_failure_logs_with_cleanup(self):
        for success in [True, False]:
            with tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                (state / "evidence").mkdir()
                created = []

                def mapping(state, name, field, value):
                    return {
                        "kind": "ConfigMap",
                        "metadata": {"name": name},
                        "data": {field + ".json": canonical(value).decode()},
                    }

                spec = {
                    "serviceAccountName": "promoter",
                    "containers": [
                        {
                            "command": ["python", "-m", "mlsecops.promotion_controller"],
                            "resources": {"limits": {}, "requests": {}},
                        }
                    ],
                }

                def kubectl(state, args, value=None):
                    if args[0] == "create":
                        observed = copy.deepcopy(value)
                        observed["metadata"]["uid"] = "owned-uid"
                        created.append(observed)
                        return SimpleNamespace(stdout=canonical(observed))
                    return SimpleNamespace(
                        stdout=canonical(
                            {"status": "pass", "release_ready": False, "cases": ["verified"]}
                        )
                        if success
                        else b"PRIVATE-DIAGNOSTIC"
                    )

                def wait(*args):
                    return (
                        {"type": "Complete" if success else "Failed"},
                        {
                            "metadata": {
                                "name": "probe-pod",
                                "ownerReferences": [{"uid": "owned-uid"}],
                            },
                            "spec": created[-1]["spec"]["template"]["spec"],
                            "status": {
                                "containerStatuses": [
                                    {"state": {"terminated": {"exitCode": 0 if success else 1}}}
                                ]
                            },
                        },
                        2.5,
                    )

                with (
                    patch.object(native.kube_promotion, "configuration_map", side_effect=mapping),
                    patch.object(
                        native.kube_promotion, "pod_spec", return_value=copy.deepcopy(spec)
                    ),
                    patch.object(native, "mount_api"),
                    patch.object(native, "workspace_id", return_value="test"),
                    patch.object(native, "kubectl", side_effect=kubectl),
                    patch.object(native, "wait_job", side_effect=wait),
                    patch.object(native, "verify_running_image"),
                    patch.object(native.kube_storage, "verify_resource"),
                    patch.object(native.kube_promotion, "cleanup") as cleanup,
                ):
                    if success:
                        self.assertEqual(native.invoke(state, PROFILE, {}, {})["status"], "pass")
                    else:
                        with self.assertRaisesRegex(Rejected, "job_failed"):
                            native.invoke(state, PROFILE, {}, {})
                    self.assertEqual(cleanup.call_args.kwargs, {"namespace": "ml-serving"})
                pod = created[-1]["spec"]["template"]["spec"]
                self.assertEqual(pod["serviceAccountName"], "serving")
                self.assertEqual(pod["containers"][0]["command"][2], "mlsecops.kube_serving_probe")
                self.assertEqual(len(list((state / "evidence").glob("*-private.log"))), 1)

    def test_normal_config_selects_kubernetes_only_with_valid_matching_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            token = directory / "token"
            token.write_text("b" * 64)
            token.chmod(0o600)
            config = {
                "storage_client": "/client",
                "trust_client": "/trust-client",
                "context": {"policy": {"environment": "local-cpu"}},
                "trusted_root": "root",
                "expected_policy": "a" * 64,
                "expected_serving_image": PROFILE["image_id"],
                "minimum_sequence": 1,
                "trust_root": "root",
                "minimum_trust_version": 1,
                "audit_directory": str(directory / "audit"),
                "token_file": str(token),
                "kubernetes_worker": PROFILE,
            }
            path = directory / "config.json"
            path.write_bytes(canonical(config))
            with (
                patch.object(serving_http.trust, "Lease"),
                patch.object(serving_http.release_reader, "Reader"),
                patch.object(serving_http.serving, "Engine") as engine,
                patch.object(serving_http, "create_app"),
            ):
                serving_http.configured(path)
                factory = engine.call_args.kwargs["worker_factory"]
                self.assertEqual(factory.func.__module__, "mlsecops.kube_serving_runtime")
                self.assertEqual(factory.keywords["profile"], PROFILE)
                for bad in [None, {}, {**PROFILE, "image_id": "sha256:" + "e" * 64}]:
                    engine.reset_mock()
                    path.write_bytes(canonical({**config, "kubernetes_worker": bad}))
                    with self.assertRaises(Rejected):
                        serving_http.configured(path)
                    engine.assert_not_called()


if __name__ == "__main__":
    unittest.main()
