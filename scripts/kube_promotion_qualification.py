import copy
import io
import runpy
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import kube_promotion, kube_storage, promotion_state
from mlsecops.contracts import Rejected, canonical, digest, write_json


class KubernetesPromotionContracts(unittest.TestCase):
    def config(self):
        return {
            "schema_version": 1,
            "storage_client": "/client",
            "trust_client": "/trust-client",
            "context": {"policy": {"environment": "local-cpu"}},
            "trusted_root": "public",
            "expected_policy": "a" * 64,
            "expected_serving_image": "sha256:" + "b" * 64,
            "trust_root": "public",
            "minimum_trust_version": 1,
        }

    def request(self):
        return {
            "schema_version": 1,
            "proposal_reference": "c" * 64,
            "policy_reference": "d" * 64,
            "assurance_reference": None,
            "approval_reference": None,
        }

    def test_only_two_separate_credentials_and_pinned_command_are_mounted(self):
        profile = {"image": "image@sha256:" + "b" * 64, "image_id": "sha256:" + "b" * 64}
        spec = kube_promotion.pod_spec(profile, "owned-config", "owned-request")
        self.assertEqual(spec["serviceAccountName"], "promoter")
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertEqual(
            [v["secret"]["secretName"] for v in spec["volumes"] if "secret" in v],
            ["storage-client", "trust-client"],
        )
        self.assertEqual(len(spec["initContainers"]), 2)
        mounts = spec["containers"][0]["volumeMounts"]
        self.assertEqual(
            {v["mountPath"] for v in mounts},
            {"/tmp", "/client", "/trust-client", "/config.json", "/request.json"},
        )
        self.assertTrue(all(v["readOnly"] for v in mounts if v["mountPath"] != "/tmp"))
        self.assertFalse(any("hostPath" in v or "projected" in v for v in spec["volumes"]))
        self.assertEqual(
            spec["containers"][0]["command"],
            [
                "python",
                "-m",
                "mlsecops.promotion_controller",
                "--config",
                "/config.json",
                "--request",
                "/request.json",
            ],
        )
        for container in [*spec["initContainers"], *spec["containers"]]:
            self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
            self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])

    def test_request_cannot_override_configuration_or_embed_credentials(self):
        config, request = self.config(), self.request()
        kube_promotion.validate_inputs(config, request)
        for field, value in (
            ("storage_client", "/private"),
            ("trust_client", "/client"),
            ("schema_version", True),
        ):
            with self.assertRaises(Rejected):
                kube_promotion.validate_inputs({**config, field: value}, request)
        for altered in (
            {**request, "trusted_root": "foreign"},
            {**request, "proposal_reference": None},
            {**request, "policy_reference": "alias"},
            {**request, "schema_version": 2},
        ):
            with self.assertRaises(Rejected):
                kube_promotion.validate_inputs(config, altered)
        with self.assertRaises(Rejected):
            kube_promotion.validate_inputs(
                {**config, "context": {"padding": "x" * (512 * 1024)}}, request
            )

    def test_model_ledger_operator_uses_verified_kubernetes_backend(self):
        checksum = digest(promotion_state.migration_sql().encode())
        with (
            patch.object(kube_storage, "validate") as validate,
            patch.object(kube_storage, "admin", side_effect=["", "", "1:" + checksum]) as admin,
            patch.object(promotion_state, "admin") as docker,
        ):
            self.assertEqual(
                promotion_state.install("state", backend=kube_storage.binding), checksum
            )
            validate.assert_called_once_with("state")
            self.assertIn("CREATE SCHEMA ml_promotion", admin.call_args_list[1].args[1])
            docker.assert_not_called()
        with (
            patch.object(kube_storage, "validate"),
            patch.object(kube_storage, "admin", side_effect=["", "", "a" * 64]),
            patch.object(promotion_state, "admin") as docker,
        ):
            promotion_state.configure("state", "local-cpu", "a" * 64, backend=kube_storage.binding)
            docker.assert_not_called()
        with (
            patch.object(kube_storage, "validate", side_effect=Rejected("foreign")),
            patch.object(kube_storage, "admin") as admin,
            self.assertRaises(Rejected),
        ):
            promotion_state.install("state", backend=kube_storage.binding)
        admin.assert_not_called()

    def receipt(self):
        return {
            "state": "recorded-not-activated",
            "release_ready": False,
            "environment": "local-cpu",
            "sequence": 1,
            "proposal_reference": self.request()["proposal_reference"],
            "request_sha256": "e" * 64,
            "subject_sha256": "f" * 64,
        }

    def cluster(
        self, *, terminal="Complete", code=0, content=None, changed=False, fail_create=None
    ):
        self.profile = {
            "image": "immutable@sha256:" + "1" * 64,
            "image_id": "sha256:" + "b" * 64,
            "source_fingerprint": "frozen-source",
        }
        self.objects, self.deleted = {}, []

        def kubectl(state, arguments, document=None):
            if arguments[0] == "create":
                if fail_create is not None and len(self.objects) == fail_create:
                    raise Rejected("create-failed")
                observed = copy.deepcopy(document)
                observed["metadata"]["uid"] = "uid-" + str(len(self.objects))
                self.objects[kube_storage.reference(document)] = observed
                return SimpleNamespace(stdout=canonical(observed))
            if arguments[0] == "logs":
                return SimpleNamespace(
                    stdout=content if content is not None else canonical(self.receipt())
                )
            self.assertEqual(arguments[0], "delete")
            reference = "/".join((arguments[1], kube_promotion.NAMESPACE, arguments[2]))
            self.deleted.append(reference)
            del self.objects[reference]
            return SimpleNamespace(stdout=b"")

        def wait(state, namespace, name, timeout):
            job = self.objects[f"Job/{namespace}/{name}"]
            spec = copy.deepcopy(job["spec"]["template"]["spec"])
            if changed:
                spec["automountServiceAccountToken"] = True
            return (
                {"type": terminal},
                {
                    "spec": spec,
                    "metadata": {
                        "name": "pod",
                        "uid": "pod-uid",
                        "ownerReferences": [{"uid": job["metadata"]["uid"]}],
                    },
                    "status": {
                        "containerStatuses": [{"state": {"terminated": {"exitCode": code}}}]
                    },
                },
                1,
            )

        for module, field, replacement in (
            (kube_storage, "validate", lambda state: {}),
            (kube_promotion.kube_trust, "validate", lambda state: {}),
            (kube_promotion, "image_profile", lambda *args: self.profile),
            (kube_promotion, "workspace_id", lambda state: "a" * 32),
            (kube_promotion, "source_fingerprint", lambda root: "frozen-source"),
            (kube_promotion, "kubectl", kubectl),
            (kube_promotion, "wait_job", wait),
            (kube_promotion, "verify_running_image", lambda *args: None),
            (
                kube_storage,
                "get",
                lambda state, document: copy.deepcopy(
                    self.objects.get(kube_storage.reference(document))
                ),
            ),
        ):
            self.enterContext(patch.object(module, field, replacement))

    def invoke(self):
        return kube_promotion.invoke(Path.cwd(), "state", self.config(), self.request())

    def test_success_verifies_receipt_and_removes_only_its_job_and_maps(self):
        self.cluster()
        result = self.invoke()
        self.assertEqual(result["receipt"], self.receipt())
        self.assertEqual(result["execution"]["image_id"], self.config()["expected_serving_image"])
        self.assertEqual(self.objects, {})
        self.assertEqual(len(self.deleted), 3)
        self.assertTrue(self.deleted[0].startswith("Job/"))

    def test_normal_verifier_refusal_is_distinct_from_job_crash_or_invalid_receipt(self):
        self.cluster(terminal="Failed", code=1, content=b"promotion_rejected\n")
        self.assertEqual(self.invoke()["status"], "rejected")
        self.assertEqual(self.objects, {})
        for terminal, code, content, reason in (
            ("Failed", 137, b"promotion_rejected\n", "job_failed"),
            ("Failed", 1, b"private exception\n", "job_failed"),
            (
                "Complete",
                0,
                canonical({**self.receipt(), "release_ready": True}),
                "receipt_invalid",
            ),
        ):
            self.cluster(terminal=terminal, code=code, content=content)
            with self.assertRaisesRegex(Rejected, reason):
                self.invoke()
            self.assertEqual(self.objects, {})
        with self.assertRaisesRegex(Rejected, "missing_exit"):
            kube_promotion.outcome({"type": "Complete"}, {}, b"", self.config(), self.request())

    def test_sequence_conflict_is_distinct_from_expiry_generic_refusal_and_crash(self):
        self.cluster(terminal="Failed", code=1, content=b"promotion_sequence_conflict\n")
        result = self.invoke()
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason"], "promotion_sequence_conflict")
        self.assertIsNone(result["receipt"])
        self.assertEqual(self.objects, {})
        for content in (b"promotion_sequence_conflict extra\n", b"promotion_sequence_conflict"):
            self.cluster(terminal="Failed", code=1, content=content)
            with self.assertRaisesRegex(Rejected, "job_failed"):
                self.invoke()

    def test_rollback_history_refusal_is_exact_and_cleanup_completes(self):
        for reason in ("rollback_from_history", "rollback_target_history", "rollback_head_changed"):
            self.cluster(terminal="Failed", code=1, content=(reason + "\n").encode())
            result = self.invoke()
            self.assertEqual(result["reason"], reason)
            self.assertIsNone(result["receipt"])
            self.assertEqual(self.objects, {})
            self.cluster(terminal="Failed", code=1, content=(reason + ":private\n").encode())
            with self.assertRaisesRegex(Rejected, "job_failed"):
                self.invoke()

    def test_image_pod_and_source_changes_block_success_and_cleanup_still_runs(self):
        self.cluster()
        self.profile["image_id"] = "sha256:" + "e" * 64
        with self.assertRaisesRegex(Rejected, "image_pin_mismatch"):
            self.invoke()
        self.assertEqual(self.objects, {})
        self.cluster(changed=True)
        with self.assertRaisesRegex(Rejected, "pod_changed"):
            self.invoke()
        self.assertEqual(self.objects, {})
        self.cluster()
        with (
            patch.object(kube_promotion, "source_fingerprint", return_value="changed"),
            self.assertRaisesRegex(Rejected, "source_changed"),
        ):
            self.invoke()
        self.assertEqual(self.objects, {})

    def test_partial_creation_cleanup_and_foreign_uid_are_fail_closed(self):
        self.cluster(fail_create=1)
        with self.assertRaisesRegex(Rejected, "create-failed"):
            self.invoke()
        self.assertEqual(self.objects, {})
        document = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "owned", "namespace": "ml-promoter"},
        }
        observed = {**document, "metadata": {**document["metadata"], "uid": "foreign"}}
        with (
            patch.object(kube_storage, "get", return_value=observed),
            patch.object(kube_promotion, "kubectl") as delete,
            self.assertRaisesRegex(Rejected, "cleanup_unconfirmed"),
        ):
            kube_promotion.cleanup("state", [(document, "owned-uid")])
        delete.assert_not_called()
        observed["metadata"]["uid"] = "owned-uid"
        with (
            patch.object(kube_storage, "get", return_value=observed),
            patch.object(kube_promotion, "kubectl"),
            self.assertRaisesRegex(Rejected, "cleanup_unconfirmed"),
        ):
            kube_promotion.cleanup("state", [(document, "owned-uid")])

    def test_configure_validates_before_operator_changes_and_never_runs_for_submit(self):
        with (
            patch.object(kube_promotion.kube_trust, "validate"),
            patch.object(promotion_state, "install") as install,
            patch.object(promotion_state, "configure") as configure,
        ):
            self.assertEqual(
                kube_promotion.configure("state", self.config())["status"], "configured"
            )
            self.assertIs(install.call_args.kwargs["backend"], kube_storage.binding)
            self.assertIs(configure.call_args.kwargs["backend"], kube_storage.binding)
            install.reset_mock()
            with self.assertRaises(Rejected):
                kube_promotion.configure("state", {**self.config(), "trust_client": "/other"})
            install.assert_not_called()
        self.cluster()
        with (
            patch.object(promotion_state, "install") as install,
            patch.object(promotion_state, "configure") as configure,
        ):
            self.invoke()
            install.assert_not_called()
            configure.assert_not_called()

    def test_cli_exit_codes_and_diagnostics_do_not_leak_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            config, request = Path(directory) / "config.json", Path(directory) / "request.json"
            write_json(config, self.config())
            write_json(request, self.request())
            common = ["--state", directory, "--config", str(config)]
            with (
                patch.object(kube_promotion, "configure", return_value={"status": "configured"}),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(kube_promotion.main(["configure", *common]), 0)
            for status, expected in (("recorded-not-activated", 0), ("rejected", 1)):
                with (
                    patch.object(kube_promotion, "invoke", return_value={"status": status}),
                    redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(
                        kube_promotion.main(["submit", *common, "--request", str(request)]),
                        expected,
                    )
            with redirect_stderr(io.StringIO()):
                self.assertEqual(kube_promotion.main(["submit", *common]), 1)
            for error, expected in ((Rejected("private secret"), 1), (KeyboardInterrupt(), 130)):
                with (
                    patch.object(kube_promotion, "invoke", side_effect=error),
                    redirect_stderr(io.StringIO()) as output,
                ):
                    self.assertEqual(
                        kube_promotion.main(["submit", *common, "--request", str(request)]),
                        expected,
                    )
                self.assertEqual(output.getvalue(), "kubernetes_promotion_rejected\n")
        with (
            patch("sys.argv", ["kube-promotion"]),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as outcome,
        ):
            runpy.run_module("mlsecops.kube_promotion", run_name="__main__")
        self.assertEqual(outcome.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
