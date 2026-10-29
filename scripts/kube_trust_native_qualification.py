import copy
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, read_json, write_json
from scripts import kube_trust_native as target


class KubernetesTrustNativeContracts(unittest.TestCase):
    def test_hosted_guard_precedes_any_infrastructure_or_output_access(self):
        for platform, environment in (
            ("win32", {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}),
            ("linux", {}),
            ("linux", {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}),
        ):
            with (
                patch.object(target.sys, "platform", platform),
                patch.dict(target.os.environ, environment, clear=True),
                patch.object(target.kube_storage, "validate") as validate,
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(target.main(["--state", "private"]), 1)
                validate.assert_not_called()
        with (
            patch.object(target.sys, "platform", "linux"),
            patch.dict(
                target.os.environ,
                {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"},
                clear=True,
            ),
        ):
            target.hosted()

    def test_stale_success_is_invalidated_before_work_and_failure_is_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            output = state / "evidence/kubernetes-trust.json"
            write_json(output, {"status": "pass"})

            def failed(*args):
                self.assertEqual(read_json(output)["status"], "inconclusive")
                raise Rejected("private detail")

            with (
                patch.object(target, "hosted"),
                patch.object(target.kube_storage, "validate"),
                patch.object(target, "qualify", side_effect=failed),
                redirect_stderr(io.StringIO()) as errors,
            ):
                self.assertEqual(target.main(["--state", str(state)]), 1)
            self.assertEqual(read_json(output), {"status": "fail", "release_ready": False})
            self.assertEqual(errors.getvalue(), "kubernetes_trust_native_rejected\n")
            with (
                patch.object(target, "hosted"),
                patch.object(target.kube_storage, "validate"),
                patch.object(target, "qualify", return_value={"status": "pass"}),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(target.main(["--state", str(state)]), 0)
            with (
                patch.object(target, "hosted"),
                patch.object(target.kube_storage, "validate"),
                patch.object(target, "write_json", side_effect=OSError("private path")),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(target.main(["--state", str(state)]), 1)

    def job(self, *, failed=False, changed=False, bad_report=False):
        self.document = None
        self.deleted = False

        def kubectl(state, arguments, document=None):
            if arguments[0] == "create":
                self.document = copy.deepcopy(document)
                self.document["metadata"]["uid"] = "owned-job"
                return SimpleNamespace(stdout=canonical(self.document))
            if arguments[0] == "delete":
                self.deleted = True
                return SimpleNamespace(stdout=b"")
            self.assertEqual(arguments[0], "logs")
            return SimpleNamespace(
                stdout=canonical(
                    {
                        "status": "fail" if bad_report else "pass",
                        "role": "promoter",
                        "release_ready": False,
                        "cases": ["controlled"],
                    }
                )
            )

        def wait(*args):
            spec = copy.deepcopy(self.document["spec"]["template"]["spec"])
            if changed:
                spec["automountServiceAccountToken"] = True
            return (
                {"type": "Failed" if failed else "Complete"},
                {
                    "spec": spec,
                    "metadata": {"name": "owned-pod", "ownerReferences": [{"uid": "owned-job"}]},
                },
                1,
            )

        for module, name, replacement in (
            (target, "workspace_id", lambda state: "a" * 32),
            (target, "kubectl", kubectl),
            (target, "wait_job", wait),
            (target, "verify_running_image", lambda *args: None),
            (
                target.kube_storage,
                "get",
                lambda *args: None if self.deleted else copy.deepcopy(self.document),
            ),
        ):
            self.enterContext(patch.object(module, name, replacement))

    def test_owned_reader_job_is_verified_and_removed_after_success(self):
        self.job()
        result = target.reader(
            "state",
            {"image": "image", "image_id": "id"},
            "promoter",
            "root",
            "policy",
            2,
            ["a" * 64],
            unavailable=True,
        )
        self.assertEqual(result["status"], "pass")
        self.assertTrue(self.deleted)
        command = self.document["spec"]["template"]["spec"]["containers"][0]["command"]
        self.assertIn("--unavailable", command)
        self.assertIn("--revoked", command)

    def test_failed_or_drifted_or_invalid_reader_is_not_pass_and_still_cleaned(self):
        for arguments, code in (
            ({"failed": True}, "job_failed"),
            ({"changed": True}, "pod_boundary_changed"),
            ({"bad_report": True}, "report_invalid"),
        ):
            with self.subTest(arguments=arguments):
                self.job(**arguments)
                with self.assertRaisesRegex(Rejected, code):
                    target.reader(
                        "state",
                        {"image": "image", "image_id": "id"},
                        "promoter",
                        "root",
                        "policy",
                        1,
                    )
                self.assertTrue(self.deleted)

    def test_outage_scale_refuses_foreign_statefulset_or_unexpected_state(self):
        document = {
            "kind": "StatefulSet",
            "metadata": {"name": "postgres", "namespace": "ml-trust"},
            "spec": {"replicas": 1, "template": {"spec": {}}},
        }
        original = {**document, "metadata": {**document["metadata"], "uid": "owned"}}
        with (
            patch.object(target.kube_storage, "get", return_value=original),
            patch.object(target, "kubectl") as scale,
        ):
            target.scale("state", document, "owned", 0)
            self.assertIn("--replicas=0", scale.call_args.args[1])
        for observed in (
            {**original, "metadata": {**original["metadata"], "uid": "foreign"}},
            {**original, "spec": {**original["spec"], "replicas": 0}},
        ):
            with (
                patch.object(target.kube_storage, "get", return_value=observed),
                patch.object(target, "kubectl") as scale,
                self.assertRaises(Rejected),
            ):
                target.scale("state", document, "owned", 0)
            scale.assert_not_called()


if __name__ == "__main__":
    unittest.main()
