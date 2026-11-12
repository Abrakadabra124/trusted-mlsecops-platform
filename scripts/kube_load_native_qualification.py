import copy
import io
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, canonical, read_json
from scripts import kube_candidate_native as candidate
from scripts import kube_load_native as native
from scripts import kube_serving_native as serving
from scripts.kube_serving_runtime_qualification import PROFILE


class NativeLoadContracts(unittest.TestCase):
    def test_fresh_storage_installs_promotion_schema_before_candidate_snapshot(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(native, "hosted"),
            patch("mlsecops.promotion_state.install") as install,
            patch.object(native, "prepare", return_value={"profile": {}, "actual": {}}) as prepare,
        ):
            state = Path(temporary)

            def qualify(*args, **kwargs):
                from mlsecops import kube_storage

                install.assert_called_once_with(state, backend=kube_storage.binding)
                prepare.assert_called_once_with(state, state, "trusted-mlsecops:dev")
                raise Rejected("qualification_reached")

            with patch.object(native, "qualify", side_effect=qualify):
                with self.assertRaisesRegex(Rejected, "qualification_reached"):
                    native.run(state, state)
            with (
                patch.object(native, "prepare", side_effect=Rejected("preparation_failed")),
                patch.object(native, "qualify") as observe,
                self.assertRaisesRegex(Rejected, "preparation_failed"),
            ):
                native.run(state, state)
            observe.assert_not_called()

    def test_failure_site_contains_only_owned_public_source_location(self):
        self.assertEqual(native.failure_site(Rejected("PRIVATE")), {"module": "unknown", "line": 0})
        with patch.object(candidate, "hosted"):
            try:
                candidate.qualify("unused", "unused", "unused", load=True, privacy=True)
            except Rejected as failure:
                site = native.failure_site(failure)
        self.assertEqual(site["module"], "scripts.kube_candidate_native")
        self.assertGreater(site["line"], 0)
        try:
            exec(compile("raise ValueError('PRIVATE')", "/foreign/secret.py", "exec"), {})
        except ValueError as failure:
            site = native.failure_site(failure)
        self.assertEqual(site["module"], "scripts.kube_load_native_qualification")
        self.assertNotIn("PRIVATE", str(site))
        self.assertNotIn("secret", str(site))

    def test_mode_conflicts_do_not_create_resources(self):
        for options in (
            {},
            {"candidate_probe": True, "privacy_operator": Mock()},
            {"candidate_probe": True, "cli_privacy": True},
            {"candidate_probe": True, "coordinator": Mock()},
            {"candidate_probe": True, "trust_target": serving.Target.MODEL_REVOCATION},
        ):
            with patch.object(serving, "kubectl") as api, self.assertRaises(Rejected):
                serving.invoke(Path("unused"), PROFILE, {}, {}, load_operator=Mock(), **options)
            api.assert_not_called()
        for options in (
            {"privacy": True},
            {"include_trust_lifecycle": True},
            {"include_key_revocation": True},
            {},
        ):
            with (
                patch.object(candidate, "hosted"),
                patch.object(candidate, "command") as command,
                self.assertRaises(Rejected),
            ):
                candidate.qualify(
                    Path("unused"),
                    Path("unused"),
                    "image",
                    load=1 if not options else True,
                    **options,
                )
            command.assert_not_called()

    def test_load_dispatch_deadline_observer_and_owned_cleanup(self):
        for failed, cause in (
            (False, "unknown"),
            ("measure", "unknown"),
            ("shutdown", "audit_shutdown_pending"),
            ("shutdown", "PRIVATE"),
            ("shutdown", ["PRIVATE"]),
        ):
            created = []
            report = (
                {
                    "status": "fail",
                    "release_ready": False,
                    "code": "load_probe_rejected",
                    "phase": failed,
                    "cause": cause,
                }
                if failed
                else {"status": "pass", "release_ready": False}
            )
            observer = Mock()
            observer.finish.side_effect = lambda report, raw: report

            def api(state, args, value=None, **kwargs):
                if args[0] == "create":
                    document = copy.deepcopy(value)
                    document["metadata"]["uid"] = "uid-" + str(len(created))
                    created.append(document)
                    return SimpleNamespace(stdout=canonical(document))
                if args[0] == "logs":
                    return SimpleNamespace(stdout=canonical(report) + b"\n")
                raise AssertionError(args)

            def wait(*args, **kwargs):
                self.assertEqual(args[3], 360)
                pod = {
                    "metadata": {
                        "name": "owned",
                        "ownerReferences": [{"uid": created[-1]["metadata"]["uid"]}],
                    },
                    "spec": created[-1]["spec"]["template"]["spec"],
                    "status": {
                        "containerStatuses": [
                            {"state": {"terminated": {"exitCode": int(bool(failed))}}}
                        ]
                    },
                }
                kwargs["observe"](pod)
                return {"type": "Failed" if failed else "Complete"}, pod, 150

            with (
                tempfile.TemporaryDirectory() as temporary,
                patch.object(serving, "kubectl", side_effect=api),
                patch.object(serving, "wait_job", side_effect=wait),
                patch.object(serving, "verify_running_image"),
                patch.object(serving, "workspace_id", return_value="a" * 32),
                patch.object(serving.kube_promotion, "cleanup") as cleanup,
                patch.object(serving.kube_security_events, "validate") as audit,
                patch("mlsecops.kube_serving_handoff.require_probe_slot") as slot,
                patch("mlsecops.kube_serving_handoff.wait_pods_absent") as pods,
                patch.object(serving.kube_storage, "verify_resource"),
                patch.object(
                    serving.kube_promotion,
                    "configuration_map",
                    side_effect=lambda state, name, field, value: {
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                        "metadata": {"name": name},
                        "data": {field: "{}"},
                    },
                ),
                patch.object(
                    serving.kube_promotion,
                    "pod_spec",
                    return_value={
                        "containers": [
                            {
                                "name": "worker",
                                "command": ["python", "-m", "old"],
                                "resources": {"limits": {}, "requests": {}},
                                "volumeMounts": [],
                            }
                        ],
                        "volumes": [
                            {
                                "name": "scratch",
                                "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"},
                            }
                        ],
                    },
                ),
                patch.object(sys, "stdout", io.StringIO()) as output,
            ):
                (Path(temporary) / "evidence").mkdir()
                config = {"context": {"policy": {"environment": "local-cpu"}}, "trust_root": "root"}
                if failed:
                    with self.assertRaisesRegex(Rejected, "job_failed"):
                        serving.invoke(
                            Path(temporary),
                            PROFILE,
                            config,
                            {},
                            candidate_probe=True,
                            load_operator=observer,
                        )
                    if type(cause) is str and cause in serving.load_diagnostics.FAILURES:
                        self.assertIn('"phase":"' + failed + '"', output.getvalue())
                        self.assertIn('"cause":"' + cause + '"', output.getvalue())
                    else:
                        self.assertIn('"probe_failure":"unclassified"', output.getvalue())
                    self.assertNotIn("PRIVATE", output.getvalue())
                else:
                    result = serving.invoke(
                        Path(temporary),
                        PROFILE,
                        config,
                        {},
                        candidate_probe=True,
                        load_operator=observer,
                    )
                    self.assertEqual(result["status"], "pass")
                    observer.finish.assert_called_once()
                observer.start.assert_called_once()
                observer.observe.assert_called_once()
                cleanup.assert_called_once()
                audit.assert_called_once_with(
                    Path(temporary), profile=PROFILE, environment="local-cpu", authority_root="root"
                )
                slot.assert_called_once_with(Path(temporary), marker=audit.return_value)
                pods.assert_called_once_with(Path(temporary))
                self.assertEqual(created[-1]["spec"]["activeDeadlineSeconds"], 360)
                pod = created[-1]["spec"]["template"]["spec"]
                secret_names = [
                    volume["secret"]["secretName"]
                    for volume in pod["volumes"]
                    if "secret" in volume
                ]
                self.assertIn("security-serving", secret_names)
                self.assertNotIn("security-promoter", secret_names)
                self.assertEqual(pod["containers"][0]["resources"]["limits"]["memory"], "1Gi")
                self.assertEqual(
                    pod["volumes"][0],
                    {"name": "scratch", "emptyDir": {"medium": "Memory", "sizeLimit": "640Mi"}},
                )
                self.assertEqual(
                    created[-1]["spec"]["template"]["spec"]["containers"][0]["command"][2],
                    "mlsecops.load_probe",
                )

    def test_public_projection_has_no_private_packet_and_preserves_failed_profile(self):
        result = {
            key: "fixture"
            for key in (
                "source",
                "source_dirty",
                "started_at",
                "finished_at",
                "candidate_reference",
                "proposal_reference",
                "model_sha256",
                "subject_sha256",
                "qualification_permit_sha256",
            )
        }
        result.update(
            full_M14="inconclusive",
            release_ready=False,
            native={"profile_met": False},
            private_key="PRIVATE",
        )
        prepared = {"profile": {"image_id": "image"}, "actual": {"proposal": "signed"}}
        order = []

        def prepare(*args):
            order.append("prepare")
            return prepared

        def observe(*args, **kwargs):
            order.append("qualify")
            return result

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(native, "hosted"),
            patch.object(native, "prepare", side_effect=prepare) as preparation,
            patch.object(native, "qualify", side_effect=observe) as qualify,
            patch("mlsecops.promotion_state.install"),
        ):
            state = Path(temporary)
            public = native.run(state, state)
            self.assertEqual(public["status"], "fail")
            self.assertNotIn("PRIVATE", str(public))
            self.assertEqual(read_json(state / "evidence/kubernetes-load-private.json"), result)
            self.assertEqual(read_json(state / "evidence/kubernetes-load-public.json"), public)
            self.assertEqual(order, ["prepare", "qualify"])
            preparation.assert_called_once_with(state, state, "trusted-mlsecops:dev")
            qualify.assert_called_once_with(
                state,
                state,
                "trusted-mlsecops:dev",
                load=True,
                prepared=(prepared["profile"], prepared["actual"]),
            )

    def test_exit_code_and_sanitized_failure_diagnostics(self):
        for result, wanted in (
            ({"status": "pass"}, 0),
            ({"status": "fail"}, 1),
            (Rejected("load_resource_tail_missing"), 1),
            (RuntimeError("PRIVATE"), 1),
            (Rejected("load_private_value"), 1),
        ):
            with (
                patch.object(
                    native,
                    "run",
                    side_effect=result if isinstance(result, Exception) else None,
                    return_value=result,
                ),
                patch.object(sys, "stdout", io.StringIO()) as output,
            ):
                self.assertEqual(native.main(), wanted)
            self.assertNotIn("PRIVATE", output.getvalue())
            self.assertNotIn("load_private_value", output.getvalue())
        with (
            patch("scripts.kube_trust_native.hosted", side_effect=Rejected("not-hosted")),
            patch.object(sys, "stdout", io.StringIO()),
            self.assertRaises(SystemExit) as stop,
        ):
            runpy.run_path(native.__file__, run_name="__main__")
        self.assertEqual(stop.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
