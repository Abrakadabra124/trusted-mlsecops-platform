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
    def test_failed_readiness_diagnostic_is_read_only_and_does_not_echo_private_errors(self):
        config = {
            key: "unused"
            for key in (
                "storage_client",
                "trust_client",
                "trusted_root",
                "expected_policy",
                "expected_serving_image",
                "minimum_sequence",
                "trust_root",
                "minimum_trust_version",
            )
        }
        config["context"] = {"policy": {"environment": "local-cpu"}}
        with (
            patch("mlsecops.release_reader.Reader") as reader,
            patch("mlsecops.trust.Lease"),
            patch("mlsecops.kube_serving_runtime.Worker") as worker,
        ):
            self.assertEqual(kube_serving_probe.diagnose(config), "reader-verified")
            reader.return_value.load.side_effect = Rejected("trust_service_unavailable")
            self.assertEqual(
                kube_serving_probe.diagnose(config), "reader-trust_service_unavailable"
            )
            reader.return_value.load.side_effect = Rejected("PRIVATE-CREDENTIAL")
            self.assertEqual(kube_serving_probe.diagnose(config), "reader-other-refusal")
            worker.assert_not_called()

    def test_probe_error_codes_preserve_known_assertions_without_private_text(self):
        import json

        for message, expected in [
            (
                "kube_serving_probe:three-HTTP-predictions",
                "kube_serving_probe:three-HTTP-predictions",
            ),
            ("PRIVATE-TOKEN", "unclassified"),
            ("kube_serving_probe:three-HTTP-predictions PRIVATE-TOKEN", "unclassified"),
        ]:
            with (
                patch.object(kube_serving_probe, "enforce", side_effect=Rejected(message)),
                patch.object(kube_serving_probe.sys, "stdout", io.StringIO()) as output,
            ):
                self.assertEqual(kube_serving_probe.main(), 1)
                report = json.loads(output.getvalue())
            self.assertEqual(report["code"], expected)
            self.assertNotIn("PRIVATE-TOKEN", str(report))

    def test_approved_probe_obeys_actual_http_body_contract(self):
        self.approved_probe("ordinary")

    def test_expiry_probe_uses_existing_http_process_without_stopping_worker(self):
        self.approved_probe("expiry")

    def approved_probe(self, mode):
        import asyncio
        from unittest.mock import Mock

        from starlette.requests import Request

        from mlsecops.contracts import read_json
        from mlsecops.controller_api import APIError

        active = [False]
        model, bundle = "a" * 64, "b" * 64
        worker = {
            "metadata": {
                "uid": "pod-uid",
                "labels": {"job-name": "serving-worker-owned"},
                "ownerReferences": [{"uid": "job-uid"}],
            }
        }
        api = Mock()

        def api_request(resource, *args, **kwargs):
            if kwargs.get("method") == "POST":
                raise APIError(403, "Forbidden")
            if kwargs.get("method") == "DELETE":
                active[0] = False
                return {}
            return {"items": [worker] if active[0] else []}

        api.request.side_effect = api_request
        api.exchange.side_effect = APIError(403, "Forbidden")
        process = Mock(returncode=0)
        process.poll.return_value = None
        connection, pending = Mock(), []

        def http_request(method, path, *, body, headers):
            if path == "/livez":
                code, payload = 200, {"live": True}
            elif not headers.get("Authorization"):
                code, payload = 401, {"error": "unauthorized"}
            elif not active[0]:
                code, payload = 503, {"error": "not_ready"}
            elif path == "/readyz":
                code, payload = 200, {"ready": True}
            else:

                async def receive():
                    return {"type": "http.request", "body": body, "more_body": False}

                scope = {
                    "type": "http",
                    "method": method,
                    "path": path,
                    "query_string": b"",
                    "headers": [
                        (key.lower().encode(), value.encode()) for key, value in headers.items()
                    ]
                    + [(b"content-length", str(len(body)).encode())],
                }
                try:
                    rows = asyncio.run(serving_http.read_body(Request(scope, receive)))
                    code, payload = (
                        200,
                        {
                            "model_sha256": model,
                            "bundle_sha256": bundle,
                            "predictions": [{"score": 0.75} for row in rows],
                        },
                    )
                except serving_http.BodyLimit:
                    code, payload = 413, {"error": "body_limit"}
                except Rejected:
                    code, payload = 422, {"error": "invalid_input"}
            pending.append((code, payload))

        connection.request.side_effect = http_request

        def response():
            code, payload = pending.pop(0)
            return Mock(status=code, read=lambda n: canonical(payload))

        connection.getresponse.side_effect = response
        temporary = tempfile.TemporaryDirectory

        def launch(args, **kwargs):
            self.assertTrue(Path(read_json(Path(args[-1]))["audit_directory"]).is_dir())
            active[0] = True
            return process

        def stop(process):
            active[0] = False
            process.poll.return_value = 0

        with (
            patch.object(kube_serving_probe, "Client", return_value=api),
            patch.object(
                kube_serving_probe.tempfile,
                "TemporaryDirectory",
                side_effect=lambda **kwargs: temporary(prefix="serving-probe-test-"),
            ),
            patch.object(kube_serving_probe.subprocess, "Popen", side_effect=launch),
            patch.object(kube_serving_probe.http.client, "HTTPConnection", return_value=connection),
            patch.object(kube_serving_probe, "stop", side_effect=stop),
            patch.object(
                kube_serving_probe.kube_serving_expiry, "exercise", return_value={"expiry": True}
            ) as expiry,
        ):
            result = kube_serving_probe.qualify(
                {"kubernetes_worker": PROFILE},
                {
                    "ready": True,
                    "features": [[0.5] * 6],
                    "scores": [0.75],
                    "model": model,
                    "bundle": bundle,
                    **({"expires_at": 123} if mode == "expiry" else {}),
                },
            )
        self.assertEqual(result["max_golden_error"], 0)
        if mode == "ordinary":
            self.assertIn("stopped-worker-503", result["cases"])
            expiry.assert_not_called()
        else:
            self.assertNotIn("stopped-worker-503", result["cases"])
            self.assertEqual(result["lifecycle"], {"expiry": True})
            expiry.assert_called_once()

    def test_refusal_probe_prepares_private_audit_before_ordinary_cli_start(self):
        from unittest.mock import Mock

        from mlsecops.contracts import read_json
        from mlsecops.controller_api import APIError

        api = Mock()

        def api_request(resource, *args, **kwargs):
            if kwargs.get("method") == "POST":
                raise APIError(403, "Forbidden")
            return {"items": []}

        api.request.side_effect = api_request
        api.exchange.side_effect = APIError(403, "Forbidden")
        process = Mock(returncode=0)
        process.poll.return_value = None
        connection = Mock()
        pending = []
        connection.request.side_effect = lambda method, path, **kwargs: pending.append(path)

        def response():
            path = pending.pop(0)
            return Mock(
                status=200 if path == "/livez" else 503,
                read=lambda n: canonical({"status": "controlled"}),
            )

        connection.getresponse.side_effect = response
        temporary = tempfile.TemporaryDirectory

        def launch(args, **kwargs):
            config = read_json(Path(args[-1]))
            audit = Path(config["audit_directory"])
            self.assertTrue(audit.is_dir(), "audit directory must preexist before CLI starts")
            return process

        def stop(process):
            process.poll.return_value = 0

        with (
            patch.object(kube_serving_probe, "Client", return_value=api),
            patch.object(
                kube_serving_probe.tempfile,
                "TemporaryDirectory",
                side_effect=lambda **kwargs: temporary(prefix="serving-probe-test-"),
            ),
            patch.object(kube_serving_probe.subprocess, "Popen", side_effect=launch),
            patch.object(kube_serving_probe.http.client, "HTTPConnection", return_value=connection),
            patch.object(kube_serving_probe, "stop", side_effect=stop),
        ):
            result = kube_serving_probe.qualify(
                {"kubernetes_worker": PROFILE}, {"ready": False, "features": [[0.5] * 6]}
            )
        self.assertEqual(result["status"], "pass")
        self.assertIn("refused-before-worker-start", result["cases"])

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
        from unittest.mock import Mock

        for success, coordinated, foreign in [
            (True, False, False),
            (False, False, False),
            (True, True, False),
            (True, True, True),
        ]:
            with tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                (state / "evidence").mkdir()
                created = []
                coordinator, acknowledgements = Mock(), Mock()
                markers = []

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
                    result = (
                        canonical({"status": "pass", "release_ready": False, "cases": ["verified"]})
                        if success
                        else b"PRIVATE-DIAGNOSTIC"
                    )
                    return SimpleNamespace(stdout=b"\n".join([*markers, result]))

                def wait(*args, **kwargs):
                    pod = {
                        "metadata": {
                            "name": "probe-pod",
                            "ownerReferences": [{"uid": "foreign-uid" if foreign else "owned-uid"}],
                        },
                        "spec": created[-1]["spec"]["template"]["spec"],
                        "status": {
                            "containerStatuses": [
                                {"state": {"terminated": {"exitCode": 0 if success else 1}}}
                            ]
                        },
                    }
                    if coordinated:
                        for phase in ["ready", "denied"]:
                            markers.append(
                                canonical(
                                    {"event": "trust-fault", "phase": phase, "fault": "outage"}
                                )
                            )
                            kwargs["observe"](pod)
                    return {"type": "Complete" if success else "Failed"}, pod, 2.5

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
                    patch.object(native, "acknowledge", acknowledgements),
                ):
                    if foreign:
                        with self.assertRaisesRegex(Rejected, "pod_changed"):
                            native.invoke(
                                state, PROFILE, {}, {"fault": "outage"}, coordinator=coordinator
                            )
                        coordinator.assert_not_called()
                        acknowledgements.assert_not_called()
                    elif success:
                        self.assertEqual(
                            native.invoke(
                                state,
                                PROFILE,
                                {},
                                {"fault": "outage"} if coordinated else {},
                                coordinator=coordinator if coordinated else None,
                            )["status"],
                            "pass",
                        )
                        if coordinated:
                            self.assertEqual(
                                [c.args[0] for c in coordinator.call_args_list], ["ready", "denied"]
                            )
                            self.assertEqual(acknowledgements.call_count, 2)
                    else:
                        with self.assertRaisesRegex(Rejected, "job_failed"):
                            native.invoke(state, PROFILE, {}, {})
                    self.assertEqual(cleanup.call_args.kwargs, {"namespace": "ml-serving"})
                pod = created[-1]["spec"]["template"]["spec"]
                self.assertEqual(pod["serviceAccountName"], "serving")
                self.assertEqual(pod["containers"][0]["command"][2], "mlsecops.kube_serving_probe")
                self.assertEqual(
                    len(list((state / "evidence").glob("*-private.log"))), 0 if foreign else 1
                )

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
