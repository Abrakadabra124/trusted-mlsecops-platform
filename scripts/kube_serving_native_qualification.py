import copy
import io
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import controller_resources, kube_serving_probe, serving_http
from mlsecops.contracts import Rejected, canonical
from scripts import kube_serving_native as native
from scripts.kube_serving_runtime_qualification import PROFILE


class NativeContracts(unittest.TestCase):
    def test_serving_configuration_is_separate_from_promotion_and_requires_exact_input(self):
        from scripts.kube_promotion_native import configuration

        arguments = dict(
            context={"policy": {"environment": "local-cpu"}},
            trusted_root="root",
            expected_policy="a" * 64,
            expected_serving_image=PROFILE["image_id"],
        )
        promotion = configuration("/client", "/trust-client", arguments, "authority")
        before = canonical(promotion)
        config = native.serving_configuration(promotion)
        self.assertEqual(config["identity_audit_file"], "/security/identity-audit.json")
        self.assertNotIn("security_audit_config", config)
        self.assertNotIn("schema_version", config)
        self.assertEqual(config["expected_serving_image"], PROFILE["image_id"])
        config["context"]["policy"]["environment"] = "changed"
        self.assertEqual(canonical(promotion), before)
        for changed in (
            {**promotion, "schema_version": 1},
            {**promotion, "foreign": True},
            {**promotion, "security_audit_config": "/other/audit.json"},
        ):
            with self.assertRaises(Rejected):
                native.serving_configuration(changed)

    def test_missing_or_promoter_identity_and_unverified_audit_never_create_serving_jobs(self):
        config = {
            "identity_audit_file": "/security/identity-audit.json",
            "context": {"policy": {"environment": "local-cpu"}},
            "trust_root": "root",
        }
        with (
            patch.object(native, "kubectl") as api,
            patch.object(native.kube_security_events, "validate") as validate,
        ):
            for bad in (
                {},
                {**config, "identity_audit_file": "/security/audit.json"},
                {**config, "security_audit_config": "/security/audit.json"},
            ):
                with self.assertRaisesRegex(Rejected, "serving_audit_configuration"):
                    native.invoke(Path("unused"), PROFILE, bad, {})
            validate.assert_not_called()
            validate.side_effect = Rejected("missing_owned_state")
            with self.assertRaisesRegex(Rejected, "missing_owned_state"):
                native.invoke(Path("unused"), PROFILE, config, {})
            api.assert_not_called()

    def test_prepare_requires_campaign_before_actual_refusal_and_does_not_continue_on_failure(self):
        for failure in (False, True):
            order = []

            def campaign(*args):
                order.append("campaign")
                if failure:
                    raise Rejected("campaign_incomplete")

            def actual(*args):
                order.append("actual")
                return {"candidate": "verified-refusal"}

            with (
                patch.object(native, "hosted"),
                patch.object(
                    native,
                    "command",
                    side_effect=lambda args: "a" * 40 if args[-1] == "HEAD" else "",
                ),
                patch.object(native, "source_fingerprint", return_value="b" * 64),
                patch.object(native.kube_storage, "validate"),
                patch.object(native.kube_trust, "bootstrap"),
                patch.object(
                    native.controller_bootstrap, "bootstrap", return_value={"profile": PROFILE}
                ),
                patch.object(native, "initialize_campaign", side_effect=campaign),
                patch.object(native, "actual", side_effect=actual),
                patch("sys.stdout", io.StringIO()),
            ):
                if failure:
                    with self.assertRaisesRegex(Rejected, "campaign_incomplete"):
                        native.prepare(Path.cwd(), Path.cwd() / ".runtime", "image")
                    self.assertEqual(order, ["campaign"])
                else:
                    result = native.prepare(Path.cwd(), Path.cwd() / ".runtime", "image")
                    self.assertEqual(order, ["campaign", "actual"])
                    self.assertEqual(result["actual"], {"candidate": "verified-refusal"})

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

    def test_privacy_observes_ordinary_cli_and_closed_audit_only_after_termination(self):
        self.approved_probe("privacy")

    def test_expiry_probe_uses_existing_http_process_without_stopping_worker(self):
        self.approved_probe("expiry")

    def test_live_fault_probe_preserves_cli_process_boundary(self):
        self.approved_probe("fault")

    def test_failed_startup_readiness_and_oversized_response_still_stop_owned_process(self):
        for fault in ("exit", "deadline", "readiness", "overflow"):
            with self.subTest(fault=fault), self.assertRaises(Rejected):
                self.approved_probe("ordinary", fault=fault)

    def test_startup_retry_and_delayed_owned_pod_disappearance_are_bounded(self):
        self.approved_probe("ordinary", fault="retry")
        self.approved_probe("ordinary", fault="retry-status")
        self.approved_probe("ordinary", fault="lingering")

    def approved_probe(self, mode, *, fault=None):
        import asyncio
        from unittest.mock import Mock

        from starlette.requests import Request

        from mlsecops.contracts import read_json
        from mlsecops.controller_api import APIError

        active = [False]
        attempts = [0]
        linger = [fault == "lingering"]
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
            if not active[0] and linger[0] and attempts[0] > 0:
                linger[0] = False
                return {"items": [worker]}
            return {"items": [worker] if active[0] else []}

        api.request.side_effect = api_request
        api.exchange.side_effect = APIError(403, "Forbidden")
        process = Mock(returncode=0)
        process.poll.return_value = None
        privacy = Mock() if mode == "privacy" else None
        if privacy is not None:

            def closed(directory, output, expected):
                self.assertEqual(process.poll(), 0)
                self.assertFalse(active[0])
                self.assertTrue(directory.is_dir())
                self.assertEqual(output, b"")
                return {"controlled_privacy": True}

            privacy.closed.side_effect = closed
        connection, pending = Mock(), []

        def http_request(method, path, *, body, headers):
            if path == "/livez":
                attempts[0] += 1
                if fault == "retry" and attempts[0] == 1:
                    raise OSError("controlled transient connection")
                code, payload = 200, {"live": True}
                if fault == "retry-status" and attempts[0] == 1:
                    code = 503
            elif not headers.get("Authorization"):
                code, payload = 401, {"error": "unauthorized"}
            elif not active[0]:
                code, payload = 503, {"error": "not_ready"}
            elif path == "/readyz":
                code, payload = (
                    (503, {"error": "not_ready"})
                    if fault == "readiness"
                    else (200, {"ready": True})
                )
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
            return Mock(
                status=code,
                read=lambda n: b"x" * 65537 if fault == "overflow" else canonical(payload),
            )

        connection.getresponse.side_effect = response
        temporary = tempfile.TemporaryDirectory

        def launch(args, **kwargs):
            self.assertEqual(args[1:4], ["-m", "mlsecops.serving_http", "--startup-diagnostics"])
            self.assertTrue(Path(read_json(Path(args[-1]))["audit_directory"]).is_dir())
            active[0] = True
            if fault == "exit":
                process.poll.return_value = 1
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
            patch.object(kube_serving_probe, "stop", side_effect=stop) as stopped,
            patch.object(kube_serving_probe.time, "sleep"),
            patch.object(kube_serving_probe.time, "monotonic", side_effect=[0, 101])
            if fault == "deadline"
            else nullcontext(),
            patch.object(
                kube_serving_probe.kube_serving_lifecycle, "exercise", return_value={"fault": True}
            ) as lifecycle,
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
                    **({"fault": "outage"} if mode == "fault" else {}),
                },
                **({"privacy": privacy} if privacy is not None else {}),
            )
        self.assertEqual(result["max_golden_error"], 0)
        stopped.assert_called_once()
        if mode not in {"expiry", "fault"}:
            self.assertIn("stopped-worker-503", result["cases"])
            expiry.assert_not_called()
            if privacy is not None:
                for callback in (
                    privacy.configure,
                    privacy.exercise,
                    privacy.fenced,
                    privacy.closed,
                ):
                    callback.assert_called_once()
                self.assertGreater(privacy.observe.call_count, 0)
                self.assertEqual(result["privacy"], {"controlled_privacy": True})
        elif mode == "expiry":
            self.assertNotIn("stopped-worker-503", result["cases"])
            self.assertEqual(result["lifecycle"], {"expiry": True})
            expiry.assert_called_once()
        else:
            self.assertEqual(result["lifecycle"], {"fault": True})
            lifecycle.assert_called_once()

    def test_privacy_modes_and_unexpected_admission_or_RBAC_never_start_the_cli(self):
        from unittest.mock import Mock

        from mlsecops.controller_api import APIError

        for expected in (
            {"ready": False},
            {"ready": True, "fault": "outage"},
            {"ready": True, "expires_at": 1},
        ):
            with patch.object(kube_serving_probe, "Client") as client, self.assertRaises(Rejected):
                kube_serving_probe.qualify({}, expected, privacy=Mock())
            client.assert_not_called()
        for fault in ("admission", "RBAC"):
            api = Mock()

            def request(resource, *args, **kwargs):
                if kwargs.get("method") == "POST":
                    if fault == "admission":
                        return {"metadata": {"uid": "owned"}}
                    raise APIError(403, "Forbidden")
                return {"items": []}

            api.request.side_effect = request
            with (
                patch.object(kube_serving_probe, "Client", return_value=api),
                patch.object(kube_serving_probe, "remove") as remove,
                patch.object(kube_serving_probe.subprocess, "Popen") as launch,
            ):
                with self.assertRaises(Rejected):
                    kube_serving_probe.qualify({"kubernetes_worker": PROFILE}, {"ready": True})
                launch.assert_not_called()
                if fault == "admission":
                    self.assertEqual(remove.call_args.args[-1], "owned")

    def test_shutdown_timeout_kills_only_the_owned_process_group_and_reports_failure(self):
        from unittest.mock import Mock

        process = Mock(pid=12345)
        process.poll.return_value = None
        process.wait.side_effect = [kube_serving_probe.subprocess.TimeoutExpired("owned", 20), 0]
        with (
            patch.object(kube_serving_probe.os, "killpg", create=True) as kill,
            patch.object(kube_serving_probe.signal, "SIGKILL", 9, create=True),
            self.assertRaisesRegex(Rejected, "shutdown_deadline"),
        ):
            kube_serving_probe.stop(process)
        kill.assert_called_once_with(12345, 9)
        self.assertEqual(process.wait.call_count, 2)

    def test_probe_cli_entrypoint_reads_explicit_paths_and_prints_checked_result(self):
        with (
            patch.object(kube_serving_probe, "enforce"),
            patch.object(kube_serving_probe, "Arguments") as parser,
            patch.object(kube_serving_probe, "read_json", return_value={}),
            patch.object(kube_serving_probe, "qualify", return_value={"status": "pass"}) as qualify,
            patch.object(kube_serving_probe.sys, "stdout", io.StringIO()) as output,
        ):
            parser.return_value.parse_args.return_value = SimpleNamespace(
                config=Path("config"), request=Path("request")
            )
            self.assertEqual(kube_serving_probe.main(), 0)
            qualify.assert_called_once()
            self.assertEqual(output.getvalue(), '{"status":"pass"}\n')

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
            patch.object(
                kube_serving_probe, "diagnose", return_value="reader-trust_policy_changed"
            ),
        ):
            for reader_refusal in ({}, {"reader_refusal": "trust_policy_changed"}):
                process.poll.return_value = None
                result = kube_serving_probe.qualify(
                    {"kubernetes_worker": PROFILE},
                    {"ready": False, "features": [[0.5] * 6], **reader_refusal},
                )
                self.assertEqual(result["status"], "pass")
                self.assertIn("refused-before-worker-start", result["cases"])
                self.assertEqual("expected-reader-refusal" in result["cases"], bool(reader_refusal))

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

    def test_already_terminated_cli_is_waited_without_signalling_a_stale_pid(self):
        from unittest.mock import Mock

        process = Mock(returncode=0)
        process.poll.return_value = 0
        kube_serving_probe.stop(process)
        process.send_signal.assert_not_called()
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

        for success, coordinated, foreign, privacy, cli in [
            (True, False, False, False, False),
            (False, False, False, False, False),
            (True, True, False, False, False),
            (True, True, True, False, False),
            (True, False, False, True, False),
            (True, False, True, True, False),
            (True, False, False, False, True),
            (True, False, True, False, True),
        ]:
            with tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                (state / "evidence").mkdir()
                created = []
                coordinator, acknowledgements = Mock(), Mock()
                privacy_operator = Mock()
                privacy_operator.start.side_effect = lambda: self.assertEqual(created, [])
                privacy_operator.finish.side_effect = lambda report, raw: report
                markers = []
                config = {
                    "identity_audit_file": "/security/identity-audit.json",
                    "context": {"policy": {"environment": "local-cpu"}},
                    "trust_root": "root",
                }

                def mapping(state, name, field, value):
                    return {
                        "kind": "ConfigMap",
                        "metadata": {"name": name},
                        "data": {field + ".json": canonical(value).decode()},
                    }

                spec = {
                    "serviceAccountName": "promoter",
                    "volumes": [
                        {"name": "scratch", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}}
                    ],
                    "containers": [
                        {
                            "command": ["python", "-m", "mlsecops.promotion_controller"],
                            "resources": {"limits": {}, "requests": {}},
                            "volumeMounts": [],
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
                    return SimpleNamespace(
                        stdout=b"\n".join([*markers, result]) + (b"\n" if cli else b"")
                    )

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
                    if privacy or cli:
                        kwargs["observe"](pod)
                    elif coordinated:
                        for phase in ["ready", "denied"]:
                            markers.append(
                                canonical(
                                    {"event": "trust-fault", "phase": phase, "fault": "outage"}
                                )
                            )
                            kwargs["observe"](pod)
                    return {"type": "Complete" if success else "Failed"}, pod, 2.5

                with (
                    patch.object(native.kube_security_events, "validate") as audit_profile,
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
                    patch.object(native.cli_exchange, "Receiver") as receiver,
                ):
                    receiver.return_value.finish.return_value = (b"private",)
                    if foreign:
                        with self.assertRaisesRegex(Rejected, "pod_changed"):
                            native.invoke(
                                state,
                                PROFILE,
                                config,
                                {"ready": True} if cli else {"fault": "outage"},
                                coordinator=coordinator if coordinated else None,
                                candidate_probe=privacy,
                                privacy_operator=privacy_operator if privacy else None,
                                cli_privacy=cli,
                            )
                        coordinator.assert_not_called()
                        acknowledgements.assert_not_called()
                        privacy_operator.observe.assert_not_called()
                    elif success:
                        self.assertEqual(
                            native.invoke(
                                state,
                                PROFILE,
                                config,
                                {"ready": True}
                                if cli
                                else {"fault": "outage"}
                                if coordinated
                                else {},
                                coordinator=coordinator if coordinated else None,
                                candidate_probe=privacy,
                                privacy_operator=privacy_operator if privacy else None,
                                cli_privacy=cli,
                            )["status"],
                            "pass",
                        )
                        if coordinated:
                            self.assertEqual(
                                [c.args[0] for c in coordinator.call_args_list], ["ready", "denied"]
                            )
                            self.assertEqual(acknowledgements.call_count, 2)
                        if privacy:
                            privacy_operator.observe.assert_called_once()
                            privacy_operator.finish.assert_called_once()
                            privacy_operator.start.assert_called_once()
                        if cli:
                            receiver.return_value.observe.assert_called_once()
                            receiver.return_value.finish.assert_called_once()
                    else:
                        with self.assertRaisesRegex(Rejected, "job_failed"):
                            native.invoke(state, PROFILE, config, {})
                    self.assertEqual(cleanup.call_args.kwargs, {"namespace": "ml-serving"})
                pod = created[-1]["spec"]["template"]["spec"]
                self.assertEqual(pod["serviceAccountName"], "serving")
                secrets = [v["secret"]["secretName"] for v in pod["volumes"] if "secret" in v]
                self.assertNotIn("security-promoter", secrets)
                self.assertNotIn("security-trust", secrets)
                if privacy:
                    self.assertNotIn("security-serving", secrets)
                    audit_profile.assert_not_called()
                else:
                    self.assertIn("security-serving", secrets)
                    audit_profile.assert_called_once_with(
                        state, profile=PROFILE, environment="local-cpu", authority_root="root"
                    )
                self.assertEqual(
                    pod["containers"][0]["command"][2],
                    "scripts.kube_cli_privacy_probe"
                    if cli
                    else "scripts.kube_privacy_probe"
                    if privacy
                    else "mlsecops.kube_serving_probe",
                )
                self.assertEqual(
                    len(list((state / "evidence").glob("*-private.log"))), 0 if foreign else 1
                )

    def test_privacy_mode_conflicts_refuse_before_resource_creation(self):
        from unittest.mock import Mock

        for options in (
            {},
            {"candidate_probe": True, "coordinator": Mock()},
            {"candidate_probe": True, "trust_target": native.Target.MODEL_REVOCATION},
        ):
            with patch.object(native, "kubectl") as api, self.assertRaises(Rejected):
                native.invoke(Path("unused"), PROFILE, {}, {}, privacy_operator=Mock(), **options)
            api.assert_not_called()

    def test_normal_config_selects_kubernetes_only_with_valid_matching_profile(self):
        from scripts.kube_promotion_native import configuration

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            token = directory / "token"
            token.write_text("b" * 64)
            token.chmod(0o600)
            arguments = {
                "context": {"policy": {"environment": "local-cpu"}},
                "trusted_root": "root",
                "expected_policy": "a" * 64,
                "expected_serving_image": PROFILE["image_id"],
            }
            config = {
                **native.serving_configuration(
                    configuration("/client", "/trust-client", arguments, "root")
                ),
                "minimum_sequence": 1,
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
                patch.object(serving_http, "create_app") as app,
                patch.object(serving_http.security_identity_http, "configured") as identity,
            ):
                serving_http.configured(path)
                identity.assert_called_once_with("/security/identity-audit.json")
                self.assertIs(app.call_args.kwargs["identity_audit"], identity.return_value)
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
