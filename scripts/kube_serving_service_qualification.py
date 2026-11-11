"""Persistent serving contracts. No local cluster, SQL or container execution."""

import copy
import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest, write_json
from scripts.kube_serving_runtime_qualification import PROFILE


class PersistentServing(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("mlsecops.kube_serving_service"))
        from mlsecops import kube_serving_service
        from scripts.kube_promotion_native import configuration

        self.subject = kube_serving_service
        self.promotion = configuration(
            "/client",
            "/trust-client",
            dict(
                context={"policy": {"environment": "local-cpu"}},
                trusted_root="root",
                expected_policy="a" * 64,
                expected_serving_image=PROFILE["image_id"],
            ),
            "authority",
        )

    def test_wrong_image_unknown_promotion_fields_or_identity_cannot_form_service(self):
        for promotion in (
            {**self.promotion, "extra": True},
            {**self.promotion, "expected_serving_image": "sha256:" + "f" * 64},
            {**self.promotion, "security_audit_config": "/foreign/audit.json"},
        ):
            with self.assertRaises(Rejected):
                self.subject.configuration(promotion, PROFILE)

    def test_persistent_service_has_one_identity_and_no_promotion_or_worker_credentials(self):
        config = self.subject.configuration(self.promotion, PROFILE)
        before = canonical(self.promotion)
        config["context"]["policy"]["environment"] = "changed"
        self.assertEqual(canonical(self.promotion), before)
        config = self.subject.configuration(self.promotion, PROFILE)
        self.assertEqual(config["token_file"], "/security/service.token")
        self.assertEqual(config["identity_audit_file"], "/security/identity-audit.json")
        self.assertNotIn("security_audit_config", config)
        mapping, deployment = self.subject.documents("a" * 32, PROFILE, config)
        self.assertTrue(mapping["immutable"])
        self.assertNotIn(b'service.token":', canonical(mapping))
        self.assertEqual(deployment["spec"]["strategy"], {"type": "Recreate"})
        self.assertEqual(deployment["spec"]["replicas"], 1)
        spec = deployment["spec"]["template"]["spec"]
        self.assertEqual(spec["restartPolicy"], "Always")
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertEqual(spec["serviceAccountName"], "serving")
        self.assertEqual(
            [
                v["persistentVolumeClaim"]["claimName"]
                for v in spec["volumes"]
                if "persistentVolumeClaim" in v
            ],
            ["security-serving"],
        )
        encoded = canonical(spec)
        self.assertNotIn(b"security-promoter", encoded)
        self.assertNotIn(b"security-trust", encoded)
        self.assertNotIn(b"security_event_provision", encoded)
        self.assertNotIn(b"/request.json", encoded)
        container = spec["containers"][0]
        self.assertEqual(
            container["command"],
            ["python", "-m", "mlsecops.serving_http", "--config", "/config.json"],
        )
        self.assertIn(b"/readyz", canonical(container["readinessProbe"]))
        self.assertIn(b"/livez", canonical(container["livenessProbe"]))
        self.assertNotIn("ports", container)
        self.assertEqual(container["resources"]["limits"]["memory"], "1Gi")
        for initializer in spec["initContainers"]:
            self.assertFalse({"startupProbe", "readinessProbe", "livenessProbe"} & set(initializer))
        initializer = next(c for c in spec["initContainers"] if c["name"] == "http-audit-directory")
        self.assertEqual(initializer["volumeMounts"], [{"name": "scratch", "mountPath": "/tmp"}])

    def test_restart_has_atomic_uid_precondition_and_verifies_old_pod_absence(self):
        for remains in (False, True):
            with (
                patch.object(self.subject, "validate", return_value={}),
                patch.object(
                    self.subject,
                    "pod",
                    return_value={"metadata": {"uid": "owned", "name": "service-pod"}},
                ),
                patch.object(self.subject, "kubectl") as api,
                patch.object(self.subject, "wait_live", return_value="replacement") as wait,
                patch.object(
                    self.subject.kube_storage, "get", return_value={} if remains else None
                ),
            ):
                if remains:
                    with self.assertRaisesRegex(Rejected, "old_pod_present"):
                        self.subject.restart("state")
                else:
                    self.assertEqual(
                        self.subject.restart("state"), {"before": "owned", "after": "replacement"}
                    )
                self.assertEqual(api.call_args.args[2]["preconditions"], {"uid": "owned"})
                wait.assert_called_once_with("state", {}, previous="owned")

    def test_readback_refuses_a_replacement_during_execution(self):
        for after in ("owned", "foreign"):
            with (
                patch.object(self.subject, "validate", return_value={}),
                patch.object(
                    self.subject,
                    "pod",
                    side_effect=[
                        {"metadata": {"name": "pod", "uid": uid}} for uid in ("owned", after)
                    ],
                ),
                patch.object(
                    self.subject, "kubectl", return_value=SimpleNamespace(stdout=b'{"safe":true}')
                ),
            ):
                if after == "owned":
                    self.assertEqual(self.subject.execute("state", "code"), {"safe": True})
                else:
                    with self.assertRaisesRegex(Rejected, "pod_changed"):
                        self.subject.execute("state", "code")

    def test_corrupt_marker_or_audit_identity_never_reaches_cluster_mutation(self):
        config = self.subject.configuration(self.promotion, PROFILE)
        marker = dict(
            schema_version=1,
            ready=True,
            workspace_id="a" * 32,
            profile=PROFILE,
            config=config,
            config_sha256=digest(canonical(config)),
            audit_pin="b" * 64,
            resources={},
        )
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            target = state / "kubernetes-serving-service/resources.json"
            for field, value in (
                ("ready", False),
                ("workspace_id", "c" * 32),
                ("config_sha256", "d" * 64),
                ("audit_pin", "e" * 64),
                ("resources", {}),
            ):
                write_json(target, {**marker, field: value})
                with (
                    patch.object(self.subject, "workspace_id", return_value="a" * 32),
                    patch.object(
                        self.subject.kube_security_events,
                        "validate",
                        return_value={"pins": {"serving": "b" * 64}},
                    ),
                    patch.object(self.subject, "kubectl") as api,
                    self.subTest(field=field),
                    self.assertRaises(Rejected),
                ):
                    self.subject.validate(state)
                api.assert_not_called()

    def test_missing_or_changed_marker_never_adopts_or_restarts_service(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            with (
                patch.object(self.subject, "kubectl") as api,
                self.assertRaises(Rejected),
            ):
                self.subject.restart(state)
            api.assert_not_called()

    def test_bootstrap_checks_existing_audit_before_creating_any_service(self):
        with (
            patch.object(
                self.subject.kube_security_events, "validate", side_effect=Rejected("audit_missing")
            ),
            patch.object(self.subject, "kubectl") as api,
            self.assertRaisesRegex(Rejected, "audit_missing"),
        ):
            self.subject.bootstrap(Path("unused"), PROFILE, self.promotion)
        api.assert_not_called()

    def test_no_public_listener_or_alternative_credential_paths(self):
        config = self.subject.configuration(self.promotion, PROFILE)
        for field, value in (
            ("token_file", "/tmp/token"),
            ("identity_audit_file", "/security/audit.json"),
            ("audit_directory", "/audit/state"),
            ("kubernetes_worker", {**PROFILE, "image_id": "sha256:" + "e" * 64}),
        ):
            changed = copy.deepcopy(config)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.subject.documents("a" * 32, PROFILE, changed)


if __name__ == "__main__":
    unittest.main()
