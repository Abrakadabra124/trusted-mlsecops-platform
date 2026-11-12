"""Role-bound audit Pod plans; these tests do not claim a running cluster."""

import importlib.util
import unittest

from mlsecops import kube_worker
from mlsecops.contracts import Rejected, canonical


class AuditResources(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("mlsecops.kube_security_resources"))
        from mlsecops import kube_security_resources

        self.subject = kube_security_resources
        self.workspace = "a" * 32
        self.image = "trusted-mlsecops:sha-" + "b" * 64

    def test_unknown_roles_or_secret_inventory_cannot_receive_privileged_files(self):
        for role in ("worker", "trainer", "evaluator", "operator", "", None, []):
            with self.assertRaises(Rejected):
                self.subject.provision_spec(self.image, role, "owned-config")
            with self.assertRaises(Rejected):
                self.subject.secret(self.workspace, role, {})
        for role in ("promoter", "trust", "collector", "serving"):
            files = {name: b"fixture" for name in self.subject.FILES[role]}
            for invalid in (
                {},
                {**files, "ca.key": b"private"},
                {**files, "../escape": b"private"},
                {**files, "registry.json": b"x" * 32769},
                {**files, "registry.json": "text"},
                {**files, "registry.json": b""},
                {name: b"x" * 32768 for name in files},
            ):
                with self.assertRaises(Rejected):
                    self.subject.secret(self.workspace, role, invalid)
            secret = self.subject.secret(self.workspace, role, files)
            self.assertTrue(secret["immutable"])
            self.assertEqual(set(secret["data"]), set(files))
            self.assertNotIn("ca.key", secret["data"])
            if role != "collector":
                self.assertFalse({"receipt.pem", "collector.pem", "operator.token"} & set(files))

    def test_public_observer_mount_cannot_choose_private_paths_or_shell_names(self):
        for area, public, names in (
            ("../escape", True, ("observer.json",)),
            (None, True, ("observer.json",)),
            ("observer", False, ("observer.json",)),
            ("observer", True, ()),
            ("observer", True, ("../producer.pem",)),
            ("observer", True, ("rotation-65.json",)),
            ("observer", True, ("rotation-1.json",)),
            ("observer", True, ("rotation-2.json;echo",)),
        ):
            spec = kube_worker.pod_spec(self.image, "serving", ["module"])
            before = canonical(spec)
            with self.subTest(area=area, public=public, names=names), self.assertRaises(Rejected):
                self.subject.private_files(spec, "owned", names, public=public, area=area)
            self.assertEqual(canonical(spec), before)
        spec = kube_worker.pod_spec(self.image, "serving", ["module"])
        self.subject.private_files(
            spec, "owned", ("observer.json", "rotation-2.json"), public=True, area="observer"
        )
        self.assertEqual(spec["containers"][0]["volumeMounts"][-1]["mountPath"], "/observer")

    def test_provision_job_has_only_public_config_and_one_role_persistent_volume(self):
        for role in ("promoter", "trust", "collector", "serving"):
            spec = self.subject.provision_spec(self.image, role, "owned-config")
            self.assertFalse(spec["automountServiceAccountToken"])
            self.assertEqual(spec["securityContext"]["runAsUser"], 65532)
            self.assertEqual(spec["securityContext"]["fsGroupChangePolicy"], "OnRootMismatch")
            self.assertEqual(
                spec["containers"][0]["command"],
                [
                    "python",
                    "-m",
                    "mlsecops.security_event_provision",
                    "--config",
                    "/security/provision.json",
                ],
            )
            self.assertFalse(any("secret" in volume for volume in spec["volumes"]))
            self.assertFalse(
                any("hostPath" in volume or "projected" in volume for volume in spec["volumes"])
            )
            claims = [
                v["persistentVolumeClaim"]["claimName"]
                for v in spec["volumes"]
                if "persistentVolumeClaim" in v
            ]
            self.assertEqual(
                claims, ["security-serving" if role == "serving" else "security-events"]
            )
            self.assertEqual(spec["restartPolicy"], "Never")

    def test_runtime_has_no_initializer_for_missing_persistent_state(self):
        for role in ("collector", "trust"):
            spec = self.subject.runtime_spec(self.image, role)
            encoded = canonical(spec)
            self.assertNotIn(b"security_event_provision", encoded)
            self.assertNotIn(b"initialize", encoded)
            self.assertEqual(spec["restartPolicy"], "Always")
            mounts = spec["containers"][0]["volumeMounts"]
            private = next(m for m in mounts if m["mountPath"] == "/security")
            self.assertTrue(private["readOnly"])
            self.assertEqual(private["subPath"], "security")
            self.assertEqual(spec["securityContext"]["fsGroupChangePolicy"], "OnRootMismatch")
            for container in (*spec["initContainers"], *spec["containers"]):
                self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
                self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
                self.assertEqual(container["securityContext"]["capabilities"], {"drop": ["ALL"]})
            if role == "trust":
                self.assertEqual(spec["serviceAccountName"], "serving")
                self.assertIn(b"trust-client", encoded)
                self.assertNotIn(b"storage-client", encoded)
            else:
                self.assertNotIn(b"trust-client", encoded)
        with self.assertRaises(Rejected):
            self.subject.runtime_spec(self.image, "promoter")

    def test_promoter_extends_existing_spec_without_changing_worker_spec(self):
        initial = kube_worker.pod_spec(self.image, "promoter", ["mlsecops.promotion_controller"])
        before = canonical(initial)
        spec = self.subject.promoter_spec(initial)
        self.assertEqual(canonical(initial), before)
        self.assertEqual(spec["containers"][0]["command"], initial["containers"][0]["command"])
        self.assertEqual(
            [v["secret"]["secretName"] for v in spec["volumes"] if "secret" in v],
            ["security-promoter"],
        )
        for identity in ("trainer", "evaluator", "serving", "controller"):
            worker = kube_worker.pod_spec(self.image, identity, ["mlsecops.worker"])
            with self.assertRaises(Rejected):
                self.subject.promoter_spec(worker)
            self.assertNotIn(b"security-promoter", canonical(worker))

    def test_networks_use_exact_namespaces_service_accounts_and_one_tls_port(self):
        documents = self.subject.base_resources(self.workspace)
        policies = [d for d in documents if d["kind"] == "CiliumNetworkPolicy"]
        self.assertEqual(len(policies), 3)
        for policy in policies:
            spec = policy["spec"]
            self.assertTrue(spec["endpointSelector"]["matchLabels"])
            for flow in (*spec.get("ingress", []), *spec.get("egress", [])):
                self.assertEqual(
                    flow["toPorts"], [{"ports": [{"port": "8443", "protocol": "TCP"}]}]
                )
                for endpoint in flow.get("fromEndpoints", flow.get("toEndpoints", [])):
                    self.assertIn(self.subject.ACCOUNT, endpoint["matchLabels"])
                    self.assertIn(self.subject.POD_NAMESPACE, endpoint["matchLabels"])
                self.assertNotIn("toEntities", flow)
                self.assertNotIn("toCIDR", flow)
        boundary = next(p for p in policies if p["metadata"]["namespace"] == "ml-audit")
        self.assertEqual(boundary["spec"]["egressDeny"], [{"toEntities": ["all"]}])
        self.assertNotIn(b"trainer", canonical(policies))
        self.assertNotIn(b"evaluator", canonical(policies))

    def test_serving_mounts_only_its_identity_and_distinct_persistent_state(self):
        initial = kube_worker.pod_spec(self.image, "serving", ["mlsecops.serving_http"])
        before = canonical(initial)
        spec = self.subject.serving_spec(initial)
        self.assertEqual(canonical(initial), before)
        self.assertEqual(spec["containers"][0]["command"], initial["containers"][0]["command"])
        self.assertEqual(
            [v["secret"]["secretName"] for v in spec["volumes"] if "secret" in v],
            ["security-serving"],
        )
        self.assertEqual(
            [
                v["persistentVolumeClaim"]["claimName"]
                for v in spec["volumes"]
                if "persistentVolumeClaim" in v
            ],
            ["security-serving"],
        )
        self.assertNotIn(b"security-promoter", canonical(spec))
        self.assertNotIn(b"security-trust", canonical(spec))
        self.assertNotIn(b"security_event_provision", canonical(spec))
        for account in ("trainer", "evaluator", "controller", "promoter", "collector"):
            worker = kube_worker.pod_spec(self.image, account, ["mlsecops.worker"])
            with self.assertRaises(Rejected):
                self.subject.serving_spec(worker)
            self.assertNotIn(b"security-serving", canonical(worker))

    def test_same_namespace_claims_and_network_resources_are_unique(self):
        documents = self.subject.base_resources(self.workspace)
        references = [
            (d["kind"], d["metadata"].get("namespace"), d["metadata"]["name"]) for d in documents
        ]
        self.assertEqual(len(references), len(set(references)))
        claims = [
            d
            for d in documents
            if d["kind"] == "PersistentVolumeClaim" and d["metadata"]["namespace"] == "ml-serving"
        ]
        self.assertEqual(
            {d["metadata"]["name"] for d in claims}, {"security-events", "security-serving"}
        )
        quota = self.subject.namespace_resources("ml-serving", "serving", self.workspace)[3][
            "spec"
        ]["hard"]
        self.assertEqual(quota["persistentvolumeclaims"], "2")
        self.assertEqual(quota["count/secrets"], "5")

    def test_four_separate_claims_and_single_replica_recreate_runtime(self):
        documents = self.subject.base_resources(self.workspace)
        claims = [d for d in documents if d["kind"] == "PersistentVolumeClaim"]
        self.assertEqual(
            {d["metadata"]["namespace"] for d in claims}, {"ml-audit", "ml-serving", "ml-promoter"}
        )
        self.assertEqual(len(claims), 4)
        for claim in claims:
            self.assertEqual(claim["spec"]["storageClassName"], "trusted-mlsecops-storage")
            self.assertEqual(claim["spec"]["accessModes"], ["ReadWriteOnce"])
        for role in ("trust", "collector"):
            deployment = self.subject.deployment(self.workspace, self.image, role)
            self.assertEqual(deployment["apiVersion"], "apps/v1")
            self.assertEqual(deployment["spec"]["replicas"], 1)
            self.assertEqual(deployment["spec"]["strategy"], {"type": "Recreate"})
            self.assertEqual(
                deployment["spec"]["selector"]["matchLabels"],
                deployment["spec"]["template"]["metadata"]["labels"],
            )


if __name__ == "__main__":
    unittest.main()
