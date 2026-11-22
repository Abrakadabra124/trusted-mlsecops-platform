import copy
import re
import runpy
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical
from scripts import image_audit_contract as contract
from scripts import kube_coredns_probe as probe


class CoreDNSProbeTests(unittest.TestCase):
    def setUp(self):
        self.pin = contract.runtime_coredns()
        self.spec = {"name": "coredns", "image": self.pin.spec_image}
        self.deployment = {
            "spec": {"replicas": 2, "template": {"spec": {"containers": [self.spec]}}}
        }
        pod = {
            "metadata": {},
            "spec": {"nodeName": probe.NODE, "containers": [self.spec]},
            "status": {
                "phase": "Running",
                "containerStatuses": [
                    {
                        "name": "coredns",
                        "ready": True,
                        "state": {"running": {}},
                        "imageID": self.pin.reference,
                    },
                ],
            },
        }
        self.pods = [copy.deepcopy(pod), copy.deepcopy(pod)]
        for i, replica in enumerate(self.pods):
            replica["metadata"]["name"] = f"coredns-{i}"
        self.cri = {"status": {"id": self.pin.config, "repoDigests": [self.pin.reference]}}
        self.selector = {"k8s-app": "kube-dns"}
        self.pid = "1234"
        self.answer = "10.79.0.1"
        self.cli = self.enterContext(patch.object(probe, "command", side_effect=self.command))
        self.enterContext(patch.object(probe, "validate_cluster"))
        self.kube = self.enterContext(patch.object(probe, "kubectl", side_effect=self.kubectl))

    def kubectl(self, state, args, **kwargs):
        if args[0] == "rollout":
            return None
        data = {
            "deployment/coredns": self.deployment,
            "pods": {"items": self.pods},
            "service/kube-dns": {"spec": {"clusterIP": "10.79.0.10", "selector": self.selector}},
            "service/kubernetes": {"spec": {"clusterIP": "10.79.0.1"}},
        }
        return CompletedProcess(args, 0, stdout=canonical(data[args[1]]))

    def command(self, args):
        if args[:4] == ["docker", "exec", probe.NODE, "crictl"]:
            self.assertEqual(args[4:], ["inspecti", self.pin.reference])
            return canonical(self.cri).decode()
        if args[:2] == ["docker", "inspect"]:
            return self.pid
        self.assertEqual(
            args[:8], ["sudo", "-n", "nsenter", "--target", "1234", "--net", "--", "dig"]
        )
        self.assertIn("@10.79.0.10", args)
        self.assertIn("kubernetes.default.svc.cluster.local.", args)
        self.assertIn("A", args)
        return self.answer

    def test_workflow_module_entry_point(self):
        with (
            patch("mlsecops.cluster.kubectl", self.kube),
            patch("mlsecops.cluster.validate_cluster", probe.validate_cluster),
            patch("mlsecops.inventory.command", self.cli),
            patch("builtins.print") as log,
        ):
            runpy.run_path(probe.__file__, run_name="__main__")
        self.assertIn("kubernetes.default.svc.cluster.local. A 10.79.0.1", log.call_args.args[0])

    def test_rollout_all_replicas_and_service_answer(self):
        result = probe.verify()
        self.assertIn("10.79.0.1", result)
        self.assertEqual(
            self.kube.call_args_list[0].args[1][:3], ["rollout", "status", "deployment/coredns"]
        )
        self.assertEqual(self.cli.call_args_list[-1].args[0][0], "sudo")

    def test_bootstrap_dns_patch_matches_runtime_pin(self):
        # Authenticated and anonymous readback in publisher run 45029534828.
        self.assertEqual(
            (self.pin.tag, self.pin.manifest, self.pin.config),
            (
                "1.15.0-deps-r1-75ed1469660bb69bf0fc2157b9b3e4ed38993910",
                "sha256:907db90829056dc7adc96851cedd0ffef7d82c916d92a935aa140c58333a7424",
                "sha256:d2c1556be74ac5be00316f062c317b9a964cc5da83d7d1141b2ce5b9083ca7f6",
            ),
        )
        kind = Path(__file__).resolve().parents[1] / "infra" / "kind.yaml"
        (dns_patch,) = re.findall(r"^        dns:\n((?:          .+\n)+)", kind.read_text(), re.M)
        self.assertEqual(
            dns_patch.splitlines(),
            [
                f'          imageRepository: "{self.pin.image_repository}"',
                f'          imageTag: "{self.pin.tag}@{self.pin.manifest}"',
            ],
        )

    def test_published_deployment_pods_and_cri_use_the_same_pin(self):
        image = (
            f"ghcr.io/abrakadabra124/trusted-mlsecops-platform/coredns:"
            f"{self.pin.tag}@{self.pin.manifest}"
        )
        self.assertEqual(self.pin.spec_image, image)
        self.assertEqual(probe.COREDNS_SPEC_IMAGE, contract.UPSTREAM_COREDNS.spec_image)
        self.assertNotEqual(probe.COREDNS_CONFIG, self.pin.config)
        result = probe.verify()
        self.assertIn(image, result)
        for pod in self.pods:
            self.assertIn(
                f"pod={pod['metadata']['name']} imageID={self.pin.reference} "
                f"manifest={self.pin.manifest} config={self.pin.config}",
                result.splitlines(),
            )
        self.assertEqual(
            sum(call.args[0][4:5] == ["inspecti"] for call in self.cli.call_args_list), 2
        )
        for wrong in (
            image.split("@")[0],
            image.replace("/coredns:", "/coredns/coredns:"),
            self.pin.reference,
            contract.COREDNS_SPEC_IMAGE,
        ):
            self.spec["image"] = wrong
            with self.subTest(image=wrong), self.assertRaisesRegex(Rejected, "rollout"):
                probe.verify()
        self.spec["image"] = image
        status = self.pods[-1]["status"]["containerStatuses"][0]
        for wrong in (image.split("@")[0], contract.COREDNS_REFERENCE):
            status["imageID"] = wrong
            with self.subTest(image_id=wrong), self.assertRaisesRegex(Rejected, "image_id"):
                probe.verify()
        status["imageID"] = self.pin.reference
        self.cri["status"]["repoDigests"] = [contract.COREDNS_REFERENCE]
        with self.assertRaisesRegex(Rejected, "runtime_identity"):
            probe.verify()

    def test_published_pin_requires_complete_digests_and_publisher_tag(self):
        pin = self.pin
        for repo, tag, manifest, config in (
            (pin.image_repository + "/coredns", pin.tag, pin.manifest, pin.config),
            (pin.image_repository, "latest", pin.manifest, pin.config),
            (pin.image_repository, pin.tag, None, pin.config),
            (pin.image_repository, pin.tag, pin.manifest, None),
            (pin.image_repository, pin.tag, "sha256:" + "0" * 64, pin.config),
            (pin.image_repository, pin.tag, pin.manifest, pin.manifest),
            (pin.image_repository, pin.tag, pin.manifest, contract.COREDNS_CONFIG),
        ):
            with self.subTest(repo=repo, tag=tag, manifest=manifest, config=config):
                with self.assertRaisesRegex(Rejected, "invalid_coredns_pin"):
                    contract.CoreDNSPin(repo, tag, manifest, config)

    def test_rejects_empty_partial_and_mixed_rollout(self):
        original = copy.deepcopy(self.pods)
        for mut in (
            lambda p: p.clear(),
            lambda p: p.pop(),
            lambda p: p.__setitem__(1, copy.deepcopy(p[0])),
            lambda p: p[1]["metadata"].update(deletionTimestamp="terminating"),
            lambda p: p[1]["spec"].update(nodeName="foreign"),
            lambda p: p[1]["spec"]["containers"][0].update(
                image="registry.k8s.io/coredns/coredns:latest"
            ),
            lambda p: p[1]["status"]["containerStatuses"][0].update(ready=False),
            lambda p: p[1]["status"]["containerStatuses"][0].update(imageID="mutable:tag"),
        ):
            self.pods = copy.deepcopy(original)
            mut(self.pods)
            with self.subTest(mutation=mut), self.assertRaises(Rejected):
                probe.verify()
        self.pods = original
        self.spec["image"] = "other"
        with self.assertRaises(Rejected):
            probe.verify()

    def test_single_ready_pod_and_scaled_down_deployment_do_not_qualify(self):
        self.deployment["spec"]["replicas"] = 1
        self.pods.pop()
        with self.assertRaisesRegex(Rejected, "rollout_mismatch"):
            probe.verify()
        self.cli.assert_not_called()

    def test_rejects_cri_manifest_or_config_mismatch_in_second_replica(self):
        for status in (
            {"id": "wrong", "repoDigests": [self.pin.reference]},
            {"id": self.pin.config, "repoDigests": []},
        ):
            self.cli.side_effect = [
                canonical(self.cri).decode(),
                canonical({"status": status}).decode(),
            ]
            with self.subTest(status=status), self.assertRaisesRegex(Rejected, "runtime_identity"):
                probe.verify()

    def test_refuses_foreign_dns_selector_and_missing_node_namespace(self):
        self.selector = {"app": "other"}
        with self.assertRaisesRegex(Rejected, "service_selector"):
            probe.verify()
        self.selector = {"k8s-app": "kube-dns"}
        for self.pid in ("", "0", "1"):
            with self.subTest(pid=self.pid), self.assertRaisesRegex(Rejected, "node_pid"):
                probe.verify()

    def test_dns_requires_exact_api_service_address(self):
        for self.answer in ("", "10.79.0.2", "10.79.0.1\n10.79.0.2"):
            with self.subTest(answer=self.answer), self.assertRaises(Rejected):
                probe.verify()
