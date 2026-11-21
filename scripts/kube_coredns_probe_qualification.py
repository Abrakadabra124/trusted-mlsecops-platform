import copy
import runpy
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical
from scripts import kube_coredns_probe as probe


class CoreDNSProbeTests(unittest.TestCase):
    def setUp(self):
        self.spec = {"name": "coredns", "image": probe.COREDNS_SPEC_IMAGE}
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
                        "imageID": probe.COREDNS_REFERENCE,
                    },
                ],
            },
        }
        self.pods = [copy.deepcopy(pod), copy.deepcopy(pod)]
        self.cri = {
            "status": {"id": probe.COREDNS_CONFIG, "repoDigests": [probe.COREDNS_REFERENCE]}
        }
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
            self.assertEqual(args[4:], ["inspecti", probe.COREDNS_REFERENCE])
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
        pin = f"v1.15.0@{probe.COREDNS_MANIFEST}"
        kind = Path(__file__).resolve().parents[1] / "infra" / "kind.yaml"
        self.assertIn(f'dns:\n          imageTag: "{pin}"', kind.read_text())

    def test_rejects_empty_partial_and_mixed_rollout(self):
        original = copy.deepcopy(self.pods)
        for mut in (
            lambda p: p.clear(),
            lambda p: p.pop(),
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

    def test_rejects_cri_manifest_or_config_mismatch(self):
        for status in (
            {"id": "wrong", "repoDigests": [probe.COREDNS_REFERENCE]},
            {"id": probe.COREDNS_CONFIG, "repoDigests": []},
        ):
            self.cri["status"] = status
            with self.subTest(status=status), self.assertRaises(Rejected):
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
