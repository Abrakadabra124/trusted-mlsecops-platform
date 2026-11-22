"""Controlled cases for a disposable CoreDNS replacement. No local cluster is required."""

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import coredns_candidate_adoption as adoption


class CandidateRollout(unittest.TestCase):
    def setUp(self):
        self.enterContext(redirect_stdout(io.StringIO()))
        self.config = "sha256:" + "a" * 64
        self.manifest = "sha256:" + "b" * 64
        self.tag = "localhost/coredns-candidate:" + self.config[7:]
        self.elf = "c" * 64
        self.pod = {
            "metadata": {"uid": "pod-one"},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]},
        }
        self.cid = "1" * 64
        self.status = {"containerID": "containerd://" + self.cid, "imageID": self.manifest}
        self.live = {
            "info": {"pid": 123},
            "status": {
                "id": self.cid,
                "state": "CONTAINER_RUNNING",
                "metadata": {"name": "coredns"},
                "labels": {"io.kubernetes.pod.uid": "pod-one"},
                "imageRef": self.manifest,
                "imageId": self.config,
            },
        }
        self.inspect = self.enterContext(
            patch.object(adoption, "node_json", return_value=self.live)
        )
        self.hash = self.enterContext(
            patch.object(adoption, "command", return_value=self.elf + "  /proc/123/exe")
        )
        self.enterContext(
            patch(
                "scripts.etcd_candidate_adoption.image_manifest",
                return_value=(self.manifest, {"config": {"digest": self.config}}),
            )
        )
        self.enterContext(
            patch.object(
                adoption,
                "image_manifest",
                return_value=(self.manifest, {"config": {"digest": adoption.probe.COREDNS_CONFIG}}),
            )
        )

    def replica(self):
        return adoption.replica(
            self.pod, self.status, self.tag, self.config, self.manifest, self.elf
        )

    def test_live_bytes_and_container_identity(self):
        self.assertEqual(self.replica(), self.cid)
        self.hash.assert_called_once_with(
            ["docker", "exec", adoption.cluster.NODE, "sha256sum", "/proc/123/exe"]
        )
        self.assertEqual(self.inspect.call_count, 2)

    def test_only_original_archive_loads_and_only_verified_rollout_exports_config(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        archive = root / "coredns-dependency/candidate.tar"
        archive.parent.mkdir()
        archive.write_bytes(b"pre-scan bytes")
        output = root / "outputs"
        env = dict(
            GITHUB_SHA="a" * 40,
            RUNNER_TEMP=str(root),
            GITHUB_OUTPUT=str(output),
            QUALIFIED_CONFIG=self.config,
            QUALIFIED_ELF=self.elf,
            QUALIFIED_ARCHIVE_SHA256=digest(archive.read_bytes()),
        )
        self.enterContext(patch.dict(adoption.os.environ, env))
        for target in ("hosted", "run_owner", "cluster.bootstrap", "cluster.validate_cluster"):
            self.enterContext(patch(f"scripts.coredns_candidate_adoption.{target}"))
        recovery = self.enterContext(patch.object(adoption.Recovery, "begin")).return_value
        recovery.record = {"cluster": {"containers": {self.cid: {}}}}
        self.hash.return_value = adoption.cluster.NODE
        manifest = self.enterContext(
            patch.object(adoption, "loaded_candidate_manifest", return_value=self.manifest)
        )
        exercise = self.enterContext(
            patch.object(adoption, "exercise", side_effect=Rejected("rollback_failed"))
        )
        with self.assertRaisesRegex(Rejected, "rollback_failed"):
            adoption.main("run")
        self.assertFalse(output.exists())
        exercise.side_effect = None
        adoption.main("run")
        exercise.assert_called_with(self.tag, self.config, self.manifest, self.elf)
        manifest.assert_called_with(self.tag, self.config)
        self.assertEqual(
            self.hash.call_args.args[0],
            [
                "kind",
                "load",
                "image-archive",
                "--name",
                adoption.cluster.NAME,
                "--nodes",
                adoption.cluster.NODE,
                str(archive),
            ],
        )
        self.assertEqual(output.read_text().splitlines(), ["live_config=" + self.config])
        archive.write_bytes(b"different")
        with self.assertRaisesRegex(Rejected, "archive_changed_before_kind_load"):
            adoption.main("run")
        self.assertEqual(exercise.call_count, 2)

    def test_wrong_bytes_ref_config_pid_pod_or_restart_refuse(self):
        for section, key, value in (
            ("info", "pid", 0),
            ("status", "imageId", self.manifest),
            ("status", "imageRef", "example:mutable"),
            ("status", "state", "CONTAINER_EXITED"),
            ("status", "labels", {"io.kubernetes.pod.uid": "other"}),
        ):
            with (
                self.subTest(key=key),
                patch.dict(self.live[section], {key: value}),
                self.assertRaises(Rejected),
            ):
                self.replica()
        with patch.dict(self.status, imageID="other:tag"), self.assertRaises(Rejected):
            self.replica()
        self.hash.return_value = "d" * 64 + "  /proc/123/exe"
        with self.assertRaises(Rejected):
            self.replica()
        self.hash.return_value = self.elf + "  /proc/123/exe"
        self.inspect.side_effect = [self.live, {**self.live, "info": {"pid": 124}}]
        with self.assertRaises(Rejected):
            self.replica()

    def test_duplicate_replica_or_missing_second_refuses(self):
        second = copy.deepcopy(self.pod)
        second["metadata"]["uid"] = "pod-two"
        for pods in ([(self.pod, self.status)], [(self.pod, self.status), (second, self.status)]):
            with (
                self.subTest(size=len(pods)),
                patch.object(adoption.probe, "ready_replicas", return_value=pods),
                self.assertRaises(Rejected),
            ):
                adoption.verify_phase("candidate", self.tag, self.config, self.manifest, self.elf)

    def test_dns_only_after_both_replicas_and_matching_service_endpoints(self):
        second = copy.deepcopy(self.pod)
        second["metadata"]["uid"] = "pod-two"
        cid2 = "2" * 64
        status2 = {**self.status, "containerID": "containerd://" + cid2}
        live2 = copy.deepcopy(self.live)
        live2["info"]["pid"] = 234
        live2["status"].update(id=cid2, labels={"io.kubernetes.pod.uid": "pod-two"})
        self.inspect.side_effect = lambda op, cid: self.live if cid == self.cid else live2
        self.hash.side_effect = lambda args: self.elf + "  " + args[-1]
        endpoints = [
            {"targetRef": {"uid": uid}, "conditions": {"ready": True}}
            for uid in ("pod-one", "pod-two")
        ]
        with (
            patch.object(
                adoption.probe,
                "ready_replicas",
                return_value=[(self.pod, self.status), (second, status2)],
            ) as ready,
            patch.object(adoption.probe, "get", return_value={"items": [{"endpoints": endpoints}]}),
            patch.object(adoption.probe, "service_answer", return_value="ok") as dns,
        ):
            adoption.verify_phase("candidate", self.tag, self.config, self.manifest, self.elf)
            ready.assert_called_once_with(adoption.STATE, self.tag, "Never")
            self.assertEqual(
                [c.args[0][-1] for c in self.hash.call_args_list],
                ["/proc/123/exe", "/proc/234/exe"],
            )
            dns.assert_called_once_with(adoption.STATE)
            endpoints.append({"targetRef": {"uid": "unexpected"}, "conditions": {"ready": True}})
            with (
                patch.object(adoption.time, "monotonic", side_effect=[0, 46]),
                self.assertRaisesRegex(Rejected, "backends"),
            ):
                adoption.verify_phase("candidate", self.tag, self.config, self.manifest, self.elf)
            self.assertEqual(dns.call_count, 1)

    def test_candidate_probe_failure_restores_exact_original_template(self):
        original = {
            "metadata": {"labels": {"k8s-app": "kube-dns"}},
            "spec": {
                "containers": [
                    {
                        "name": "coredns",
                        "image": adoption.probe.COREDNS_SPEC_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                    }
                ]
            },
        }
        deployment = {"metadata": {"uid": "deploy"}, "spec": {"template": copy.deepcopy(original)}}

        def apply(state, args):
            patch_ops = json.loads(args[args.index("-p") + 1])
            self.assertEqual(patch_ops[0]["value"], deployment["metadata"]["uid"])
            self.assertEqual(patch_ops[1]["value"], deployment["spec"]["template"])
            deployment["spec"]["template"] = patch_ops[2]["value"]
            return CompletedProcess(args, 0, stdout=canonical(deployment))

        def verify(phase, *args):
            if phase == "candidate":
                self.assertEqual(
                    deployment["spec"]["template"]["spec"]["containers"][0]["imagePullPolicy"],
                    "Never",
                )
                raise Rejected("controlled_candidate_failure")

        with (
            patch.object(
                adoption.probe, "get", side_effect=lambda *a, **k: copy.deepcopy(deployment)
            ),
            patch.object(adoption.cluster, "kubectl", side_effect=apply),
            patch.object(adoption, "verify_phase", side_effect=verify) as phases,
            self.assertRaisesRegex(Rejected, "controlled_candidate_failure"),
        ):
            adoption.exercise(self.tag, self.config, self.manifest, self.elf)
        self.assertEqual(deployment["spec"]["template"], original)
        self.assertEqual(
            [c.args[0] for c in phases.call_args_list], ["baseline", "candidate", "rollback"]
        )
