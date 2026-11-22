"""Offline PVC transaction tests. All host and cluster interfaces are simulated."""

import copy
import io
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from mlsecops.contracts import Rejected, canonical, decode
from scripts import local_path_pvc as pvc
from scripts import local_path_pvc_images as images


class PVCQualification(unittest.TestCase):
    def test_ready_binds_deployment_replicaset_and_running_container(self):
        uid, rs_uid, pod_uid = (str(uuid4()) for _ in range(3))
        ref, cfg = "example@sha256:" + "a" * 64, "sha256:" + "b" * 64
        container = {"name": pvc.DEP, "image": ref, "imagePullPolicy": "Never"}
        spec = {"replicas": 1, "template": {"spec": {"containers": [container]}}}
        dep = {
            "spec": spec,
            "metadata": {"uid": uid, "generation": 4},
            "status": {
                "observedGeneration": 4,
                "updatedReplicas": 1,
                "readyReplicas": 1,
                "availableReplicas": 1,
            },
        }

        def owner(kind, name, oid):
            return {"name": name, "kind": kind, "uid": oid, "controller": True}

        rs = {"metadata": {"uid": rs_uid, "ownerReferences": [owner("Deployment", pvc.DEP, uid)]}}
        pod = {
            "metadata": {"uid": pod_uid, "ownerReferences": [owner("ReplicaSet", "rs", rs_uid)]},
            "spec": {"nodeName": pvc.NODE, "containers": [container]},
            "status": {
                "phase": "Running",
                "containerStatuses": [{"name": pvc.DEP, "ready": True, "state": {"running": {}}}],
            },
        }
        with (
            patch.object(pvc, "deployment", return_value=dep),
            patch.object(pvc, "get", return_value=rs),
            patch.object(
                pvc, "kubectl", return_value=SimpleNamespace(stdout=canonical({"items": [pod]}))
            ),
            patch.object(pvc, "verify_running_image", return_value=ref) as verify,
        ):
            self.assertEqual(pvc.ready(None, uid, spec, cfg)["imageID"], ref)
            verify.assert_called_once_with(pod, cfg)
            for target, key, value in (
                (rs["metadata"], "uid", str(uuid4())),
                (dep["status"], "readyReplicas", 0),
                (dep["metadata"], "uid", str(uuid4())),
            ):
                with (
                    self.subTest(key=key),
                    patch.dict(target, {key: value}),
                    self.assertRaises(Rejected),
                ):
                    pvc.ready(None, uid, spec, cfg)
            verify.side_effect = Rejected("runtime_image_config_mismatch")
            with self.assertRaisesRegex(Rejected, "runtime_image_config_mismatch"):
                pvc.ready(None, uid, spec, cfg)

    def test_node_rejects_foreign_docker_cluster_or_host_bind_under_storage(self):
        node = {
            "metadata": {"name": pvc.NODE, "uid": str(uuid4())},
            "status": {
                "addresses": [{"type": "InternalIP", "address": "172.18.0.2"}],
                "conditions": [{"type": "Ready", "status": "True"}],
            },
        }
        host = {
            "Config": {"Labels": {"io.x-k8s.kind.cluster": images.NAME}},
            "NetworkSettings": {"Networks": {"kind": {"IPAddress": "172.18.0.2"}}},
            "State": {"Running": True},
            "Mounts": [],
        }
        with (
            patch.object(images, "validate_cluster", return_value={"namespace_uid": str(uuid4())}),
            patch.object(
                images, "kubectl", return_value=SimpleNamespace(stdout=canonical({"items": [node]}))
            ),
            patch.object(
                images,
                "command",
                side_effect=lambda args: (
                    pvc.NODE if args[0] == "kind" else canonical([host]).decode()
                ),
            ),
        ):
            self.assertEqual(images.owned_node(None)["node_uid"], node["metadata"]["uid"])
            for doc, change in (
                (host["Config"], {"Labels": {}}),
                (host, {"Mounts": [{"Type": "bind", "Destination": "/var"}]}),
            ):
                with patch.dict(doc, change), self.assertRaises(Rejected):
                    images.owned_node(None)

    def exercise_fake(self, fault=None):
        objects, events, evidence, retries = {}, [], {}, []
        token = uuid4().hex
        name = "lp-" + token
        aliases = {"pvc": "persistentvolumeclaims", "pod": "pods", "pv": "persistentvolumes"}
        marker = None
        directory_exists = False

        def get(state, resource, key, ns=None):
            return objects.get((aliases.get(resource, resource), key))

        def api(state, args, value=None):
            nonlocal marker, directory_exists
            body = b""
            if args[0] == "create":
                doc = copy.deepcopy(value)
                meta = doc["metadata"]
                meta["uid"] = str(uuid4())
                resource = pvc.TYPES[doc["kind"]]
                objects[resource, meta["name"]] = doc
                if resource == "pods":
                    claim = objects["persistentvolumeclaims", name]
                    pv_name, path = pvc.location(claim)
                    if not directory_exists:
                        directory_exists = True
                        claim["status"] = {"phase": "Bound"}
                        claim["spec"]["volumeName"] = pv_name
                        objects["persistentvolumes", pv_name] = {
                            "metadata": {
                                "name": pv_name,
                                "uid": str(uuid4()),
                                "annotations": {"pv.kubernetes.io/provisioned-by": pvc.DRIVER},
                            },
                            "spec": {
                                "claimRef": claim["metadata"].copy(),
                                "hostPath": {"path": path},
                                "storageClassName": name,
                                "persistentVolumeReclaimPolicy": "Delete",
                            },
                            "status": {"phase": "Bound"},
                        }
                    doc["spec"]["nodeName"] = pvc.NODE
                    doc["status"] = {"phase": "Running", "containerStatuses": [{"ready": True}]}
                body = canonical(doc)
            elif args[0] == "exec":
                events.append(args[1])
                if args[1].endswith("-write"):
                    marker = args[-1]
                else:
                    self.assertNotIn(("pods", name + "-write"), objects)
                    body = ("foreign\n" if fault == "marker" else marker + "\n").encode()
            elif args[0] == "delete":
                resource, key = args[1].split("/")[-2:]
                self.assertIn(resource, pvc.TYPES.values())
                doc = objects[resource, key]
                self.assertEqual(value["preconditions"], {"uid": doc["metadata"]["uid"]})
                self.assertEqual(doc["metadata"]["labels"][pvc.LABEL], token)
                del objects[resource, key]
                if resource == "persistentvolumeclaims":
                    del objects["persistentvolumes", pvc.location(doc)[0]]
                    directory_exists = fault == "orphan"
            else:
                self.fail(args)
            return SimpleNamespace(stdout=body)

        def poll(check, reason, seconds=90):
            result = check()
            if not result:
                raise Rejected("local_path_" + reason)
            return result

        with (
            patch.object(pvc, "get", get),
            patch.object(pvc, "kubectl", api),
            patch.object(pvc, "wait", poll),
            patch.object(pvc, "verify_running_image", return_value="config") as checked,
            patch.object(
                pvc, "directory", side_effect=lambda c: "present" if directory_exists else "absent"
            ),
        ):
            if fault:
                with self.assertRaises(Rejected):
                    pvc.exercise(None, token, "worker", "config", evidence, retries)
            else:
                pvc.exercise(None, token, "worker", "config", evidence, retries)
            if fault == "orphan":
                self.assertNotIn("reclaimed", evidence)
                directory_exists = False
                for callback in retries:
                    callback()
            self.assertEqual(events, [name + "-write", name + "-read"])
            self.assertEqual(checked.call_count, 2)
            self.assertFalse(objects)
            self.assertTrue(evidence["reclaimed"])
            self.assertEqual(bool(evidence.get("remount_verified")), fault != "marker")
        return evidence

    def test_lifecycle_checks_the_marker_and_observes_cleanup_independently(self):
        for fault in (None, "marker", "orphan"):
            with self.subTest(fault=fault):
                self.exercise_fake(fault)

    def test_cleanup_refuses_recreated_foreign_pod(self):
        document = pvc.consumer("lp-test", "image", True)
        old = {
            "metadata": {
                "uid": str(uuid4()),
                "name": "lp-test-write",
                "labels": {pvc.LABEL: "owned"},
            }
        }
        foreign = copy.deepcopy(old)
        foreign["metadata"]["uid"] = str(uuid4())
        retries = []
        with (
            patch.object(pvc, "get", side_effect=[None, foreign]),
            patch.object(
                pvc, "kubectl", return_value=SimpleNamespace(stdout=canonical(old))
            ) as api,
        ):
            with self.assertRaisesRegex(Rejected, "foreign_resource"):
                with pvc.owned(None, document, "owned", retries):
                    pass
            self.assertEqual(api.call_count, 1)
            self.assertEqual(len(retries), 1)

    def test_import_uses_immutable_node_reference_and_removes_only_owned_aliases(self):
        cfg, desc = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        repo = "docker.io/library/lp-test"
        tag, ref = repo + ":test", repo + "@" + desc
        for invalid in (False, True):
            names = {"unrelated:tag"}

            def execute(cmd, **kwargs):
                if "import" in cmd:
                    self.assertEqual(cmd[cmd.index("--index-name") + 1], tag)
                    names.add(tag)

            def command(cmd):
                if "-q" in cmd:
                    return "\n".join(names)
                if "ls" in cmd:
                    return f"{cmd[-1].removeprefix('name==')} application/vnd.oci.image.index.v1+json {desc} 1B"
                if "tag" in cmd:
                    names.add(cmd[-1])
                elif "rm" in cmd:
                    names.remove(cmd[-1])
                else:
                    return canonical({"status": {"id": desc if invalid else cfg}}).decode()
                return ""

            with (
                self.subTest(invalid=invalid),
                patch.object(images.subprocess, "run", execute),
                patch.object(images, "command", command),
                patch.object(images, "image_config", return_value=cfg),
            ):
                if invalid:
                    with (
                        self.assertRaisesRegex(Rejected, "imported_config"),
                        images.loaded(repo, cfg),
                    ):
                        self.fail("foreign config accepted")
                else:
                    with images.loaded(repo, cfg) as image:
                        self.assertEqual(image, ref)
                self.assertEqual(names, {"unrelated:tag"})

    def test_public_record_and_local_refusal_start_no_commands(self):
        observed = self.exercise_fake()
        cfg = "sha256:" + "a" * 64
        evidence = dict(
            observed,
            baseline={"deployment_uid": str(uuid4()), "config_id": pvc.STOCK_ID},
            candidate={"config_id": cfg, "imageID": "private.repo/image@" + cfg},
            restored={"config_id": pvc.STOCK_ID},
            aliases_removed=True,
            resources_absent=True,
            candidate_after_reclaim=True,
            retain_inventory_sha256="checked",
        )
        report = pvc.public_report(evidence, None)
        self.assertEqual(report["status"], "pass")
        self.assertTrue(report["cleanup_verified"])
        self.assertEqual(report["candidate_runtime_digest"], cfg)
        for text in ("private.repo", "backing_path", "marker", "env", "pod_uid"):
            self.assertNotIn(text, canonical(report).decode())
        with (
            patch.dict(pvc.os.environ, GITHUB_ACTIONS="false"),
            patch.object(pvc, "owned_node") as node,
            redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(pvc.main(["--image-id", cfg]), 1)
            node.assert_not_called()
        refused = decode(out.getvalue().encode())
        self.assertEqual(set(refused), set(report))
        self.assertEqual(refused["reason"], "local_path_hosted_only")
        self.assertFalse(refused["cleanup_verified"])

    def test_only_exact_owned_backing_path_can_be_observed_or_reclaimed(self):
        claim = {
            "metadata": {"uid": str(uuid4()), "namespace": pvc.NS, "name": "lp-test"},
            "spec": {"storageClassName": "lp-test"},
        }
        name, path = pvc.location(claim)
        pv = {
            "metadata": {
                "name": name,
                "uid": str(uuid4()),
                "annotations": {"pv.kubernetes.io/provisioned-by": "rancher.io/local-path"},
            },
            "spec": {
                "storageClassName": "lp-test",
                "persistentVolumeReclaimPolicy": "Delete",
                "claimRef": claim["metadata"].copy(),
                "hostPath": {"path": path},
            },
        }
        pvc.check_pv(claim, pv)
        for field, value in (
            ("hostPath", {"path": path + "/../foreign"}),
            ("hostPath", {"path": path + "-other"}),
            ("storageClassName", "standard"),
            ("persistentVolumeReclaimPolicy", "Retain"),
            ("claimRef", {**claim["metadata"], "uid": str(uuid4())}),
        ):
            with (
                self.subTest(field=field),
                patch.dict(pv["spec"], {field: value}),
                self.assertRaises(Rejected),
            ):
                pvc.check_pv(claim, pv)

    def test_consumer_has_only_a_pvc_no_token_and_read_only_second_mount(self):
        for writer in (True, False):
            pod = pvc.consumer("lp-test", "image-ref", writer)
            spec = pod["spec"]
            self.assertFalse(spec["automountServiceAccountToken"])
            self.assertTrue(spec["securityContext"]["runAsNonRoot"])
            self.assertEqual(
                spec["volumes"],
                [{"name": "data", "persistentVolumeClaim": {"claimName": "lp-test"}}],
            )
            (container,) = spec["containers"]
            self.assertEqual(container["imagePullPolicy"], "Never")
            self.assertEqual(container["volumeMounts"][0].get("readOnly", False), not writer)
            self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])

    def test_lost_patch_response_still_restores_original_and_verifies_readiness(self):
        original = {
            "metadata": {"uid": str(uuid4())},
            "spec": {
                "strategy": {"type": "Recreate"},
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": pvc.DEP,
                                "image": "original",
                                "imagePullPolicy": "IfNotPresent",
                                "args": ["keep"],
                            }
                        ]
                    }
                },
            },
        }
        current = copy.deepcopy(original)

        def patch_spec(state, uid, before, after):
            self.assertEqual(current["spec"], before)
            current["spec"] = copy.deepcopy(after)
            if after != original["spec"]:
                raise Rejected("lost_response")

        with (
            patch.object(pvc, "deployment", side_effect=lambda state: copy.deepcopy(current)),
            patch.object(pvc, "patch_spec", side_effect=patch_spec),
            patch.object(pvc, "ready", return_value={"imageID": "verified"}) as ready,
        ):
            evidence = {}
            with (
                self.assertRaisesRegex(Rejected, "lost_response"),
                pvc.rollout(None, original, "new", "id", evidence),
            ):
                self.fail("unconfirmed rollout")
            self.assertEqual(current, original)
            self.assertIn("restored", evidence)
            ready.assert_called_with(
                None, original["metadata"]["uid"], original["spec"], pvc.STOCK_ID
            )
