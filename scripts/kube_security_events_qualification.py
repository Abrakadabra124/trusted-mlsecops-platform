"""Operator ownership boundaries, without Docker, Kubernetes or SQL execution."""

import copy
import importlib.util
import io
import runpy
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import kube_security_resources as resources
from mlsecops import kube_storage, signing
from mlsecops.contracts import Rejected, canonical, decode, digest, read_json, write_json


class AuditOperator(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("mlsecops.kube_security_events"))
        from mlsecops import kube_security_events

        self.subject = kube_security_events
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.marker = {"resources": {}}
        self.workspace = "a" * 32
        self.document = resources.base_resources(self.workspace)[0]

    def test_creation_never_adopts_existing_resource_and_checks_recorded_uid(self):
        observed = {
            **copy.deepcopy(self.document),
            "metadata": {**self.document["metadata"], "uid": "owned"},
        }
        with (
            patch.object(kube_storage, "get", return_value=observed),
            patch.object(self.subject, "kubectl") as api,
        ):
            with self.assertRaisesRegex(Rejected, "unowned"):
                self.subject.create("state", self.directory, self.marker, self.document)
            api.assert_not_called()
        with (
            patch.object(kube_storage, "get", return_value=None),
            patch.object(
                self.subject, "kubectl", return_value=SimpleNamespace(stdout=canonical(observed))
            ) as api,
        ):
            self.assertEqual(
                self.subject.create("state", self.directory, self.marker, self.document), observed
            )
            api.assert_called_once()
        key = kube_storage.reference(self.document)
        self.assertEqual(self.marker["resources"][key], "owned")
        with (
            patch.object(kube_storage, "get", return_value=observed),
            patch.object(self.subject, "kubectl") as api,
        ):
            self.subject.create("state", self.directory, self.marker, self.document)
            api.assert_not_called()
        for changed in (None, {**observed, "metadata": {**observed["metadata"], "uid": "foreign"}}):
            with (
                patch.object(kube_storage, "get", return_value=changed),
                self.assertRaises(Rejected),
            ):
                self.subject.create("state", self.directory, self.marker, self.document)

    def test_service_ip_is_bound_to_owned_service_and_ipv4_only(self):
        service = next(
            d for d in resources.base_resources(self.workspace) if d["kind"] == "Service"
        )
        service["metadata"]["uid"] = "service-owned"
        service["spec"].update(
            clusterIP="10.96.0.10", clusterIPs=["10.96.0.10"], ipFamilies=["IPv4"]
        )
        self.marker["resources"][kube_storage.reference(service)] = "service-owned"
        with patch.object(kube_storage, "get", return_value=service):
            self.assertEqual(
                self.subject.service_address("state", self.workspace, self.marker), "10.96.0.10"
            )
        for field, value in (
            ("clusterIP", "8.8.8.8"),
            ("clusterIPs", ["10.96.0.11"]),
            ("ipFamilies", ["IPv6"]),
            ("externalIPs", ["8.8.8.8"]),
        ):
            changed = copy.deepcopy(service)
            changed["spec"][field] = value
            with (
                patch.object(kube_storage, "get", return_value=changed),
                self.assertRaises(Rejected),
            ):
                self.subject.service_address("state", self.workspace, self.marker)

    def test_pvc_binding_and_backing_volume_identity_are_not_inferred_from_name(self):
        claim = next(
            d
            for d in resources.base_resources(self.workspace)
            if d["kind"] == "PersistentVolumeClaim"
        )
        observed = copy.deepcopy(claim)
        observed["metadata"]["uid"] = "claim-owned"
        observed["spec"]["volumeName"] = "pv-owned"
        observed["status"] = {"phase": "Bound"}
        volume = {
            "metadata": {"uid": "volume-owned"},
            "spec": {
                "persistentVolumeReclaimPolicy": "Retain",
                "storageClassName": resources.CLASS,
                "claimRef": {
                    "uid": "claim-owned",
                    "name": claim["metadata"]["name"],
                    "namespace": claim["metadata"]["namespace"],
                },
                "hostPath": {"path": "/owned/volume"},
            },
        }
        with patch.object(kube_storage, "get", side_effect=[observed, volume]):
            result = self.subject.volume("state", claim, "claim-owned")
        self.assertEqual(result["uid"], "volume-owned")
        for field, value in (
            ("persistentVolumeReclaimPolicy", "Delete"),
            ("storageClassName", "foreign"),
            ("claimRef", {"uid": "foreign"}),
        ):
            changed = copy.deepcopy(volume)
            changed["spec"][field] = value
            with (
                patch.object(kube_storage, "get", side_effect=[observed, changed]),
                self.assertRaises(Rejected),
            ):
                self.subject.volume("state", claim, "claim-owned")
        for changed in (
            None,
            {**observed, "status": {"phase": "Pending"}},
            {**observed, "spec": claim["spec"]},
        ):
            with (
                patch.object(kube_storage, "get", return_value=changed),
                self.assertRaises(Rejected),
            ):
                self.subject.volume("state", claim, "claim-owned")

    def test_private_pod_refuses_extra_env_host_access_or_ephemeral_container(self):
        expected = resources.runtime_spec("pinned-image", "collector")
        self.subject.pod_spec(expected, copy.deepcopy(expected))
        changes = []
        for flag in ("hostNetwork", "hostPID", "hostIPC"):
            changed = copy.deepcopy(expected)
            changed[flag] = True
            changes.append(changed)
        changed = copy.deepcopy(expected)
        changed["ephemeralContainers"] = [{"name": "foreign"}]
        changes.append(changed)
        for collection in ("containers", "initContainers"):
            for field, value in (
                ("env", [{"name": "PYTHONPATH", "value": "/tmp"}]),
                ("envFrom", [{"secretRef": {"name": "foreign"}}]),
                ("volumeDevices", [{"name": "foreign"}]),
                ("lifecycle", {"postStart": {"exec": {"command": ["false"]}}}),
            ):
                changed = copy.deepcopy(expected)
                changed[collection][0][field] = value
                changes.append(changed)
        for changed in changes:
            with self.assertRaises(Rejected):
                self.subject.pod_spec(expected, changed)


class AuditBootstrap(unittest.TestCase):
    setUp = AuditOperator.setUp  # Reuse fixture setup without rediscovering its tests.

    def world(self):
        self.objects, self.creates, self.deletes = {}, [], []
        self.profile = {"image": "pinned@sha256:" + "b" * 64, "image_id": "sha256:" + "b" * 64}
        self.root_key = signing.create_key(self.directory / "root.pem")
        self.context = dict(environment="local-cpu", initial_root=self.root_key, policy="c" * 64)
        self.bad_code = self.bad_owner = self.bad_report = self.fail_kind = False
        self.pods_override = None

        def get(state, document):
            return copy.deepcopy(self.objects.get(kube_storage.reference(document)))

        def kubectl(state, arguments, document=None, **options):
            operation = arguments[0]
            if operation == "create":
                if document["kind"] == self.fail_kind:
                    raise Rejected("test_create_failure")
                observed = copy.deepcopy(document)
                observed["metadata"]["uid"] = "owned-" + str(len(self.creates))
                key = kube_storage.reference(observed)
                self.creates.append(key)
                if document["kind"] == "Service":
                    observed["spec"].update(
                        clusterIP="10.96.0.10", clusterIPs=["10.96.0.10"], ipFamilies=["IPv4"]
                    )
                if document["kind"] == "PersistentVolumeClaim":
                    name = (
                        "pv-"
                        + document["metadata"]["namespace"]
                        + "-"
                        + document["metadata"]["name"]
                    )
                    observed["spec"]["volumeName"] = name
                    observed["status"] = {"phase": "Bound"}
                    self.objects["PersistentVolume/_/" + name] = {
                        "metadata": {"name": name, "uid": name + "-uid"},
                        "spec": {
                            "persistentVolumeReclaimPolicy": "Retain",
                            "storageClassName": resources.CLASS,
                            "claimRef": {
                                "uid": observed["metadata"]["uid"],
                                "name": document["metadata"]["name"],
                                "namespace": document["metadata"]["namespace"],
                            },
                        },
                    }
                self.objects[key] = observed
                return SimpleNamespace(stdout=canonical(observed))
            if operation == "delete":
                key = "/".join((arguments[1], arguments[arguments.index("-n") + 1], arguments[2]))
                self.deletes.append(key)
                del self.objects[key]
            elif operation == "rollout":
                pass
            elif operation == "logs":
                return SimpleNamespace(stdout=canonical(self.report))
            elif operation == "get":
                namespace = arguments[arguments.index("-n") + 1]
                deployment = next(
                    v
                    for v in self.objects.values()
                    if v.get("kind") == "Deployment" and v["metadata"]["namespace"] == namespace
                )
                self.objects[f"ReplicaSet/{namespace}/owned-rs"] = {
                    "metadata": {
                        "uid": "rs-owned",
                        "ownerReferences": [
                            {
                                "uid": deployment["metadata"]["uid"],
                                "kind": "Deployment",
                                "controller": True,
                            }
                        ],
                    },
                }
                pod = {
                    "metadata": {
                        "name": "owned-pod",
                        "uid": "pod-owned",
                        "ownerReferences": [
                            {
                                "name": "owned-rs",
                                "uid": "rs-owned",
                                "kind": "ReplicaSet",
                                "controller": True,
                            }
                        ],
                    },
                    "spec": copy.deepcopy(deployment["spec"]["template"]["spec"]),
                    "status": {"conditions": [{"type": "Ready", "status": "True"}]},
                }
                return SimpleNamespace(
                    stdout=canonical(
                        {"items": [pod] if self.pods_override is None else self.pods_override(pod)}
                    )
                )
            else:
                raise AssertionError(operation)
            return SimpleNamespace(stdout=b"")

        def wait(state, namespace, name, timeout):
            job = self.objects[f"Job/{namespace}/{name}"]
            config = self.objects[f"ConfigMap/{namespace}/{name}"]
            value = decode(config["data"]["provision.json"].encode())
            self.report = {
                key: value[key]
                for key in ("schema_version", "role", "producer_id", "registry_sha256")
            }
            self.report.update(
                state_sha256=digest(value["producer_id"].encode()), release_ready=False
            )
            if self.bad_report:
                self.report["role"] = "foreign"
            pod = {
                "metadata": {
                    "name": "job-pod",
                    "ownerReferences": [
                        {"uid": "foreign" if self.bad_owner else job["metadata"]["uid"]}
                    ],
                },
                "spec": copy.deepcopy(job["spec"]["template"]["spec"]),
                "status": {
                    "containerStatuses": [
                        {"state": {"terminated": {"exitCode": 1 if self.bad_code else 0}}}
                    ]
                },
            }
            return {"type": "Complete"}, pod, 0.01

        for module, name, replacement in (
            (kube_storage, "get", get),
            (self.subject, "kubectl", kubectl),
            (self.subject, "wait_job", wait),
            (self.subject, "verify_running_image", lambda *_: None),
            (self.subject, "workspace_id", lambda _: self.workspace),
            (self.subject, "image_profile", lambda *_: self.profile),
            (kube_storage, "validate", lambda _: {}),
            (self.subject.kube_trust, "validate", lambda _: {}),
        ):
            self.enterContext(patch.object(module, name, replacement))

    def bootstrap(self):
        return self.subject.bootstrap(self.directory, self.directory, **self.context)

    def state_marker(self, changed=None):
        path = self.subject.directory(self.directory) / "resources.json"
        marker = read_json(path)
        if changed is not None:
            changed(marker)
            write_json(path, marker)
        return marker

    def test_bootstrap_records_real_materials_public_pins_owned_resources_and_exact_retry(self):
        self.world()
        marker = self.bootstrap()
        self.assertTrue(marker["ready"])
        self.assertEqual(set(marker["pins"]), set(resources.ROLES))
        self.assertEqual(len(self.deletes), 8)
        self.assertFalse(any(k.startswith(("Job/", "ConfigMap/")) for k in marker["resources"]))
        before = canonical(marker), list(self.creates)
        self.assertEqual(self.bootstrap(), marker)
        self.assertEqual(before, (canonical(self.state_marker()), self.creates))
        for changed in (
            {"profile": {}},
            {"environment": "other"},
            {"initial_root": "foreign"},
            {"authority_root": "foreign"},
        ):
            with self.assertRaises(Rejected):
                self.subject.validate(self.directory, **changed)

    def test_rotated_profile_retains_anchor_and_requires_owned_signed_config(self):
        from scripts import kube_observer_profile_qualification as profiles

        fixture = profiles.ObserverProfile()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.world()
        self.context["initial_root"] = fixture.fx.old_public
        marker = self.bootstrap()
        marker["observer"] = fixture.created()
        mapping = self.subject.kube_observer_profile.mapping(
            self.workspace, marker["observer"], marker["context"]
        )
        self.subject.create(self.directory, self.subject.directory(self.directory), marker, mapping)
        document = self.subject.runtime(marker, "trust")
        key = kube_storage.reference(document)
        document["metadata"]["uid"] = marker["resources"][key]
        self.objects[key] = document
        self.subject.save(self.subject.directory(self.directory), marker)
        created = list(self.creates)
        for root in (fixture.fx.old_public, fixture.fx.new_public):
            self.assertEqual(self.subject.validate(self.directory, authority_root=root), marker)
        self.assertEqual(marker["context"]["initial_root"], fixture.fx.old_public)
        with self.assertRaises(Rejected):
            self.subject.validate(self.directory, initial_root=fixture.fx.new_public)
        changed = copy.deepcopy(marker)
        changed["observer"]["rotations"][0]["package"]["acceptance"]["signatures"] = []
        self.subject.save(self.subject.directory(self.directory), changed)
        with self.assertRaises(Rejected):
            self.subject.validate(self.directory)
        self.subject.save(self.subject.directory(self.directory), marker)
        self.objects[kube_storage.reference(mapping)]["metadata"]["uid"] = "foreign"
        with self.assertRaises(Rejected):
            self.subject.validate(self.directory)
        self.assertEqual(created, self.creates)

    def test_same_namespace_serving_and_observer_volumes_cannot_be_swapped_or_recreated(self):
        self.world()
        marker = self.bootstrap()
        self.assertNotEqual(marker["pins"]["trust"], marker["pins"]["serving"])
        self.assertNotEqual(marker["volumes"]["trust"], marker["volumes"]["serving"])
        created = list(self.creates)
        original = self.state_marker()
        self.state_marker(lambda m: m["volumes"].update(serving=m["volumes"]["trust"]))
        with self.assertRaisesRegex(Rejected, "volume_changed"):
            self.subject.validate(self.directory)
        write_json(self.subject.directory(self.directory) / "resources.json", original)
        key = "PersistentVolumeClaim/ml-serving/security-serving"
        del self.objects[key]
        with self.assertRaises(Rejected):
            self.bootstrap()
        self.assertEqual(created, self.creates)
        self.assertNotIn(key, self.objects)

    def test_foreign_profile_or_existing_incomplete_directory_never_creates_or_rekeys(self):
        self.world()
        first = resources.base_resources(self.workspace)[0]
        self.objects[kube_storage.reference(first)] = first
        with self.assertRaisesRegex(Rejected, "unowned_profile"):
            self.bootstrap()
        self.assertEqual(self.creates, [])
        self.assertFalse(self.subject.directory(self.directory).exists())
        self.objects.clear()
        self.subject.directory(self.directory).mkdir()
        with self.assertRaises(Rejected):
            self.bootstrap()
        self.assertEqual(self.creates, [])

    def test_provisioning_failure_cleans_only_known_jobs_and_cannot_reinitialize(self):
        self.world()
        self.bad_report = True
        with self.assertRaisesRegex(Rejected, "provision_receipt"):
            self.bootstrap()
        self.assertEqual(len(self.deletes), 2)
        before = list(self.creates)
        self.bad_report = False
        with self.assertRaises(Rejected):
            self.bootstrap()
        self.assertEqual(self.creates, before)
        self.assertFalse(self.state_marker()["ready"])

    def test_failed_job_wrong_owner_and_create_failure_are_not_adopted_as_success(self):
        self.world()
        owned = self.subject.materials.create(
            self.directory / "materials", workspace=self.workspace, **self.context
        )
        marker = dict(
            workspace_id=self.workspace, resources={}, profile=self.profile, pins={}, volumes={}
        )
        for flag in ("bad_code", "bad_owner", "fail_kind"):
            setattr(self, flag, "Job" if flag == "fail_kind" else True)
            with self.assertRaises(Rejected):
                self.subject.provision(self.directory, self.directory, marker, owned, "promoter")
            setattr(self, flag, False)
            self.assertEqual(marker["resources"], {})
            self.assertEqual(marker["pins"], {})

    def test_missing_inventory_changed_service_or_volume_refuses_before_any_repair(self):
        self.world()
        self.bootstrap()
        original = self.state_marker()
        for change in (
            lambda m: m.update(schema_version=True),
            lambda m: m.update(ready=False),
            lambda m: m.update(pins={}),
            lambda m: m.update(volumes={}),
            lambda m: m.update(resources={}),
            lambda m: m.update(address="10.96.0.11"),
            lambda m: m["volumes"]["collector"].update(uid="foreign"),
        ):
            self.state_marker(change)
            with self.assertRaises(Rejected):
                self.subject.validate(self.directory)
            write_json(self.subject.directory(self.directory) / "resources.json", original)
        before = list(self.creates)
        claim_key = "PersistentVolumeClaim/ml-promoter/security-events"
        self.objects[claim_key]["metadata"]["uid"] = "replacement"
        with self.assertRaises(Rejected):
            self.subject.validate(self.directory)
        self.assertEqual(self.creates, before)

    def test_pod_count_owner_readiness_and_extra_env_are_checked_live(self):
        self.world()
        marker = self.bootstrap()
        document = resources.deployment(self.workspace, self.profile["image"], "collector")
        variants = [lambda p: [], lambda p: [p, p]]

        def changed(field, value):
            def mutate(pod):
                pod["metadata"][field] = value
                return [pod]

            return mutate

        variants.extend(
            (
                changed("ownerReferences", []),
                changed("ownerReferences", [{"kind": "Job"}]),
                changed("deletionTimestamp", "now"),
            )
        )

        def not_ready(pod):
            pod["status"]["conditions"] = []
            return [pod]

        variants.append(not_ready)
        self.pods_override = not_ready
        self.assertTrue(self.subject.live(self.directory, document, marker, require_ready=False))
        for invalid in (None, 0, "false"):
            with self.assertRaisesRegex(Rejected, "readiness_mode"):
                self.subject.live(self.directory, document, marker, require_ready=invalid)
        for variant in variants:
            self.pods_override = variant
            with self.assertRaises(Rejected):
                self.subject.live(self.directory, document, marker)
        self.pods_override = None
        with (
            patch.object(kube_storage, "get", return_value={"metadata": {"uid": "foreign"}}),
            self.assertRaises(Rejected),
        ):
            self.subject.live(self.directory, document, marker)

    def test_cleanup_refuses_foreign_uid_or_unconfirmed_deletion(self):
        self.world()
        doc = resources.resource("ConfigMap", "owned", self.workspace, "ml-audit", data={})
        marker = {"resources": {}}
        self.subject.create(self.directory, self.directory, marker, doc)
        key = kube_storage.reference(doc)
        self.objects[key]["metadata"]["uid"] = "foreign"
        with self.assertRaisesRegex(Rejected, "cleanup_unconfirmed"):
            self.subject.cleanup(self.directory, self.directory, marker, [doc])
        self.assertEqual(self.deletes, [])
        self.objects[key]["metadata"]["uid"] = marker["resources"][key]
        with (
            patch.object(self.subject, "kubectl"),
            self.assertRaisesRegex(Rejected, "cleanup_unconfirmed"),
        ):
            self.subject.cleanup(self.directory, self.directory, marker, [doc])
        self.assertIn(key, marker["resources"])

    def test_cli_success_failure_keyboard_interrupt_and_module_entrypoint_are_private(self):
        self.world()
        arguments = [
            "--state",
            str(self.directory),
            "--environment",
            "local-cpu",
            "--initial-root",
            self.root_key,
            "--policy",
            "c" * 64,
        ]
        with redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()):
            self.assertEqual(self.subject.main(arguments), 0)
        self.assertEqual(
            set(decode(output.getvalue().encode())), {"status", "registry_sha256", "release_ready"}
        )
        for error, code in ((Rejected("private fixture"), 1), (KeyboardInterrupt(), 130)):
            with (
                patch.object(self.subject, "bootstrap", side_effect=error),
                redirect_stdout(io.StringIO()) as output,
                redirect_stderr(io.StringIO()) as errors,
            ):
                self.assertEqual(self.subject.main(arguments), code)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(errors.getvalue(), "kube_security_rejected\n")
        with (
            patch.object(sys, "argv", ["security", "--unexpected"]),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as stopped,
        ):
            runpy.run_path(self.subject.__file__, run_name="__main__")
        self.assertEqual(stopped.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
