import copy
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical
from scripts import image_scope


def sha(value):
    return "sha256:" + value * 64


class RuntimeImageScopeContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.workspace = "a" * 32
        self.revision = "b" * 40
        self.fingerprint = "c" * 64
        self.profile = {
            "image": "docker.io/library/worker@" + sha("8"),
            "image_id": sha("3"),
            "config_id": sha("7"),
            "manifest_id": sha("8"),
            "source_fingerprint": self.fingerprint,
            "source_revision": self.revision,
        }
        self.marker = {"ready": True, "profile": self.profile, "resources": {"policy": {}}}
        self.cluster = {"workspace_id": self.workspace, "namespace_uid": "owned-namespace"}
        self.container = {
            "Id": "d" * 64,
            "Image": sha("2"),
            "Config": {"Labels": {image_scope.WORKSPACE_LABEL: self.workspace}},
        }
        self.node = {
            "Id": "e" * 64,
            "Image": sha("1"),
            "Config": {"Labels": {"io.x-k8s.kind.cluster": image_scope.NAME}},
        }
        self.tracking = {
            "pg": {"Id": "f" * 64, "Image": sha("2")},
            "server": {"Id": "0" * 64, "Image": sha("4")},
        }
        self.pods = {
            "items": [
                {
                    "metadata": {"namespace": "kube-system", "name": "system-pod"},
                    "spec": {
                        "containers": [{"name": "system", "image": "registry.example/system:v1"}]
                    },
                    "status": {"containerStatuses": [{"name": "system", "imageID": sha("5")}]},
                }
            ]
        }
        self.cri = {
            "status": {"id": sha("5"), "repoDigests": ["registry.example/system@" + sha("6")]}
        }
        self.listed = self.container["Id"]
        self.commands = []
        self.resolve_image = lambda ref: (
            sha("7") if ref in {sha("3"), sha("7"), sha("8")} else sha("5")
        )

    def command(self, args, **kwargs):
        self.commands.append(args)
        if args[0] == "git":
            return self.revision
        if args[:2] == ["docker", "ps"]:
            return self.listed
        if args[:2] == ["docker", "inspect"]:
            return canonical(
                [self.node if args[-1] == image_scope.NODE else self.container]
            ).decode()
        if "inspecti" in args:
            return canonical(self.cri).decode()
        raise AssertionError(args)

    def collect(self):
        with ExitStack() as stack:
            for name, value in (
                ("workspace_id", self.workspace),
                ("validate_cluster", self.cluster),
                ("source_fingerprint", self.fingerprint),
                ("verify_saved", self.marker),
            ):
                stack.enter_context(patch.object(image_scope, name, return_value=value))
            stack.enter_context(patch.object(image_scope, "read_json", return_value=self.marker))
            stack.enter_context(patch.object(image_scope, "command", side_effect=self.command))
            stack.enter_context(
                patch.object(
                    image_scope,
                    "kubectl",
                    return_value=SimpleNamespace(stdout=canonical(self.pods)),
                )
            )
            stack.enter_context(
                patch.object(
                    image_scope, "image_inventory", side_effect=lambda ref: {"image_id": ref}
                )
            )
            stack.enter_context(
                patch.object(
                    image_scope,
                    "image_config",
                    side_effect=self.resolve_image,
                )
            )
            stack.enter_context(
                patch.object(image_scope.tracking_service, "verify", return_value=self.tracking)
            )
            stack.enter_context(patch.object(image_scope.storage_bootstrap, "validate"))
            return image_scope.collect(self.root, self.root)

    def test_observes_node_controllers_pods_and_both_storage_paths(self):
        observed = self.collect()
        self.assertEqual(len(observed["targets"]), 5)
        self.assertEqual(
            {target["reference"] for target in observed["targets"]},
            {sha("1"), sha("2"), sha("3"), sha("4"), "registry.example/system@" + sha("6")},
        )
        self.assertEqual(observed["controller_profile"], self.profile)
        self.assertEqual(len(observed["containers"]), 4)
        self.assertEqual(observed, self.collect())
        self.assertTrue(
            all("pull" not in cmd and "run" not in cmd and "rm" not in cmd for cmd in self.commands)
        )

    def test_tool_failure_reports_only_the_fixed_observation_stage(self):
        for reason in (
            "required_tool_failed",
            "required_tool_unavailable",
            "image_scope_digest_invalid",
        ):
            with patch.object(
                image_scope, "image_config", side_effect=Rejected(reason)
            ) as operation:
                expected = (
                    "image_scope_" + reason + ":pod-manifest-config"
                    if reason.startswith("required_tool_")
                    else reason
                )
                with self.assertRaisesRegex(Rejected, expected):
                    image_scope.observe("pod-manifest-config", operation, "sha256:" + "a" * 64)

    def test_known_controller_config_reuses_local_image_without_registry_pull(self):
        self.pods["items"][0]["status"]["containerStatuses"][0]["imageID"] = sha("7")
        observed = self.collect()
        self.assertEqual(len(observed["targets"]), 4)
        self.assertFalse(any("inspecti" in command for command in self.commands))

    def test_cri_lookup_uses_resolved_config_when_pod_reports_manifest_digest(self):
        self.pods["items"][0]["status"]["containerStatuses"][0]["imageID"] = sha("a")
        original = self.command

        def command(args, **kwargs):
            if "inspecti" in args and args[-1] != sha("5"):
                raise Rejected("required_tool_failed")
            return original(args, **kwargs)

        self.command = command
        self.assertEqual(len(self.collect()["targets"]), 5)

    def test_refuses_changed_profile_owner_and_non_digest_container_ids(self):
        mutations = (
            lambda: self.profile.update(source_revision="a" * 40),
            lambda: self.profile.update(source_fingerprint="a" * 64),
            lambda: self.profile.update(config_id=sha("9")),
            lambda: self.marker.update(ready=False),
            lambda: self.marker.update(resources={}),
            lambda: self.cluster.update(workspace_id="b" * 32),
            lambda: self.node["Config"].update(Labels={}),
            lambda: self.container["Config"].update(Labels={}),
            lambda: self.container.update(Id="changed"),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.setUp()
                mutate()
                with self.assertRaises(Rejected):
                    self.collect()

    def test_refuses_missing_ambiguous_or_unpinned_cri_identity(self):
        for status in (
            {},
            {"id": sha("9"), "repoDigests": ["registry.example/system@" + sha("6")]},
            {"id": sha("5"), "repoDigests": []},
            {"id": sha("5"), "repoDigests": ["registry.example/system:latest"]},
            {"id": sha("5"), "repoDigests": ["https://token@registry.example/system@" + sha("6")]},
            {"id": sha("5"), "repoDigests": ["registry.example/system@" + sha("8")]},
        ):
            with self.subTest(status=status):
                self.cri = {"status": status}
                with self.assertRaises(Rejected):
                    self.collect()

    def test_refuses_empty_or_oversized_pod_inventory(self):
        original = self.pods["items"]
        for items in ([], original * 257):
            self.pods["items"] = items
            with self.assertRaises(Rejected):
                self.collect()

    def test_cri_failure_distinguishes_missing_references_from_identity_mismatch(self):
        for status, reason in (
            ({"id": sha("9"), "repoDigests": []}, "config_mismatch"),
            ({"id": sha("5"), "repoDigests": None}, "references_invalid"),
            ({"id": sha("5"), "repoDigests": ["x"] * 17}, "references_invalid"),
            ({"id": sha("5"), "repoDigests": []}, "references_missing"),
        ):
            with self.subTest(reason=reason):
                self.cri = {"status": status}
                with self.assertRaisesRegex(Rejected, "image_scope_cri_" + reason + "$"):
                    self.collect()

    def test_local_only_cri_image_keeps_exact_config_and_export_alias(self):
        self.cri["status"].update(repoDigests=[], repoTags=["registry.example/system:v1"])
        target = next(row for row in self.collect()["targets"] if row["config_id"] == sha("5"))
        self.assertEqual(target["reference"], sha("5"))
        self.assertEqual(target["containerd_reference"], "registry.example/system:v1")
        self.assertFalse(any("pull" in cmd or "export" in cmd for cmd in self.commands))

    def test_local_export_aliases_are_bounded_and_never_accept_credentials_or_options(self):
        for tags in (
            None,
            [],
            [None],
            ["x"] * 17,
            ["--all"],
            ["https://host/image:v1"],
            ["user:password@host/image:v1"],
            ["image:tag\n--all"],
            ["image"],
        ):
            self.cri["status"].update(repoDigests=[], repoTags=tags)
            with self.subTest(tags=tags), self.assertRaises(Rejected):
                self.collect()

    def test_local_export_deduplicates_and_reuses_an_existing_host_config(self):
        self.cri["status"].update(repoDigests=[], repoTags=["registry.example/system:v1"])
        self.pods["items"].append(copy.deepcopy(self.pods["items"][0]))
        self.assertEqual(len(self.collect()["targets"]), 5)
        original = self.command
        count = 0

        def changing(args, **kwargs):
            nonlocal count
            if "inspecti" in args:
                count += 1
                if count == 2:
                    self.cri["status"]["repoTags"] = ["registry.example/system:v2"]
            return original(args, **kwargs)

        self.command = changing
        with self.assertRaisesRegex(Rejected, "local_reference_changed"):
            self.collect()
        self.command = original
        self.container["Image"] = sha("5")
        target = next(t for t in self.collect()["targets"] if t["reference"] == sha("5"))
        self.assertNotIn("containerd_reference", target)
        self.assertEqual(target["config_id"], sha("5"))
        self.profile["image_id"] = sha("5")
        old_resolver = self.resolve_image
        self.resolve_image = lambda value: sha("7") if value == sha("5") else old_resolver(value)
        self.pods["items"][0]["status"]["containerStatuses"][0]["imageID"] = sha("a")
        with self.assertRaisesRegex(Rejected, "ambiguous_target"):
            self.collect()

    def test_refuses_duplicate_or_unbounded_container_inventory(self):
        for value in (
            self.listed + "\n" + self.listed,
            "not-an-id",
            "\n".join(f"{index:064x}" for index in range(257)),
        ):
            self.listed = value
            with self.assertRaises(Rejected):
                self.collect()

    def test_all_container_kinds_are_observed(self):
        pod = self.pods["items"][0]
        pod["spec"]["initContainers"] = [{"name": "init", "image": "registry.example/system:v1"}]
        pod["status"]["initContainerStatuses"] = [{"name": "init", "imageID": sha("5")}]
        pod["spec"]["ephemeralContainers"] = [
            {"name": "debug", "image": "registry.example/system:v1"}
        ]
        pod["status"]["ephemeralContainerStatuses"] = [{"name": "debug", "imageID": sha("5")}]
        self.assertEqual(len(self.collect()["pods"]), 3)

    def test_refuses_invalid_image_and_duplicate_resource_identity(self):
        self.node["Image"] = "system:latest"
        with self.assertRaisesRegex(Rejected, "digest_invalid"):
            self.collect()
        self.node["Image"] = sha("1")
        for identifier in (self.container["Id"], "not-a-container-id"):
            self.tracking["server"]["Id"] = identifier
            with self.assertRaisesRegex(Rejected, "container_identity_invalid"):
                self.collect()

    def test_refuses_more_than_64_unique_images(self):
        self.listed = "\n".join(f"{index:064x}" for index in range(64))
        original_command = self.command

        def command(args, **kwargs):
            if args[:2] == ["docker", "inspect"] and args[-1] != image_scope.NODE:
                return canonical(
                    [
                        {
                            "Id": args[-1],
                            "Image": "sha256:" + args[-1],
                            "Config": self.container["Config"],
                        }
                    ]
                ).decode()
            return original_command(args, **kwargs)

        self.command = command
        with self.assertRaisesRegex(Rejected, "target_limit"):
            self.collect()

    def test_refuses_registry_identity_changing_between_pods(self):
        second = copy.deepcopy(self.pods["items"][0])
        second["metadata"]["name"] = "system-pod-2"
        second["status"]["containerStatuses"][0]["imageID"] = sha("6")
        self.pods["items"].append(second)
        self.cri["status"]["repoDigests"] = ["registry.example/system@" + sha("9")]
        original_command = self.command
        original_resolver = self.resolve_image
        observed = [None]

        def command(args, **kwargs):
            if "inspecti" in args:
                observed[0] = args[-1]
                self.cri["status"]["id"] = observed[0]
            return original_command(args, **kwargs)

        self.command = command
        self.resolve_image = lambda ref: (
            observed[0] if ref == sha("9") else ref if ref == sha("6") else original_resolver(ref)
        )
        with self.assertRaisesRegex(Rejected, "ambiguous_target"):
            self.collect()

    def test_coverage_requires_every_actual_digest_and_complete_scan(self):
        snapshot = self.collect()
        components = [
            {
                "name": target["name"],
                "runtime_image_id": target["reference"],
                "image_config_id": target["config_id"] or sha("a"),
                "scan_executed": True,
                "sbom_validated": True,
                "coverage_profile": "worker",
                "status": "pass",
                "catalogued_packages": 5,
            }
            for target in snapshot["targets"]
        ]
        result = image_scope.coverage(snapshot, components)
        self.assertEqual(result, {"status": "pass", "expected_images": 5, "covered_images": 5})
        plain = next(
            i for i, target in enumerate(snapshot["targets"]) if target["config_id"] is None
        )
        bound = next(
            i for i, target in enumerate(snapshot["targets"]) if target["config_id"] is not None
        )
        for mutate in (
            lambda rows: rows.pop(),
            lambda rows: rows.append(rows[0]),
            lambda rows: rows[0].update(scan_executed=False),
            lambda rows: rows[0].update(sbom_validated=False),
            lambda rows: rows[0].update(status="inconclusive"),
            lambda rows: rows[0].update(coverage_profile="unapproved-system"),
            lambda rows: rows[plain].update(runtime_image_id=sha("f")),
            lambda rows: rows[0].update(catalogued_packages=0),
            lambda rows: rows[bound].update(image_config_id=sha("f")),
        ):
            changed = copy.deepcopy(components)
            mutate(changed)
            with self.subTest(mutation=mutate):
                self.assertEqual(image_scope.coverage(snapshot, changed)["status"], "inconclusive")
        components[0]["status"] = "fail"
        self.assertEqual(image_scope.coverage(snapshot, components)["status"], "pass")


if __name__ == "__main__":
    unittest.main()
