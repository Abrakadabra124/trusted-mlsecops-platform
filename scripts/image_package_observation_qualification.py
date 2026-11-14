import copy
import unittest
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import image_audit_contract as contract
from scripts import image_scope
from scripts.image_audit_contract import observe_packages
from scripts.image_audit_qualification import fixtures
from scripts.image_system_inventory_fixture import LOCAL_PATH_INVENTORY


def local_path_observation():
    evidence = copy.deepcopy(LOCAL_PATH_INVENTORY)
    return {
        "image_id": evidence["image_config"],
        "distro": evidence["distro"],
        "packages": [
            {
                "type": kind,
                "name": name,
                "version": version,
                "foundBy": "go-module-binary-cataloger"
                if kind == "go-module"
                else "dpkg-db-cataloger",
                "paths": [
                    evidence["binary_path"]
                    if kind == "go-module"
                    else f"/var/lib/dpkg/status.d/{name}"
                ],
            }
            for kind, name, version in evidence["rows"]
        ],
    }


class PackageObservationTests(unittest.TestCase):
    def test_local_path_matches_independent_binary_and_dpkg_inventory(self):
        observation = local_path_observation()
        self.assertEqual(len(observation["packages"]), 61)
        self.assertTrue(contract.local_path_inventory_matches(observation))

    def test_local_path_refuses_changed_identity_inventory_and_catalogers(self):
        observation = local_path_observation()
        binary = next(i for i, p in enumerate(observation["packages"]) if p["type"] == "go-module")
        for change in (
            lambda o: o.update(image_id="sha256:" + "0" * 64),
            lambda o: o.update(distro=None),
            lambda o: o["distro"].update(versionID="12.15"),
            lambda o: o["packages"].pop(),
            lambda o: o["packages"].append(o["packages"][0]),
            lambda o: o["packages"][binary].update(version="UNKNOWN"),
            lambda o: o["packages"][binary].update(paths=["/other"]),
            lambda o: o["packages"][binary].update(foundBy="file-cataloger"),
            lambda o: o["packages"][0].update(type="rpm"),
            lambda o: o["packages"][0].update(foundBy="file-cataloger"),
            lambda o: o["packages"][0].update(paths=[]),
        ):
            modified = copy.deepcopy(observation)
            change(modified)
            with self.subTest(change=change):
                self.assertFalse(contract.local_path_inventory_matches(modified))
        for malformed in (None, {}, {**observation, "packages": None}):
            self.assertFalse(contract.local_path_inventory_matches(malformed))

    def test_local_path_coverage_does_not_override_high_unknown_or_scan_binding(self):
        observation = local_path_observation()
        sbom, report, match, _, timestamp = fixtures()
        image_id = observation["image_id"]
        sbom["source"]["metadata"]["imageID"] = image_id
        sbom["distro"] = observation["distro"]
        sbom["artifacts"] = [
            {**p, "id": str(i), "locations": [{"path": p["paths"][0]}]}
            for i, p in enumerate(observation["packages"])
        ]
        report["source"]["target"]["imageID"] = image_id
        report["distro"] = {"name": "debian", "version": "13"}
        match["artifact"] = {k: sbom["artifacts"][0][k] for k in ("id", "name", "version", "type")}
        report["matches"] = [match]
        snapshot = {"targets": [{"name": "runtime-012", "config_id": image_id}]}
        for severity, expected, code in (
            ("Critical", "fail", 2),
            ("High", "fail", 2),
            ("Unknown", "inconclusive", 0),
            ("Low", "pass", 0),
        ):
            match["vulnerability"]["severity"] = severity
            result = contract.assess(
                sbom,
                report,
                image_id,
                {"github.com/rancher/local-path-provisioner", "stdlib", "base-files"},
                code,
                timestamp,
            )
            self.assertEqual(result["status"], expected)
            component = {
                **result,
                "name": "runtime-012",
                "scan_executed": True,
                "sbom_validated": True,
                "image_config_id": image_id,
                "coverage_profile": "local-path-provisioner",
                "package_observation": observation,
                "catalogued_packages": 61,
            }
            self.assertEqual(
                image_scope.coverage(snapshot, [component])["covered_images"],
                0 if severity == "Unknown" else 1,
            )
        for change in (
            {"scan_executed": False},
            {"sbom_validated": False},
            {"image_config_id": "sha256:" + "0" * 64},
            {"package_observation": {}},
            {"status": "inconclusive"},
        ):
            self.assertEqual(
                image_scope.coverage(snapshot, [{**component, **change}])["covered_images"], 0
            )

    def test_coredns_requires_the_reviewed_binary_and_complete_package_inventory(self):
        packages = [
            {
                "name": "stdlib",
                "version": "go1.26.6",
                "type": "go-module",
                "foundBy": "go-module-binary-cataloger",
                "paths": ["/coredns"],
            },
            {
                "name": "base-files",
                "version": "12.4+deb12u15",
                "type": "deb",
                "foundBy": "dpkg-db-cataloger",
                "paths": ["/var/lib/dpkg/status.d/base-files"],
            },
        ]
        observation = {
            "image_id": contract.COREDNS_CONFIG,
            "distro": {"id": "debian", "versionID": "12"},
            "packages": packages,
        }
        pin = digest(canonical(sorted([p["type"], p["name"], p["version"]] for p in packages)))
        with patch.object(contract, "COREDNS_PACKAGES_SHA256", pin):
            self.assertTrue(contract.coredns_inventory_matches(observation))
            for change in (
                lambda o: o.update(image_id="sha256:" + "0" * 64),
                lambda o: o.update(distro=None),
                lambda o: o["packages"].pop(),
                lambda o: o["packages"].append(o["packages"][0]),
                lambda o: o["packages"][0].update(version="UNKNOWN"),
                lambda o: o["packages"][0].update(paths=["/other"]),
                lambda o: o["packages"][0].update(foundBy="file-cataloger"),
                lambda o: o["packages"][1].update(foundBy="file-cataloger"),
                lambda o: o["packages"][1].update(paths=[]),
            ):
                modified = copy.deepcopy(observation)
                change(modified)
                with self.subTest(change=change):
                    self.assertFalse(contract.coredns_inventory_matches(modified))

    def test_bound_projection_retains_unknown_distro_without_granting_coverage(self):
        sbom, _, _, image, _ = fixtures()
        sbom["distro"] = None
        sbom["private_field"] = "secret-canary"
        sbom["artifacts"][0]["metadata"] = {"secret": "secret-canary"}
        sbom["artifacts"][0]["locations"] = [
            {"path": "/usr/bin/example", "annotations": {"secret": "secret-canary"}}
        ]
        result = observe_packages(sbom, image)
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["scope"], "package-observation-not-application-coverage")
        self.assertEqual(result["image_id"], image)
        self.assertEqual(result["package_count"], 2)
        self.assertIsNone(result["distro"])
        self.assertNotIn("secret-canary", str(result))
        self.assertEqual(result["packages"][0]["paths"], ["/usr/bin/example"])

    def test_empty_inventory_is_visible_and_never_passes(self):
        sbom, _, _, image, _ = fixtures()
        sbom["artifacts"] = []
        result = observe_packages(sbom, image)
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["packages"], [])

    def test_omitted_optional_distro_fields_preserve_package_observation(self):
        sbom, _, _, image, _ = fixtures()
        for declared in ({}, {"id": "debian"}, {"versionID": "12"}):
            with self.subTest(declared=declared):
                sbom["distro"] = declared
                result = observe_packages(sbom, image)
                self.assertEqual(result["package_count"], 2)
                self.assertEqual(result["status"], "inconclusive")
                self.assertEqual(
                    result["distro"], {key: declared.get(key) for key in ("id", "versionID")}
                )

    def test_unknown_versions_remain_visible_without_inference(self):
        sbom, _, _, image, _ = fixtures()
        sbom["artifacts"][0]["version"] = ""
        sbom["artifacts"][1]["version"] = "(devel)"
        result = observe_packages(sbom, image)
        self.assertEqual({p["version"] for p in result["packages"]}, {"", "(devel)"})
        self.assertEqual(result["status"], "inconclusive")

    def test_multiple_instances_and_go_binary_locations_are_retained(self):
        sbom, _, _, image, _ = fixtures()
        first = {
            "id": "first",
            "name": "k8s.io/kubernetes",
            "version": "v1.36.4",
            "type": "go-module",
            "foundBy": "go-module-binary-cataloger",
            "locations": [{"accessPath": "/usr/bin/kubelet"}],
        }
        second = {**first, "id": "second", "locations": [{"path": "/usr/bin/kubeadm"}]}
        sbom["artifacts"] = [first, second]
        result = observe_packages(sbom, image)
        self.assertEqual(result["package_count"], 2)
        self.assertEqual(
            {tuple(p["paths"]) for p in result["packages"]},
            {("/usr/bin/kubelet",), ("/usr/bin/kubeadm",)},
        )
        self.assertEqual(result["package_types"], {"go-module": 2})

    def test_changed_binding_and_malformed_inventory_are_rejected(self):
        sbom, _, _, image, _ = fixtures()
        for mutate in (
            lambda d: d["source"]["metadata"].update(imageID="sha256:" + "b" * 64),
            lambda d: d["descriptor"].update(version="other"),
            lambda d: d["source"].update(type="directory"),
            lambda d: d.update(artifacts=[d["artifacts"][0]] * 4097),
            lambda d: d["artifacts"].append(d["artifacts"][0]),
            lambda d: d["artifacts"][0].update(version=False),
            lambda d: d["artifacts"][0].update(name="x\n::warning::private"),
            lambda d: d["artifacts"][0].update(name="x" * 1025),
            lambda d: d["artifacts"][0].update(locations=[{"path": 42}]),
            lambda d: d["artifacts"][0].update(locations=[{"path": "/tmp/a"}] * 65),
            lambda d: d.update(distro={"id": "debian", "versionID": False}),
            lambda d: d.update(distro={"id": None}),
            lambda d: d.update(distro=[]),
            lambda d: d.update(distro="debian"),
            lambda d: d.pop("source"),
        ):
            changed = copy.deepcopy(sbom)
            mutate(changed)
            with self.subTest(mutation=mutate), self.assertRaises(Rejected):
                observe_packages(changed, image)


if __name__ == "__main__":
    unittest.main()
