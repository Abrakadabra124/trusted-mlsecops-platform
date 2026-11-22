import copy
import unittest
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import image_audit_contract as contract
from scripts import image_coredns_fixture, image_kubernetes_inventory, image_scope
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


# Version delta measured by the two-image qualification at a008a2e, run 45024790177.
_REBUILD_VERSIONS = {
    "github.com/coredns/coredns": "v1.15.0+dirty",
    "github.com/klauspost/compress": "v1.20.2",
    "golang.org/x/crypto": "v0.59.0",
    "golang.org/x/mod": "v0.42.0",
    "golang.org/x/net": "v0.62.0",
    "golang.org/x/sync": "v0.25.0",
    "golang.org/x/sys": "v0.50.0",
    "golang.org/x/term": "v0.48.0",
    "golang.org/x/text": "v0.44.0",
    "stdlib": "go1.27.4",
}


def coredns_sbom(image_id=contract.COREDNS_CONFIG, versions=None):
    sbom, _, _, _, _ = fixtures()
    sbom["source"]["metadata"]["imageID"] = image_id
    sbom["distro"] = {"id": "debian", "versionID": "12.15"}
    artifacts = []
    for kind, records in (
        ("deb", image_coredns_fixture.DEB),
        ("go-module", image_coredns_fixture.GO_MODULES),
    ):
        for line in records.splitlines():
            name, version = line.split()
            if versions and kind == "go-module":
                version = versions.get(name, version)
            status = f"/var/lib/dpkg/status.d/{name}"
            paths = (
                [status, status + ".md5sums", f"/usr/share/doc/{name}/copyright"]
                if kind == "deb"
                else ["/coredns"]
            )
            artifacts.append(
                {
                    "id": str(len(artifacts)),
                    "name": name,
                    "version": version,
                    "type": kind,
                    "foundBy": "dpkg-db-cataloger"
                    if kind == "deb"
                    else "go-module-binary-cataloger",
                    "locations": [{"path": path} for path in paths],
                }
            )
    sbom["artifacts"] = artifacts
    return sbom


def coredns_rebuild_sbom(image_id):
    return coredns_sbom(image_id, _REBUILD_VERSIONS)


def coredns_observation():
    return observe_packages(coredns_sbom(), contract.COREDNS_CONFIG)


class PackageObservationTests(unittest.TestCase):
    def test_kubernetes_independent_inventory_never_infers_release_versions(self):
        config, original = next(iter(image_kubernetes_inventory.INVENTORIES.items()))
        binary = original["binary_paths"][-1]
        packages = [
            {
                "type": "go-module",
                "name": "k8s.io/api",
                "version": "UNKNOWN",
                "foundBy": "go-module-binary-cataloger",
                "paths": [binary],
            },
            {
                "type": "deb",
                "name": "base-files",
                "version": "12.4+deb12u14",
                "foundBy": "dpkg-db-cataloger",
                "paths": ["/var/lib/dpkg/status.d/base-files"],
            },
        ]
        rows = sorted([p["type"], p["name"], p["version"], p["paths"][0]] for p in packages)
        spec = {**original, "scanner_rows_sha256": digest(canonical(rows)), "package_count": 2}
        observation = {"image_id": config, "distro": original["distro"], "packages": packages}
        with patch.dict(image_kubernetes_inventory.INVENTORIES, {config: spec}, clear=True):
            result = image_kubernetes_inventory.diagnose(observation)
            self.assertTrue(result["independent_inventory_verified"])
            self.assertEqual(result["status"], "inconclusive")
            self.assertEqual(result["reason"], "image_audit_kubernetes_module_versions_unresolved")
            self.assertGreater(result["unversioned_module_instances"], 0)
            before = copy.deepcopy(observation)
            for change in (
                lambda o: o["packages"][0].update(version="v0.36.4"),
                lambda o: o["packages"][0].update(version="v0.0.0"),
                lambda o: o["packages"].pop(),
                lambda o: o["packages"].append(o["packages"][0]),
                lambda o: o["packages"][0].update(paths=["/other"]),
                lambda o: o["packages"][0].update(foundBy="file-cataloger"),
                lambda o: o["packages"][0].update(paths=[]),
                lambda o: o["packages"][0].pop("name"),
                lambda o: o["packages"][1].update(paths=[]),
                lambda o: o["packages"][1].update(type="rpm"),
                lambda o: o["packages"][1].update(foundBy="file-cataloger"),
                lambda o: o.update(distro={"id": "debian", "versionID": "13"}),
                lambda o: o.update(packages=None),
            ):
                changed = copy.deepcopy(observation)
                change(changed)
                with self.subTest(change=change):
                    rejected = image_kubernetes_inventory.diagnose(changed)
                    self.assertFalse(rejected["independent_inventory_verified"])
                    self.assertEqual(
                        rejected["reason"], "image_audit_kubernetes_inventory_mismatch"
                    )
                    self.assertEqual(rejected["status"], "inconclusive")
            self.assertEqual(observation, before)
            for malformed in (None, {}, {"image_id": []}):
                self.assertIsNone(image_kubernetes_inventory.diagnose(malformed))
            self.assertIsNone(
                image_kubernetes_inventory.diagnose(
                    {**observation, "image_id": "sha256:" + "0" * 64}
                )
            )
            component = {
                "name": "runtime-000",
                "image_config_id": config,
                "scan_executed": True,
                "sbom_validated": False,
                "status": "fail",
                "coverage_profile": "unapproved-system",
                "catalogued_packages": 2,
                "application_inventory": result,
            }
            snapshot = {"targets": [{"name": "runtime-000", "config_id": config}]}
            self.assertEqual(image_scope.coverage(snapshot, [component])["covered_images"], 0)

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

    def test_coredns_requires_the_entire_independent_inventory_and_exact_manifest(self):
        observed = coredns_observation()
        ref = contract.COREDNS_REFERENCE
        self.assertEqual(observed["package_types"], {"deb": 5, "go-module": 197})
        self.assertTrue(contract.coredns_inventory_matches(observed, ref))
        for bad_ref in (
            None,
            ref.replace("registry.k8s.io", "mirror"),
            contract.COREDNS_CONFIG,
            ref.replace("3429e3bb", "00000000"),
        ):
            with self.subTest(reference=bad_ref):
                self.assertFalse(contract.coredns_inventory_matches(observed, bad_ref))
        for change in (
            lambda o: o.update(image_id="sha256:" + "0" * 64),
            lambda o: o.update(
                image_id="sha256:97efff2babf85310d6f87bd969ac64d7006bbbadb147c90579d68d57634750f4"
            ),
            lambda o: o.update(distro=None),
            lambda o: o["distro"].update(versionID="12"),
            lambda o: o.update(package_count=202.0),
            lambda o: o.update(status="pass"),
            lambda o: o["package_types"].update(deb=4),
            lambda o: o["packages"].pop(),
            lambda o: o["packages"].append(o["packages"][0]),
            lambda o: o["packages"].__setitem__(1, o["packages"][0]),
            lambda o: o["packages"][0].update(version="UNKNOWN"),
            lambda o: o["packages"][0].update(paths=["/other"]),
            lambda o: o["packages"][0].update(foundBy="file-cataloger"),
            lambda o: next(p for p in o["packages"] if p["type"] == "deb")["paths"].pop(),
            lambda o: next(p for p in o["packages"] if p["name"] == "stdlib").update(
                version="go1.26.6"
            ),
            lambda o: next(p for p in o["packages"] if p["name"] == "golang.org/x/net").update(
                version="v0.57.0"
            ),
        ):
            modified = copy.deepcopy(observed)
            change(modified)
            with self.subTest(change=change):
                self.assertFalse(contract.coredns_inventory_matches(modified, ref))
        observed["packages"].reverse()
        self.assertTrue(contract.coredns_inventory_matches(observed, ref))

    def test_published_coredns_requires_registry_identity_and_all_202_rows(self):
        pin = contract.PUBLISHED_COREDNS
        obs = observe_packages(coredns_rebuild_sbom(pin.config), pin.config)
        with patch.object(contract, "PUBLISHED_COREDNS", None):
            self.assertIsNone(contract.coredns_coverage_profile(obs, pin.reference))
        profile = contract.coredns_coverage_profile
        self.assertEqual(profile(obs, pin.reference), contract.PUBLISHED_COREDNS_PROFILE)
        self.assertEqual(profile(coredns_observation(), contract.COREDNS_REFERENCE), "coredns")
        for ref in (
            pin.reference.replace("ghcr.io", "mirror"),
            pin.reference.replace("/coredns@", "/other@"),
            pin.reference.replace(pin.manifest, contract.COREDNS_MANIFEST),
            contract.COREDNS_REFERENCE,
            pin.spec_image,
            pin.config,
        ):
            with self.subTest(ref=ref):
                self.assertIsNone(profile(obs, ref))
        for change in (
            lambda o: o.update(image_id=contract.COREDNS_CONFIG),
            # The earlier unpublished build in 45024790177 had identical normalized rows.
            lambda o: o.update(
                image_id="sha256:a8426fd4b9b65a0aa360d299954cac8a044d0ea5138970c84f4c2e757cbce3b5"
            ),
            lambda o: o["distro"].update(versionID="13"),
            lambda o: o["packages"].pop(),
            lambda o: o["packages"].__setitem__(1, o["packages"][0]),
            lambda o: o["packages"][0].update(paths=["/foreign"]),
            lambda o: o["packages"][0].update(foundBy="other"),
            lambda o: next(p for p in o["packages"] if p["type"] == "deb").update(version="0"),
            lambda o: o.update(status="pass"),
        ):
            modified = copy.deepcopy(obs)
            change(modified)
            with self.subTest(change=change):
                self.assertIsNone(profile(modified, pin.reference))

    def test_published_coredns_preserves_findings_and_standard_severity_policy(self):
        pin = contract.PUBLISHED_COREDNS
        sbom = coredns_rebuild_sbom(pin.config)
        _, report, match, _, timestamp = fixtures()
        report["source"]["target"]["imageID"] = pin.config
        match["artifact"] = {k: sbom["artifacts"][0][k] for k in ("id", "name", "version", "type")}
        for severities, expected, code in (
            (("Critical",), "fail", 2),
            (("High",), "fail", 2),
            (("Unknown",), "inconclusive", 0),
            (("Medium", "Unknown"), "inconclusive", 0),
            (("Unknown", "High"), "fail", 2),
            (("Unknown", "Critical"), "fail", 2),
            (("Medium",), "pass", 0),
        ):
            with self.subTest(severities=severities):
                report["matches"] = [
                    {**match, "vulnerability": {"id": f"test-{s}", "severity": s}}
                    for s in severities
                ]
                result = contract.assess(
                    sbom,
                    report,
                    pin.config,
                    {"stdlib", "base-files", "github.com/coredns/coredns"},
                    code,
                    timestamp,
                )
                self.assertEqual(result["status"], expected)
                for severity in severities:
                    self.assertEqual(result["severity_counts"][severity], 1)
                self.assertCountEqual(
                    [(f["id"], f["severity"]) for f in result["findings"]],
                    [(f"test-{s}", s) for s in severities],
                )

    def test_coredns_coverage_binds_target_component_and_observation(self):
        obs = coredns_observation()
        ref, config = contract.COREDNS_REFERENCE, contract.COREDNS_CONFIG
        target = {"name": "runtime-007", "config_id": config, "reference": ref}
        item = {
            "name": "runtime-007",
            "observed_reference": ref,
            "image_config_id": config,
            "runtime_image_id": config,
            "catalogued_packages": 202,
            "scan_executed": True,
            "sbom_validated": True,
            "coverage_profile": "coredns",
            "status": "fail",
            "package_observation": obs,
        }

        def covered(component, expected):
            return image_scope.coverage({"targets": [expected]}, [component])["covered_images"]

        self.assertEqual(covered(item, target), 1)
        for field, value in (
            ("catalogued_packages", 201),
            ("runtime_image_id", "other"),
            ("observed_reference", "other"),
            ("scan_executed", False),
            ("sbom_validated", False),
            ("status", "inconclusive"),
        ):
            with self.subTest(field=field):
                self.assertEqual(covered({**item, field: value}, target), 0)
        self.assertEqual(covered(item, {**target, "reference": "other"}), 0)
        self.assertEqual(covered(item, {**target, "config_id": "other"}), 0)
        pin = contract.PUBLISHED_COREDNS
        obs = observe_packages(coredns_rebuild_sbom(pin.config), pin.config)
        target.update(config_id=pin.config, reference=pin.reference)
        item.update(
            observed_reference=pin.reference,
            runtime_image_id=pin.config,
            image_config_id=pin.config,
            package_observation=obs,
        )
        self.assertEqual(covered(item, target), 0)
        item["coverage_profile"] = contract.PUBLISHED_COREDNS_PROFILE
        self.assertEqual(covered(item, target), 1)
        self.assertEqual(covered(item, {**target, "reference": ref}), 0)
        self.assertEqual(covered({**item, "image_config_id": config}, target), 0)

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
