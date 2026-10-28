import copy
import unittest

from mlsecops.contracts import Rejected
from scripts.image_audit_contract import observe_packages
from scripts.image_audit_qualification import fixtures


class PackageObservationTests(unittest.TestCase):
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
            lambda d: d.pop("source"),
        ):
            changed = copy.deepcopy(sbom)
            mutate(changed)
            with self.subTest(mutation=mutate), self.assertRaises(Rejected):
                observe_packages(changed, image)


if __name__ == "__main__":
    unittest.main()
