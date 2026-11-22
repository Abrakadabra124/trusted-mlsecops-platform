"""Controlled registry tests; these fixtures are not the private 588-row replay."""

import copy
import importlib
import importlib.util
import json
import tempfile
import unittest
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import image_kubernetes_inventory as inventory

CONFIG = "sha256:b0f70fa6ec47eb5682e7030c5799ea8ba42e52f5e7ea24f0f46bd9e8170b183c"
MANIFEST = "sha256:feb6509b541379d76b37cf6e7a5c1e3767458f7468288525f75574672fee1b18"
BINARY = "/usr/local/bin/kube-apiserver"
PSEUDO = "v0.0.0-20260820030627-bb826b1d4856"
PROOF = "a1e16b7cb7ec48b1429d7af449785ac5109eca61c37a9ef122faf014bf415bae"
DEPENDENCIES = (
    "api",
    "apiextensions-apiserver",
    "apimachinery",
    "apiserver",
    "client-go",
    "cloud-provider",
    "cluster-bootstrap",
    "component-base",
    "component-helpers",
    "controller-manager",
    "csi-translation-lib",
    "dynamic-resource-allocation",
    "endpointslice",
    "externaljwt",
    "kms",
    "kube-aggregator",
    "kube-controller-manager",
    "kube-proxy",
    "kube-scheduler",
    "kubectl",
    "kubelet",
    "metrics",
    "mount-utils",
    "pod-security-admission",
    "streaming",
)
ALL_MODULES = (*DEPENDENCIES, "cri-api", "cri-client")
DATA = Path(__file__).with_name("image_kubernetes_aliases_registry.json")


def raw_hash(packages):
    return digest(
        canonical(
            sorted([p["type"], p["name"], p["version"], p["foundBy"], p["paths"]] for p in packages)
        )
    )


def controlled_observation():
    packages = [
        {
            "type": "go-module",
            "name": "k8s.io/" + name,
            "version": "UNKNOWN",
            "foundBy": "go-module-binary-cataloger",
            "paths": [BINARY],
        }
        for name in DEPENDENCIES
    ]
    for name, version, path in (
        ("k8s.io/apimachinery", "UNKNOWN", "/go-runner"),
        ("k8s.io/component-base", PSEUDO, "/go-runner"),
        ("k8s.io/kubernetes", "v1.36.4", BINARY),
        ("example.org/external", "v1.2.3", BINARY),
    ):
        packages.append(
            {
                "type": "go-module",
                "name": name,
                "version": version,
                "foundBy": "go-module-binary-cataloger",
                "paths": [path],
            }
        )
    packages.append(
        {
            "type": "deb",
            "name": "base-files",
            "version": "12.4+deb12u14",
            "foundBy": "dpkg-db-cataloger",
            "paths": ["/usr/share/doc/base-files/copyright", "/var/lib/dpkg/status.d/base-files"],
        }
    )
    return {
        "image_id": CONFIG,
        "distro": {"id": "debian", "versionID": "12.14"},
        "packages": packages,
        "package_count": len(packages),
        "package_types": dict(Counter(p["type"] for p in packages)),
        "status": "inconclusive",
        "scope": "package-observation-not-application-coverage",
    }


@contextmanager
def controlled_registry(api):
    """Keep real diagnose, but bind a small explicitly synthetic package inventory."""
    observation = controlled_observation()
    spec = copy.deepcopy(inventory.INVENTORIES[CONFIG])
    spec["package_count"] = len(observation["packages"])
    spec["scanner_rows_sha256"] = digest(
        canonical(
            sorted(
                [
                    p["type"],
                    p["name"],
                    p["version"],
                    p["paths"][0]
                    if p["type"] == "go-module"
                    else "/var/lib/dpkg/status.d/" + p["name"],
                ]
                for p in observation["packages"]
            )
        )
    )
    registry = json.loads(DATA.read_bytes())
    registry["images"][CONFIG]["scanner_rows_sha256"] = spec["scanner_rows_sha256"]
    registry["images"][CONFIG]["full_rows_sha256"] = raw_hash(observation["packages"])
    with (
        patch.dict(inventory.INVENTORIES, {CONFIG: spec}),
        patch.object(api, "_registry", return_value=registry),
    ):
        yield observation, registry


class KubernetesAliasesTests(unittest.TestCase):
    def api(self):
        name = "scripts.image_kubernetes_aliases"
        self.assertIsNotNone(importlib.util.find_spec(name), "Task 1 registry not implemented")
        return importlib.import_module(name)

    def test_coordinates_are_complete_sorted_and_exclude_auxiliary_modules(self):
        api = self.api()
        expected = tuple(
            sorted(
                [("k8s.io/" + name, "v0.36.4") for name in ALL_MODULES]
                + [("k8s.io/kubernetes", "v1.36.4")]
            )
        )
        self.assertEqual(api.coordinates(), expected)
        for module, version in expected:
            self.assertEqual(
                api.validate_coordinate(module, version), f"pkg:golang/{module}@{version}"
            )
        self.assertEqual(api.proof_digest(), PROOF)

    def test_unreviewed_coordinates_cannot_reach_scanner(self):
        api = self.api()
        for module, version in (
            ("k8s.io/cli-runtime", "v0.36.4"),
            ("k8s.io/code-generator", "v0.36.4"),
            ("k8s.io/component-base", "v1.36.4"),
            ("k8s.io/kubernetes", "v0.36.4"),
            ("k8s.io/api", "v0.36.5"),
            ("k8s.io/api", PSEUDO),
            ("k8s.io/api", "UNKNOWN"),
            ("k8s.io/api", "(devel)"),
            ("k8s.io/api", "not-a-version"),
            ("k8s.io/api ", "v0.36.4"),
            ("K8S.io/api", "v0.36.4"),
            ("pkg:golang/k8s.io/api", "v0.36.4"),
            ("../api", "v0.36.4"),
            ("k8s.io/api", "v0.36.4\n"),
            (None, "v0.36.4"),
            ([], "v0.36.4"),
            ("k8s.io/api", []),
        ):
            with self.subTest(module=module, version=version), self.assertRaises(Rejected):
                api.validate_coordinate(module, version)

    def test_unknown_config_does_not_gain_mapping_from_neighbor_proof(self):
        api = self.api()
        for observation in (
            None,
            [],
            {},
            {"image_id": []},
            {"image_id": False},
            {"image_id": "sha256:" + "0" * 64, "proof_digest": PROOF},
        ):
            self.assertIsNone(api.resolve(observation, CONFIG))

    def test_exact_config_and_registry_manifest_bindings_remain_distinct(self):
        api = self.api()
        with controlled_registry(api) as (observation, _):
            before = copy.deepcopy(observation)
            for reference, binding in (
                (CONFIG, "config"),
                ("registry.k8s.io/kube-apiserver@" + MANIFEST, "manifest"),
                ("localhost:5000/mirror/kube-apiserver:v1.36.4@" + MANIFEST, "manifest"),
            ):
                result = api.resolve(observation, reference)
                self.assertEqual(result["reference_binding"], binding)
                self.assertEqual(result["image_config_id"], CONFIG)
                self.assertEqual(result["manifest_digest"], MANIFEST)
                self.assertEqual(result["proof_digest"], PROOF)
                self.assertEqual(result["schema_version"], 1)
                self.assertEqual(result["scope"], "kubernetes-supplemental-mapping")
                self.assertEqual(
                    result["source_revision"], "bb826b1d48562f110659e64e8ec444327433db95"
                )
                self.assertEqual(len(result["instances"]), 28)
                self.assertEqual(
                    result["coordinates"],
                    sorted(
                        [["k8s.io/" + n, "v0.36.4"] for n in DEPENDENCIES]
                        + [["k8s.io/kubernetes", "v1.36.4"]]
                    ),
                )
                runners = [i for i in result["instances"] if i["binary_path"] == "/go-runner"]
                self.assertEqual(
                    runners,
                    [
                        {
                            "module": "k8s.io/apimachinery",
                            "observed_version": "UNKNOWN",
                            "binary_path": "/go-runner",
                            "version": "v0.36.4",
                        },
                        {
                            "module": "k8s.io/component-base",
                            "observed_version": PSEUDO,
                            "binary_path": "/go-runner",
                            "version": "v0.36.4",
                        },
                    ],
                )
                self.assertNotIn("sbom_validated", result)
                self.assertNotIn("coverage_profile", result)
                self.assertEqual(
                    result["scanner_rows_sha256"],
                    inventory.INVENTORIES[CONFIG]["scanner_rows_sha256"],
                )
            self.assertEqual(observation, before)

    def test_wrong_or_malformed_reference_fails_known_image(self):
        api = self.api()
        with controlled_registry(api) as (observation, _):
            for reference in (
                None,
                [],
                False,
                "",
                MANIFEST,
                "sha256:" + "0" * 64,
                "registry.k8s.io/kube-apiserver:v1.36.4",
                "registry.k8s.io/kube-apiserver@sha256:" + "0" * 64,
                "registry.k8s.io/kube-apiserver@" + MANIFEST + "\n",
                "https://registry.k8s.io/kube-apiserver@" + MANIFEST,
                "/kube-apiserver@" + MANIFEST,
                "a//b@" + MANIFEST,
                "evil@@kube-apiserver@" + MANIFEST,
                "a/../b@" + MANIFEST,
                "registry.k8s.io/kube apiserver@" + MANIFEST,
                "registry.k8s.io/" + "x" * 600 + "@" + MANIFEST,
            ):
                with self.subTest(reference=reference), self.assertRaises(Rejected):
                    api.resolve(observation, reference)

    def test_changed_complete_inventory_cannot_be_repaired_by_caller_proof(self):
        api = self.api()
        changes = (
            lambda o: o["packages"].pop(),
            lambda o: o["packages"].append(copy.deepcopy(o["packages"][0])),
            lambda o: o["packages"].append({**o["packages"][0], "name": "foreign"}),
            lambda o: o["packages"][0].update(name="k8s.io/foreign"),
            lambda o: o["packages"][0].update(version="v0.36.4"),
            lambda o: o["packages"][0].update(paths=["/go-runner"]),
            lambda o: o["packages"][0].update(paths=[]),
            lambda o: o["packages"][0].update(paths=[BINARY, BINARY]),
            lambda o: o["packages"][0].update(foundBy="file-cataloger"),
            lambda o: o["packages"][0].update(type="deb"),
            lambda o: o["packages"][-1]["paths"].append("/foreign"),
            lambda o: o["packages"][-1]["paths"].reverse(),
            lambda o: o["packages"][-1].update(foundBy="file-cataloger"),
            lambda o: o["packages"][-2].update(version="v9.9.9"),
            lambda o: o.update(distro={"id": "debian", "versionID": "13"}),
            lambda o: o.update(package_count=0),
            lambda o: o.update(package_count=True),
            lambda o: o.update(package_types={"go-module": 30}),
            lambda o: o.update(
                image_id="sha256:c27613cea70f9808cc25955886c764ad38de589a9faeb2a8341cb27af6714684"
            ),
        )
        with controlled_registry(api) as (observation, _):
            for change in changes:
                changed = copy.deepcopy(observation)
                change(changed)
                changed.update(proof_digest=PROOF, equal=True, independent_inventory_verified=True)
                with self.subTest(change=change), self.assertRaises(Rejected):
                    api.resolve(changed, CONFIG)

    def test_root_runner_and_observed_versions_are_not_interchangeable(self):
        api = self.api()
        with controlled_registry(api) as (observation, _):
            for selector, replacement in (
                (
                    lambda p: p["name"] == "k8s.io/component-base" and p["paths"] == ["/go-runner"],
                    {"name": "k8s.io/kubernetes", "version": "v1.36.4"},
                ),
                (
                    lambda p: p["name"] == "k8s.io/kubernetes",
                    {"name": "k8s.io/component-base", "version": PSEUDO},
                ),
                (lambda p: p["name"] == "k8s.io/kubernetes", {"paths": ["/go-runner"]}),
                (lambda p: p["version"] == PSEUDO, {"version": "(devel)"}),
            ):
                changed = copy.deepcopy(observation)
                next(p for p in changed["packages"] if selector(p)).update(replacement)
                with self.assertRaises(Rejected):
                    api.resolve(changed, CONFIG)

    def test_malformed_known_observation_fails_closed(self):
        api = self.api()
        changes = (
            lambda o: o.pop("packages"),
            lambda o: o.update(packages=None),
            lambda o: o.update(packages={}),
            lambda o: o["packages"].append(None),
            lambda o: o["packages"][0].pop("name"),
            lambda o: o["packages"][0].update(name=[]),
            lambda o: o["packages"][0].update(version=1),
            lambda o: o["packages"][0].update(paths=BINARY),
            lambda o: o["packages"][0].update(paths=(BINARY,)),
            lambda o: o["packages"][0].update(paths=[None]),
            lambda o: o["packages"][0].update(extra="private-canary"),
            lambda o: o.pop("package_count"),
            lambda o: o.pop("package_types"),
        )
        with controlled_registry(api) as (observation, _):
            for change in changes:
                changed = copy.deepcopy(observation)
                change(changed)
                with self.subTest(change=change), self.assertRaises(Rejected):
                    api.resolve(changed, CONFIG)

    def test_real_diagnose_is_required_even_if_full_rows_digest_matches(self):
        api = self.api()
        with controlled_registry(api) as (observation, registry):
            observation["packages"][0]["version"] = "v0.36.4"
            registry["images"][CONFIG]["full_rows_sha256"] = raw_hash(observation["packages"])
            with self.assertRaises(Rejected):
                api.resolve(observation, CONFIG)

    def test_package_order_is_irrelevant_but_multiplicity_and_paths_are_exact(self):
        api = self.api()
        with controlled_registry(api) as (observation, _):
            first = api.resolve(observation, CONFIG)
            observation["packages"].reverse()
            self.assertEqual(api.resolve(observation, CONFIG), first)
            first["instances"][0]["version"] = "malicious"
            first["coordinates"].clear()
            self.assertEqual(api.resolve(observation, CONFIG)["instances"][0]["version"], "v0.36.4")
            self.assertEqual(len(api.resolve(observation, CONFIG)["coordinates"]), 26)

    def test_any_registry_proof_or_mapping_substitution_is_rejected_by_all_apis(self):
        api = self.api()
        original = json.loads(DATA.read_bytes())
        changes = (
            lambda r: r.update(workspace_matrix_sha256="0" * 64),
            lambda r: r.update(source_revision="0" * 40),
            lambda r: r["coordinates"].pop(),
            lambda r: r["coordinates"].append(r["coordinates"][0]),
            lambda r: r["coordinates"].append(["k8s.io/cli-runtime", "v0.36.4"]),
            lambda r: r["modules"][0].update(published_commit="0" * 40),
            lambda r: r["modules"][0].update(tag_object="0" * 40),
            lambda r: r["modules"][0].update(inventory_sha256="0" * 64),
            lambda r: r["modules"][0].update(archive_sha256="0" * 64),
            lambda r: r["known_root"].update(version="v1.36.5"),
            lambda r: r["materials"].update(root_proxy_info_sha256="0" * 64),
            lambda r: r["fixed_path_deltas"][0].update(sha256="0" * 64),
            lambda r: r["fixed_path_deltas"][0].update(path="foreign"),
            lambda r: r["fixed_path_deltas"][0].update(mode="100755"),
            lambda r: r["fixed_path_deltas"].append(copy.deepcopy(r["fixed_path_deltas"][0])),
            lambda r: r["images"][CONFIG]["instances"].pop(),
            lambda r: r["images"][CONFIG]["instances"].append(
                copy.deepcopy(r["images"][CONFIG]["instances"][0])
            ),
            lambda r: r["images"][CONFIG]["instances"][0].update(module="k8s.io/kubernetes"),
            lambda r: r["materials"].update(source_spdx_sha256="0" * 64),
            lambda r: r["recipes"].update(parent_verify_sha256="0" * 64),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            with patch.object(api, "_REGISTRY_PATH", path):
                for change in changes:
                    altered = copy.deepcopy(original)
                    change(altered)
                    path.write_bytes(canonical(altered))
                    for operation in (
                        api.coordinates,
                        api.proof_digest,
                        lambda: api.validate_coordinate("k8s.io/api", "v0.36.4"),
                        lambda: api.resolve(controlled_observation(), CONFIG),
                    ):
                        with (
                            self.subTest(change=change, operation=operation),
                            self.assertRaises(Rejected),
                        ):
                            operation()
                path.write_bytes(b"x" * (128 * 1024 + 1))
                with self.assertRaises(Rejected):
                    api.proof_digest()

    def test_unavailable_registry_never_returns_last_cached_proof(self):
        api = self.api()
        self.assertEqual(api.proof_digest(), PROOF)
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(api, "_REGISTRY_PATH", Path(directory) / "missing.json"),
            self.assertRaises(Rejected),
        ):
            api.proof_digest()

    def test_batch_proof_binds_complete_registry_including_known_root_materials(self):
        api = self.api()
        self.assertEqual(api.proof_digest(), digest(DATA.read_bytes()))

    def test_new_independent_inventory_does_not_implicitly_extend_fixed_registry(self):
        api = self.api()
        unknown = "sha256:" + "1" * 64
        with patch.dict(inventory.INVENTORIES, {unknown: inventory.INVENTORIES[CONFIG]}):
            self.assertIsNone(api.resolve({"image_id": unknown}, unknown))

    def test_instance_binding_check_rejects_inconsistent_trusted_fixture(self):
        api = self.api()
        for change in (
            lambda rows: rows.pop(),
            lambda rows: rows.append(copy.deepcopy(rows[0])),
            lambda rows: rows[0].update(module="k8s.io/foreign"),
            lambda rows: rows[0].update(binary_path="/foreign"),
            lambda rows: rows[0].update(observed_version="v0.36.4"),
        ):
            with controlled_registry(api) as (observation, registry):
                change(registry["images"][CONFIG]["instances"])
                with self.assertRaises(Rejected):
                    api.resolve(observation, CONFIG)


if __name__ == "__main__":
    unittest.main()
