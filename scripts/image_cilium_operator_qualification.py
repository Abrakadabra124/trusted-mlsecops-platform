"""Offline qualification against package inputs transcribed from the two pinned ELF files."""

import copy
import unittest

from mlsecops.contracts import Rejected
from scripts import image_cilium_operator_inventory as registry
from scripts.image_audit_contract import SYFT_VERSION, observe_packages
from scripts.image_cilium_operator_fixture import BUILDINFO_BY_PATH

GOPS = "github.com/google/gops"
OPERATOR = "/usr/bin/cilium-operator-generic"
BINARY = "/usr/bin/gops"
INDEX = "c6e7de6665aa9701db86c4fe46828a75a0d167afe084a9ffb5bce34b2c4fa8c4"
REFERENCE = "quay.io/cilium/operator-generic@sha256:" + INDEX
CONFIG = "sha256:56a7372da23608057bd206438f0655e1e6e7d8df9934cffe78be4ff9954afea5"
BINARY_SHA256 = "80cf2af7f90f1b5f6b515021fea1188a109200febae33b8ebe4b006347a95e3a"


def observation():
    artifacts = []
    for path, modules in BUILDINFO_BY_PATH.items():
        for name, version in modules.items():
            artifacts.append(
                {
                    "id": str(len(artifacts)),
                    "type": "go-module",
                    "name": name,
                    "version": "UNKNOWN" if version == "(devel)" else version,
                    "foundBy": "go-module-binary-cataloger",
                    "locations": [{"path": path}],
                }
            )
    return observe_packages(
        {
            "descriptor": {"name": "syft", "version": SYFT_VERSION},
            "source": {"type": "image", "metadata": {"imageID": CONFIG}},
            "artifacts": artifacts,
            "distro": {},
        },
        CONFIG,
    )


class OperatorRegistryTests(unittest.TestCase):
    def setUp(self):
        self.observed = observation()

    def test_only_the_exact_image_and_coordinate_are_registered(self):
        self.assertEqual(
            (registry.PROFILE, registry.REFERENCE, registry.CONFIG),
            ("cilium-operator-supplemental", REFERENCE, CONFIG),
        )
        self.assertEqual(registry.coordinates(), ((GOPS, "v0.3.29"),))
        self.assertEqual(
            registry.validate_coordinate(GOPS, "v0.3.29"),
            "pkg:golang/github.com/google/gops@v0.3.29",
        )
        for module, version in (
            (GOPS, "v0.3.28"),
            (GOPS, "UNKNOWN"),
            (GOPS, "(devel)"),
            (GOPS, "v0.3.29 "),
            (GOPS.upper(), "v0.3.29"),
            ([], None),
        ):
            with self.subTest(module=module, version=version), self.assertRaises(Rejected):
                registry.validate_coordinate(module, version)

    def test_registry_pins_bind_the_reviewed_rebuild_receipt(self):
        self.assertEqual(
            registry.proof_digest(),
            "3b83b668fe444f8595dcace1fedf2d24f322b09dfcb061dc2329e494b303cc9f",
        )
        mapping = registry.resolve(self.observed, REFERENCE)
        self.assertEqual(mapping["rebuild_run_id"], "44953814982")
        self.assertEqual(mapping["source_revision"], "a2d8f7790eac63a6668583a060cb45903410a91b")

    def test_known_config_refuses_every_other_reference(self):
        for reference in (
            None,
            CONFIG,
            REFERENCE.upper(),
            REFERENCE + " ",
            REFERENCE.replace("quay.io", "example.org"),
            REFERENCE.replace("@", ":v1.20.5@"),
            REFERENCE.split("@")[0] + ":v1.20.5",
            REFERENCE.replace(
                INDEX, "3362404f43b6a01cf6e370fb637dac427b7b0259ff2629faa9e5b665121a3a76"
            ),
        ):
            with self.subTest(reference=reference), self.assertRaises(Rejected):
                registry.resolve(self.observed, reference)

    def test_only_an_unknown_config_falls_through(self):
        self.assertIsNone(registry.resolve({"image_id": "sha256:" + "0" * 64}, REFERENCE))
        for malformed in (None, {}, {"image_id": None}, {"image_id": "wrong"}):
            with self.subTest(malformed=malformed), self.assertRaises(Rejected):
                registry.resolve(malformed, REFERENCE)

    def test_only_normalized_unknown_distro_is_accepted(self):
        for distro in (None, {"id": None, "versionID": None}, {"id": "", "versionID": ""}):
            with self.subTest(distro=distro):
                self.assertIsNotNone(
                    registry.resolve({**self.observed, "distro": distro}, REFERENCE)
                )
        for distro in (
            {},
            "scratch",
            {"id": "scratch", "versionID": None},
            {"id": None, "versionID": "1.20.5"},
            {"id": False, "versionID": None},
        ):
            with self.subTest(distro=distro), self.assertRaises(Rejected):
                registry.resolve({**self.observed, "distro": distro}, REFERENCE)

    def test_known_config_rejects_inconsistent_normalized_envelope(self):
        for field in self.observed.keys() - {"image_id"}:
            bad = self.observed.copy()
            del bad[field]
            with self.subTest(missing=field), self.assertRaises(Rejected):
                registry.resolve(bad, REFERENCE)
        for change in (
            {"status": "pass"},
            {"scope": registry.PROFILE},
            {"package_count": 175.0},
            {"package_count": 174},
            {"package_types": {"go-module": 175.0}},
            {"package_types": {"go-module": 174, "deb": 1}},
            {"packages": None},
        ):
            with self.subTest(change=change), self.assertRaises(Rejected):
                registry.resolve({**self.observed, **change}, REFERENCE)

    def test_projection_requires_all_rows_with_multiplicity_and_provenance(self):
        first, *tail = self.observed["packages"]
        for packages in (tail, [first, first, *tail], [tail[0], *tail], [None, *tail]):
            bad = {
                **self.observed,
                "packages": packages,
                "package_count": len(packages),
                "package_types": {"go-module": len(packages)},
            }
            with self.subTest(count=len(packages)), self.assertRaises(Rejected):
                registry.resolve(bad, REFERENCE)
        for change in (
            {"paths": [BINARY]},
            {"paths": []},
            {"paths": [OPERATOR, BINARY]},
            {"paths": OPERATOR},
            {"foundBy": "go-module-file-cataloger"},
            {"type": "deb"},
            {"name": "other"},
            {"version": "v0.0.0"},
            {"name": []},
            {"extra": "x"},
        ):
            packages = [{**first, **change}, *tail]
            with self.subTest(change=change), self.assertRaises(Rejected):
                registry.resolve({**self.observed, "packages": packages}, REFERENCE)

    def test_rejects_cross_binary_version_transfer_and_additional_unknown(self):
        for path, name, version in (
            (BINARY, GOPS, "v0.3.28"),
            (BINARY, GOPS, "v0.3.29"),
            (BINARY, GOPS, "(devel)"),
            (OPERATOR, GOPS, "UNKNOWN"),
            (OPERATOR, GOPS, "v0.3.29"),
            (BINARY, "stdlib", "UNKNOWN"),
        ):
            bad = copy.deepcopy(self.observed)
            (row,) = [p for p in bad["packages"] if p["paths"] == [path] and p["name"] == name]
            row["version"] = version
            with self.subTest(path=path, name=name, version=version), self.assertRaises(Rejected):
                registry.resolve(bad, REFERENCE)

    def test_full_inventory_resolves_one_instance_without_changing_observation(self):
        before = copy.deepcopy(self.observed)
        self.assertEqual(self.observed["package_types"], {"go-module": 175})
        packages = self.observed["packages"]
        self.assertEqual(sum(p["paths"] == [OPERATOR] for p in packages), 166)
        self.assertEqual(sum(p["paths"] == [BINARY] for p in packages), 9)
        self.assertEqual(
            [(p["name"], p["paths"]) for p in packages if p["version"] == "UNKNOWN"],
            [(GOPS, [BINARY])],
        )
        self.assertIn(
            (GOPS, "v0.3.28", [OPERATOR]), [(p["name"], p["version"], p["paths"]) for p in packages]
        )
        result = registry.resolve(self.observed, REFERENCE)
        self.assertEqual(self.observed, before)
        self.assertEqual(result["image_config_id"], CONFIG)
        self.assertEqual(result["coordinates"], [[GOPS, "v0.3.29"]])
        self.assertEqual(
            result["full_rows_sha256"],
            "3b10dcf9cf77fe216e497fb54aa1917a37acf8af48564d2dba7e277a21b6be94",
        )
        (instance,) = result["instances"]
        self.assertEqual(
            [
                instance[k]
                for k in ("binary_path", "module", "observed_version", "version", "binary_sha256")
            ],
            [BINARY, GOPS, "UNKNOWN", "v0.3.29", BINARY_SHA256],
        )
        self.assertEqual(result["proof_digest"], registry.proof_digest())
        self.assertFalse(
            {"status", "decision", "coverage_profile", "sbom_validated", "release_ready"}
            & result.keys()
        )
        self.assertEqual(
            result, registry.resolve({**self.observed, "packages": packages[::-1]}, REFERENCE)
        )
        result["coordinates"][0][1] = "wrong"
        self.assertEqual(
            registry.resolve(self.observed, REFERENCE)["coordinates"], [[GOPS, "v0.3.29"]]
        )


if __name__ == "__main__":
    unittest.main()
