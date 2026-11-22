"""Offline qualification using the independent OCI inventory and the native observation digest."""

import copy
import unittest
from collections import Counter
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import image_etcd_inventory as registry
from scripts.image_audit_contract import observe_packages
from scripts.image_etcd_inventory_fixture import observation, sbom

MANIFEST = "sha256:3ced7fbdc4cadcec31ab34a7513bc97be2b70db923e7154e2d88a980016b5e8b"
REFERENCE = "registry.k8s.io/etcd@" + MANIFEST
CONFIG = "sha256:be2dd319600bac16f542b8e46e1b78511c35a31e46829ee9acc82a83c94aa377"
VERSION = "v3.6.17"
PREFIX = "go.etcd.io/etcd/"
BIN = "/usr/local/bin/"
REPLACED = ("api/v3", "client/pkg/v3", "client/v3", "pkg/v3", "server/v3")


class EtcdRegistryTests(unittest.TestCase):
    def setUp(self):
        self.observed = observation()

    def test_config_and_reference_binding(self):
        self.assertEqual(
            (registry.PROFILE, registry.CONFIG, registry.REFERENCE),
            ("etcd-supplemental", CONFIG, REFERENCE),
        )
        self.assertIsNone(registry.resolve({"image_id": "sha256:" + "1" * 64}, REFERENCE))
        for bad in (None, [], {}, {"image_id": None}, {"image_id": CONFIG.upper()}):
            with self.subTest(bad=bad), self.assertRaises(Rejected):
                registry.resolve(bad, REFERENCE)
        for ref in (
            None,
            CONFIG,
            "registry.k8s.io/etcd:3.6.17-0",
            REFERENCE.replace("registry.k8s.io", "example.com"),
            REFERENCE.replace("@", ":3.6.17-0@"),
            REFERENCE + " ",
            "registry.k8s.io/etcd@sha256:"
            "f84fa13db51b1458a5a51d7eb3fa303c179dd28f5d337935418a5bae4a305e5f",
        ):
            with self.subTest(ref=ref), self.assertRaises(Rejected):
                registry.resolve(self.observed, ref)

    def test_only_proven_replacements_are_supplemental_coordinates(self):
        self.assertEqual(registry.coordinates(), tuple((PREFIX + m, VERSION) for m in REPLACED))
        for module, version in registry.coordinates():
            self.assertEqual(
                registry.validate_coordinate(module, version), f"pkg:golang/{module}@{version}"
            )
        for module, version in (
            (PREFIX + "etcdctl/v3", VERSION),
            (PREFIX + "etcdutl/v3", VERSION),
            ("../api", VERSION),
            ("go.etcd.io/raft/v3", VERSION),
            (PREFIX + "api/v3", "UNKNOWN"),
            (PREFIX + "api/v3", "(devel)"),
            (PREFIX + "api/v3", "v3.6.16"),
            ([], VERSION),
            (PREFIX + "api/v3", None),
        ):
            with self.subTest(module=module, version=version), self.assertRaises(Rejected):
                registry.validate_coordinate(module, version)

    def test_missing_source_or_changed_proof_refuses_every_mapping_entry_point(self):
        self.assertEqual(
            registry.proof_digest(),
            "464fc8a3327a90fbe8a2985f5f461bdf5c4621d4a80839ed6a211a2b58088bf3",
        )
        client = PREFIX + "client/v3"
        release = registry._RELEASES[client]
        binary = registry._BINARIES[BIN + "etcdutl"]
        for change in (
            patch.dict(registry._RELEASES, {}, clear=True),
            patch.dict(registry._RELEASES, {client: release._replace(source_dir="client")}),
            patch.dict(registry._RELEASES, {client: release._replace(zip_sha256="0" * 64)}),
            patch.dict(registry._BINARIES, {BIN + "etcdutl": binary._replace(replaces=())}),
            patch.dict(registry._BINARIES, {BIN + "etcdutl": binary._replace(main=client)}),
        ):
            with change:
                for function, args in (
                    (registry.proof_digest, ()),
                    (registry.coordinates, ()),
                    (registry.validate_coordinate, (client, VERSION)),
                    (registry.resolve, (self.observed, REFERENCE)),
                ):
                    with (
                        self.subTest(api=function.__name__),
                        self.assertRaisesRegex(Rejected, "^image_audit_etcd_proof_mismatch$"),
                    ):
                        function(*args)

    def test_exact_observation_envelope(self):
        for key in self.observed:
            with self.subTest(missing=key), self.assertRaises(Rejected):
                registry.resolve({k: v for k, v in self.observed.items() if k != key}, REFERENCE)
        for delta in (
            {"status": "pass"},
            {"scope": registry.PROFILE},
            {"extra": True},
            {"distro": {"id": "debian", "versionID": "13"}},
            {"package_count": 154.0},
            {"package_count": 153},
            {"package_types": {"deb": 6.0, "go-module": 148}},
            {"package_types": {"go-module": 154}},
            {"package_types": []},
            {"packages": None},
            {"packages": self.observed["packages"][:-1]},
        ):
            with self.subTest(delta=list(delta)), self.assertRaises(Rejected):
                registry.resolve({**self.observed, **delta}, REFERENCE)

    def test_provenance_paths_and_multiplicity(self):
        rows = self.observed["packages"]
        for original, changes in (
            (
                next(p for p in rows if p["type"] == "deb"),
                (
                    {"paths": ["/var/lib/dpkg/status"]},
                    {"paths": None},
                    {"paths": ["", [], ""]},
                    {"foundBy": "go-module-binary-cataloger"},
                    {"version": []},
                    {"version": "0.0"},
                    {"extra": False},
                ),
            ),
            (
                next(p for p in rows if p["version"] == "UNKNOWN"),
                (
                    {"version": VERSION},
                    {"version": "(devel)"},
                    {"name": "../api"},
                ),
            ),
            (
                next(
                    p for p in rows if p["name"] == PREFIX + "server/v3" and p["version"] == VERSION
                ),
                (
                    {"paths": [BIN + "etcdutl"]},
                    {"version": "UNKNOWN"},
                ),
            ),
            (next(p for p in rows if p["name"] == "stdlib"), ({"version": "go1.26.10"},)),
            (next(p for p in rows if p["name"] == "golang.org/x/net"), ({"version": "v0.61.0"},)),
        ):
            for change in changes:
                bad = rows.copy()
                bad[rows.index(original)] = {**original, **change}
                with (
                    self.subTest(name=original["name"], change=change),
                    self.assertRaises(Rejected),
                ):
                    registry.resolve({**self.observed, "packages": bad}, REFERENCE)
        for substitute in (None, rows[1]):
            with self.subTest(substitute=substitute), self.assertRaises(Rejected):
                registry.resolve({**self.observed, "packages": [substitute, *rows[1:]]}, REFERENCE)

    def test_raw_sbom_retains_artifact_ids_and_is_fresh_per_call(self):
        raw = sbom()
        self.assertEqual(len({a["id"] for a in raw["artifacts"]}), 154)
        self.assertEqual(observe_packages(raw, CONFIG), self.observed)
        raw["artifacts"][0]["locations"][0]["path"] = "/changed"
        self.assertNotEqual(observe_packages(raw, CONFIG), self.observed)
        self.assertEqual(observe_packages(sbom(), CONFIG), self.observed)

    def test_independent_observation_matches_native_run(self):
        # Canonical COMPLETE observation from run 44954907094, step 10, runtime-008.
        self.assertEqual(
            digest(canonical(self.observed)),
            "a1239553042f660e59a23ad426aeacfa8eb5c3c7cd1da2284940a43e0fedc355",
        )
        self.assertEqual(self.observed["package_types"], {"deb": 6, "go-module": 148})
        self.assertEqual(
            Counter(p["paths"][0] for p in self.observed["packages"] if p["type"] == "go-module"),
            {BIN + "etcd": 64, BIN + "etcdctl": 33, BIN + "etcdutl": 51},
        )

    def test_resolves_every_path_preserving_the_original_observation(self):
        before = copy.deepcopy(self.observed)
        result = registry.resolve(self.observed, REFERENCE)
        self.assertEqual(
            result["full_rows_sha256"],
            "96cf1a57ab93e0093a29998a24f67918edf6043226896bc00baba1bad60f7a00",
        )
        self.assertEqual(result["source_revision"], "0689586e360e2c6b46f95ad5634c25d5fa1683db")
        self.assertEqual(result["coordinates"], [list(pair) for pair in registry.coordinates()])
        self.assertEqual(result["proof_digest"], registry.proof_digest())
        unknown = [
            (p["paths"][0], p["name"]) for p in before["packages"] if p["version"] == "UNKNOWN"
        ]
        self.assertCountEqual(
            [(i["binary_path"], i["module"]) for i in result["instances"]], unknown
        )
        self.assertEqual(len(unknown), 13)
        targets = dict(
            zip(
                REPLACED,
                ("../api", "../client/pkg", "../client/v3", "../pkg", "../server"),
                strict=True,
            )
        )
        for i in result["instances"]:
            self.assertEqual(i["replace_path"], targets[i["module"].removeprefix(PREFIX)])
            self.assertEqual((i["observed_version"], i["version"]), ("UNKNOWN", VERSION))
        self.assertCountEqual(
            [
                (m["binary_path"], m["module"], m["observed_version"])
                for m in result["main_modules"]
            ],
            [
                (BIN + b, PREFIX + m + "/v3", VERSION)
                for b, m in (("etcd", "server"), ("etcdctl", "etcdctl"), ("etcdutl", "etcdutl"))
            ],
        )
        self.assertFalse(
            {"status", "decision", "findings", "sbom_validated", "release_ready"} & result.keys()
        )
        self.assertEqual(self.observed, before)
        self.assertEqual(
            result, registry.resolve({**before, "packages": before["packages"][::-1]}, REFERENCE)
        )
        result["instances"].clear()
        self.assertEqual(len(registry.resolve(before, REFERENCE)["instances"]), 13)


if __name__ == "__main__":
    unittest.main()
