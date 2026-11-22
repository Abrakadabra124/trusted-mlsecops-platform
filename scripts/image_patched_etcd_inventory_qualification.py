"""Offline tests. A controlled GHCR identity exercises the future join without authorizing one."""

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import image_patched_etcd_inventory as registry
from scripts.image_audit_contract import observe_packages
from scripts.image_etcd_inventory_fixture import sbom as upstream_sbom

TEST_CONFIG = "sha256:" + "1" * 64
TEST_MANIFEST = "sha256:" + "2" * 64
TEST_REFERENCE = "ghcr.io/example/etcd@" + TEST_MANIFEST
PREFIX = "go.etcd.io/etcd/"
VERSION = "v3.6.17"


def sbom(config):
    # All eleven differences from the pristine fixture were checked independently
    # against BOTH buildinfo transcripts. Never use this fixture as registry proof.
    value = upstream_sbom()
    value["source"]["metadata"]["imageID"] = config
    for p in value["artifacts"]:
        if (
            p["name"] in {PREFIX + d + "/v3" for d in ("server", "etcdctl", "etcdutl")}
            and p["version"] == VERSION
        ):
            p["version"] = VERSION + "+dirty"
        for name, version in (("crypto", "v0.59.0"), ("sys", "v0.50.0"), ("text", "v0.44.0")):
            if p["name"] == "golang.org/x/" + name:
                p["version"] = version
    return value


class PatchedEtcdTests(unittest.TestCase):
    def test_reviewed_recipe_and_independent_static_proof(self):
        root = Path(__file__).resolve().parents[1]
        recipe = (root / "images/candidates/etcd/Dockerfile").read_bytes().replace(b"\r\n", b"\n")
        self.assertEqual(digest(recipe), registry._RECIPE_SHA256)
        self.assertEqual(
            digest(canonical(registry._static_materials())), registry._STATIC_PROOF_SHA256
        )

    def published(self):
        self.enterContext(
            patch.multiple(
                registry, REFERENCE=TEST_REFERENCE, CONFIG=TEST_CONFIG, _MANIFEST=TEST_MANIFEST
            )
        )
        return observe_packages(sbom(TEST_CONFIG), TEST_CONFIG)

    def test_pending_publication_cannot_authorize_any_entry_point(self):
        with patch.multiple(registry, REFERENCE=None, CONFIG=None, _MANIFEST=None):
            for fn, args in (
                (registry.proof_digest, ()),
                (registry.coordinates, ()),
                (registry.validate_coordinate, (PREFIX + "api/v3", VERSION)),
                (
                    registry.resolve,
                    (observe_packages(sbom(TEST_CONFIG), TEST_CONFIG), TEST_REFERENCE),
                ),
            ):
                with self.subTest(fn=fn.__name__), self.assertRaisesRegex(Rejected, "publication"):
                    fn(*args)

    def test_exact_projection_and_coordinates(self):
        o = self.published()
        before = copy.deepcopy(o)
        mapping = registry.resolve(o, TEST_REFERENCE)
        self.assertEqual(o, before)
        self.assertEqual(mapping["image_config_id"], TEST_CONFIG)
        self.assertEqual(
            mapping["full_rows_sha256"],
            "3009716cb46e683a5826568ade37aa6760ffe4ded64c7066b7d6a5e1154c1c62",
        )
        self.assertEqual(mapping["proof_digest"], registry.proof_digest())
        self.assertEqual(
            (o["package_count"], o["package_types"]), (154, {"go-module": 148, "deb": 6})
        )
        expected = tuple(
            sorted(
                (PREFIX + x, VERSION)
                for x in (
                    "api/v3",
                    "client/pkg/v3",
                    "client/v3",
                    "etcdctl/v3",
                    "etcdutl/v3",
                    "pkg/v3",
                    "server/v3",
                )
            )
        )
        self.assertEqual(registry.coordinates(), expected)
        self.assertEqual(mapping["coordinates"], [list(pair) for pair in expected])
        for module, version in expected:
            self.assertEqual(
                registry.validate_coordinate(module, version), f"pkg:golang/{module}@{version}"
            )
        for group, observed, count in (
            ("instances", "UNKNOWN", 13),
            ("main_modules", VERSION + "+dirty", 3),
        ):
            values = mapping[group]
            self.assertEqual(len(values), count)
            self.assertEqual({item["observed_version"] for item in values}, {observed})
            for item in values:
                self.assertIn((item["module"], item["version"]), expected)
                (row,) = [
                    p
                    for p in o["packages"]
                    if p["paths"] == [item["binary_path"]] and p["name"] == item["module"]
                ]
                self.assertEqual(row["version"], observed)
        self.assertFalse(
            {"coverage_profile", "sbom_validated", "decision", "status"} & mapping.keys()
        )

    def test_pristine_and_foreign_not_interchangeable(self):
        o = self.published()
        self.assertIsNone(registry.resolve({**o, "image_id": "sha256:" + "9" * 64}, TEST_REFERENCE))
        for ref in (
            None,
            TEST_CONFIG,
            TEST_REFERENCE.replace("example", "another"),
            TEST_REFERENCE + ":tag",
        ):
            with self.subTest(ref=ref), self.assertRaises(Rejected):
                registry.resolve(o, ref)
        upstream = upstream_sbom()
        upstream["source"]["metadata"]["imageID"] = TEST_CONFIG
        with self.assertRaises(Rejected):
            registry.resolve(observe_packages(upstream, TEST_CONFIG), TEST_REFERENCE)
        for args in (
            (PREFIX + "server/v3", VERSION + "+dirty"),
            ("golang.org/x/crypto", "v0.59.0"),
            (PREFIX + "api/v3", "(devel)"),
            ([], VERSION),
        ):
            with self.subTest(args=args), self.assertRaises(Rejected):
                registry.validate_coordinate(*args)

    def test_every_row_and_location_is_bound(self):
        o = self.published()
        for i, original in enumerate(o["packages"]):
            for field, value in (
                ("version", "changed"),
                ("paths", original["paths"] + ["/usr/share/licenses/LICENSE"]),
                ("foundBy", "different"),
            ):
                packages = o["packages"].copy()
                packages[i] = {**original, field: value}
                with self.subTest(i=i, field=field), self.assertRaises(Rejected):
                    registry.resolve({**o, "packages": packages}, TEST_REFERENCE)
        packages = o["packages"].copy()
        packages[0] = packages[1]
        with self.assertRaises(Rejected):
            registry.resolve({**o, "packages": packages}, TEST_REFERENCE)

    def test_envelope_binding_and_fixed_source_proof(self):
        o = self.published()
        for change in (
            {"package_count": 154.0},
            {"package_types": {"go-module": 148, "deb": 6.0}},
            {"distro": {"id": "debian", "versionID": "13"}},
            {"scope": "etcd-supplemental"},
            {"status": "pass"},
            {"packages": o["packages"][:-1]},
            {"distro": None},
        ):
            with self.subTest(change=list(change)), self.assertRaises(Rejected):
                registry.resolve({**o, **change}, TEST_REFERENCE)
        with patch.object(registry, "_RECIPE_SHA256", "f" * 64):
            for fn, args in (
                (registry.proof_digest, ()),
                (registry.coordinates, ()),
                (registry.resolve, (o, TEST_REFERENCE)),
            ):
                with self.assertRaisesRegex(Rejected, "proof"):
                    fn(*args)


if __name__ == "__main__":
    unittest.main()
