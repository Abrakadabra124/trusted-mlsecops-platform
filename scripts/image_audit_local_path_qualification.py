"""Offline contracts for the published provisioner's normal runtime audit."""

import copy
import unittest
from unittest.mock import patch

from mlsecops import local_path_pin as pin
from mlsecops.contracts import canonical, digest
from scripts import image_audit_contract as contract
from scripts import image_scope
from scripts.image_audit_qualification import fixtures
from scripts.image_local_path_pair_qualification import observation

# Test-only registry manifest. The shared runtime pin comes from GHCR readback.
TEST_REFERENCE = pin.REPOSITORY + "@sha256:" + "1" * 64


def rebuilt_sbom():
    sbom = fixtures()[0]
    sbom["source"]["metadata"]["imageID"] = pin.PUBLISHED_CONFIG
    sbom["distro"] = {"id": "debian", "versionID": "13.6"}
    versions = {
        "github.com/klauspost/compress": "v1.20.2",
        "github.com/rancher/local-path-provisioner": "v0.0.37+dirty",
        "golang.org/x/net": "v0.62.0",
        "golang.org/x/sys": "v0.49.0",
        "golang.org/x/term": "v0.47.0",
        "golang.org/x/text": "v0.43.0",
        "stdlib": "go1.27.4",
    }
    rows = observation(True)["packages"] + [
        r for r in observation()["packages"] if r["type"] == "deb"
    ]
    artifacts = []
    for i, row in enumerate(rows):
        name = row["name"]
        paths = ["/usr/local/bin/local-path-provisioner"]
        if row["type"] == "deb":
            status = f"/var/lib/dpkg/status.d/{name}"
            paths = [status, status + ".md5sums", f"/usr/share/doc/{name}/copyright"]
        artifacts.append(
            {
                "id": str(i),
                "type": row["type"],
                "foundBy": row["foundBy"],
                "name": name,
                "version": versions.get(name, row["version"]),
                "locations": [{"path": path} for path in paths],
            }
        )
    sbom["artifacts"] = artifacts
    return sbom


class PublishedLocalPathTests(unittest.TestCase):
    def setUp(self):
        self.obs = contract.observe_packages(rebuilt_sbom(), pin.PUBLISHED_CONFIG)
        self.enterContext(patch.object(pin, "PUBLISHED_REFERENCE", TEST_REFERENCE))

    def test_native_rows_and_full_observation(self):
        rows = self.obs["packages"]
        self.assertEqual(
            digest(canonical(sorted(rows, key=canonical))),
            "89714093ff769e817e6c6d7a4c2f47a2bd335b2f8802c573adbe37f63298287b",
        )
        rows.reverse()
        self.assertTrue(contract.published_local_path_matches(self.obs, TEST_REFERENCE))
        for key, value in (
            ("package_count", 58),
            ("package_types", {"go-module": 59}),
            ("distro", {"id": "debian", "versionID": "13"}),
            ("image_id", contract.LOCAL_PATH_CONFIG),
            ("status", "pass"),
            ("packages", rows[:-1]),
            ("packages", rows + rows[:1]),
            ("packages", rows[:-1] + rows[:1]),
        ):
            with self.subTest(key=key):
                self.assertFalse(
                    contract.published_local_path_matches({**self.obs, key: value}, TEST_REFERENCE)
                )
        for kind in ("go-module", "deb"):
            for key, value in (
                ("paths", ["/elsewhere"]),
                ("foundBy", "other"),
                ("name", "other"),
                ("version", "other"),
            ):
                changed = copy.deepcopy(self.obs)
                next(p for p in changed["packages"] if p["type"] == kind)[key] = value
                with self.subTest(kind=kind, key=key):
                    self.assertFalse(contract.published_local_path_matches(changed, TEST_REFERENCE))

    def test_pin_disabled_and_foreign_bindings(self):
        for ref in (
            None,
            pin.PUBLISHED_CONFIG,
            pin.REPOSITORY + ":candidate",
            "docker.io/kindest/local-path-provisioner:v20260820-69b56db7",
            TEST_REFERENCE[:-1] + "2",
            "other.example/image@" + TEST_REFERENCE.split("@")[1],
        ):
            with self.subTest(ref=ref):
                self.assertFalse(contract.published_local_path_matches(self.obs, ref))
        with patch.object(pin, "PUBLISHED_REFERENCE", None):
            self.assertFalse(contract.published_local_path_matches(self.obs, TEST_REFERENCE))
            self.assertFalse(contract.published_local_path_matches(self.obs, None))
        for invalid in (
            pin.REPOSITORY + "@" + pin.PUBLISHED_CONFIG,
            pin.REPOSITORY + ":latest",
            pin.REPOSITORY + "@sha256:" + "0" * 64,
            "other.example/image@" + TEST_REFERENCE.split("@")[1],
        ):
            with self.subTest(invalid=invalid), patch.object(pin, "PUBLISHED_REFERENCE", invalid):
                self.assertFalse(contract.published_local_path_matches(self.obs, invalid))

    def test_reconciliation_cannot_relabel_or_cross_bind_the_candidate(self):
        target = {
            "name": "runtime-001",
            "reference": TEST_REFERENCE,
            "config_id": pin.PUBLISHED_CONFIG,
        }
        item = {
            "name": target["name"],
            "role": "system",
            "coverage_profile": "local-path-provisioner-published",
            "observed_reference": TEST_REFERENCE,
            "scan_executed": True,
            "sbom_validated": True,
            "package_binding_validated": True,
            "status": "pass",
            "catalogued_packages": 59,
            "diagnostic_only": False,
            "image_id": pin.PUBLISHED_CONFIG,
            "image_config_id": pin.PUBLISHED_CONFIG,
            "runtime_image_id": pin.PUBLISHED_CONFIG,
            "package_observation": self.obs,
            "packages": 59,
            "report_digest": "b" * 64,
            "sbom_digest": "c" * 64,
            "scanner_exit_code": 0,
            "database": {"built": "2026-11-22T12:00:00Z", "schema_version": "v6.1.10"},
        }

        def covered(target, item):
            return image_scope.coverage({"targets": [target]}, [item])["covered_images"]

        self.assertEqual(covered(target, item), 1)
        for key, value in (
            ("coverage_profile", "worker"),
            ("coverage_profile", "local-path-provisioner"),
            ("observed_reference", pin.PUBLISHED_CONFIG),
            ("image_config_id", contract.LOCAL_PATH_CONFIG),
            ("runtime_image_id", contract.LOCAL_PATH_CONFIG),
            ("image_id", contract.LOCAL_PATH_CONFIG),
            ("scan_executed", False),
            ("sbom_validated", False),
            ("diagnostic_only", True),
            ("catalogued_packages", 61),
            ("status", "inconclusive"),
            ("package_binding_validated", False),
            ("database", {}),
            ("report_digest", None),
            ("sbom_digest", ""),
            ("scanner_exit_code", 1),
        ):
            with self.subTest(key=key):
                self.assertEqual(covered(target, {**item, key: value}), 0)
        for key, value in (
            ("reference", TEST_REFERENCE[:-1] + "3"),
            ("config_id", contract.LOCAL_PATH_CONFIG),
        ):
            self.assertEqual(covered({**target, key: value}, item), 0)


if __name__ == "__main__":
    unittest.main()
