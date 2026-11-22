"""Offline tests of the diagnostic boundary; full native evidence is run 44959047516."""

import copy
import unittest
from unittest.mock import patch

from mlsecops.contracts import canonical, digest
from scripts import image_cilium_agent_inventory as agent
from scripts import image_scope


class AgentInventoryTests(unittest.TestCase):
    def setUp(self):
        # A small controlled inventory exercises the same comparison as the native one.
        rows = [
            {
                "type": "deb",
                "name": "apt",
                "version": "3.2.1ubuntu0.1",
                "paths": ["/var/lib/dpkg/status"],
                "foundBy": "dpkg-db-cataloger",
            },
            {
                "type": "go-module",
                "name": "github.com/kubernetes-sigs/iptables-wrappers",
                "version": "UNKNOWN",
                "paths": ["/usr/sbin/iptables-wrapper"],
                "foundBy": "go-module-binary-cataloger",
            },
        ]
        for path in ("/opt/cni/bin/cilium-cni", "/usr/bin/hubble"):
            rows.append(
                {
                    "type": "go-module",
                    "name": "github.com/cilium/cilium",
                    "version": "v1.20.5+dirty",
                    "paths": [path],
                    "foundBy": "go-module-binary-cataloger",
                }
            )
        self.obs = {
            "status": "inconclusive",
            "scope": "package-observation-not-application-coverage",
            "image_id": agent.CONFIG,
            "distro": {"id": "ubuntu", "versionID": "26.04"},
            "package_count": len(rows),
            "package_types": {"deb": 1, "go-module": 3},
            "packages": rows,
        }
        checksum = digest(canonical({**self.obs, "packages": sorted(rows, key=canonical)}))
        self.enterContext(patch.object(agent, "_OBSERVATION_PIN", (len(rows), checksum)))

    def test_unrelated_configs_fall_through_and_wrong_reference_refuses_evidence(self):
        for obs in (None, [], {}, {**self.obs, "image_id": "sha256:" + "0" * 64}):
            self.assertIsNone(agent.diagnose(obs, agent.REFERENCE))
        for ref in (
            None,
            agent.CONFIG,
            agent.REFERENCE.replace("cilium/cilium@", "cilium/operator-generic@"),
        ):
            result = agent.diagnose(self.obs, ref)
            self.assertFalse(result["independent_inventory_verified"])
            self.assertNotIn("wrapper_rebuild", result)
            self.assertNotIn("unverified_main_modules", result)

    def test_diagnostic_never_authorizes_a_scan_or_changes_an_observation(self):
        before = copy.deepcopy(self.obs)
        result = agent.diagnose(self.obs, agent.REFERENCE)
        self.assertTrue(result["independent_inventory_verified"])
        self.assertEqual(result["status"], "inconclusive")
        wrapper = result["wrapper_rebuild"]
        self.assertEqual(wrapper["binary_path"], "/usr/sbin/iptables-wrapper")
        self.assertEqual(wrapper["observed_version"], "UNKNOWN")
        self.assertEqual(wrapper["module_version"], "v0.0.0-20260420133543-bfef9e5087a1")
        self.assertEqual((wrapper["run_id"], wrapper["run_attempt"]), ("45020196030", 1))
        self.assertEqual(wrapper["revision"], "bfef9e5087a198b50a4124bb9ce9d2c7c99025dd")
        dirty = result["unverified_main_modules"]
        self.assertEqual(
            {r["binary_path"] for r in dirty}, {"/opt/cni/bin/cilium-cni", "/usr/bin/hubble"}
        )
        for r in dirty:
            self.assertEqual(r["observed_version"], "v1.20.5+dirty")
            self.assertTrue(r["vcs_modified"])
            self.assertEqual(r["vcs_revision"], "150121410c147fad575ac5dcbce6de923be69042")
            self.assertNotIn("module_version", r)
        self.assertEqual(
            (result["gops_rebuild"]["binary_path"], result["gops_rebuild"]["release"]),
            ("/usr/bin/gops", "v0.3.29"),
        )
        self.assertNotIn("coordinates", result)
        self.assertEqual(before, self.obs)
        self.obs["packages"].reverse()
        self.assertEqual(result, agent.diagnose(self.obs, agent.REFERENCE))
        target = {"name": "runtime-005", "config_id": agent.CONFIG, "reference": agent.REFERENCE}
        item = {
            "name": target["name"],
            "status": "inconclusive",
            "image_config_id": agent.CONFIG,
            "coverage_profile": "unapproved-system",
            "sbom_validated": False,
            "scan_executed": True,
            "package_observation": self.obs,
            "catalogued_packages": self.obs["package_count"],
            "application_inventory": result,
        }
        self.assertEqual(image_scope.coverage({"targets": [target]}, [item])["covered_images"], 0)

    def test_no_diagnosis_of_verified_materials_after_any_inventory_drift(self):
        for mutate in (
            lambda o: o["packages"].pop(),
            lambda o: o["packages"].append(o["packages"][0]),
            lambda o: o["packages"].__setitem__(0, o["packages"][1]),
            lambda o: o["packages"][1].update(version="v3"),
            lambda o: o["packages"][1].update(version="v0.0.0-20260420133543-bfef9e5087a1"),
            lambda o: o["packages"][2].update(version="v1.20.5"),
            lambda o: o["packages"][3].update(version="v1.20.5"),
            lambda o: o["packages"][2].update(paths=["/usr/bin/hubble"]),
            lambda o: o["packages"][0].update(paths="/var/lib/dpkg/status"),
            lambda o: o["packages"][0]["paths"].append("/extra"),
            lambda o: o["packages"][0].update(foundBy="other"),
            lambda o: o["distro"].update(versionID="26"),
            lambda o: o.update(package_count=float(o["package_count"])),
            lambda o: o["package_types"].update(deb=True),
            lambda o: o.update(status="pass"),
            lambda o: o.update(extra=True),
        ):
            obs = copy.deepcopy(self.obs)
            mutate(obs)
            with self.subTest(change=mutate):
                result = agent.diagnose(obs, agent.REFERENCE)
                self.assertFalse(result["independent_inventory_verified"])
                self.assertEqual(result["status"], "inconclusive")
                self.assertNotIn("wrapper_rebuild", result)
                self.assertNotIn("unverified_main_modules", result)
