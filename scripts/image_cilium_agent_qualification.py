"""Qualification against the normalized native runtime-005 observation from run 44959047516."""

import copy
import unittest
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import image_cilium_agent_inventory as agent
from scripts import image_scope
from scripts.image_cilium_agent_fixture import observation

CILIUM = "github.com/cilium/cilium"
GOPS = "github.com/google/gops"
WRAPPER = "github.com/kubernetes-sigs/iptables-wrappers"
PAIRS = ((CILIUM, "v1.20.5"), (GOPS, "v0.3.29"), (WRAPPER, "v0.0.0-20260420133543-bfef9e5087a1"))
PATHS = {
    "/usr/bin/cilium-envoy",
    "/usr/bin/cilium-envoy-starter",
    "/usr/local/bin/clang",
    "/usr/local/bin/llc",
    "/usr/local/bin/bpftool",
}


class AgentInventoryTests(unittest.TestCase):
    def setUp(self):
        self.obs = observation()

    def test_native_observation_resolves_three_coordinates_in_four_specific_executables(self):
        self.assertEqual(
            digest(canonical(self.obs)),
            "127dc6f158473f22d8b2603e08a7e30aa89dfd1f082da5a2f22fcf58628d9271",
        )
        self.assertEqual(agent.PROFILE, "cilium-agent-go-supplemental")
        self.assertEqual(agent.coordinates(), PAIRS)
        for module, version in PAIRS:
            self.assertEqual(
                agent.validate_coordinate(module, version), f"pkg:golang/{module}@{version}"
            )
        before = copy.deepcopy(self.obs)
        result = agent.resolve(self.obs, agent.REFERENCE)
        self.assertEqual(before, self.obs)
        self.assertEqual(result["coordinates"], [list(pair) for pair in PAIRS])
        expected = {
            "/usr/bin/gops": (PAIRS[1], "UNKNOWN", "44953814982", "136997375909"),
            "/usr/sbin/iptables-wrapper": (PAIRS[2], "UNKNOWN", "45020196030", "137201153917"),
            "/opt/cni/bin/cilium-cni": (PAIRS[0], "v1.20.5+dirty", "45020758284", "137202903438"),
            "/usr/bin/hubble": (PAIRS[0], "v1.20.5+dirty", "45020758284", "137202903680"),
        }
        self.assertEqual(len(result["instances"]), len(expected))
        for i in result["instances"]:
            self.assertEqual(
                (
                    (i["module"], i["version"]),
                    i["observed_version"],
                    i["rebuild_run_id"],
                    i["rebuild_job_id"],
                ),
                expected[i["binary_path"]],
            )
            self.assertEqual(
                sum(
                    (p["name"], p["version"], p["paths"])
                    == (i["module"], i["observed_version"], [i["binary_path"]])
                    for p in self.obs["packages"]
                ),
                1,
            )
        self.assertEqual(
            result["full_rows_sha256"],
            "8a4384e7221fd5a9f50e63509d94fd47f8e416d09f530a7b8a7c02f2337bc46c",
        )
        self.assertEqual(result["proof_digest"], agent.proof_digest())
        self.obs["packages"].reverse()
        self.assertEqual(result, agent.resolve(self.obs, agent.REFERENCE))
        result["instances"].clear()
        self.assertEqual(len(agent.resolve(self.obs, agent.REFERENCE)["instances"]), 4)

    def test_proof_binds_the_native_gaps_and_rebuild_receipts(self):
        self.assertEqual(
            agent.proof_digest(), "03dd13d403f2fda6c8b6626e99055327576114a157012793b36b483ccf3003df"
        )
        for field, value in (("_NATIVE_FILES", ()), ("_RECEIPTS", {})):
            with (
                self.subTest(field=field),
                patch.object(agent, field, value),
                self.assertRaisesRegex(Rejected, "proof_mismatch"),
            ):
                agent.resolve(self.obs, agent.REFERENCE)

    def test_malformed_identity_foreign_reference_and_unregistered_coordinates(self):
        for bad in (None, [], {}, {"image_id": "bad"}):
            with self.assertRaises(Rejected):
                agent.resolve(bad, agent.REFERENCE)
            self.assertIsNone(agent.diagnose(bad, agent.REFERENCE))
        other = dict(self.obs, image_id="sha256:" + "0" * 64)
        self.assertIsNone(agent.resolve(other, agent.REFERENCE))
        for ref in (
            None,
            agent.CONFIG,
            agent.REFERENCE.upper(),
            agent.REFERENCE + " ",
            agent.REFERENCE.replace("cilium/cilium@", "cilium/operator-generic@"),
        ):
            with self.assertRaisesRegex(Rejected, "reference_mismatch"):
                agent.resolve(self.obs, ref)
            self.assertEqual(
                agent.diagnose(self.obs, ref)["reason"],
                "image_audit_cilium_agent_inventory_mismatch",
            )
        for module, version in (
            (CILIUM, "v1.20.5+dirty"),
            (GOPS, "v0.3.28"),
            (WRAPPER, "v3"),
            (WRAPPER, "UNKNOWN"),
            ("clang", "19.1.7"),
            ([], None),
        ):
            with self.assertRaises(Rejected):
                agent.validate_coordinate(module, version)

    def test_inventory_requires_exact_native_rows_paths_counts_and_original_versions(self):
        def row(obs, name, version):
            return next(p for p in obs["packages"] if p["name"] == name and p["version"] == version)

        for mutate in (
            lambda o: o["packages"].pop(),
            lambda o: o["packages"].append(o["packages"][0]),
            lambda o: o["packages"].__setitem__(0, o["packages"][1]),
            lambda o: row(o, WRAPPER, "UNKNOWN").update(version=PAIRS[2][1]),
            lambda o: row(o, GOPS, "v0.3.28").update(version="v0.3.29"),
            lambda o: row(o, CILIUM, "v1.20.5+dirty").update(version="v1.20.5"),
            lambda o: row(o, GOPS, "UNKNOWN").update(paths=["/usr/bin/hubble"]),
            lambda o: o["packages"][0]["paths"].pop(),
            lambda o: o["packages"][0].update(foundBy="other"),
            lambda o: o["distro"].update(versionID="26"),
            lambda o: o.update(package_count=947.0),
            lambda o: o["package_types"].update(deb=124.0),
            lambda o: o.update(extra=True),
        ):
            obs = copy.deepcopy(self.obs)
            mutate(obs)
            with (
                self.subTest(change=mutate),
                self.assertRaisesRegex(Rejected, "inventory_mismatch"),
            ):
                agent.resolve(obs, agent.REFERENCE)
            d = agent.diagnose(obs, agent.REFERENCE)
            self.assertFalse(d["independent_inventory_verified"])
            self.assertNotIn("wrapper_rebuild", d)
            self.assertNotIn("uncovered_native_applications", d)

    def test_confirmed_modules_leave_native_diagnostic_and_coverage_open(self):
        d = agent.diagnose(self.obs, agent.REFERENCE)
        self.assertTrue(d["independent_inventory_verified"])
        self.assertEqual(d["reason"], "image_audit_cilium_agent_application_provenance_incomplete")
        self.assertEqual(d["status"], "inconclusive")
        self.assertEqual(d["wrapper_rebuild"]["observed_version"], "UNKNOWN")
        self.assertEqual(d["gops_rebuild"]["release"], "v0.3.29")
        self.assertEqual(len(d["main_module_rebuilds"]), 2)
        self.assertEqual({g["binary_path"] for g in d["uncovered_native_applications"]}, PATHS)
        m = agent.resolve(self.obs, agent.REFERENCE)
        self.assertFalse(m["application_coverage_complete"])
        self.assertFalse({"status", "decision", "release_ready", "sbom_validated"} & m.keys())
        self.assertEqual(m["uncovered_native_applications"], d["uncovered_native_applications"])
        target = {"name": "runtime-005", "config_id": agent.CONFIG, "reference": agent.REFERENCE}
        for profile in ("unapproved-system", agent.PROFILE):
            item = {
                "name": target["name"],
                "image_config_id": agent.CONFIG,
                "observed_reference": agent.REFERENCE,
                "coverage_profile": profile,
                "sbom_validated": True,
                "scan_executed": True,
                "status": "pass",
                "catalogued_packages": 947,
                "package_observation": self.obs,
                "application_inventory": d,
            }
            self.assertEqual(
                image_scope.coverage({"targets": [target]}, [item])["covered_images"], 0
            )
