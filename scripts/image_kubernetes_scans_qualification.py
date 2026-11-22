"""Controlled runner/join tests; these do not claim native scanner execution."""

import copy
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import image_audit as audit
from scripts import image_cilium_agent_inventory as agent
from scripts import image_etcd_inventory as etcd
from scripts import image_etcd_inventory_fixture as etcd_fixture
from scripts import image_kubernetes_scans as scans
from scripts import image_patched_etcd_inventory as patched_etcd
from scripts import image_patched_etcd_inventory_qualification as patched_fixture
from scripts.image_audit_qualification import fixtures as image_fixture
from scripts.image_go_supplemental_qualification import fixture as module_fixture

CILIUM_COORD = ("github.com/google/gops", "v0.3.29")
CILIUM_PURL = "pkg:golang/github.com/google/gops@v0.3.29"
CILIUM_REASON = "image_audit_runtime_application_coverage_unapproved"


class SupplementalScanContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.cache = self.root / "cache"
        self.cache.mkdir()
        (self.cache / "db").write_bytes(b"fixed")
        self.db_files = audit.snapshot(self.cache)
        self.module_scan = module_fixture(timestamp=datetime.now(UTC))
        self.db = self.module_scan["expected_database"]
        self.original_code = 0
        self.coords = (("k8s.io/api", "v0.36.4"), ("k8s.io/kubernetes", "v1.36.4"))
        self.mapping = {
            "proof_digest": "a" * 64,
            "image_config_id": "sha256:" + "b" * 64,
            "coordinates": [list(pair) for pair in self.coords],
            "instances": [{"module": "k8s.io/api", "version": "v0.36.4"}],
        }
        self.cilium = SimpleNamespace(
            PROFILE="cilium-operator-supplemental",
            REFERENCE="quay.io/cilium/operator-generic@sha256:" + "1" * 64,
            coordinates=lambda: (CILIUM_COORD,),
            validate_coordinate=lambda m, v: f"pkg:golang/{m}@{v}",
            proof_digest=lambda: "d" * 64,
            resolve=lambda observation, reference: {
                "image_config_id": observation["image_id"],
                "proof_digest": "d" * 64,
                "coordinates": [list(CILIUM_COORD)],
            },
        )
        self.patches = [
            patch.object(scans.aliases, "coordinates", return_value=self.coords),
            patch.object(scans.aliases, "proof_digest", return_value="a" * 64),
            patch.object(
                scans.aliases, "validate_coordinate", side_effect=lambda m, v: f"pkg:golang/{m}@{v}"
            ),
            patch.object(scans.aliases, "resolve", return_value=self.mapping),
            patch.object(
                scans.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"")
            ),
            patch.object(audit, "scanner", side_effect=self.scanner),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def scanner(self, run, name, image, arguments, mounts, network=False):
        self.assertEqual(image, audit.GRYPE_IMAGE)
        self.assertFalse(network)
        self.assertTrue(all(path.is_absolute() for path, _, _ in mounts))
        self.assertEqual(mounts[0], (self.cache, "/cache", False))
        purl = arguments[0]
        report = copy.deepcopy(self.module_scan["report"])
        report["source"] = {"type": "purl", "target": purl}
        cdx = copy.deepcopy(self.module_scan["cdx"])
        package = cdx["components"][0]
        trace = self.module_scan["trace"].replace(package["purl"].encode(), purl.encode())
        module, version = purl.removeprefix("pkg:golang/").split("@")
        package.update(name=module, version=version, purl=purl)
        for match in report["matches"]:
            match["artifact"].update(name=module, version=version, purl=purl)
        (run / f"{name}.json").write_bytes(canonical(report))
        (run / f"{name}.log").write_bytes(trace)
        (run / f"{name}.cid").write_text("c" * 64, encoding="ascii")
        self.assertEqual(mounts[1][1:], ("/output", True))
        (mounts[1][0] / "report.json").write_bytes(canonical(cdx))
        return self.module_scan["returncode"], run / f"{name}.json"

    def batch(self, **kwargs):
        return scans.run_batch(self.root, self.cache, self.db, self.db_files, **kwargs)

    def agent_supplement(self, severities=()):
        from scripts.image_cilium_agent_fixture import observation

        self.module_scan = module_fixture(severities, timestamp=self.module_scan["timestamp"])
        observed = observation()
        sbom, report, match, _, _ = image_fixture()
        sbom["source"]["metadata"]["imageID"] = agent.CONFIG
        sbom["distro"] = observed["distro"]
        sbom["artifacts"] = [
            {**row, "id": str(i), "locations": [{"path": p} for p in row["paths"]]}
            for i, row in enumerate(observed["packages"])
        ]
        report["source"]["target"]["imageID"] = agent.CONFIG
        report["descriptor"] = self.module_scan["report"]["descriptor"]
        report["distro"] = {"name": "ubuntu", "version": "26.04"}
        match["artifact"] = {k: sbom["artifacts"][0][k] for k in ("id", "name", "type", "version")}
        match["vulnerability"]["severity"] = "Low"
        report["matches"] = [match, match]
        self.sbom, self.report = self.root / "sbom.json", self.root / "report.json"
        self.sbom.write_bytes(canonical(sbom))
        self.report.write_bytes(canonical(report))
        self.target = {"reference": agent.REFERENCE, "config_id": agent.CONFIG}
        self.component = {
            **scans.assess(sbom, report, agent.CONFIG, set(), 0, diagnostic_only=True),
            "image_config_id": agent.CONFIG,
            "observed_reference": agent.REFERENCE,
            "reason": "image_audit_cilium_agent_application_provenance_incomplete",
            "package_observation": scans.observe_packages(sbom, agent.CONFIG),
            "sbom_digest": digest(canonical(sbom)),
            "report_digest": digest(canonical(report)),
        }
        return audit.supplement_system_image(
            self.component,
            self.target,
            self.sbom,
            self.report,
            0,
            self.root,
            self.cache,
            self.db,
            self.db_files,
            registry=agent,
        )

    def test_noble_receipt_adds_known_materials_to_partial_agent_only(self):
        from scripts import image_bpftool_materials as materials
        from scripts import image_bpftool_scan as native

        component = self.agent_supplement(("High",))
        originals = list(component["findings"])
        control = dict(
            package="libc6-dev",
            installed="2.39-0ubuntu8.3",
            type="deb",
            source_package="glibc",
            namespace=native.NAMESPACE,
            id=native.ADVISORY,
            severity="Medium",
            fix={"state": "fixed", "versions": [native.FIXED]},
        )
        receipt = {
            "scope": "static-build-inputs-ubuntu-noble",
            "binary_sha256": materials.BINARY_SHA256,
            "release_ready": False,
            "packages": {k: list(v) for k, v in materials.PACKAGES.items()},
            "database": self.db,
            "control_advisory": native.ADVISORY,
            "db_sha256": "a" * 64,
            "findings": [control],
            "materials": {
                "exit_code": 0,
                "sbom_sha256": "b" * 64,
                "grype_sha256": "c" * 64,
                "log_sha256": "d" * 64,
            },
            "fixed_metadata_control": {
                "exit_code": 0,
                "sbom_sha256": "e" * 64,
                "grype_sha256": "f" * 64,
                "log_sha256": "1" * 64,
            },
        }
        with patch.object(native, "collect", return_value=receipt):
            with self.assertRaisesRegex(Rejected, "database_digest"):
                audit.supplement_native_agent(
                    component,
                    self.target,
                    self.root,
                    self.cache,
                    self.db,
                    {"6/vulnerability.db": "0" * 64},
                )
            self.assertEqual(component["findings"], originals)
            audit.supplement_native_agent(
                component,
                self.target,
                self.root,
                self.cache,
                self.db,
                {"6/vulnerability.db": "a" * 64},
            )
        self.assertEqual(component["findings"], originals + [control])
        self.assertEqual(
            component["vulnerability_count"], len({f["id"] for f in component["findings"]})
        )
        self.assertTrue(scans.join_valid(component, self.target, registry=agent))
        self.assertFalse(scans.coverage_valid(component, self.target, registry=agent))
        receipt["binary_sha256"] = "0" * 64
        self.assertFalse(scans.join_valid(component, self.target, registry=agent))

    def test_agent_adds_severe_go_findings_without_native_coverage(self):
        joined = self.agent_supplement(("High", "Critical"))
        self.assertEqual(joined["status"], "fail")
        self.assertTrue(joined["diagnostic_only"])
        self.assertFalse(joined["sbom_validated"])
        self.assertEqual(joined["reason"], self.component["reason"])
        evidence = joined["cilium_agent_go_supplemental"]
        self.assertEqual(evidence["original_result"]["findings"], self.component["findings"])
        self.assertEqual(
            [r["module"] for r in evidence["scans"]], [m for m, _ in agent.coordinates()]
        )
        self.assertEqual(
            joined["findings"],
            self.component["findings"]
            + [finding for row in evidence["scans"] for finding in row["findings"]],
        )
        self.assertEqual(joined["severity_counts"]["Low"], 2)
        self.assertEqual(joined["severity_counts"]["High"], 3)
        self.assertEqual(joined["severity_counts"]["Critical"], 3)
        self.assertFalse(scans.coverage_valid(joined, self.target, registry=agent))
        evidence["scans"][1]["database"] = {"built": "different"}
        self.assertFalse(scans.join_valid(joined, self.target, registry=agent))

    def test_clean_agent_go_scans_remain_inconclusive(self):
        joined = self.agent_supplement()
        self.assertEqual(joined["status"], "inconclusive")
        self.assertEqual(joined["findings"], self.component["findings"])
        self.assertTrue(scans.join_valid(joined, self.target, registry=agent))
        for field, value in (
            ("status", "pass"),
            ("diagnostic_only", False),
            ("sbom_validated", True),
        ):
            with self.subTest(field=field):
                self.assertFalse(
                    scans.join_valid(joined | {field: value}, self.target, registry=agent)
                )

    def test_fake_scan_and_cross_registry_replay(self):
        kube = self.batch()
        cilium = self.batch(registry=self.cilium)
        self.assertEqual(cilium.directory, self.root / "cilium-operator-modules")
        self.assertEqual(kube.directory, self.root / "kubernetes-modules")
        self.assertEqual(audit.scanner.call_count, len(self.coords) + 1)
        self.assertEqual(audit.scanner.call_args.args[3][0], CILIUM_PURL)
        results = scans.read_batch(cilium, self.db, registry=self.cilium)
        self.assertEqual([r["purl"] for r in results], [CILIUM_PURL])
        for batch, registry in ((kube, self.cilium), (cilium, scans.aliases)):
            with self.subTest(registry=registry), self.assertRaises(Rejected):
                scans.read_batch(batch, self.db, registry=registry)
        with (
            patch.object(scans.aliases, "proof_digest", self.cilium.proof_digest),
            patch.object(scans.aliases, "coordinates", self.cilium.coordinates),
            self.assertRaisesRegex(Rejected, "batch_binding"),
        ):
            scans.read_batch(cilium, self.db)

    def test_etcd_requires_all_five_versioned_modules_and_its_own_receipts(self):
        batch = self.batch(registry=etcd)
        self.assertEqual(batch.directory.name, "etcd-modules")
        results = scans.read_batch(batch, self.db, registry=etcd)
        self.assertEqual(len(results), 5)
        self.assertEqual([(r["module"], r["version"]) for r in results], list(etcd.coordinates()))
        with self.assertRaises(Rejected):
            scans.read_batch(batch, self.db, registry=self.cilium)
        with self.assertRaises(Rejected):
            scans.read_batch(replace(batch, receipts=batch.receipts[:-1]), self.db, registry=etcd)

    def test_etcd_join_preserves_both_unknown_findings_and_refuses_another_target(self):
        sbom = etcd_fixture.sbom()
        _, report, _, _, _ = image_fixture()
        report["descriptor"] = self.module_scan["report"]["descriptor"]
        report["source"]["target"]["imageID"] = etcd.CONFIG
        report["distro"]["version"] = "13"
        for package in sbom["artifacts"]:
            if package["name"] == "golang.org/x/crypto":
                report["matches"].append(
                    {
                        "artifact": {k: package[k] for k in ("id", "type", "name", "version")},
                        "vulnerability": {"id": "GO-2026-5932", "severity": "Unknown"},
                    }
                )
        self.assertEqual(len(report["matches"]), 2)
        self.sbom = self.root / "sbom.json"
        self.report = self.root / "report.json"
        self.sbom.write_bytes(canonical(sbom))
        self.report.write_bytes(canonical(report))
        self.component = {
            **scans.assess(sbom, report, etcd.CONFIG, set(), 0, diagnostic_only=True),
            "image_config_id": etcd.CONFIG,
            "package_observation": scans.observe_packages(sbom, etcd.CONFIG),
            "sbom_digest": digest(canonical(sbom)),
            "report_digest": digest(canonical(report)),
            "observed_reference": etcd.REFERENCE,
            "reason": CILIUM_REASON,
        }
        self.target = {"config_id": etcd.CONFIG, "reference": etcd.REFERENCE}
        self.created = self.batch(registry=etcd)
        result = self.joined(registry=etcd)
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["findings"], self.component["findings"])
        self.assertEqual(result["severity_counts"]["Unknown"], 2)
        self.assertEqual(result["unique_vulnerabilities"], 1)
        self.assertTrue(scans.coverage_valid(result, self.target, registry=etcd))
        changed = {**self.target, "reference": self.cilium.REFERENCE}
        self.assertFalse(scans.coverage_valid(result, changed, registry=etcd))
        result["findings"].clear()
        self.assertFalse(scans.coverage_valid(result, self.target, registry=etcd))

    def test_patched_etcd_joins_only_its_own_receipts_and_preserves_original_finding(self):
        config = patched_etcd.CONFIG
        reference = patched_etcd.REFERENCE
        sbom = patched_fixture.sbom(config)
        report = image_fixture()[1]
        report["descriptor"] = self.module_scan["report"]["descriptor"]
        report["source"]["target"]["imageID"] = config
        report["distro"]["version"] = "13"
        package = next(p for p in sbom["artifacts"] if p["type"] == "deb")
        report["matches"].append(
            {
                "artifact": {k: package[k] for k in ("id", "type", "name", "version")},
                "vulnerability": {"id": "CVE-2026-12345", "severity": "Medium"},
            }
        )
        self.sbom = self.root / "patched-sbom.json"
        self.report = self.root / "patched-grype.json"
        self.sbom.write_bytes(canonical(sbom))
        self.report.write_bytes(canonical(report))
        self.component = {
            **scans.assess(sbom, report, config, set(), 0, diagnostic_only=True),
            "image_config_id": config,
            "package_observation": scans.observe_packages(sbom, config),
            "sbom_digest": digest(canonical(sbom)),
            "report_digest": digest(canonical(report)),
            "observed_reference": reference,
            "reason": CILIUM_REASON,
        }
        self.target = {"config_id": config, "reference": reference}
        self.created = self.batch(registry=patched_etcd)
        self.assertEqual(self.created.directory.name, "etcd-patched-modules")
        with self.assertRaises(Rejected):
            scans.read_batch(self.created, self.db, registry=etcd)
        result = self.joined(registry=patched_etcd)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["severity_counts"]["Medium"], 1)
        self.assertEqual(result["findings"], self.component["findings"])
        self.assertTrue(scans.coverage_valid(result, self.target, registry=patched_etcd))
        self.assertFalse(scans.coverage_valid(result, self.target, registry=etcd))
        upstream = {"config_id": etcd.CONFIG, "reference": etcd.REFERENCE}
        self.assertFalse(scans.coverage_valid(result, upstream, registry=patched_etcd))

    def test_cilium_fake_scanner_reporting_a_different_release_is_rejected(self):
        def wrong_release(run, name, image, arguments, mounts):
            self.assertEqual(arguments[0], CILIUM_PURL)
            wrong = CILIUM_PURL.replace("v0.3.29", "v0.3.28")
            return self.scanner(run, name, image, [wrong, *arguments[1:]], mounts)

        with patch.object(audit, "scanner", wrong_release), self.assertRaises(Rejected):
            self.batch(registry=self.cilium)

    def test_custom_registry_cannot_select_other_profile_coordinate_or_scanner_input(self):
        for field, value in (
            ("PROFILE", "../kubernetes-modules"),
            ("PROFILE", "kubernetes-supplemental"),
            ("REFERENCE", None),
            ("REFERENCE", "local/cilium:tag"),
            ("coordinates", lambda: ()),
            ("coordinates", lambda: (CILIUM_COORD,) * 2),
            ("coordinates", lambda: (("github.com/google/gops", "v0.3.28"),)),
            ("validate_coordinate", lambda m, v: "dir:/cache"),
        ):
            with (
                self.subTest(field=field, value=value),
                patch.object(self.cilium, field, value),
                self.assertRaises(Rejected),
            ):
                self.batch(registry=self.cilium)
        audit.scanner.assert_not_called()

    def test_fixed_complete_batch_and_replay(self):
        batch = self.batch()
        results = scans.read_batch(batch, self.db)
        self.assertEqual(len(results), 2)
        self.assertEqual(
            {r["purl"] for r in results}, {f"pkg:golang/{m}@{v}" for m, v in self.coords}
        )

    def test_invalid_coordinate_prevents_any_launch(self):
        with patch.object(scans.aliases, "validate_coordinate", side_effect=Rejected("bad")):
            with self.assertRaises(Rejected):
                self.batch()
        audit.scanner.assert_not_called()

    def test_database_changed_prevents_launch(self):
        (self.cache / "db").write_bytes(b"changed")
        with self.assertRaises(Rejected):
            self.batch()
        audit.scanner.assert_not_called()

    def test_database_changed_during_scan(self):
        def mutate(*args, **kwargs):
            result = self.scanner(*args, **kwargs)
            (self.cache / "db").write_bytes(b"changed")
            return result

        with patch.object(audit, "scanner", side_effect=mutate), self.assertRaises(Rejected):
            self.batch()

    def test_changed_raw_bytes_cannot_replay(self):
        for suffix in (".json", ".cdx.json", ".log", ".cid"):
            with self.subTest(suffix=suffix):
                batch = self.batch()
                path = batch.directory / ("module-00" + suffix)
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                with self.assertRaises(Rejected):
                    scans.read_batch(batch, self.db)
                path.write_bytes(original)
                # Each batch owns an exclusive directory; use a new parent.
                self.root = self.root / "next"
                self.root.mkdir()

    def test_incomplete_extra_duplicate_receipts(self):
        batch = self.batch()
        for receipts in (
            batch.receipts[:-1],
            batch.receipts + batch.receipts[:1],
            batch.receipts[:1] * 2,
        ):
            with self.subTest(receipts=receipts), self.assertRaises(Rejected):
                scans.read_batch(replace(batch, receipts=receipts), self.db)

    def test_wrong_proof_or_database(self):
        batch = self.batch()
        with self.assertRaises(Rejected):
            scans.read_batch(replace(batch, proof="d" * 64), self.db)
        with self.assertRaises(Rejected):
            scans.read_batch(batch, {**self.db, "built": "changed"})

    def test_cleanup_failure_stops_batch(self):
        with (
            patch.object(
                scans.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=0, stdout=b"c" * 64),
            ),
            self.assertRaises(Rejected),
        ):
            self.batch()
        self.assertEqual(audit.scanner.call_count, 1)

    def test_missing_invalid_cid_or_list_error(self):
        for content in (None, "bad"):
            path = self.root / "owned.cid"
            if content is not None:
                path.write_text(content)
            with self.subTest(content=content), self.assertRaises(Rejected):
                scans.confirm_absent(path)
        path.write_text("c" * 64)
        with (
            patch.object(
                scans.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout=b"")
            ),
            self.assertRaises(Rejected),
        ):
            scans.confirm_absent(path)

    def original(self, severity=None):
        findings = (
            []
            if severity is None
            else [
                {
                    "id": "CVE-original",
                    "severity": severity,
                    "package": "k8s.io/api",
                    "installed": "UNKNOWN",
                    "type": "go-module",
                    "fix": {"state": "unknown", "versions": []},
                }
            ]
        )
        return {
            "image_id": self.mapping["image_config_id"],
            "diagnostic_only": True,
            "database": self.db,
            "status": "fail" if severity in ("High", "Critical") else "inconclusive",
            "findings": findings,
        }

    def join_fixture(self, severity=None):
        self.sbom = self.root / "sbom.json"
        self.report = self.root / "report.json"
        self.sbom.write_bytes(b"{}")
        self.report.write_bytes(b"{}")
        self.observation = {"image_id": self.mapping["image_config_id"]}
        self.component = {
            "name": "runtime-001",
            "image_config_id": self.mapping["image_config_id"],
            "sbom_digest": digest(b"{}"),
            "report_digest": digest(b"{}"),
            "package_observation": self.observation,
            "scan_executed": True,
            "reason": "image_audit_kubernetes_module_versions_unresolved",
            "status": self.original(severity)["status"],
            "findings": self.original(severity)["findings"],
            "catalogued_packages": 138,
        }
        self.target = {
            "name": "runtime-001",
            "config_id": self.mapping["image_config_id"],
            "reference": self.mapping["image_config_id"],
        }
        for p in (
            patch.object(scans, "observe_packages", return_value=self.observation),
            patch.object(scans, "assess", return_value=self.original(severity)),
        ):
            p.start()
            self.addCleanup(p.stop)
        self.created = self.batch()

    def joined(self, **kwargs):
        return scans.join(
            self.component,
            self.sbom,
            self.report,
            self.original_code,
            self.created,
            self.target["reference"],
            self.db,
            **kwargs,
        )

    def cilium_join_fixture(self):
        sbom, report, match, config, _ = image_fixture()
        sbom["distro"] = {}
        report.update(
            distro=None, matches=[match], descriptor=self.module_scan["report"]["descriptor"]
        )
        self.sbom = self.root / "sbom.json"
        self.report = self.root / "report.json"
        self.sbom.write_bytes(canonical(sbom))
        self.report.write_bytes(canonical(report))
        self.observation = scans.observe_packages(sbom, config)
        self.original_code = 2
        self.component = {
            **scans.assess(sbom, report, config, set(), self.original_code, diagnostic_only=True),
            "image_config_id": config,
            "package_observation": self.observation,
            "sbom_digest": digest(canonical(sbom)),
            "report_digest": digest(canonical(report)),
            "observed_reference": self.cilium.REFERENCE,
            "reason": CILIUM_REASON,
        }
        self.target = {"config_id": config, "reference": self.cilium.REFERENCE}
        self.created = self.batch(registry=self.cilium)

    def test_cilium_join_binds_evidence_to_profile_and_target(self):
        self.cilium_join_fixture()
        result = self.joined(registry=self.cilium)
        self.assertEqual(result["coverage_profile"], self.cilium.PROFILE)
        self.assertNotIn("kubernetes_supplemental", result)
        self.assertNotIn("reason", result)
        evidence = result["cilium_operator_supplemental"]
        self.assertEqual(set(evidence), {"mapping", "original_result", "scans"})
        self.assertIsNone(evidence["original_result"]["distro"])
        self.assertEqual([r["purl"] for r in evidence["scans"]], [CILIUM_PURL])
        self.assertEqual(result["findings"], self.component["findings"])
        self.assertEqual(result["status"], "fail")
        self.assertTrue(scans.coverage_valid(result, self.target, registry=self.cilium))
        self.assertFalse(scans.coverage_valid(result, self.target))
        for key, value in (
            ("reference", self.target["config_id"]),
            ("reference", self.cilium.REFERENCE.replace("quay.io", "other.example")),
            ("config_id", "sha256:" + "0" * 64),
            ("containerd_reference", "local/cilium:tag"),
        ):
            target = {**self.target, key: value}
            with self.subTest(target=target):
                self.assertFalse(scans.coverage_valid(result, target, registry=self.cilium))
        for key, value in (
            ("observed_reference", "local/cilium:tag"),
            ("image_config_id", "sha256:" + "0" * 64),
            ("coverage_profile", "kubernetes-supplemental"),
            ("local_alias", "local/cilium:tag"),
            ("containerd_export", {}),
        ):
            with self.subTest(key=key):
                changed = {**result, key: value}
                self.assertFalse(scans.coverage_valid(changed, self.target, registry=self.cilium))
        cilium = self.created
        self.created = self.batch()
        with self.assertRaises(Rejected):
            self.joined(registry=self.cilium)
        self.created = cilium
        with (
            patch.dict(self.component, reason="image_audit_kubernetes_module_versions_unresolved"),
            self.assertRaisesRegex(Rejected, "batch_binding"),
        ):
            self.joined()

    def test_cilium_join_rejects_wrong_reason_alias_and_empty_mapping(self):
        self.cilium_join_fixture()
        for key, value in (
            ("reason", "image_audit_kubernetes_module_versions_unresolved"),
            ("reason", "image_audit_snapshot_changed"),
            ("observed_reference", self.target["config_id"]),
            ("local_alias", "local/cilium:tag"),
            ("containerd_export", {}),
        ):
            with self.subTest(key=key), patch.dict(self.component, {key: value}):
                with self.assertRaises(Rejected):
                    self.joined(registry=self.cilium)
        with patch.dict(self.target, reference="local/cilium:tag"), self.assertRaises(Rejected):
            self.joined(registry=self.cilium)
        with patch.object(self.cilium, "resolve", wraps=self.cilium.resolve) as resolve:
            mapping = self.cilium.resolve(self.observation, self.cilium.REFERENCE)
            for key, value in (("coordinates", []), ("proof_digest", "a" * 64)):
                resolve.return_value = {**mapping, key: value}
                with self.subTest(key=key), self.assertRaises(Rejected):
                    self.joined(registry=self.cilium)

    def test_join_retains_original_findings_and_coverage(self):
        self.join_fixture("High")
        original = copy.deepcopy(self.component)
        result = self.joined()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["findings"], self.original("High")["findings"])
        self.assertEqual(result["findings"][0]["installed"], "UNKNOWN")
        self.assertEqual(self.component, original)
        self.assertNotIn("reason", result)
        self.assertTrue(scans.coverage_valid(result, self.target))

    def test_join_unknown_stays_inconclusive_and_empty_passes(self):
        self.join_fixture("Unknown")
        self.assertEqual(self.joined()["status"], "inconclusive")
        self.component["findings"] = []
        with patch.object(scans, "assess", return_value=self.original()):
            result = self.joined()
        self.assertEqual(result["status"], "pass")
        self.assertTrue(scans.coverage_valid(result, self.target))

    def test_additive_findings_never_deduplicate_original(self):
        first = self.original("High")
        result = scans.joined_result(first, [first])
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual(result["unique_vulnerabilities"], 1)
        self.assertEqual(result["severity_counts"]["High"], 2)

    def test_changed_original_inputs_rejected(self):
        self.join_fixture()
        for path in (self.sbom, self.report):
            path.write_bytes(b"changed")
            with self.subTest(path=path), self.assertRaises(Rejected):
                self.joined()
            path.write_bytes(b"{}")
        with patch.object(scans, "observe_packages", return_value={}), self.assertRaises(Rejected):
            self.joined()
        with patch.object(scans.aliases, "resolve", return_value=None), self.assertRaises(Rejected):
            self.joined()
        original = self.original()
        original["database"] = {}
        with patch.object(scans, "assess", return_value=original), self.assertRaises(Rejected):
            self.joined()

    def test_join_missing_required_coordinate(self):
        self.join_fixture()
        self.mapping["coordinates"].append(["k8s.io/foreign", "v0.36.4"])
        with self.assertRaises(Rejected):
            self.joined()

    def test_unrelated_original_failure_is_never_cleared(self):
        self.join_fixture()
        for reason in ("image_audit_snapshot_changed", "image_audit_cleanup_failed", "", False):
            self.component.update(status="inconclusive", reason=reason)
            with self.subTest(reason=reason), self.assertRaises(Rejected):
                self.joined()

    def test_original_decision_must_agree_before_join(self):
        self.join_fixture()
        self.component.pop("reason")
        self.component["status"] = "fail"
        with self.assertRaises(Rejected):
            self.joined()

    def test_same_status_cannot_replace_or_drop_duplicate_original_findings(self):
        self.join_fixture("High")
        original = self.component["findings"][0]
        for rows in ([], [original, original], [original | {"id": "different"}]):
            self.component["findings"] = rows
            with self.subTest(rows=rows), self.assertRaises(Rejected):
                self.joined()

    def test_profile_or_boolean_alone_cannot_grant_coverage(self):
        from scripts import image_scope

        self.join_fixture()
        incomplete = {
            **self.component,
            "status": "pass",
            "coverage_profile": "kubernetes-supplemental",
            "sbom_validated": True,
        }
        incomplete.pop("reason")
        self.assertFalse(scans.coverage_valid(incomplete, self.target))
        snapshot = {"targets": [self.target]}
        self.assertEqual(image_scope.coverage(snapshot, [incomplete])["covered_images"], 0)
        complete = self.joined()
        self.assertEqual(image_scope.coverage(snapshot, [complete])["covered_images"], 1)
        # A complete four-image qualification must not shrink the runtime denominator.
        snapshot["targets"].append({**self.target, "name": "another-runtime-image"})
        self.assertEqual(
            image_scope.coverage(snapshot, [complete]),
            {"status": "inconclusive", "expected_images": 2, "covered_images": 1},
        )

    def test_tampered_join_and_bindings_not_covered(self):
        self.join_fixture("High")
        good = self.joined()
        variants = []
        for key, value in (
            ("findings", []),
            ("status", "pass"),
            ("severity_counts", {}),
            ("reason", "image_audit_snapshot_changed"),
        ):
            variants.append({**good, key: value})
        for key, value in (("mapping", {}), ("scans", []), ("original_result", self.original())):
            invalid = copy.deepcopy(good)
            invalid["kubernetes_supplemental"][key] = value
            variants.append(invalid)
        for key, value in (
            ("purl", "foreign"),
            ("database", {}),
            ("package_identity_bound", False),
            ("matching_completed", False),
            ("cleanup_verified", False),
            ("artifact_digests", {}),
        ):
            invalid = copy.deepcopy(good)
            invalid["kubernetes_supplemental"]["scans"][0][key] = value
            variants.append(invalid)
        invalid = copy.deepcopy(good)
        invalid["kubernetes_supplemental"]["scans"][0]["artifact_digests"][".log"] = "bad"
        variants.append(invalid)
        for invalid in variants:
            with self.subTest(invalid=invalid):
                self.assertFalse(scans.coverage_valid(invalid, self.target))
        self.assertFalse(scans.coverage_valid(good, {**self.target, "config_id": "foreign"}))
        with patch.object(scans.aliases, "resolve", return_value=None):
            self.assertFalse(scans.coverage_valid(good, self.target))
        for key, value in (("image_id", "foreign"), ("diagnostic_only", False)):
            invalid = copy.deepcopy(good)
            invalid["kubernetes_supplemental"]["original_result"][key] = value
            self.assertFalse(scans.coverage_valid(invalid, self.target))

    def test_registry_changed_during_batch(self):
        with (
            patch.object(scans.aliases, "proof_digest", side_effect=["a" * 64, "b" * 64]),
            self.assertRaises(Rejected),
        ):
            self.batch()

    def test_cleanup_os_or_decode_failure(self):
        path = self.root / "owned.cid"
        path.write_bytes(b"\xff")
        with self.assertRaises(Rejected):
            scans.confirm_absent(path)
        path.write_bytes(b"c" * 64)
        with (
            patch.object(scans.subprocess, "run", side_effect=OSError),
            self.assertRaises(Rejected),
        ):
            scans.confirm_absent(path)

    def test_scanner_changed_output_path(self):
        def wrong_path(*args, **kwargs):
            code, path = self.scanner(*args, **kwargs)
            return code, path.with_name("foreign.json")

        with patch.object(audit, "scanner", side_effect=wrong_path), self.assertRaises(Rejected):
            self.batch()


if __name__ == "__main__":
    unittest.main()
