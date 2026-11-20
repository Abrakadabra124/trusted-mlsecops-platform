"""Controlled runner/join tests; these do not claim native scanner execution."""

import copy
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import image_audit as audit
from scripts import image_kubernetes_scans as scans


class SupplementalScanContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.cache = self.root / "cache"
        self.cache.mkdir()
        (self.cache / "db").write_bytes(b"fixed")
        self.db_files = audit.snapshot(self.cache)
        self.db = {"schema_version": "v6.1.3", "built": "2026-11-20T00:00:00Z"}
        self.coords = (("k8s.io/api", "v0.36.4"), ("k8s.io/kubernetes", "v1.36.4"))
        self.mapping = {
            "proof_digest": "a" * 64,
            "image_config_id": "sha256:" + "b" * 64,
            "coordinates": [list(pair) for pair in self.coords],
            "instances": [{"module": "k8s.io/api", "version": "v0.36.4"}],
        }
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
            patch.object(scans.single, "assess", side_effect=self.assess),
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
        (run / f"{name}.json").write_bytes(canonical({"purl": purl}))
        (run / f"{name}.log").write_bytes(b"trace")
        (run / f"{name}.cid").write_text("c" * 64, encoding="ascii")
        self.assertEqual(mounts[1][1:], ("/output", True))
        (mounts[1][0] / "report.json").write_bytes(canonical({"purl": purl}))
        return 0, run / f"{name}.json"

    def assess(self, module, version, report, cdx, trace, code, expected_database, timestamp=None):
        self.assertEqual(report["purl"], f"pkg:golang/{module}@{version}")
        self.assertEqual(cdx["purl"], report["purl"])
        return {
            "purl": report["purl"],
            "status": "pass",
            "findings": [],
            "matches": 0,
            "unique_vulnerabilities": 0,
            "severity_counts": {s: 0 for s in scans.SEVERITIES},
            "database": expected_database,
            "scanner_exit_code": code,
            "package_identity_bound": True,
            "matching_completed": True,
        }

    def batch(self):
        return scans.run_batch(self.root, self.cache, self.db, self.db_files)

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

    def joined(self):
        return scans.join(
            self.component,
            self.sbom,
            self.report,
            0,
            self.created,
            self.target["reference"],
            self.db,
        )

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
