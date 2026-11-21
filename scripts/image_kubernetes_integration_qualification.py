"""Controlled integration of Kubernetes supplements into the full observed audit."""

import tempfile
import unittest
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch, sentinel

from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, read_json
from scripts import image_audit as audit
from scripts.image_audit_qualification import fixtures
from scripts.image_kubernetes_native import targets


class KubernetesAuditIntegration(unittest.TestCase):
    def audit(self, fault=None):
        reviewed = targets()
        observed = [
            dict(name=f"runtime-{i:03}", reference=f"sha256:{i:064x}", config_id=f"sha256:{i:064x}")
            for i in range(14)
        ]
        local_cases = {
            "local",
            "local-proof",
            "changed-archive",
            "proof-io",
            "registry-fallback",
            "upstream-local",
            "config-local",
        }
        for row, known in zip(observed[:4], reviewed, strict=True):
            row.update(reference=known["reference"], config_id=known["config_id"])
            if fault in local_cases:
                row.update(
                    reference="docker.io/library/import-2026-08-26@sha256:"
                    + row["name"][-3:].zfill(64),
                    containerd_reference=f"registry.k8s.io/{known['name']}-amd64:v1.36.4",
                )
                if fault == "config-local":
                    row["reference"] = known["config_id"]
                if fault == "upstream-local":
                    row["reference"] = known["reference"]
        if fault in ("operator-join", "operator-io"):
            observed[5].update(
                reference=audit.image_cilium_operator_inventory.REFERENCE,
                config_id=audit.image_cilium_operator_inventory.CONFIG,
            )
        runtime = {"targets": observed, "source_revision": "r", "source_fingerprint": "f"}
        by_ref = {row["reference"]: row["config_id"] for row in observed}
        names = {row["name"]: row for row in observed}
        built = datetime.now(UTC).isoformat()
        db = {"schema_version": "v6.1.10", "built": built}
        calls = []

        def command(args, **kwargs):
            if "save" in args:
                Path(args[args.index("--output") + 1]).write_bytes(b"controlled image archive")
            return "r" if args[-1] == "HEAD" else ""

        def scanner(run, name, image, args, mounts=(), network=False):
            calls.append(name)
            path = run / f"{name}.json"
            sbom, report, match, config, _ = fixtures()
            role = name.removesuffix("-sbom").removesuffix("-scan")
            config = names.get(role, {}).get("config_id", config)
            report["descriptor"]["db"]["status"]["built"] = built
            code = 0
            if name == "db-update":
                (mounts[0][0] / "db").write_bytes(b"same-run")
            if name.endswith("-sbom"):
                sbom["source"]["metadata"]["imageID"] = config
                report = sbom
            if name.endswith("-scan"):
                report["source"]["target"]["imageID"] = config
                report["matches"] = [match]
                code = 2
                if fault in ("replay", "read-error") and role == observed[0]["name"]:
                    match["vulnerability"]["severity"] = "Low"
                    code = 0
                if fault == "original" and role == observed[3]["name"]:
                    report["source"]["target"]["imageID"] = "foreign"
                if fault == "database" and role == observed[3]["name"]:
                    report["descriptor"]["db"]["status"]["schemaVersion"] = "v6.1.11"
            path.write_bytes(canonical(report))
            return code, path

        def batch(run, cache, expected, db_files):
            calls.append("batch")
            self.assertEqual(expected, db)
            self.assertEqual(cache, run / "cache")
            self.assertEqual(db_files, audit.snapshot(cache))
            if fault == "cleanup":
                raise Rejected("kubernetes_scan_cleanup_unconfirmed")
            if fault == "batch-io":
                raise OSError("private-evidence-path")
            return sentinel.batch

        coordinate = audit.image_kubernetes_aliases.coordinates()[0]

        def resolve(observation, reference):
            if fault == "mapping" and reference == reviewed[3]["reference"]:
                raise Rejected("image_audit_kubernetes_alias_inventory_mismatch")
            if fault == "unmapped" and reference == reviewed[3]["reference"]:
                return None
            config = observation["image_id"]
            manifest = audit.image_kubernetes_inventory.INVENTORIES[config]["manifest_digest"]
            binding = audit.image_kubernetes_aliases._reference_binding(reference, config, manifest)
            return {
                "image_config_id": config,
                "coordinates": [list(coordinate)],
                "reference_binding": binding,
                "manifest_digest": manifest,
            }

        def read_batch(batch, expected, timestamp=None, *, registry=audit.image_kubernetes_aliases):
            self.assertIs(registry, audit.image_kubernetes_aliases)
            calls.append("join")
            self.assertIs(batch, sentinel.batch)
            self.assertEqual(expected, db)
            if fault == "replay" and calls.count("join") == 2:
                raise Rejected("kubernetes_scan_artifact_changed")
            if fault == "read-error" and calls.count("join") == 2:
                raise OSError("private-evidence-path")
            return [
                dict(
                    module=coordinate[0],
                    version=coordinate[1],
                    purl=audit.image_kubernetes_aliases.validate_coordinate(*coordinate),
                    database=db,
                    matching_completed=True,
                    package_identity_bound=True,
                    cleanup_verified=True,
                    artifact_digests={
                        suffix: "a" * 64 for suffix in audit.image_kubernetes_scans.SUFFIXES
                    },
                    findings=[{"id": "supplemental-fixture", "severity": "Low"}],
                )
            ]

        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder).resolve()
            (root / "scripts").mkdir()
            (root / "scripts/tracking_spike.py").touch()

            def local_export(row, archive):
                if fault == "registry-fallback":
                    raise Rejected("image_audit_local_export_failed")
                archive.write_bytes(b"checked local archive")
                return {"Id": row["config_id"], "Config": {}}

            def proof(archive, reference, config):
                calls.append("local-proof")
                if fault == "local-proof" and config == reviewed[-1]["config_id"]:
                    raise Rejected("kubernetes_export_identity_invalid")
                self.assertEqual(archive.read_bytes(), b"checked local archive")
                if fault == "changed-archive":
                    archive.write_bytes(b"changed after verification")
                if fault == "proof-io":
                    raise OSError("private-evidence-path")
                return dict(
                    runtime_digest=reference.split("@")[-1],
                    selected_manifest_digest=None
                    if reference == config
                    else reference.split("@")[-1],
                    config_id=config,
                    diff_ids=["sha256:" + "1" * 64],
                    layer_digests=["sha256:" + "2" * 64],
                )

            if fault in local_cases:
                stack.enter_context(patch.object(audit, "export_local_image", local_export))
                stack.enter_context(patch("scripts.image_kubernetes_export.verify", proof))
            if fault == "report-bytes":

                def read_once(path, limit):
                    raw = bounded_read(path, limit)
                    if path.name == "runtime-000-scan.json":
                        changed = decode(raw)
                        changed["matches"] *= 2
                        path.write_bytes(canonical(changed))
                        self.original_digest = digest(raw)
                    return raw

                stack.enter_context(patch.object(audit, "bounded_read", read_once))
            for attr, fn in {
                "command": command,
                "source_fingerprint": lambda root: "f",
                "inspect_image": lambda ref: {
                    "Id": by_ref.get(ref, "sha256:" + "a" * 64),
                    "Config": {"Labels": {}},
                },
                "identity": lambda path, details: details["Id"],
                "scanner": scanner,
                "detection_control": lambda *args: None,
                "go_detection_control": lambda *args: None,
                "wolfi_detection_control": lambda *args: None,
            }.items():
                stack.enter_context(patch.object(audit, attr, fn))
            stack.enter_context(patch.object(audit.tracking_spike, "materials", return_value="t"))
            stack.enter_context(patch.object(audit.image_scope, "collect", return_value=runtime))
            stack.enter_context(
                patch.object(
                    audit.image_kubernetes_inventory,
                    "diagnose",
                    side_effect=lambda obs: (
                        {"reason": "image_audit_kubernetes_module_versions_unresolved"}
                        if obs["image_id"] in audit.image_kubernetes_inventory.INVENTORIES
                        else None
                    ),
                )
            )
            stack.enter_context(patch.object(audit.image_kubernetes_aliases, "resolve", resolve))
            stack.enter_context(patch.object(audit.image_kubernetes_scans, "run_batch", batch))
            stack.enter_context(
                patch.object(audit.image_kubernetes_scans, "read_batch", read_batch)
            )
            if fault in ("operator-join", "operator-io"):

                def supplement(component, target, *args):
                    calls.append("operator")
                    self.assertTrue(component["scan_executed"])
                    self.assertEqual(component["observed_reference"], target["reference"])
                    if fault == "operator-io":
                        raise OSError("private-evidence-path")
                    return {**component, "cilium_operator_supplemental": {"controlled": True}}

                stack.enter_context(patch.object(audit, "supplement_operator", supplement))
            result = audit.audit(root, runtime_state=root / ".runtime")
            persisted = read_json(root / audit.REPORT)
        self.assertEqual(calls.count("db-update"), 1)
        self.assertEqual(result["runtime_scope"]["expected_images"], 14)
        self.assertEqual(result["status"], "fail")
        self.assertFalse(result["release_ready"])
        for row in observed:
            self.assertIn(row["name"] + "-scan", calls)
        for component in persisted["components"]:
            if component.get("scan_executed"):
                self.assertEqual(component["findings"][0]["id"], "CVE-2026-12345")
        return result, calls

    def test_one_batch_after_all_originals_and_one_join_per_reviewed_image(self):
        report, calls = self.audit()
        self.assertEqual(calls.count("batch"), 1)
        self.assertEqual(calls.count("join"), 4)
        self.assertLess(calls.index("runtime-013-scan"), calls.index("batch"))
        self.assertEqual(report["runtime_scope"]["covered_images"], 4)
        self.assertNotIn("kubernetes_supplemental_error", report)

    def test_operator_supplement_keeps_the_original_findings_and_isolates_io_failure(self):
        for fault in ("operator-join", "operator-io"):
            with self.subTest(fault=fault):
                report, calls = self.audit(fault)
                component = next(
                    row for row in report["components"] if row["name"] == "runtime-005"
                )
                self.assertEqual(calls.count("operator"), 1)
                self.assertEqual(component["severity_counts"]["High"], 1)
                self.assertEqual(component["status"], "fail")
                if fault == "operator-io":
                    self.assertFalse(component["sbom_validated"])
                    self.assertEqual(
                        component["reason"], report["cilium_operator_supplemental_error"]
                    )
                    self.assertIsNone(report["vulnerability_count"])
                else:
                    self.assertIn("cilium_operator_supplemental", component)
                self.assertNotIn(b"private-evidence-path", canonical(report))

    def test_late_replay_failure_retains_verified_findings_without_group_credit(self):
        for fault in ("replay", "read-error"):
            with self.subTest(fault=fault):
                report, calls = self.audit(fault)
                self.assertEqual(calls.count("join"), 4)
                self.assertEqual(report["runtime_scope"]["covered_images"], 0)
                self.assertEqual(
                    report["kubernetes_supplemental_error"],
                    "image_audit_kubernetes_join_incomplete",
                )
                rows = [row for row in report["components"] if row["name"].startswith("runtime-")]
                self.assertEqual([len(row["findings"]) for row in rows], [2, 1, 2, 2] + [1] * 10)
                self.assertEqual(rows[0]["status"], "inconclusive")
                self.assertNotIn(b"private-evidence-path", canonical(report))

    def test_cleanup_refusal_keeps_all_originals_without_module_coverage(self):
        report, calls = self.audit("cleanup")
        self.assertEqual(calls.count("batch"), 1)
        self.assertNotIn("join", calls)
        self.assertEqual(report["runtime_scope"]["covered_images"], 0)
        self.assertEqual(
            report["kubernetes_supplemental_error"], "kubernetes_scan_cleanup_unconfirmed"
        )
        for component in report["components"]:
            if component["name"].startswith("runtime-"):
                self.assertTrue(component["scan_executed"])
                self.assertEqual(component["severity_counts"]["High"], 1)

    def test_missing_fourth_original_or_mapping_never_credits_the_other_three(self):
        for fault in ("original", "database", "mapping", "unmapped"):
            with self.subTest(fault=fault):
                report, calls = self.audit(fault)
                self.assertNotIn("batch", calls)
                self.assertEqual(report["runtime_scope"]["covered_images"], 0)
                row = next(c for c in report["components"] if c["name"] == "runtime-003")
                self.assertEqual(row["scan_executed"], fault in ("mapping", "unmapped"))

    def test_batch_io_failure_withholds_count_and_private_path(self):
        report, calls = self.audit("batch-io")
        self.assertNotIn("join", calls)
        self.assertEqual(report["runtime_scope"]["covered_images"], 0)
        self.assertIsNone(report["vulnerability_count"])
        self.assertNotIn(b"private-evidence-path", canonical(report))

    def test_all_four_local_archives_are_verified_for_both_existing_reference_forms(self):
        for case, binding in (("upstream-local", "manifest"), ("config-local", "config")):
            with self.subTest(case=case):
                report, calls = self.audit(case)
                self.assertEqual(calls.count("local-proof"), 4)
                self.assertEqual(report["runtime_scope"]["covered_images"], 4)
                for row in [c for c in report["components"] if "local_alias" in c]:
                    self.assertEqual(
                        row["kubernetes_supplemental"]["mapping"]["reference_binding"], binding
                    )
                    self.assertEqual(row["containerd_export"]["config_id"], row["image_config_id"])

    def test_original_report_digest_binds_the_bytes_assessed_before_file_changes(self):
        report, _ = self.audit("report-bytes")
        row = next(c for c in report["components"] if c["name"] == "runtime-000")
        self.assertEqual(row["report_digest"], self.original_digest)
        self.assertEqual(len(row["findings"]), 1)
        self.assertEqual(row["reason"], "kubernetes_scan_original_changed")
        self.assertEqual(report["runtime_scope"]["covered_images"], 0)

    def test_containerd_repack_keeps_observed_reference_and_uses_config_binding(self):
        report, calls = self.audit("local")
        self.assertEqual(calls.count("batch"), 1)
        self.assertEqual(report["runtime_scope"]["covered_images"], 4)
        for row in [c for c in report["components"] if "local_alias" in c]:
            mapping = row["kubernetes_supplemental"]["mapping"]
            self.assertEqual(mapping["reference_binding"], "config")
            self.assertTrue(row["observed_reference"].startswith("docker.io/library/import-"))
            self.assertNotEqual(
                mapping["manifest_digest"], row["containerd_export"]["runtime_digest"]
            )
            target = {
                "name": row["name"],
                "reference": row["observed_reference"],
                "containerd_reference": row["local_alias"],
                "config_id": row["image_config_id"],
            }
            changed = row | {
                "containerd_export": row["containerd_export"]
                | {"selected_manifest_digest": "sha256:" + "c" * 64}
            }
            # A well-formed replacement of the local chain cannot reuse the retained join.
            with patch.object(audit.image_kubernetes_aliases, "resolve", return_value=mapping):
                self.assertTrue(audit.image_kubernetes_scans.coverage_valid(row, target))
                self.assertFalse(audit.image_kubernetes_scans.coverage_valid(changed, target))

    def test_failed_local_proof_or_registry_fallback_preserves_original_findings(self):
        for fault in ("local-proof", "changed-archive", "proof-io", "registry-fallback"):
            with self.subTest(fault=fault):
                report, calls = self.audit(fault)
                self.assertNotIn("batch", calls)
                self.assertEqual(report["runtime_scope"]["covered_images"], 0)
                self.assertEqual(
                    sum(
                        row["scan_executed"]
                        for row in report["components"]
                        if row["name"].startswith("runtime-")
                    ),
                    14,
                )


if __name__ == "__main__":
    unittest.main()
