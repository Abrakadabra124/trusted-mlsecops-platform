"""Exercise the observed node join with temporary scanner files and no container runtime."""

import copy
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import image_audit as audit
from scripts import image_observed_kubectl as subject
from scripts.image_audit_qualification import fixtures
from scripts.image_go_supplemental_qualification import MODULE, fixture

inv = subject.inv


class ObservedKubectlTests(unittest.TestCase):
    def setUp(self):
        self.run = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.cache = self.run / "cache"
        (self.cache / "6").mkdir(parents=True)
        (self.cache / "6/vulnerability.db").write_bytes(b"current database")
        self.files = audit.snapshot(self.cache)
        stamp = datetime.now(UTC)
        sbom, raw, hit, _, _ = fixtures()
        self.scanner_fixture = fixture(("High",), timestamp=stamp)
        raw["descriptor"] = self.scanner_fixture["report"]["descriptor"]
        sbom["source"]["metadata"]["imageID"] = raw["source"]["target"]["imageID"] = inv.CONFIG
        rows = [inv.row(m, "UNKNOWN") for m in inv.MODULES]
        rows.extend(inv.row(f"example.org/m{i}", "v1.0.0") for i in range(82 - len(rows)))
        qualified = subject.qualified_subject()
        self.enterContext(
            patch.object(inv, "ROWS_SHA", digest(canonical(sorted(rows, key=canonical))))
        )
        self.enterContext(
            patch.object(
                subject,
                "SUBJECT_SHA",
                digest(canonical({**qualified, "inventory_sha256": inv.ROWS_SHA})),
            )
        )
        sbom["artifacts"] = [
            {**r, "id": str(i), "locations": [{"accessPath": inv.BINARY}]}
            for i, r in enumerate(rows)
        ]
        # Same package and version in another file must not join by name.
        sbom["artifacts"].extend(
            {**rows[0], "id": str(i), "locations": [{"path": "/other"}]} for i in range(82, 878)
        )
        for i in (0, 0, 82):
            raw["matches"].append(
                {
                    **hit,
                    "artifact": {
                        k: sbom["artifacts"][i][k] for k in ("id", "name", "version", "type")
                    },
                }
            )
        original = subject.assess(sbom, raw, inv.CONFIG, set(), 2, diagnostic_only=True)
        self.db = original["database"]
        observation = subject.observe_packages(sbom, inv.CONFIG)
        self.enterContext(
            patch.object(
                subject,
                "OBSERVATION",
                digest(
                    canonical(
                        {**observation, "packages": sorted(observation["packages"], key=canonical)}
                    )
                ),
            )
        )
        self.node = dict(
            **original,
            vulnerability_count=original["unique_vulnerabilities"],
            name="runtime-019",
            role="system",
            runtime_image_id=inv.CONFIG,
            image_config_id=inv.CONFIG,
            observed_reference=inv.CONFIG,
            host_roles=["kind-node"],
            coverage_profile="unapproved-system",
            package_binding_validated=True,
            scan_executed=True,
            sbom_validated=False,
            reason="image_audit_runtime_application_coverage_unapproved",
            package_observation=observation,
        )
        for label, key, data in (("sbom", "sbom_digest", sbom), ("scan", "report_digest", raw)):
            content = canonical(data)
            (self.run / f"runtime-019-{label}.json").write_bytes(content)
            self.node[key] = digest(content)
        self.observed = dict(
            containers=[dict(image_id=inv.CONFIG, role="kind-node")],
            targets=[dict(name=self.node["name"], reference=inv.CONFIG, config_id=None)],
        )
        self.report = dict(
            components=[self.node],
            database_files=self.files,
            go_detection_controls={k: {"status": "pass"} for k in subject.GO_CONTROLS},
        )
        self.enterContext(patch.object(subject.scans, "confirm_absent"))
        self.scanner = self.enterContext(
            patch.object(audit, "scanner", side_effect=self.fake_scanner)
        )

    def fake_scanner(self, run, name, image, args, mounts):
        module, version = args[0].removeprefix("pkg:golang/").split("@")
        self.assertEqual(image, audit.GRYPE_IMAGE)
        self.assertEqual(mounts[0], (self.cache, "/cache", False))

        def material(key):
            value = self.scanner_fixture[key]
            content = value if isinstance(value, bytes) else canonical(value)
            return content.replace(MODULE.encode(), module.encode()).replace(
                b"v0.36.4", version.encode()
            )

        path = run / f"{name}.json"
        path.write_bytes(material("report"))
        (mounts[1][0] / "report.json").write_bytes(material("cdx"))
        path.with_suffix(".log").write_bytes(material("trace"))
        path.with_suffix(".cid").write_bytes(b"f" * 64)
        return self.scanner_fixture["returncode"], path

    def attach(self, batch):
        subject.attach(self.report, self.observed, self.run, self.cache, self.db, self.files, batch)

    def test_eight_reused_one_fresh_and_all_occurrences_retained(self):
        batch = subject.scans.run_batch(self.run, self.cache, self.db, self.files)
        self.scanner.reset_mock()
        before = copy.deepcopy(self.node)
        self.attach(batch)
        self.assertNotIn("kubectl_attribution_error", self.report)
        self.assertEqual(self.scanner.call_count, 1)
        proof = self.node["kubectl_attribution"]
        self.assertEqual(self.scanner.call_args.args[3][0], "pkg:golang/k8s.io/cli-runtime@v0.36.4")
        self.assertEqual(proof["database_sha256"], self.files["6/vulnerability.db"])
        self.assertEqual(proof["original_path_findings"], before["findings"][:2])
        self.assertEqual(self.node["findings"][:3], before["findings"])
        self.assertEqual((self.node["matches"], self.node["unique_vulnerabilities"]), (12, 2))
        self.assertTrue(proof["supplemental_complete"])
        self.assertEqual([r["module"] for r in proof["scans"]], list(inv.MODULES))
        self.assertTrue(all(r["database"] == self.db for r in proof["scans"]))
        for key in (
            "coverage_profile",
            "status",
            "sbom_validated",
            "reason",
            "package_observation",
        ):
            self.assertEqual(before[key], self.node[key])

    def test_missing_batch_or_control_retains_provenance_and_every_original(self):
        before = copy.deepcopy(self.node)
        self.attach(None)
        self.assertEqual(
            self.report["kubectl_attribution_error"], "kubectl_current_batch_unavailable"
        )
        self.assertFalse(self.node.pop("kubectl_attribution")["supplemental_complete"])
        self.assertEqual(self.node, before)
        batch = subject.scans.run_batch(self.run, self.cache, self.db, self.files)
        self.scanner.reset_mock()
        self.report["go_detection_controls"].pop("stdlib")
        self.attach(batch)
        self.scanner.assert_not_called()
        self.assertFalse(self.node["kubectl_attribution"]["supplemental_complete"])

    def test_clean_nine_cannot_clear_original_node_failure(self):
        self.scanner_fixture = fixture((), timestamp=self.scanner_fixture["timestamp"])
        batch = subject.scans.run_batch(self.run, self.cache, self.db, self.files)
        findings = copy.deepcopy(self.node["findings"])
        self.attach(batch)
        self.assertNotIn("kubectl_attribution_error", self.report)
        self.assertTrue(self.node["kubectl_attribution"]["supplemental_complete"])
        self.assertEqual(self.node["findings"], findings)
        self.assertEqual(self.node["status"], "fail")
        self.assertEqual(self.node["vulnerability_count"], 1)
        self.assertFalse(self.node["sbom_validated"])

    def test_tampered_prior_receipt_or_changed_database_does_not_complete(self):
        batch = subject.scans.run_batch(self.run, self.cache, self.db, self.files)
        self.scanner.reset_mock()
        (self.cache / "6/vulnerability.db").write_bytes(b"changed")
        self.attach(batch)
        self.assertEqual(
            self.report["kubectl_attribution_error"], "kubernetes_scan_database_changed"
        )
        (batch.directory / "module-00.log").write_bytes(b"changed")
        self.attach(batch)
        self.assertEqual(
            self.report["kubectl_attribution_error"], "kubernetes_scan_artifact_changed"
        )
        self.assertFalse(self.node["kubectl_attribution"]["supplemental_complete"])
        self.assertEqual(self.node["matches"], 3)
        self.scanner.assert_not_called()

    def test_identity_or_inventory_drift_rejects_before_scanning(self):
        for field, value in (
            ("host_roles", []),
            ("runtime_image_id", "other"),
            ("image_config_id", "other"),
            ("observed_reference", "other"),
            ("image_id", "other"),
            ("local_alias", "tag"),
            ("coverage_profile", "worker"),
            ("scan_executed", False),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                subject.bind(self.observed, [{**self.node, field: value}])
        target = self.observed["targets"][0]
        for fields in (
            dict(reference=inv.AMD64),
            dict(config_id="other"),
            dict(containerd_reference="tag"),
        ):
            with self.subTest(fields=fields), self.assertRaises(Rejected):
                subject.bind({**self.observed, "targets": [{**target, **fields}]}, [self.node])
        with self.assertRaises(Rejected):
            subject.bind({**self.observed, "containers": []}, [self.node])
        with (
            patch.object(inv, "ELF_SHA", "0" * 64),
            self.assertRaisesRegex(Rejected, "qualified_subject"),
        ):
            subject.bind(self.observed, [self.node])
        self.node["package_observation"]["packages"][0]["paths"] = ["/other"]
        changed = self.node["package_observation"]
        with (
            patch.object(
                subject,
                "OBSERVATION",
                digest(
                    canonical({**changed, "packages": sorted(changed["packages"], key=canonical)})
                ),
            ),
            self.assertRaisesRegex(Rejected, "kubectl_inventory"),
        ):
            subject.bind(self.observed, [self.node])
        self.node["package_observation"]["packages"].pop()
        self.attach(None)
        self.assertNotIn("kubectl_attribution", self.node)
        self.assertEqual(self.report["kubectl_attribution_error"], "kubectl_node_inventory")

    def test_changed_primary_bytes_or_findings_refuse_attribution(self):
        self.node["findings"].pop()
        self.attach(None)
        self.assertEqual(self.report["kubectl_attribution_error"], "kubectl_original_binding")
        (self.run / "runtime-019-scan.json").write_bytes(b"{}")
        self.attach(None)
        self.assertEqual(self.report["kubectl_attribution_error"], "kubectl_original_changed")
        self.assertNotIn("kubectl_attribution", self.node)
