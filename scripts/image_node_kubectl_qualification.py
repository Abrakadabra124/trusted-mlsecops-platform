"""Offline checks for the kubectl-only binding, scanner evidence and refusal paths."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import image_node_kubectl_inventory as inv
from scripts import image_node_kubectl_scan as scan


class KubectlTests(unittest.TestCase):
    def setUp(self):
        self.lines = [
            "binary: go1.26.5",
            "path\tk8s.io/kubernetes/cmd/kubectl",
            "mod\tk8s.io/kubernetes\tv1.36.4",
            "dep\texample.org/pkg\tv1.2.3",
            *["dep\t" + m + "\t(devel)" for m in inv.MODULES],
            *["build\t" + k + "=" + v for k, v in inv.SETTINGS.items()],
        ]
        self.versions = {
            "stdlib": "go1.26.5",
            "k8s.io/kubernetes": "v1.36.4",
            "example.org/pkg": "v1.2.3",
            **dict.fromkeys(inv.MODULES, "UNKNOWN"),
        }
        rows = [inv.row(k, v) for k, v in self.versions.items()]
        self.enterContext(
            patch.object(inv, "ROWS_SHA", digest(canonical(sorted(rows, key=canonical))))
        )
        self.enterContext(patch.object(inv, "COUNT", len(rows)))

    def test_complete_go_inventory_and_proof(self):
        self.assertEqual(inv.build_info("\n".join(self.lines)), self.versions)
        self.assertEqual(len(inv.coordinates()), 9)
        self.assertIn("k8s.io/cli-runtime", inv.coordinates())
        for old, new in (
            ("modified=false", "modified=true"),
            ("k8s.io/cli-runtime", "k8s.io/other"),
            ("v1.2.3", "v1.2.4"),
            (inv.REVISION, "e" * 40),
            ("linux", "darwin"),
            ("cmd/kubectl", "cmd/kubelet"),
            ("(devel)", "v0.36.4"),
        ):
            with self.subTest(old=old), self.assertRaises(Rejected):
                inv.build_info("\n".join(self.lines).replace(old, new))
        for extra in ("=>\t./moved\t(devel)", self.lines[3]):
            with self.assertRaises(Rejected):
                inv.build_info("\n".join(self.lines + [extra]))

    def test_file_only_syft_rejects_missing_extra_moved_duplicate_or_changed(self):
        def package(k, v):
            return dict(
                id=k,
                name=k,
                version=v,
                type="go-module",
                foundBy=inv.CATALOGER,
                locations=[{"path": "usr/bin/kubectl", "accessPath": "/usr/bin/kubectl"}],
            )

        rows = [package(k, v) for k, v in self.versions.items()]
        sbom = dict(
            descriptor=dict(name="syft", version=inv.SYFT_VERSION),
            source=dict(type="directory", metadata=dict(path="/input")),
            artifacts=rows,
        )
        self.assertEqual(set(inv.check_sbom(sbom, self.versions)), set(self.versions))
        for new in (
            rows[:-1],
            rows + [rows[0]],
            rows + [package("other", "v1")],
            [{**rows[0], "version": "wrong"}, *rows[1:]],
            [{**rows[0], "locations": [{"path": "/etc/shadow"}]}, *rows[1:]],
        ):
            with self.assertRaises(Rejected):
                inv.check_sbom({**sbom, "artifacts": new}, self.versions)

    def test_baseline_eight_are_exact_and_findings_are_not_discarded(self):
        zero = dict.fromkeys(scan.SEVERITIES, 0)
        results = {
            m: dict(
                purl=f"pkg:golang/{m}@v0.36.4",
                findings=[],
                status="pass",
                matches=0,
                database=scan.DATABASE,
                severity_counts=zero,
                matching_completed=True,
                package_identity_bound=True,
                scanner_exit_code=0,
            )
            for m in inv.MODULES
        }
        self.assertTrue(scan.compare_previous(results)["matches_previous"])
        results["k8s.io/cli-runtime"]["status"] = "fail"
        self.assertTrue(scan.compare_previous(results)["matches_previous"])
        results["k8s.io/api"]["findings"] = [{"id": "control"}]
        self.assertFalse(scan.compare_previous(results)["matches_previous"])
        del results["k8s.io/api"]
        with self.assertRaises(Rejected):
            scan.compare_previous(results)

    def test_before_scanning_wrong_elf_or_db_aborts(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        binary = root / "kubectl"
        binary.write_bytes(b"foreign")
        with self.assertRaisesRegex(Rejected, "elf"):
            inv.check_elf(binary)
        with (
            patch.object(scan.audit, "snapshot", return_value={"6/vulnerability.db": "wrong"}),
            self.assertRaisesRegex(Rejected, "database"),
        ):
            scan.check_db(root)

    def test_local_entrypoint_stops_before_any_runtime(self):
        with patch.dict(os.environ, GITHUB_ACTIONS="false"), patch.object(inv, "qualify") as run:
            with self.assertRaises(SystemExit):
                inv.main()
            run.assert_not_called()

    def test_printed_json_roundtrip_preserves_duplicate_raw_matches_and_hash(self):
        raw = {"vulnerability": {"id": "TEST-1", "severity": "High"}}
        doc = {
            "status": "fail",
            "original_matches": [raw, raw],
            "supplemental": {"k8s.io/cli-runtime": {"raw_matches": [raw]}},
        }
        with redirect_stdout(io.StringIO()) as log:
            inv.emit(doc)
        data, marker = log.getvalue().rstrip().rsplit("\n", 1)
        self.assertEqual(json.loads(data), doc)
        self.assertEqual(marker, "kubectl_report_sha256=" + digest(canonical(json.loads(data))))
        with redirect_stdout(io.StringIO()) as log:
            with self.assertRaises(Rejected):
                inv.emit({"oversize": "x" * 16385})
            with patch.object(inv, "render", return_value="{}"), self.assertRaises(Rejected):
                inv.emit(doc)
        self.assertEqual(log.getvalue(), "")

    def test_no_container_start_and_cleanup_after_unsuccessful_readback(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        cid = "c" * 64
        commands = []

        def run(args, **kwargs):
            commands.append(args)
            if args[1] == "create":
                (directory / "node.cid").write_text(cid)
            elif args[1] == "inspect":
                return inv.CONFIG + " created"
            elif args[1] == "cp":
                raise Rejected("copy_failure")

        with (
            patch.object(inv, "command", side_effect=run),
            patch.object(inv, "confirm_absent") as absent,
            self.assertRaisesRegex(Rejected, "copy_failure"),
        ):
            inv.copy_binary(directory, directory / "kubectl")
        self.assertEqual([args[1] for args in commands], ["create", "inspect", "cp", "rm"])
        self.assertEqual(commands[-1], ["docker", "rm", "-v", cid])
        absent.assert_called_once_with(directory / "node.cid")

    def test_original_grype_scope_counts_occurrences_and_checks_package_id(self):
        hit = {
            "artifact": {
                "id": "stdlib-id",
                "name": "stdlib",
                "version": "go1.26.5",
                "type": "go-module",
            },
            "vulnerability": {"id": "TEST", "severity": "High"},
        }
        raw = {"matches": [hit, hit], "source": {"type": "directory", "target": "/input"}}
        by_id = {"stdlib-id": ("stdlib", "go1.26.5")}
        with patch.object(scan, "database", return_value=scan.DATABASE):
            self.assertEqual(scan.assess_original(raw, 2, by_id)["High"], 2)
            for changed, rc, ids in (
                (raw, 0, by_id),
                (raw, 2, {}),
                ({**raw, "ignoredMatches": [hit]}, 2, by_id),
                ({**raw, "source": {"type": "directory", "target": "/other"}}, 2, by_id),
            ):
                with self.assertRaises(Rejected):
                    scan.assess_original(changed, rc, ids)
