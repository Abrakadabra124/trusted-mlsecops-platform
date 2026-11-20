"""Controlled integration of Kubernetes supplements into the existing image auditor."""

import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, sentinel

from mlsecops.contracts import Rejected, canonical
from scripts import image_audit as audit
from scripts.image_audit_qualification import fixtures


class KubernetesAuditIntegration(unittest.TestCase):
    def test_original_image_auditor_runs_one_batch_then_joins_bound_artifacts(self):
        sbom, report, _, config, _ = fixtures()
        observation = {"image_id": config}
        database = {"schema_version": "v6.1.10", "built": "fixed"}
        target = {
            "name": "runtime-000",
            "reference": "registry.example/kube@" + config,
            "config_id": config,
        }
        runtime = {"targets": [target], "source_revision": "r", "source_fingerprint": "f"}
        calls = []
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory).resolve()

            def scanner(run, name, image, args, mounts=(), network=False):
                calls.append(name)
                path = run / f"{name}.json"
                document = sbom if name.endswith("-sbom") else report
                path.write_bytes(canonical(document))
                return 0, path

            def join(component, sbom_path, report_path, code, batch, reference, expected):
                self.assertEqual(component["image_config_id"], config)
                self.assertEqual(sbom_path.read_bytes(), canonical(sbom))
                self.assertEqual(report_path.read_bytes(), canonical(report))
                self.assertIs(batch, sentinel.batch)
                self.assertEqual(reference, target["reference"])
                self.assertEqual(expected, database)
                self.assertEqual(code, 0)
                calls.append("join")
                return {
                    **component,
                    "coverage_profile": "kubernetes-supplemental",
                    "sbom_validated": True,
                    "status": "pass",
                }

            mocks = {
                "source_fingerprint": {"return_value": "f"},
                "command": {
                    "side_effect": lambda args, **kwargs: "r" if args[-1] == "HEAD" else ""
                },
                "inspect_image": {
                    "return_value": {"Id": config, "Config": {"Labels": {}, "User": "invalid"}}
                },
                "identity": {"return_value": config},
                "file_hash": {"return_value": "a" * 64},
                "scanner": {"side_effect": scanner},
                "inventory": {"side_effect": Rejected("baseline-outside-this-test")},
                "observe_packages": {"return_value": observation},
                "snapshot": {"return_value": {"db": "hash"}},
                "detection_control": {"return_value": None},
                "go_detection_control": {"return_value": None},
                "wolfi_detection_control": {"return_value": None},
                "database": {"return_value": database},
                "assess": {
                    "return_value": {
                        "status": "inconclusive",
                        "database": database,
                        "findings": [],
                        "unique_vulnerabilities": 0,
                    }
                },
            }
            for name, kwargs in mocks.items():
                stack.enter_context(patch.object(audit, name, **kwargs))
            stack.enter_context(patch.object(audit.tracking_spike, "materials", return_value="t"))
            stack.enter_context(patch.object(audit.image_scope, "collect", return_value=runtime))
            stack.enter_context(
                patch.object(
                    audit.image_scope,
                    "coverage",
                    return_value={"status": "pass", "expected_images": 1, "covered_images": 1},
                )
            )
            stack.enter_context(
                patch.object(
                    audit.image_kubernetes_inventory,
                    "diagnose",
                    return_value={"reason": "unresolved"},
                )
            )
            stack.enter_context(
                patch.object(
                    audit.image_kubernetes_aliases, "resolve", return_value={"proof": "fixed"}
                )
            )
            batch = stack.enter_context(
                patch.object(
                    audit.image_kubernetes_scans,
                    "run_batch",
                    side_effect=lambda *args: calls.append("batch") or sentinel.batch,
                )
            )
            joined = stack.enter_context(
                patch.object(audit.image_kubernetes_scans, "join", side_effect=join)
            )
            result = audit.audit(root, runtime_state={})
            batch.assert_called_once()
            joined.assert_called_once()
            component = next(c for c in result["components"] if c["name"] == target["name"])
            self.assertEqual(component["coverage_profile"], "kubernetes-supplemental")
            self.assertEqual(component["status"], "pass")
            self.assertLess(calls.index("go-stdlib-detection-control"), calls.index("batch"))
            self.assertLess(calls.index("batch"), calls.index("runtime-000-scan"))
            self.assertLess(calls.index("runtime-000-scan"), calls.index("join"))
            self.assertFalse(result["release_ready"])


if __name__ == "__main__":
    unittest.main()
