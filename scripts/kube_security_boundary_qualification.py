"""Promoter-only fixed-source mounting and cleanup without Kubernetes."""

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical
from scripts import kube_privacy_bundle as bundle
from scripts import kube_security_boundary as boundary
from scripts.kube_serving_runtime_qualification import PROFILE


class BoundaryJobContracts(unittest.TestCase):
    def test_failed_boundary_readback_reports_only_validated_public_location(self):
        value = {
            "status": "fail",
            "release_ready": False,
            "code": "security_audit_boundary_probe_rejected",
            "location": {
                "exception": "Rejected",
                "source_file": "scripts/security_audit_boundary_probe.py",
                "source_line": 1,
            },
        }
        self.assertEqual(boundary.failure_diagnostic(canonical(value)), value)
        for content in (
            b"PRIVATE",
            b"x" * 65537,
            canonical({**value, "private": "PRIVATE"}),
            canonical({**value, "location": {**value["location"], "source_file": "PRIVATE"}}),
        ):
            self.assertIsNone(boundary.failure_diagnostic(content))

    def test_projected_fixture_setup_reads_image_policy_and_lock_without_sql(self):
        root = Path(__file__).resolve().parents[1]
        document, spec = boundary.materials(root, PROFILE, "a" * 32, "proof")
        volume = next(v["configMap"] for v in spec["volumes"] if v["name"] == "qualification-code")
        mount = next(
            m for m in spec["containers"][0]["volumeMounts"] if m["name"] == "qualification-code"
        )
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary) / "app"
            (app / "policies").mkdir(parents=True)
            for name in ("policies/local-cpu.json", "uv.lock"):
                shutil.copyfile(root / name, app / name)
            projected = Path(temporary) / "volume" if mount.get("subPath") else app / "scripts"
            revision = projected / "..2026_projection"
            revision.mkdir(parents=True)
            items = volume.get("items", [{"key": name, "path": name} for name in document["data"]])
            for item in items:
                path = revision / item["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(document["data"][item["key"]], encoding="utf-8")
            (projected / "..data").symlink_to(revision.name, target_is_directory=True)
            for name in {Path(item["path"]).parts[0] for item in items}:
                (projected / name).symlink_to(
                    Path("..data") / name, target_is_directory=(revision / name).is_dir()
                )
            if mount.get("subPath"):
                # A directory bind mount exposes the selected directory's entries;
                # copying that view simulates it without mount privileges or a cluster.
                shutil.copytree(
                    (projected / mount["subPath"]).resolve(), app / "scripts", symlinks=True
                )
            program = textwrap.dedent("""
                import json
                import sys
                from pathlib import Path
                from unittest.mock import patch

                app = Path(sys.argv[1]).resolve()
                sys.path[:0] = [str(app), sys.argv[2]]

                def no_external(event, arguments):
                    if event in {"socket.connect", "socket.bind", "subprocess.Popen"}:
                        raise AssertionError("fixture attempted external I/O")

                sys.addaudithook(no_external)
                from mlsecops import storage
                from scripts import candidate_lineage_qualification as lineage
                from scripts.security_audit_boundary_probe import fixtures

                fixture = None
                with patch.object(storage, "connect", side_effect=AssertionError("SQL prohibited")):
                    try:
                        fixtures.PromotionAdmissionContracts.setUpClass()
                        fixture = fixtures.PromotionAdmissionContracts()
                        fixture.setUp()
                        policy = json.loads((app / "policies/local-cpu.json").read_bytes())
                        assert lineage.CandidateLineageContracts.policy == {
                            **policy, "rows": 496, "split_counts": [64, 32, 400]
                        }
                        assert fixture.fixture.bundle.lock == (app / "uv.lock").read_bytes()
                        modules = [module for name, module in sys.modules.items()
                                   if name == "scripts" or name.startswith("scripts.")]
                        assert all(Path(module.__file__).resolve().parent == app / "scripts"
                                   for module in modules)
                    finally:
                        try:
                            if fixture is not None:
                                assert fixture.doCleanups()
                        finally:
                            fixtures.PromotionAdmissionContracts.tearDownClass()
                print(json.dumps({"policy_loaded": True, "lock_loaded": True,
                                  "fixture_cleanup": True, "mounted_imports": len(modules)}))
                """)
            result = subprocess.run(
                [sys.executable, "-I", "-B", "-W", "error", "-c", program, str(app), str(root)],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertEqual(
                json.loads(result.stdout),
                {
                    "policy_loaded": True,
                    "lock_loaded": True,
                    "fixture_cleanup": True,
                    "mounted_imports": len(document["data"]),
                },
            )

    def test_source_subdirectory_is_part_of_the_verified_pod_contract(self):
        root = Path(__file__).resolve().parents[1]
        document, spec = boundary.materials(root, PROFILE, "a" * 32, "proof")
        self.assertIs(document["immutable"], True)
        volume = next(v["configMap"] for v in spec["volumes"] if v["name"] == "qualification-code")
        self.assertEqual(
            volume["items"],
            [{"key": name, "path": "source/" + name} for name in sorted(document["data"])],
        )
        observed = copy.deepcopy(spec)
        observed.update(dnsPolicy="ClusterFirst", schedulerName="default-scheduler")
        boundary.audit_state.pod_spec(spec, observed)
        for field, value in (("subPath", "foreign"), ("subPath", None), ("readOnly", False)):
            changed = copy.deepcopy(observed)
            mount = next(
                m
                for m in changed["containers"][0]["volumeMounts"]
                if m["name"] == "qualification-code"
            )
            self.assertEqual((mount["subPath"], mount["readOnly"]), ("source", True))
            if value is None:
                del mount[field]
            else:
                mount[field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                boundary.audit_state.pod_spec(spec, changed)
        changed = copy.deepcopy(observed)
        volume = next(
            v["configMap"] for v in changed["volumes"] if v["name"] == "qualification-code"
        )
        volume["items"][0]["path"] = "foreign/__init__.py"
        with self.assertRaises(Rejected):
            boundary.audit_state.pod_spec(spec, changed)

    def test_explicit_fixture_bundle_is_bounded_and_promoter_scoped(self):
        root = Path(__file__).resolve().parents[1]
        result = bundle.manifest(root, "proof", "a" * 32, entry="security_audit_boundary_probe")
        self.assertIn("security_audit_boundary_probe.py", result["data"])
        self.assertIn("promotion_qualification.py", result["data"])
        self.assertLess(sum(len(v.encode()) for v in result["data"].values()), bundle.MAX_BYTES)
        document, spec = boundary.materials(root, PROFILE, "a" * 32, "proof")
        self.assertEqual(document["metadata"]["namespace"], "ml-promoter")
        self.assertEqual(spec["serviceAccountName"], "promoter")
        self.assertEqual(
            spec["containers"][0]["command"],
            ["python", "-m", "scripts.security_audit_boundary_probe"],
        )
        mounts = {v["mountPath"] for v in spec["containers"][0]["volumeMounts"]}
        self.assertTrue({"/client", "/security", "/audit", "/app/scripts"} <= mounts)
        self.assertNotIn("/trust-client", mounts)

    def test_unowned_host_refused_before_any_read_or_create(self):
        with (
            patch.object(boundary, "hosted", side_effect=Rejected("unowned")),
            patch.object(boundary.audit_state, "validate") as validate,
            patch.object(boundary, "kubectl") as api,
            self.assertRaises(Rejected),
        ):
            boundary.invoke(Path("unused"), PROFILE)
        validate.assert_not_called()
        api.assert_not_called()

    def test_cleanup_is_attempted_when_creation_fails(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(boundary, "hosted"),
            patch.object(boundary.audit_state, "validate", return_value={"workspace_id": "a" * 32}),
            patch.object(boundary, "kubectl", side_effect=Rejected("create")),
            patch.object(boundary.kube_promotion, "cleanup") as cleanup,
            self.assertRaises(Rejected),
        ):
            boundary.invoke(Path(temporary), PROFILE)
        cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
