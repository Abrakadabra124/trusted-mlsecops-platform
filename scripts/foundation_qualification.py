import copy
import json
import platform
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import acceptance, bootstrap, foundation, inventory
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json

ROOT = Path(__file__).resolve().parents[1]


class FoundationContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "source"
        self.root.mkdir()
        (self.root / ".python-version").write_text(platform.python_version())
        (self.root / "pyproject.toml").write_text(
            '[project]\ndependencies = ["controlled-package==1.2.3"]\n'
        )
        (self.root / "uv.lock").write_bytes(b"version = 1\n")

    def test_environment_rejects_missing_wrong_or_unpinned_dependencies(self):
        with patch.object(inventory.metadata, "version", return_value="1.2.3"):
            versions = inventory.environment_versions(self.root)
        self.assertEqual(versions["packages"], {"controlled-package": "1.2.3"})
        for observed in ("1.2.4", None):
            with patch.object(inventory.metadata, "version", return_value=observed):
                with self.assertRaisesRegex(Rejected, "dependency_version_mismatch"):
                    inventory.environment_versions(self.root)
        with patch.object(
            inventory.metadata, "version", side_effect=inventory.metadata.PackageNotFoundError
        ):
            with self.assertRaisesRegex(Rejected, "dependency_missing"):
                inventory.environment_versions(self.root)
        (self.root / "pyproject.toml").write_text('[project]\ndependencies = ["unpinned>=1"]\n')
        with self.assertRaisesRegex(Rejected, "dependency_not_exactly_pinned"):
            inventory.environment_versions(self.root)

    def test_python_pin_is_enforced_before_dependency_inspection(self):
        (self.root / ".python-version").write_text("0.0.0")
        with patch.object(inventory.metadata, "version") as lookup:
            with self.assertRaisesRegex(Rejected, "python_version_mismatch"):
                inventory.environment_versions(self.root)
        lookup.assert_not_called()

    def invoke(self, root, state, empty_path=False):
        if empty_path:
            return subprocess.CompletedProcess([], 1, b"", b"required_tool_missing:git")
        result = bootstrap.initialize(root, state)
        return subprocess.CompletedProcess([], 0, canonical(result), b"")

    def test_repeat_bootstrap_preserves_keys_and_data_in_fresh_owned_directory(self):
        with (
            patch.object(bootstrap, "collect", return_value={"controlled": True}),
            patch.object(foundation, "invoke_bootstrap", side_effect=self.invoke),
        ):
            evidence = foundation.bootstrap_probe(ROOT, self.root)
        self.assertEqual(len(evidence["cases"]), 4)
        self.assertEqual(evidence["before"], evidence["after"])
        self.assertIn("approved/bootstrap-canary.bin", evidence["before"])
        self.assertFalse(any(self.root.glob("m01-*")))

    def test_repeat_mutation_and_missing_tool_bypass_fail(self):
        def changed(root, state, empty_path=False):
            result = self.invoke(root, state, empty_path)
            sentinel = state / "approved/bootstrap-canary.bin"
            if sentinel.exists() and not empty_path:
                sentinel.write_bytes(b"changed")
            return result

        for operation in (
            changed,
            lambda root, state, empty_path=False: self.invoke(root, state, False),
        ):
            with (
                patch.object(bootstrap, "collect", return_value={"controlled": True}),
                patch.object(foundation, "invoke_bootstrap", side_effect=operation),
            ):
                with self.assertRaises(Rejected):
                    foundation.bootstrap_probe(ROOT, self.root)

    def test_bootstrap_process_failures_are_not_a_pass(self):
        for output in (
            subprocess.CompletedProcess([], 1, b"", b"controlled"),
            subprocess.CompletedProcess([], 0, b"{}", b"warning"),
            subprocess.CompletedProcess([], 0, b"{}", b""),
            subprocess.CompletedProcess([], 0, b"invalid", b""),
        ):
            with patch.object(foundation, "invoke_bootstrap", return_value=output):
                with self.assertRaises(Rejected):
                    foundation.bootstrap_probe(ROOT, self.root)
        with (
            patch.object(bootstrap, "collect", return_value={"controlled": True}),
            patch.object(
                foundation,
                "invoke_bootstrap",
                side_effect=lambda root, state, empty_path=False: (
                    subprocess.CompletedProcess([], 0, b"{}", b"")
                    if (state / "workspace.json").exists()
                    else self.invoke(root, state)
                ),
            ),
        ):
            with self.assertRaisesRegex(Rejected, "foundation_repeat_identity_changed"):
                foundation.bootstrap_probe(ROOT, self.root)

    def test_fake_receipt_missing_keys_and_changed_environment_cannot_pass(self):
        for fault in ("receipt", "key", "environment"):

            def invoke(root, state, empty_path=False):
                result = self.invoke(root, state, empty_path)
                if fault == "receipt":
                    return subprocess.CompletedProcess([], 0, b"{}", b"")
                if fault == "key":
                    (state / "keys/curator.pem").unlink()
                if fault == "environment":
                    write_json(
                        state / "inventory.json",
                        {"changed": (state / "approved/bootstrap-canary.bin").exists()},
                    )
                return result

            with (
                patch.object(bootstrap, "collect", return_value={"controlled": True}),
                patch.object(foundation, "invoke_bootstrap", side_effect=invoke),
            ):
                with self.assertRaises(Rejected):
                    foundation.bootstrap_probe(ROOT, self.root)

    def test_invocation_has_explicit_root_state_timeout_and_missing_path(self):
        with patch.object(foundation.subprocess, "run") as execute:
            foundation.invoke_bootstrap(self.root, self.root / "state", empty_path=True)
        arguments = execute.call_args.args[0]
        self.assertEqual(arguments[-2:], [str(self.root), str(self.root / "state")])
        self.assertEqual(execute.call_args.kwargs["env"]["PATH"], "")
        self.assertEqual(execute.call_args.kwargs["timeout"], 90)
        with patch.object(foundation.subprocess, "run") as execute:
            foundation.invoke_bootstrap(self.root, self.root / "state")
        self.assertIn("PATH", execute.call_args.kwargs["env"])

    def test_incompatible_version_must_reject_before_workspace_creation(self):
        outcomes = (
            (subprocess.CompletedProcess([], 1, b"", b"python_version_mismatch"), False),
            (subprocess.CompletedProcess([], 0, b"", b""), True),
            (subprocess.CompletedProcess([], 1, b"unexpected", b"python_version_mismatch"), True),
            (subprocess.CompletedProcess([], 1, b"", b"other failure"), True),
        )
        for outcome, rejects in outcomes:
            with patch.object(foundation, "invoke_bootstrap", return_value=outcome):
                if rejects:
                    with self.assertRaises(Rejected):
                        foundation.incompatible_probe(self.root, self.root)
                else:
                    foundation.incompatible_probe(self.root, self.root)

        def created(root, state, empty_path=False):
            state.mkdir()
            return subprocess.CompletedProcess([], 1, b"", b"python_version_mismatch")

        with patch.object(foundation, "invoke_bootstrap", side_effect=created):
            with self.assertRaises(Rejected):
                foundation.incompatible_probe(self.root, self.root)

    def test_public_snapshot_contains_only_names_and_hashes(self):
        (self.root / "secret.pem").write_bytes(b"private-test-key")
        (self.root / "approved").mkdir()
        (self.root / "approved/inventory.json").write_bytes(b"nested-data")
        (self.root / "inventory.json").write_bytes(b"volatile-observation")
        snapshot = foundation.snapshot(self.root)
        self.assertEqual(snapshot["secret.pem"], digest(b"private-test-key"))
        self.assertEqual(snapshot["approved/inventory.json"], digest(b"nested-data"))
        self.assertNotIn("inventory.json", snapshot)
        self.assertNotIn("private-test-key", json.dumps(snapshot))
        with patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaisesRegex(Rejected, "foundation_snapshot_symlink"):
                foundation.snapshot(self.root)

    def test_docker_inventory_excludes_environment_and_requires_digest(self):
        inspected = {
            "Id": "sha256:" + "a" * 64,
            "Os": "linux",
            "Architecture": "amd64",
            "RepoDigests": ["registry/project@sha256:" + "b" * 64],
            "Config": {"Env": ["PASSWORD=private-canary"]},
        }
        with patch.object(foundation, "command", return_value=json.dumps([inspected])):
            observed = foundation.image_inventory("controlled:reference")
        self.assertNotIn("private-canary", json.dumps(observed))
        self.assertEqual(observed["image_id"], inspected["Id"])
        for field, value in (("Id", "latest"), ("Architecture", "arm64"), ("Os", "windows")):
            invalid = {**inspected, field: value}
            with patch.object(foundation, "command", return_value=json.dumps([invalid])):
                with self.assertRaises(Rejected):
                    foundation.image_inventory("controlled:reference")

    def test_cluster_inventory_requires_every_container_status(self):
        document = {
            "items": [
                {
                    "metadata": {"namespace": "kube-system", "name": "controlled"},
                    "spec": {"containers": [{"name": "controller", "image": "controller:v1"}]},
                    "status": {
                        "containerStatuses": [
                            {"name": "controller", "imageID": "containerd://sha256:" + "c" * 64}
                        ]
                    },
                }
            ]
        }
        observed = foundation.pod_inventory(document)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["image_id"], "sha256:" + "c" * 64)
        for mutation in ("missing", "empty", "invalid"):
            invalid = copy.deepcopy(document)
            if mutation == "missing":
                invalid["items"][0]["status"]["containerStatuses"] = []
            elif mutation == "empty":
                invalid["items"] = []
            else:
                invalid["items"][0]["status"]["containerStatuses"][0]["imageID"] = "latest"
            with self.assertRaises(Rejected):
                foundation.pod_inventory(invalid)

    def test_inventory_digest_covers_declared_locks_and_baseline(self):
        (self.root / "policies").mkdir()
        write_json(
            self.root / "policies/local-cpu.json",
            {"baseline_reference": foundation.BASELINE_REFERENCE},
        )
        with patch.object(foundation, "command", return_value="uv.lock\n"):
            observed = foundation.material_inventory(self.root)
        self.assertEqual(observed["locks"]["uv.lock"], digest(b"version = 1\n"))
        (self.root / "requirements.lock").write_bytes(b"controlled==1")
        with patch.object(foundation, "command", return_value="uv.lock\nrequirements.lock"):
            observed = foundation.material_inventory(self.root)
        self.assertIn("requirements.lock", observed["locks"])
        with patch.object(foundation, "command", return_value=""):
            with self.assertRaisesRegex(Rejected, "foundation_lock_inventory_empty"):
                foundation.material_inventory(self.root)
        write_json(self.root / "policies/local-cpu.json", {"baseline_reference": "changed"})
        with self.assertRaisesRegex(Rejected, "foundation_baseline_changed"):
            foundation.material_inventory(self.root)

    def qualification_context(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        state = self.root / "state"
        state.mkdir()
        write_json(state / "workspace.json", {"workspace_id": "controlled"})
        self.collected = {
            "source_dirty": False,
            "source_revision": "a" * 40,
            "source_fingerprint": "b" * 64,
        }
        self.cluster = {
            "workspace_id": "controlled",
            "chart_sha256": foundation.CHART_SHA256,
        }
        self.versions = {
            "git": "git version controlled",
            "uv": "uv 0.12.23",
            "kind": "kind v0.33.0 go1.25 linux/amd64",
            "helm": "v4.2.4+controlled",
            "kubectl": '{"clientVersion":{"gitVersion":"v1.36.4"}}',
            "docker": "sha256:" + "a" * 64,
        }
        for name, value in (
            ("collect", self.collected),
            ("validate_cluster", self.cluster),
            ("material_inventory", {"baseline_reference": foundation.BASELINE_REFERENCE}),
            ("resolve_image", "sha256:" + "c" * 64),
            ("image_inventory", {"image_id": "sha256:" + "c" * 64}),
            ("pod_inventory", [{"image_id": "sha256:" + "c" * 64}]),
            ("bootstrap_probe", {"cases": ["controlled"], "before": {}, "after": {}}),
            ("incompatible_probe", None),
            ("kubectl", subprocess.CompletedProcess([], 0, b"{}", b"")),
        ):
            stack.enter_context(patch.object(foundation, name, return_value=value))
        stack.enter_context(
            patch.object(
                foundation, "command", side_effect=lambda arguments: self.versions[arguments[0]]
            )
        )
        return state

    def test_qualification_composes_current_probes_and_writes_evidence(self):
        state = self.qualification_context()
        result = foundation.qualify(ROOT, state)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["checks"], len(result["cases"]))
        self.assertEqual(read_json(state / "evidence/foundation-qualification.json"), result)
        self.assertEqual(len(result["p0"]), 5)
        foundation.bootstrap_probe.assert_called_once_with(ROOT, state)
        foundation.incompatible_probe.assert_called_once_with(ROOT, state)

    def test_dirty_checkout_ownership_and_tool_version_are_rejected(self):
        state = self.qualification_context()
        self.collected["source_dirty"] = True
        with self.assertRaisesRegex(Rejected, "foundation_clean_checkout_required"):
            foundation.qualify(ROOT, state)
        self.collected["source_dirty"] = False
        self.cluster["workspace_id"] = "another-workspace"
        with self.assertRaisesRegex(Rejected, "foundation_workspace_mismatch"):
            foundation.qualify(ROOT, state)
        self.cluster["workspace_id"] = "controlled"
        for name in ("uv", "kind", "helm", "kubectl"):
            original = self.versions[name]
            self.versions[name] = (
                '{"clientVersion":{"gitVersion":"v0.0.0"}}' if name == "kubectl" else "v0.0.0"
            )
            with self.assertRaisesRegex(Rejected, "foundation_.*version_mismatch"):
                foundation.qualify(ROOT, state)
            self.versions[name] = original
        self.cluster["chart_sha256"] = "changed"
        with self.assertRaisesRegex(Rejected, "foundation_cluster_version_mismatch"):
            foundation.qualify(ROOT, state)
        self.assertFalse((state / "evidence").exists())

    def test_acceptance_prerequisites_outcomes_and_evidence_hash(self):
        state = self.root / "state"
        state.mkdir()
        with patch.object(acceptance, "command", return_value="a" * 40):
            missing = acceptance.report("M01", "local-cpu", ROOT, state)
        self.assertEqual((missing["status"], missing["exit_code"]), ("inconclusive", 2))
        for name in ("workspace.json", "cluster.json", "kubeconfig"):
            (state / name).touch()
        evidence = {
            "status": "pass",
            "cases": [{"id": "controlled", "status": "pass"}],
            "checks": 1,
            "limitations": ["controlled-unit-test"],
            "image_id": "sha256:" + "c" * 64,
            "inventory": {},
            "materials": {},
        }
        write_json(state / "evidence/foundation-qualification.json", evidence)
        with (
            patch.object(acceptance, "command", return_value="a" * 40),
            patch.object(foundation, "qualify", return_value=evidence),
        ):
            result = acceptance.report("M01", "local-cpu", ROOT, state)
        self.assertEqual((result["status"], result["exit_code"]), ("pass", 0))
        self.assertEqual(
            result["artifact_hashes"]["foundation_qualification"],
            digest((state / "evidence/foundation-qualification.json").read_bytes()),
        )
        for error, expected in (
            (Rejected("controlled_failure"), ("fail", 1)),
            (Rejected("required_tool_missing:docker"), ("inconclusive", 2)),
            (OSError("controlled"), ("inconclusive", 2)),
            (subprocess.TimeoutExpired("controlled", 1), ("inconclusive", 2)),
        ):
            with (
                patch.object(acceptance, "command", return_value="a" * 40),
                patch.object(foundation, "qualify", side_effect=error),
            ):
                result = acceptance.report("M01", "local-cpu", ROOT, state)
            self.assertEqual((result["status"], result["exit_code"]), expected)


class InventoryContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "mlsecops").mkdir()
        (self.root / "mlsecops/controlled.py").write_bytes(b"controlled = True\n")
        (self.root / "policies").mkdir()
        (self.root / "policies/local-cpu.json").write_bytes(b"{}")
        for name in (".python-version", "pyproject.toml", "uv.lock", "Dockerfile"):
            (self.root / name).write_bytes(b"controlled")
        self.engine = {
            "OSType": "linux",
            "NCPU": 4,
            "MemTotal": 16 * 1024**3,
            "ServerVersion": "controlled",
        }
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.which = self.stack.enter_context(
            patch.object(inventory.shutil, "which", return_value="controlled")
        )
        self.disk = self.stack.enter_context(
            patch.object(
                inventory.shutil, "disk_usage", return_value=SimpleNamespace(free=16 * 1024**3)
            )
        )
        self.stack.enter_context(
            patch.object(
                inventory,
                "environment_versions",
                return_value={"python": "controlled", "packages": {}},
            )
        )
        self.commands = self.stack.enter_context(
            patch.object(inventory, "command", side_effect=self.command)
        )

    def command(self, arguments, timeout=30):
        if arguments[0] == "docker":
            return json.dumps(self.engine)
        return "a" * 40 if arguments[-1] == "HEAD" else ""

    def test_inventory_binds_environment_resources_materials_and_source(self):
        result = inventory.collect(self.root)
        self.assertFalse(result["source_dirty"])
        self.assertEqual(result["environment"]["python"], "controlled")
        self.assertEqual(len(result["materials"]), 5)
        self.assertEqual(result["source_fingerprint"], inventory.source_fingerprint(self.root))
        previous = result["source_fingerprint"]
        (self.root / ".python-version").write_bytes(b"changed")
        self.assertNotEqual(previous, inventory.source_fingerprint(self.root))

    def test_missing_tool_and_python_major_minor_refuse_before_engine(self):
        self.which.return_value = None
        with self.assertRaisesRegex(Rejected, "required_tool_missing"):
            inventory.collect(self.root)
        self.which.return_value = "controlled"
        with patch.object(inventory.sys, "version_info", (3, 11)):
            with self.assertRaisesRegex(Rejected, "python_3_12_required"):
                inventory.collect(self.root)
        self.commands.assert_not_called()

    def test_incompatible_engine_capacity_and_missing_material_refuse(self):
        for field, value in (("OSType", "windows"), ("NCPU", 1), ("MemTotal", 1)):
            original = self.engine[field]
            self.engine[field] = value
            with self.assertRaisesRegex(Rejected, "incompatible_docker_profile"):
                inventory.collect(self.root)
            self.engine[field] = original
        self.disk.return_value = SimpleNamespace(free=1)
        with self.assertRaisesRegex(Rejected, "insufficient_disk_headroom"):
            inventory.collect(self.root)
        self.disk.return_value = SimpleNamespace(free=16 * 1024**3)
        (self.root / "Dockerfile").unlink()
        with self.assertRaisesRegex(Rejected, "missing_material:Dockerfile"):
            inventory.collect(self.root)

    def test_source_material_link_and_absence_refuse(self):
        with patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaisesRegex(Rejected, "invalid_source_material"):
                inventory.source_fingerprint(self.root)
        (self.root / "Dockerfile").unlink()
        with self.assertRaisesRegex(Rejected, "invalid_source_material"):
            inventory.source_fingerprint(self.root)

    def test_build_pins_source_fingerprint_platform_and_revision(self):
        expected = inventory.source_fingerprint(self.root)
        self.assertEqual(inventory.build_image(self.root, "controlled:build"), expected)
        arguments = self.commands.call_args.args[0]
        self.assertIn("linux/amd64", arguments)
        self.assertIn(f"org.trusted-mlsecops.source-fingerprint={expected}", arguments)
        self.assertIn("org.opencontainers.image.revision=" + "a" * 40, arguments)


class InventoryCommandContracts(unittest.TestCase):
    def test_build_context_and_runtime_recipes_include_python_pin(self):
        self.assertIn("!.python-version", (ROOT / ".dockerignore").read_text().splitlines())
        for name in ("Dockerfile", "images/candidates/worker/Dockerfile"):
            recipe = (ROOT / name).read_text()
            self.assertIn("COPY pyproject.toml uv.lock .python-version Dockerfile ./", recipe)

    def test_command_success_failure_missing_tool_and_timeout(self):
        with patch.object(
            inventory.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, " observed \n", ""),
        ):
            self.assertEqual(inventory.command(["controlled"]), "observed")
        with patch.object(
            inventory.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, "", "private"),
        ):
            with self.assertRaisesRegex(Rejected, "^required_tool_failed$"):
                inventory.command(["controlled"])
        for error in (OSError("private"), subprocess.TimeoutExpired("controlled", 1)):
            with patch.object(inventory.subprocess, "run", side_effect=error):
                with self.assertRaisesRegex(Rejected, "^required_tool_unavailable$"):
                    inventory.command(["controlled"])


if __name__ == "__main__":
    unittest.main()
