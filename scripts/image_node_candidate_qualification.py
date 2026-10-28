import copy
import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, write_json
from scripts import image_audit
from scripts import image_node_candidate as candidate


class NodeCandidateContracts(unittest.TestCase):
    def test_candidate_scope_cannot_mix_with_runtime_or_other_candidates(self):
        for options in ({"runtime_state": Path("unused")}, {"include_candidates": True}):
            with (
                patch.object(image_audit.shutil, "disk_usage") as disk,
                self.assertRaises(Rejected),
            ):
                image_audit.audit(Path("unused"), include_node_candidate=True, **options)
            disk.assert_not_called()

    def test_hosted_build_binds_verified_archive_and_preserves_runtime_pin(self):
        for scenario in ("clean", "dirty", "disk", "kind", "archive", "source", "bytes", "build"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                calls = []

                def command(arguments, **kwargs):
                    calls.append(arguments)
                    if "--porcelain" in arguments:
                        return " M file" if scenario == "dirty" else ""
                    if arguments == ["kind", "version"]:
                        return "kind v0.33.0" if scenario != "kind" else "kind v0.32.0"
                    if arguments[:3] == ["kind", "build", "node-image"] and scenario == "build":
                        raise Rejected("controlled_build_failure")
                    return "a" * 40

                def download(path, expected):
                    if scenario == "archive":
                        raise Rejected("node_candidate_archive_digest_mismatch")
                    self.assertEqual(expected, candidate.PINS["archive_sha256"])
                    path.write_bytes(b"controlled verified archive")

                def inspect(reference):
                    return {"Id": "sha256:" + hashlib.sha256(reference.encode()).hexdigest()}

                with (
                    patch.object(candidate.platform, "system", return_value="Linux"),
                    patch.object(candidate.platform, "machine", return_value="x86_64"),
                    patch.dict(
                        candidate.os.environ,
                        {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"},
                    ),
                    patch.object(
                        candidate.shutil,
                        "disk_usage",
                        return_value=SimpleNamespace(
                            free=1 if scenario == "disk" else 20 * 1024**3
                        ),
                    ),
                    patch.object(
                        candidate,
                        "materials",
                        side_effect=[
                            "f" * 64,
                            "e" * 64 if scenario == "source" else "f" * 64,
                            "f" * 64,
                        ],
                    ),
                    patch.object(candidate, "command", side_effect=command),
                    patch.object(candidate, "download", side_effect=download),
                    patch.object(candidate, "inspect_image", side_effect=inspect),
                    patch.object(
                        candidate,
                        "file_hash",
                        return_value="0" * 64
                        if scenario == "bytes"
                        else candidate.PINS["archive_sha256"],
                    ),
                ):
                    if scenario == "clean":
                        result = candidate.build(root)
                        self.assertEqual(result["status"], "pass")
                        self.assertFalse(result["release_ready"])
                    else:
                        with self.assertRaises(Rejected):
                            candidate.build(root)
                builds = [c for c in calls if c[:3] == ["kind", "build", "node-image"]]
                if scenario in {"dirty", "disk", "kind", "archive"}:
                    self.assertFalse(builds)
                elif scenario == "clean":
                    self.assertEqual(len(builds), 1)
                    self.assertIn(candidate.PINS["base"], builds[0])
                    self.assertIn(candidate.IMAGES["candidate"], builds[0])
                    self.assertIn("file", builds[0])
                self.assertFalse(any("create" in c or "delete" in c for c in calls))

    def test_materials_change_when_recipe_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in (
                "scripts/image_node_candidate.py",
                "scripts/install_ci_tools.py",
                "infra/kind.yaml",
            ):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"pinned material")
            with patch.object(candidate, "source_fingerprint", return_value="f" * 64):
                before = candidate.materials(root)
                (root / "infra/kind.yaml").write_bytes(b"changed")
                self.assertNotEqual(before, candidate.materials(root))

    def test_download_checks_bytes_and_never_overwrites_existing_file(self):
        payload = b"verified archive bytes"
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "archive.tar.gz"
            with patch.object(
                candidate.urllib.request, "urlopen", return_value=io.BytesIO(payload)
            ):
                candidate.download(target, hashlib.sha256(payload).hexdigest())
            self.assertEqual(target.read_bytes(), payload)
            with self.assertRaises(FileExistsError):
                candidate.download(target, hashlib.sha256(payload).hexdigest())

    def test_mismatch_oversize_and_truncation_fail_before_build(self):
        for payload, expected, limit in (
            (b"wrong", "0" * 64, 100),
            (b"oversized", hashlib.sha256(b"oversized").hexdigest(), 3),
            (b"", hashlib.sha256(b"expected").hexdigest(), 100),
        ):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as temporary:
                with patch.object(
                    candidate.urllib.request, "urlopen", return_value=io.BytesIO(payload)
                ):
                    with self.assertRaises(Rejected):
                        candidate.download(Path(temporary) / "archive", expected, limit)

    def test_non_hosted_or_wrong_platform_never_calls_runtime(self):
        for system, machine, environment in (
            ("Windows", "AMD64", {}),
            ("Linux", "x86_64", {}),
            ("Linux", "aarch64", {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}),
            ("Linux", "x86_64", {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}),
        ):
            with (
                patch.object(candidate.platform, "system", return_value=system),
                patch.object(candidate.platform, "machine", return_value=machine),
                patch.dict(candidate.os.environ, environment, clear=True),
                patch.object(candidate, "command") as command,
                self.assertRaises(Rejected),
            ):
                candidate.build(Path("unused"))
            command.assert_not_called()

    def fixture(self, root):
        report = {
            "status": "pass",
            "scope": "node-candidate-build-only",
            "release_ready": False,
            "materials": candidate.PINS,
            "source_materials": "f" * 64,
            "source_revision": "a" * 40,
            "images": {
                role: {"reference": reference, "config_id": "sha256:" + str(index) * 64}
                for index, (role, reference) in enumerate(candidate.IMAGES.items(), 1)
            },
        }
        write_json(root / candidate.REPORT, report)
        return report

    def test_binding_accepts_only_exact_current_images_and_materials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = self.fixture(root)
            images = {
                item["reference"]: {"Id": item["config_id"]} for item in report["images"].values()
            }
            with (
                patch.object(candidate, "materials", return_value="f" * 64),
                patch.object(candidate, "command", return_value="a" * 40),
                patch.object(candidate, "inspect_image", side_effect=images.__getitem__),
            ):
                self.assertEqual(candidate.validate(root), report)
                for mutate in (
                    lambda r: r.update(status="inconclusive"),
                    lambda r: r.update(release_ready=True),
                    lambda r: r.update(scope="release"),
                    lambda r: r.update(source_materials="e" * 64),
                    lambda r: r.update(source_revision="b" * 40),
                    lambda r: r["materials"].update(archive_sha256="0" * 64),
                    lambda r: r["images"].pop("baseline"),
                    lambda r: r["images"]["candidate"].update(reference="other:latest"),
                    lambda r: r["images"]["candidate"].update(config_id="sha256:" + "f" * 64),
                    lambda r: r.pop("scope"),
                    lambda r: r.update(images=None),
                ):
                    forged = copy.deepcopy(report)
                    mutate(forged)
                    write_json(root / candidate.REPORT, forged)
                    with self.subTest(mutation=mutate), self.assertRaises(Rejected):
                        candidate.validate(root)


if __name__ == "__main__":
    unittest.main()
