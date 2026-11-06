import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import kube_privacy_bundle as bundle


class ProbePackagingContracts(unittest.TestCase):
    def test_actual_bundle_imports_without_host_scripts_fallback(self):
        root = Path(__file__).resolve().parents[1]
        result = bundle.manifest(root, "probe-code", "workspace")
        self.assertTrue(result["immutable"])
        self.assertEqual(
            result["metadata"]["annotations"]["trusted-mlsecops/qualification-source"],
            digest(canonical(result["data"])),
        )
        self.assertLess(len(canonical(result)), 1024 * 1024)
        with tempfile.TemporaryDirectory() as directory:
            scripts = Path(directory) / "scripts"
            scripts.mkdir()
            for filename, content in result["data"].items():
                (scripts / filename).write_text(content, encoding="utf-8")
            check = "import sys,pathlib; sys.path[:0]=[sys.argv[1],sys.argv[2]]; import scripts.kube_privacy_probe; assert all(pathlib.Path(v.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]).resolve()) for k,v in sys.modules.items() if k.startswith('scripts.') and getattr(v,'__file__',None))"
            process = subprocess.run(
                [sys.executable, "-I", "-B", "-c", check, directory, str(root)],
                capture_output=True,
                timeout=30,
                env={**os.environ, "PYTHONUTF8": "1"},
            )
            self.assertEqual(process.returncode, 0, process.stderr.decode())
            self.assertEqual(process.stdout, b"")

    def test_bundle_rejects_nonflat_modules_and_size_overflow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            entry = root / "scripts/kube_privacy_probe.py"
            entry.write_text("from scripts.private.nested import value", encoding="utf-8")
            with self.assertRaisesRegex(Rejected, "privacy_bundle_module"):
                bundle.manifest(root, "probe", "workspace")
            entry.write_text("# fixture", encoding="utf-8")
            with (
                patch.object(bundle, "MAX_BYTES", 10),
                self.assertRaisesRegex(Rejected, "privacy_bundle_limit"),
            ):
                bundle.manifest(root, "probe", "workspace")


if __name__ == "__main__":
    unittest.main()
