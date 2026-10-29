"""Pure source-lock preflight; never starts infrastructure or signs a release."""

import shutil
import tempfile
import unittest
from pathlib import Path

from mlsecops import data_source
from mlsecops.contracts import Rejected, read_json, write_json


class SourceLockContracts(unittest.TestCase):
    def test_checkout_matches_committed_lock(self):
        root = Path(__file__).resolve().parents[1]
        data_source.validate_lock(root)

    def test_signing_helper_is_pinned_and_each_signing_input_mutation_rejects(self):
        origin = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in (*data_source.INPUTS, "mlsecops/key_files.py"):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(origin / name, target)
            write_json(
                root / "data.lock",
                {**read_json(origin / "data.lock"), "inputs": data_source.inputs(root)},
            )
            data_source.validate_lock(root)
            self.assertIn("mlsecops/key_files.py", data_source.INPUTS)
            for name in ("mlsecops/key_files.py", "mlsecops/signing.py", "mlsecops/data_source.py"):
                with self.subTest(name=name):
                    target = root / name
                    original = target.read_bytes()
                    target.write_bytes(original + b"\n# synthetic mutation\n")
                    with self.assertRaisesRegex(Rejected, "source_lock_mismatch"):
                        data_source.validate_lock(root)
                    target.write_bytes(original)
                    data_source.validate_lock(root)


if __name__ == "__main__":
    unittest.main()
