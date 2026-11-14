"""Ordinary M23 acceptance CLI must replace stale pass and redact rejected packets."""

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops import acceptance, security_gate
from mlsecops.contracts import Rejected, canonical, read_json, write_json


class Dispatch(unittest.TestCase):
    def test_missing_then_failed_then_accepted_capture_uses_current_state(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            state = Path(tmp)
            output = state / "M23.json"
            write_json(output, {"gate": "M23", "status": "pass"})
            args = ["acceptance", "--gate", "M23", "--state", tmp, "--output", str(output)]
            with patch.object(sys, "argv", args):
                self.assertEqual(acceptance.main(), 2)
                self.assertEqual(read_json(output)["status"], "inconclusive")
                for stage in security_gate.STAGES:
                    write_json(security_gate.stage_path(state, stage), {})
                write_json(state / "storage.json", {})
                with patch.object(security_gate, "qualify", side_effect=Rejected("CANARY")):
                    self.assertEqual(acceptance.main(), 1)
                failed = read_json(output)
                self.assertEqual(failed["status"], "fail")
                self.assertNotIn(b"CANARY", canonical(failed))
                evidence = dict(
                    status="pass",
                    started_at=failed["started_at"],
                    source_dirty=False,
                    cases=[{"id": "a"}],
                    checks=1,
                    metrics={},
                    limitations=["synthetic"],
                    artifact_hashes={"primary": "a" * 64},
                    input_digests={
                        "candidate_reference": "b" * 64,
                        "source_revision": failed["source_revision"],
                        "source_fingerprint": failed["input_digests"]["source_fingerprint"],
                    },
                )
                with patch.object(security_gate, "qualify", return_value=evidence):
                    with patch.dict(evidence["input_digests"], source_fingerprint="f" * 64):
                        self.assertEqual(acceptance.main(), 1)
                    self.assertEqual(acceptance.main(), 0)
                passed = read_json(output)
                self.assertEqual(passed["status"], "pass")
                self.assertIs(passed["release_ready"], False)
                self.assertEqual(passed["input_digests"]["candidate_reference"], "b" * 64)
                self.assertEqual(passed["artifact_hashes"], {"primary": "a" * 64})
