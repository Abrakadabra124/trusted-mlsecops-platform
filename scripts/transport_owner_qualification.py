import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch

from mlsecops import qualification
from mlsecops.contracts import Rejected
from mlsecops.worker_transport import CleanupIncomplete


class TransportOwnerContracts(unittest.TestCase):
    def test_cleanup_incomplete_stops_each_negative_without_next_spawn_or_evidence(self):
        envelope = {
            "schema_version": 1,
            "output": {"ok": True},
            "diagnostics": {
                "bytes": 19,
                "gpu_discovery_warning": False,
                "raw_output_retained": False,
            },
        }
        for index in range(4):
            outcomes = [
                envelope,
                *[Rejected("controlled_expected") for _index in range(index)],
                CleanupIncomplete(),
            ]
            with (
                patch("sys.argv", ["qualification"]),
                patch.object(qualification, "read_json", return_value={}),
                patch.object(qualification, "initialize", return_value={}),
                patch.object(
                    qualification.subprocess,
                    "run",
                    return_value=Mock(returncode=1, stderr=b"required_tool_missing"),
                ),
                patch.object(qualification, "capture", side_effect=outcomes) as capture,
                patch.object(qualification, "write_json") as write,
                redirect_stdout(io.StringIO()) as output,
                redirect_stderr(io.StringIO()) as diagnostic,
            ):
                self.assertEqual(qualification.main(), 1)
            self.assertEqual(capture.call_count, index + 2)
            write.assert_not_called()
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(
                diagnostic.getvalue(), "Qualification failed: worker_cleanup_incomplete\n"
            )


if __name__ == "__main__":
    unittest.main()
