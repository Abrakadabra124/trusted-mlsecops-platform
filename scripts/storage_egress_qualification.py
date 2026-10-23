import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import kube_storage_qualification as qualification
from mlsecops.contracts import Rejected


class StorageEgressContracts(unittest.TestCase):
    def test_recipe_declares_probe_dependency(self):
        recipe = (
            Path(__file__).resolve().parents[1] / "images/candidates/storage/Dockerfile"
        ).read_text()
        self.assertIn("'bash=5.3-r14'", recipe)
        self.assertIn("'coreutils=9.12-r4'", recipe)
        self.assertIn('test "$(apk info | wc -l)" -eq 60', recipe)
        self.assertIn('test "$?" -eq 124', recipe)

    def test_positive_control_then_timed_denial(self):
        results = [subprocess.CompletedProcess([], 0, output, b"") for output in (b"0", b"124")]
        with (
            patch.object(qualification, "kubectl", side_effect=results) as kubectl,
            patch.object(qualification.time, "monotonic", side_effect=(10.0, 13.25)),
        ):
            report = qualification.postgres_egress_denied(Path("controlled"), "10.79.0.10")
        self.assertEqual(report["positive_control"], "connected")
        self.assertEqual(report["negative_control"], "timeout")
        self.assertEqual(report["elapsed_seconds"], 3.25)
        self.assertEqual(kubectl.call_count, 2)
        for call, target in zip(
            kubectl.call_args_list, (("127.0.0.1", "5432"), ("10.79.0.10", "53")), strict=True
        ):
            arguments = call.args[1]
            self.assertEqual(
                arguments[:8],
                ["exec", "postgres-0", "-n", "ml-storage", "-c", "postgres", "--", "bash"],
            )
            self.assertIn("timeout 3 bash", arguments[9])
            self.assertEqual(arguments[-2:], list(target))
            self.assertEqual(call.kwargs, {"timeout": 12})

    def test_invalid_targets_do_not_execute(self):
        with patch.object(qualification, "kubectl") as kubectl:
            for address in ("127.0.0.1", "10.78.0.10", "::1", "--help", "10.79.0.10;id", None):
                with self.subTest(address=address), self.assertRaises(Rejected):
                    qualification.postgres_egress_denied(Path("controlled"), address)
            kubectl.assert_not_called()

    def test_missing_tools_open_network_or_early_kill_never_pass(self):
        for first, second, duration in (
            (b"127", b"124", 3.0),
            (b"124", b"124", 3.0),
            (b"0", b"0", 3.0),
            (b"0", b"1", 3.0),
            (b"0", b"127", 3.0),
            (b"0", b"137", 3.0),
            (b"0", b"143", 3.0),
            (b"0", b"124\nPRIVATE_CANARY", 3.0),
            (b"0", b"124", 0.5),
        ):
            with (
                self.subTest(first=first, second=second, duration=duration),
                patch.object(
                    qualification,
                    "kubectl",
                    side_effect=[
                        subprocess.CompletedProcess([], 0, output, b"PRIVATE_CANARY")
                        for output in (first, second)
                    ],
                ),
                patch.object(qualification.time, "monotonic", side_effect=(10.0, 10.0 + duration)),
                self.assertRaises(Rejected) as caught,
            ):
                qualification.postgres_egress_denied(Path("controlled"), "10.79.0.10")
            self.assertNotIn("PRIVATE_CANARY", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
