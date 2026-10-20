import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import cluster
from mlsecops.contracts import Rejected


class ClusterCommandContracts(unittest.TestCase):
    def test_safe_operation_and_failure_classification(self):
        scenarios = (
            (["logs", "private-pod"], b"container is waiting to start", "logs:container_pending"),
            (["delete", "job", "private-job"], b"timed out waiting", "delete:timeout"),
            (["get", "pod", "private-pod"], b"Error from server (NotFound)", "get:not_found"),
            (["create", "-f", "-"], b"Error from server (Forbidden)", "create:forbidden"),
            (["get", "pods"], b"connection refused", "get:connection_refused"),
            (["get", "pods"], b"TLS handshake timeout", "get:timeout"),
            (["private-operation"], b"private diagnostic", "other:unknown"),
            ([], b"", "other:unknown"),
        )
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / "kubeconfig").write_text("controlled", encoding="utf-8")
            for arguments, message, expected in scenarios:
                with (
                    self.subTest(expected=expected),
                    patch.object(
                        cluster.subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess(
                            [], 1, b"PRIVATE_STDOUT_CANARY", message + b" PRIVATE_STDERR_CANARY"
                        ),
                    ),
                ):
                    with self.assertRaises(Rejected) as caught:
                        cluster.kubectl(state, arguments)
                    self.assertEqual(str(caught.exception), "kubernetes_request_failed:" + expected)

    def test_success_and_unchecked_denials_keep_result(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / "kubeconfig").write_text("controlled", encoding="utf-8")
            for returncode, check in ((0, True), (1, False)):
                result = subprocess.CompletedProcess([], returncode, b"controlled", b"Forbidden")
                with patch.object(cluster.subprocess, "run", return_value=result):
                    self.assertIs(cluster.kubectl(state, ["get", "pods"], check=check), result)


if __name__ == "__main__":
    unittest.main()
