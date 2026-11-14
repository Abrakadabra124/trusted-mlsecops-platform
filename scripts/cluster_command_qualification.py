import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from mlsecops import cluster
from mlsecops.contracts import Rejected


class ClusterCommandContracts(unittest.TestCase):
    def test_quota_counts_export_only_known_integer_resources(self):
        message = b"private-canary: exceeded quota: private-budget, requested: count/configmaps=1, used: count/configmaps=4, limited: count/configmaps=4"
        self.assertEqual(
            cluster.quota_counts(message),
            {"resource": "count/configmaps", "requested": 1, "used": 4, "limited": 4},
        )
        for changed in (
            message.replace(b"count/configmaps", b"private-resource"),
            message.replace(
                b"limited: count/configmaps=4", b"limited: count/configmaps=private-canary"
            ),
            message.replace(b"used: count/configmaps=4", b"used: count/configmaps=-1"),
        ):
            self.assertIsNone(cluster.quota_counts(changed))

    def test_report_diagnostic_is_an_exact_finite_allowlist(self):
        for operation in ("exec", "replace", "get", "other"):
            self.assertEqual(
                cluster.request_failure(Rejected(f"kubernetes_request_failed:{operation}:timeout")),
                {"operation": operation, "category": "timeout"},
            )
        for message in (
            "private-canary",
            "kubernetes_request_failed:exec:timeout:private-canary",
            "kubernetes_request_failed:private-operation:timeout",
            "kubernetes_request_failed:exec:private-canary",
        ):
            self.assertIsNone(cluster.request_failure(Rejected(message)))
        self.assertIsNone(
            cluster.request_failure(ValueError("kubernetes_request_failed:exec:timeout"))
        )

    def test_safe_operation_and_failure_classification(self):
        scenarios = (
            (["logs", "private-pod"], b"container is waiting to start", "logs:container_pending"),
            (["delete", "job", "private-job"], b"timed out waiting", "delete:timeout"),
            (["get", "pod", "private-pod"], b"Error from server (NotFound)", "get:not_found"),
            (["create", "-f", "-"], b"Error from server (Forbidden)", "create:forbidden"),
            (["create", "-f", "-"], b"(Forbidden): exceeded quota: private-budget", "create:quota"),
            (
                ["create", "-f", "-"],
                b"(Forbidden): exceeded quota: private-budget, requested: count/configmaps=1, used: count/configmaps=4, limited: count/configmaps=4",
                "create:quota",
            ),
            (
                ["create", "-f", "-"],
                b"(Forbidden): admission webhook denied the request",
                "create:admission",
            ),
            (
                ["create", "-f", "-"],
                b"(Forbidden): User private-user cannot create resource private-resource",
                "create:rbac",
            ),
            (
                ["create", "-f", "-"],
                b"(Forbidden): violates PodSecurity private-policy",
                "create:pod_security",
            ),
            (["get", "pods"], b"connection refused", "get:connection_refused"),
            (
                ["exec", "pod"],
                b"private\nmlsecops.contracts.Rejected: security_readback_deadline\ncommand terminated with exit code 1",
                "exec:readback_deadline",
            ),
            (
                ["exec", "pod"],
                b"mlsecops.contracts.Rejected: security_store_busy",
                "exec:journal_busy",
            ),
            (
                ["exec", "pod"],
                b"mlsecops.contracts.Rejected: security_store_busy:secret",
                "exec:unknown",
            ),
            (["get", "pods"], b"mlsecops.contracts.Rejected: security_store_busy", "get:unknown"),
            (["get", "pods"], b"TLS handshake timeout", "get:timeout"),
            (["private-operation"], b"private diagnostic", "other:unknown"),
            ([], b"", "other:unknown"),
        )
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / "kubeconfig").write_text("controlled", encoding="utf-8")
            for arguments, message, expected in scenarios:
                output = io.StringIO()
                with (
                    self.subTest(expected=expected),
                    redirect_stderr(output),
                    patch.object(
                        cluster.subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess(
                            [], 1, b"PRIVATE_STDOUT_CANARY", message + b"\nPRIVATE_STDERR_CANARY"
                        ),
                    ),
                ):
                    with self.assertRaises(Rejected) as caught:
                        cluster.kubectl(state, arguments)
                    self.assertEqual(str(caught.exception), "kubernetes_request_failed:" + expected)
                    operation, category = expected.split(":")
                    self.assertEqual(
                        cluster.request_failure(caught.exception),
                        {"operation": operation, "category": category},
                    )
                    counts = cluster.quota_counts(message)
                    if counts is not None:
                        self.assertEqual(
                            json.loads(output.getvalue()),
                            {"event": "kubernetes-quota-refused", **counts},
                        )
                    else:
                        self.assertEqual(output.getvalue(), "")
                    self.assertNotIn("private", output.getvalue().lower())

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
