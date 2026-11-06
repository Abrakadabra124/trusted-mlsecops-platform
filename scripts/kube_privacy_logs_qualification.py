import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import kube_privacy_logs as logs


def pod(*, terminal=True):
    return {
        "metadata": {
            "namespace": "ml-serve",
            "name": "serving-worker-pod",
            "uid": "pod-uid",
            "ownerReferences": [{"uid": "job-uid", "controller": True}],
        },
        "spec": {"containers": [{"name": "worker", "image": "image@sha256:" + "a" * 64}]},
        "status": {
            "phase": "Succeeded" if terminal else "Running",
            "containerStatuses": [
                {
                    "name": "worker",
                    "restartCount": 0,
                    "containerID": "containerd://" + "b" * 64,
                    "imageID": "image@sha256:" + "a" * 64,
                    "state": {"terminated": {"exitCode": 0}} if terminal else {"running": {}},
                }
            ],
        },
    }


class LogObservationContracts(unittest.TestCase):
    def capture(self, *, content=b"reply\n", changed=None, expected=b"reply\n", terminal=True):
        initial = pod(terminal=terminal)
        observations = [copy.deepcopy(initial), copy.deepcopy(initial)]
        if changed is not None:
            changed(observations)
        calls = []

        def kubectl(state, arguments, **options):
            calls.append(arguments)
            if arguments[0] == "get":
                return SimpleNamespace(stdout=canonical(observations.pop(0)))
            self.assertEqual(arguments[0], "logs")
            self.assertIn("--limit-bytes=" + str(logs.MAX_BYTES + 1), arguments)
            self.assertNotIn("--tail", arguments)
            return SimpleNamespace(stdout=content)

        with (
            patch.object(logs, "hosted"),
            patch.object(logs, "validate_cluster"),
            patch.object(logs, "kubectl", side_effect=kubectl),
        ):
            result = logs.capture(
                ".runtime",
                initial,
                owner_uid="job-uid",
                container="worker",
                needles=(b"synthetic-private-marker",),
                expected_output=expected,
                terminal=terminal,
            )
        return result, calls

    def test_terminal_capture_binds_exact_complete_stream_and_live_identity(self):
        (receipt, raw), calls = self.capture()
        self.assertEqual(raw, b"reply\n")
        self.assertEqual(receipt["sha256"], digest(raw))
        self.assertEqual(receipt["pod_uid"], "pod-uid")
        self.assertEqual(receipt["bytes"], 6)
        self.assertTrue(receipt["terminal"])
        self.assertTrue(receipt["exact_output"])
        self.assertFalse(receipt["release_ready"])
        self.assertEqual([c[0] for c in calls], ["get", "logs", "get"])
        self.assertNotIn("synthetic-private-marker", str(receipt))

    def test_running_service_capture_is_explicitly_a_window_not_full_lifecycle(self):
        (receipt, _), _calls = self.capture(terminal=False, expected=None)
        self.assertFalse(receipt["terminal"])
        self.assertFalse(receipt["exact_output"])
        self.assertEqual(receipt["scope"], "private-owned-pod-log-window-not-M13")

    def test_missing_truncated_extra_and_canary_output_never_pass(self):
        for content in (
            b"",
            b"reply",
            b"reply\nextra\n",
            b"synthetic-private-marker\n",
            b"x" * (logs.MAX_BYTES + 1),
        ):
            with self.subTest(size=len(content)), self.assertRaises(Rejected):
                self.capture(content=content)
        with self.assertRaisesRegex(Rejected, "privacy_log_canary"):
            self.capture(content=b"synthetic-private-marker", terminal=False, expected=None)

    def test_identity_restart_spec_and_terminal_changes_are_rejected(self):
        changes = (
            lambda p: p["metadata"].update(uid="other-pod"),
            lambda p: p["metadata"].update(name="other-pod"),
            lambda p: p["metadata"].update(namespace="other"),
            lambda p: p["metadata"]["ownerReferences"][0].update(uid="other-owner"),
            lambda p: p["spec"]["containers"][0].update(image="untrusted:latest"),
            lambda p: p["status"].update(phase="Running"),
            lambda p: p["status"]["containerStatuses"][0].update(restartCount=1),
            lambda p: p["status"]["containerStatuses"][0].update(restartCount=False),
            lambda p: p["status"]["containerStatuses"][0].update(containerID="other"),
            lambda p: p["status"]["containerStatuses"][0].update(imageID="other"),
            lambda p: p["status"]["containerStatuses"][0].update(
                state={"terminated": {"exitCode": 1}}
            ),
        )
        for change in changes:
            for index in (0, 1):
                with self.subTest(index=index, change=change), self.assertRaises(Rejected):
                    self.capture(changed=lambda rows: change(rows[index]))

    def test_invalid_or_unpinned_requests_never_read_logs(self):
        good = dict(
            owner_uid="job-uid",
            container="worker",
            needles=(b"canary",),
            expected_output=b"reply\n",
            terminal=True,
        )
        changes = (
            {"owner_uid": "foreign"},
            {"container": "other"},
            {"needles": ()},
            {"needles": (b"",)},
            {"needles": ("text",)},
            {"needles": (b"x" * 4097,)},
            {"needles": (b"x",) * 17},
            {"terminal": 1},
            {"expected_output": "text"},
            {"expected_output": b"x" * (logs.MAX_BYTES + 1)},
            {"expected_output": None},
        )
        for change in changes:
            with (
                self.subTest(change=list(change)),
                patch.object(logs, "hosted"),
                patch.object(logs, "validate_cluster"),
                patch.object(logs, "kubectl") as command,
                self.assertRaises(Rejected),
            ):
                logs.capture(".runtime", pod(), **{**good, **change})
            command.assert_not_called()

    def test_hosted_guard_precedes_cluster_and_log_access(self):
        with (
            patch.object(logs, "hosted", side_effect=Rejected("hosted")),
            patch.object(logs, "validate_cluster") as cluster,
            patch.object(logs, "kubectl") as command,
            self.assertRaisesRegex(Rejected, "^hosted$"),
        ):
            logs.capture(".runtime", {}, owner_uid="x", container="worker", needles=())
        cluster.assert_not_called()
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
