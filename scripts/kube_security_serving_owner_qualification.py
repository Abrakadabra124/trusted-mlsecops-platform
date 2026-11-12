"""Audit readback must reuse the verified HTTP owner, never overlap its identity."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import kube_serving_handoff
from mlsecops import kube_serving_service as service
from mlsecops.contracts import Rejected
from scripts import kube_security_native as subject


class ServingOwner(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.profile = {"image": "pinned", "image_id": "sha256:" + "a" * 64}
        self.snapshot = {"pin": "b" * 64, "records": []}
        self.enterContext(patch.object(subject, "hosted"))
        self.enterContext(patch.object(service, "directory", return_value=self.path))

    def test_active_owner_is_used_without_creating_a_second_job(self):
        self.assertTrue(hasattr(subject, "serving_readback"))
        with (
            patch.object(service, "validate", return_value={"profile": self.profile}),
            patch.object(service, "pod", return_value={"metadata": {"uid": "owner"}}),
            patch.object(service, "execute", return_value=self.snapshot) as execute,
            patch.object(subject, "job") as job,
        ):
            result = subject.serving_readback("state", self.profile)
        self.assertEqual(result, {"mode": "service", "pod_uid": "owner", "snapshot": self.snapshot})
        execute.assert_called_once_with("state", subject.SERVING)
        job.assert_not_called()

    def test_host_guard_runs_before_filesystem_and_remote_reads(self):
        with (
            patch.object(subject, "hosted", side_effect=Rejected("hosted-only")),
            patch.object(service, "directory") as directory,
            patch.object(service, "execute") as execute,
            self.assertRaisesRegex(Rejected, "hosted-only"),
        ):
            subject.serving_readback("state", self.profile)
        directory.assert_not_called()
        execute.assert_not_called()

    def test_absent_service_uses_existing_owned_probe(self):
        with (
            patch.object(service, "directory", return_value=self.path / "absent"),
            patch.object(service, "execute") as execute,
            patch.object(subject, "job", return_value=self.snapshot) as job,
        ):
            result = subject.serving_readback("state", self.profile)
        self.assertEqual(result, {"mode": "probe", "pod_uid": None, "snapshot": self.snapshot})
        job.assert_called_once_with("state", self.profile, subject.SERVING, serving=True)
        execute.assert_not_called()

    def test_existing_invalid_or_suspended_service_never_falls_back_to_a_job(self):
        with (
            patch.object(service, "validate", side_effect=Rejected("suspended-or-invalid")),
            patch.object(service, "execute") as execute,
            patch.object(subject, "job") as job,
            self.assertRaisesRegex(Rejected, "suspended-or-invalid"),
        ):
            subject.serving_readback("state", self.profile)
        execute.assert_not_called()
        job.assert_not_called()

    def test_changed_profile_refuses_before_remote_execution(self):
        with (
            patch.object(service, "validate", return_value={"profile": {"image": "foreign"}}),
            patch.object(service, "execute") as execute,
            patch.object(subject, "job") as job,
            self.assertRaises(Rejected),
        ):
            subject.serving_readback("state", self.profile)
        execute.assert_not_called()
        job.assert_not_called()

    def test_changed_pod_or_failed_readback_does_not_spawn_replacement(self):
        for failed in (False, True):
            with (
                self.subTest(failed=failed),
                patch.object(service, "validate", return_value={"profile": self.profile}),
                patch.object(
                    service,
                    "pod",
                    side_effect=[{"metadata": {"uid": "old"}}, {"metadata": {"uid": "other"}}],
                ),
                patch.object(
                    service,
                    "execute",
                    side_effect=Rejected("readback-failed") if failed else None,
                    return_value=self.snapshot,
                ),
                patch.object(subject, "job") as job,
                self.assertRaises(Rejected),
            ):
                subject.serving_readback("state", self.profile)
            job.assert_not_called()

    def test_direct_serving_job_refuses_existing_owner_even_with_incomplete_marker(self):
        with (
            patch.object(subject, "kubectl") as api,
            self.assertRaisesRegex(Rejected, "audit_serving_owner_present"),
        ):
            subject.job("state", self.profile, subject.SERVING, serving=True)
        api.assert_not_called()

    def test_orphaned_pod_blocks_probe_even_without_a_service_marker(self):
        with (
            patch.object(service, "directory", return_value=self.path / "absent"),
            patch.object(
                kube_serving_handoff, "require_probe_slot", side_effect=Rejected("orphaned-owner")
            ),
            patch.object(subject, "kubectl") as api,
            self.assertRaisesRegex(Rejected, "orphaned-owner"),
        ):
            subject.job("state", self.profile, subject.SERVING, serving=True)
        api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
