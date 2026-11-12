"""Two expiry observations retain one owner transfer and the original short approval."""

import importlib.util
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected


class ApprovalCampaign(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("scripts.kube_approval_campaign"))
        from scripts import kube_approval_campaign

        self.subject = kube_approval_campaign
        self.order = []
        self.fixture = SimpleNamespace(
            arguments={
                key: key
                for key in (
                    "package",
                    "policy_envelope",
                    "assurance_envelope",
                    "approval_envelope",
                    "reports",
                )
            },
            fixture=SimpleNamespace(
                bundle=SimpleNamespace(
                    materials=SimpleNamespace(fixture=SimpleNamespace(model=b"model"))
                )
            ),
        )
        self.expected = {"ready": False, "features": [[0.0]], "scores": [0.0]}
        self.enterContext(patch.object(self.subject, "hosted"))

        def owned(state, profile, operation):
            self.order.append("suspend")
            try:
                return {"value": operation(), "ownership": "verified-return"}
            finally:
                self.order.append("resume")

        self.owner = self.enterContext(
            patch.object(self.subject.ownership, "run", side_effect=owned)
        )
        self.shorten = self.enterContext(
            patch.object(
                self.subject, "shorten", side_effect=lambda *a: self.order.append("shorten") or 1090
            )
        )
        self.stage = self.enterContext(
            patch.object(self.subject, "stage", return_value={"proposal": "reference"})
        )
        self.promote = self.enterContext(
            patch.object(
                self.subject.kube_promotion,
                "invoke",
                return_value={
                    "status": "recorded-not-activated",
                    "receipt": {"subject_sha256": "b" * 64, "release_ready": False},
                },
            )
        )
        self.enterContext(patch.object(self.subject, "ledger", return_value={"unchanged": True}))

        def probe(*args):
            self.order.append("expiry" if "expires_at" in args[3] else "positive")
            return {"which": self.order[-1]}

        self.probe = self.enterContext(
            patch.object(self.subject.probes, "invoke", side_effect=probe)
        )

    def run_campaign(self):
        return self.subject.qualify(
            "root", "state", "image", "profile", "promotion", "config", self.fixture, self.expected
        )

    def test_two_real_probes_share_one_transfer_and_shortening_follows_suspend(self):
        result = self.run_campaign()
        self.assertEqual(self.order, ["suspend", "shorten", "positive", "expiry", "resume"])
        self.owner.assert_called_once()
        self.assertEqual(self.probe.call_count, 2)
        self.assertEqual(result["value"]["admitted"], {"which": "positive"})
        self.assertEqual(result["value"]["expiry"], {"which": "expiry"})
        self.assertEqual(self.probe.call_args_list[1].args[3]["expires_at"], 1090)
        self.assertTrue(self.probe.call_args_list[0].args[3]["ready"])
        self.assertFalse(self.expected["ready"])
        self.assertEqual(result["ownership"], "verified-return")

    def test_denied_or_ready_admission_cannot_run_inference(self):
        for result in (
            {"status": "rejected", "receipt": None},
            {"status": "recorded-not-activated", "receipt": None},
            {"status": "recorded-not-activated", "receipt": {"release_ready": True}},
        ):
            self.promote.return_value = result
            with self.assertRaisesRegex(Rejected, "approval_campaign_admission"):
                self.run_campaign()
            self.probe.assert_not_called()

    def test_expiry_failure_is_propagated_without_retry_or_new_approval(self):
        self.probe.side_effect = [{"status": "pass"}, Rejected("expiry_unobserved")]
        with self.assertRaisesRegex(Rejected, "expiry_unobserved"):
            self.run_campaign()
        self.shorten.assert_called_once()
        self.promote.assert_called_once()
        self.assertEqual(self.probe.call_count, 2)
        self.assertEqual(self.order[-1], "resume")

    def test_hosted_guard_and_shortening_failure_stop_before_admission(self):
        self.subject.hosted.side_effect = Rejected("hosted_only")
        with self.assertRaisesRegex(Rejected, "hosted_only"):
            self.run_campaign()
        self.owner.assert_not_called()
        self.subject.hosted.side_effect = None
        self.shorten.side_effect = Rejected("controlled_approval_window")
        with self.assertRaisesRegex(Rejected, "controlled_approval_window"):
            self.run_campaign()
        self.stage.assert_not_called()
        self.promote.assert_not_called()


if __name__ == "__main__":
    unittest.main()
