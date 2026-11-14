"""Controlled regression tests for pinned M12 scheduling and evidence ownership."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from mlsecops import inference_gate as gate
from mlsecops.contracts import Rejected, bounded_read, digest, write_json
from scripts import m12_pinned_native as staged


class PinnedWindowTests(unittest.TestCase):
    def test_case_inventory_requires_both_permit_digests(self):
        self.assertTrue(
            {"qualification-permit-payload", "qualification-permit-envelope"} <= gate.NATIVE_CASES
        )

    def test_early_pin_without_proposal_cannot_start_legacy_qualification(self):
        with (
            TemporaryDirectory() as directory,
            patch.dict(gate.os.environ, {"M12_EARLY_SHA256": "a" * 64}, clear=True),
            patch.object(gate, "hosted"),
            patch.object(gate.kube_serving_native, "prepare") as prepare,
            self.assertRaisesRegex(Rejected, "proposal_required"),
        ):
            gate.qualify(Path(directory), Path(directory))
        prepare.assert_not_called()

    def test_inline_and_staged_paths_use_the_same_long_campaign_once(self):
        packet = dict(
            owner="owned",
            prepared={"profile": "owned"},
            actual={"started_at": "early"},
            primary="controls",
            peer="candidate",
        )
        for staged_capture in (False, True):
            for fault in (
                "none",
                "bytes",
                "runner",
                "primary",
                "peer_before",
                "peer_after",
                "controlled",
            ):
                with self.subTest(staged=staged_capture, fault=fault), TemporaryDirectory() as tmp:
                    state = Path(tmp)
                    path = state / staged.PACKET
                    write_json(path, packet)
                    pin = digest(bounded_read(path)) if staged_capture else None
                    if fault == "bytes":
                        if not staged_capture:
                            continue
                        path.write_bytes(b"{}")
                    owners = ["other" if fault == "runner" else "owned", "owned"]
                    histories = [
                        "changed" if fault == "primary" else "controls",
                        "changed" if fault == "peer_before" else "candidate",
                        "changed" if fault == "peer_after" else "candidate",
                    ]
                    campaign = Mock(return_value={"status": "pass"})
                    if fault == "controlled":
                        campaign.side_effect = Rejected("controlled_outage")
                    with (
                        patch.object(staged, "hosted"),
                        patch.object(staged, "owner", side_effect=owners),
                        patch.object(staged, "verify"),
                        patch.object(staged, "capture", return_value=packet) as capture,
                        patch.object(staged.kube_authority_pair, "read", side_effect=histories),
                        patch.object(staged.kube_serving_native, "qualify", campaign),
                    ):
                        if fault == "none":
                            start, native = staged.finish(state, state, "image", "pin", pin)
                            self.assertEqual(
                                (start, native["actual_inference"]), ("early", packet["actual"])
                            )
                        else:
                            with self.assertRaises(Rejected):
                                staged.finish(state, state, "image", "pin", pin)
                        self.assertEqual(capture.call_count, int(not staged_capture))
                        if fault in ("none", "peer_after", "controlled"):
                            campaign.assert_called_once_with(
                                state, state, "image", prepared=packet["prepared"]
                            )
                        else:
                            campaign.assert_not_called()

    def test_no_long_campaign_when_early_candidate_refuses(self):
        with (
            patch.object(staged, "hosted"),
            patch.object(staged, "owner"),
            patch.object(
                staged.kube_serving_native, "prepare", return_value={"profile": {}, "actual": {}}
            ) as prepare,
            patch.object(staged.kube_authority_pair, "read"),
            patch.object(
                staged.kube_candidate_native,
                "qualify",
                side_effect=Rejected("candidate_inference_window"),
            ) as actual,
            patch.object(staged.kube_serving_native, "qualify") as controlled,
            self.assertRaisesRegex(Rejected, "candidate_inference_window"),
        ):
            staged.finish("root", "state", "image", "original", None)
        prepare.assert_called_once_with("root", "state", "image", proposal_pin="original")
        actual.assert_called_once_with("root", "state", "image", prepared=({}, {}), pinned_m12=True)
        controlled.assert_not_called()
