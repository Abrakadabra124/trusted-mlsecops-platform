"""Hosted producer orchestration checked with explicit synthetic observations and no infrastructure."""

import unittest
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected
from scripts import ci_campaign_publish as campaign
from scripts import ci_candidate_transfer as bridge
from scripts.ci_campaign_guard_qualification import SourceRun


class PublishOriginalTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.metadata = SourceRun(self)
        self.run, self.source = self.metadata.owner, self.metadata.source
        self.writer = object()
        self.origin = dict(workspace_id="c" * 32, container_id="a" * 64)
        self.key = bytes(range(32))
        self.now = 2200
        self.values = dict(proposal_issued_at=900, captured_at=999, proposal_expires_at=4000)
        self.packets = {
            name: {"context": {"issued_at": 1000, "expires_at": 2800}}
            for name in (
                "candidate-shared",
                "candidate-serving",
                "upstream-serving",
                "validation-serving",
            )
        }
        self.prepared = dict(
            owner=dict(run_owner=self.run, expected=self.source), reports={}, sealed=self.packets
        )
        self.fresh = self.enterContext(patch.object(bridge, "_fresh"))
        self.fresh.side_effect = lambda *args: (self.values, self.now)

        def observe(module, name, value):
            def seen(*args, **kwargs):
                self.events.append(name)
                return value

            return self.enterContext(patch.object(module, name, side_effect=seen))

        self.marker = observe(campaign.storage_bootstrap, "validate", self.origin)
        observe(campaign.cluster_owner, "cleanup", None)
        self.prepare = observe(campaign.producer, "prepare", self.prepared)
        self.stop = observe(campaign.recovery, "stop_owned", None)
        self.observe = observe(campaign.receipt, "offline_pin", "f" * 64)
        self.publish = observe(campaign.handoff, "publish", ("public", {"private": "receipt"}))
        self.checkpoint = Mock()

    def run_campaign(self, **changes):
        args = dict(
            api=self.writer,
            source_api=self.metadata.api,
            key=self.key,
            run_owner=self.run,
            source=self.source,
            checkpoint=self.checkpoint,
        )
        return campaign.publish_original("root", "state", **(args | changes))

    def test_single_prepare_stop_observation_and_signed_publication(self):
        self.assertEqual(self.run_campaign(), ("public", {"private": "receipt"}))
        self.assertLess(self.events.index("prepare"), self.events.index("stop_owned"))
        self.assertLess(self.events.index("stop_owned"), self.events.index("offline_pin"))
        self.assertLess(self.events.index("offline_pin"), self.events.index("publish"))
        self.prepare.assert_called_once()
        self.assertEqual(
            self.publish.call_args.kwargs["origin"], self.origin | {"offline_pin": "f" * 64}
        )
        self.assertIs(self.publish.call_args.kwargs["checkpoint"], self.checkpoint)
        self.assertIs(self.publish.call_args.args[0], self.writer)
        self.assertEqual(self.metadata.requests.count(("GET", self.metadata.run_path)), 3)
        self.fresh.assert_called_once_with("root", "state", self.prepared["owner"])

    def test_environment_or_caller_mismatch_fails_before_proposal(self):
        for changes in (
            dict(run_owner=self.run | {"run_attempt": 2}),
            dict(source=self.source | {"source_revision": "d" * 40}),
            dict(run_owner=self.run | {"producer_job": "serving"}),
            dict(key=b""),
            dict(checkpoint=None),
        ):
            with self.assertRaises(Rejected):
                self.run_campaign(**changes)
        self.prepare.assert_not_called()
        self.stop.assert_not_called()
        self.publish.assert_not_called()

    def test_producer_state_change_or_failed_offline_check_refuses_publication(self):
        self.marker.side_effect = [self.origin, self.origin | {"container_id": "f" * 64}]
        with self.assertRaises(Rejected):
            self.run_campaign()
        self.marker.side_effect = None
        self.marker.return_value = self.origin
        self.observe.side_effect = Rejected("offline")
        with self.assertRaises(Rejected):
            self.run_campaign()
        self.publish.assert_not_called()

    def test_unexpected_freeze_owner_or_source_refuses_publication(self):
        for field, new in (
            ("run_owner", self.run | {"run_attempt": 2}),
            ("expected", self.source | {"source_fingerprint": "f" * 64}),
        ):
            self.prepare.side_effect = None
            self.prepare.return_value = self.prepared | {
                "owner": self.prepared["owner"] | {field: new}
            }
            with self.assertRaises(Rejected):
                self.run_campaign()
        self.stop.assert_not_called()
        self.publish.assert_not_called()

    def test_cleanup_receipt_is_checkpointed_but_no_success_output_on_readback_drift(self):
        self.observe.side_effect = ["f" * 64, "0" * 64]
        with self.assertRaises(Rejected):
            self.run_campaign()
        self.publish.assert_called_once()

    def test_last_readback_can_leave_a_single_packet_with_only_599_seconds(self):
        for name in self.packets:
            with (
                self.subTest(name=name),
                patch.dict(self.packets[name], context={"issued_at": 999, "expires_at": 2799}),
            ):
                self.now = 2199

                def complete_upload(*args, **kwargs):
                    self.now = 2200
                    return "public", {"private": "receipt"}

                self.publish.side_effect = complete_upload
                with self.assertRaises(Rejected):
                    self.run_campaign()

    def test_checkout_matching_receipt_of_another_dispatch_never_mutates(self):
        self.metadata.env["GITHUB_SHA"] = "d" * 40
        with self.assertRaises(Rejected):
            self.run_campaign()
        self.assertEqual(self.events, [])
        self.assertEqual(self.metadata.requests, [])

    def test_attempt_superseded_during_prepare_blocks_first_store_mutation(self):
        def prepare(*args, **kwargs):
            self.metadata.rows[self.metadata.run_path]["run_attempt"] = 2
            return self.prepared

        self.prepare.side_effect = prepare
        with self.assertRaises(Rejected):
            self.run_campaign()
        self.publish.assert_not_called()

    def test_attempt_superseded_during_upload_withholds_success(self):
        def publish(*args, **kwargs):
            self.metadata.rows[self.metadata.run_path]["run_attempt"] = 2
            return "public", {"private": "receipt"}

        self.publish.side_effect = publish
        with self.assertRaises(Rejected):
            self.run_campaign()
        self.publish.assert_called_once()

    def test_standard_frozen_state_and_window_readers_can_refuse_after_upload(self):
        self.fresh.side_effect = Rejected("frozen_state_changed")
        with self.assertRaises(Rejected):
            self.run_campaign()
        self.publish.assert_called_once()
        self.fresh.side_effect = lambda *args: (self.values, self.now)
        self.packets["upstream-serving"]["context"]["expires_at"] += 1
        with self.assertRaises(Rejected):
            self.run_campaign()
