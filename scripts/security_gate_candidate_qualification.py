"""Controlled M23 candidate gate qualification, with real signatures and retained files."""

import copy
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import security_inventory_evidence as inventory
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, decode, digest, write_json
from mlsecops.security_event_ledger import Ledger
from mlsecops.security_event_outbox import Outbox, key_identity
from scripts import kube_security_outage_native as outage
from scripts import kube_security_outage_native_qualification as outage_fixtures
from scripts import security_inventory_events_native as native
from scripts import security_inventory_evidence_qualification as inventory_fixtures
from scripts import security_outage_packet_qualification as window_fixtures

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PUBLIC = "evidence/security-inventory-public.json"
INVENTORY_PRIMARY = "evidence/security-inventory-primary.json"
PROPOSAL = "evidence/release-native.json"


class CandidateGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Obtain legacy labels from the real qualify loop at mocked OS/SQL boundaries.
        campaign = inventory_fixtures.NativeRetention()
        campaign.setUp()
        cls.addClassCleanup(campaign.doCleanups)
        cls.native_cases = campaign.campaign()["cases"]

    def setUp(self):
        from mlsecops import security_gate_candidate as gate

        self.gate = gate
        self.out = outage_fixtures.RetentionContracts()
        self.out.setUp()
        self.addCleanup(self.out.doCleanups)
        self.inv = inventory_fixtures.InventoryPrimary()
        self.inv.setUp()
        self.addCleanup(self.inv.doCleanups)
        self.state = self.out.state
        self.candidate = dict(
            **self.out.primary["source"],
            model_sha256=self.out.primary["model_sha256"],
            candidate_reference=self.inv.bindings["candidate_reference"],
            evaluation_reference=self.out.binding["context"]["lineage"]["evaluation_sha256"],
        )
        for name, value in (
            ("command", self.candidate["source_revision"]),
            ("source_fingerprint", self.candidate["source_fingerprint"]),
            ("materials", self.out.public["method_materials"]),
        ):
            self.enterContext(patch.object(outage, name, return_value=value))
        self.out.primary.update(
            candidate_reference=self.candidate["candidate_reference"],
            actual_refusal=dict(
                campaign_id="7" * 32,
                candidate=self.candidate["candidate_reference"],
                model=self.candidate["model_sha256"],
                proposal=self.out.primary["proposal_reference"],
                parent_refusal="release_assurance_required",
                job_outcome="rejected",
            ),
        )
        self.out.publish()
        self.proposal = dict(
            schema_version=1,
            finished_at="2026-11-14T07:14:28.123456+00:00",
            status="pass",
            full_M10="inconclusive",
            release_ready=False,
            scope="release-proposal-and-authorization-denial-not-full-M10",
            subject_sha256=self.out.primary["subject_sha256"],
            model_sha256=self.candidate["model_sha256"],
            proposal_reference=self.out.primary["proposal_reference"],
            campaign_id=self.out.primary["actual_refusal"]["campaign_id"],
            source=self.out.primary["source"],
            source_dirty=False,
        )
        write_json(self.state / PROPOSAL, self.proposal)
        self.proposal_sha = digest((self.state / PROPOSAL).read_bytes())
        self.enterContext(patch.dict(os.environ, M23_PROPOSAL_SHA256=self.proposal_sha))
        self.out.public["observation"] = outage.reverify(ROOT, self.state)
        self.out.publish()
        packet = self.inv.packet
        old = self.inv.bindings
        for row in packet["observations"]:
            req = row["candidate_request"]
            if req is not None:
                req["evaluation_reference"] = self.candidate["evaluation_reference"]
                for key, value in req["expected"].items():
                    if value == old[key]:
                        req["expected"][key] = self.candidate[key]
                row["request_sha256"] = digest(canonical(req))
                if row["case_id"] != "candidate-request-pin":
                    row["configured_request_sha256"] = row["request_sha256"]
        self.inv.bindings = self.candidate.copy()
        packet.update(
            source=self.candidate["source_revision"],
            fingerprint=self.candidate["source_fingerprint"],
            methods={name: digest((ROOT / name).read_bytes()) for name in inventory.METHODS},
            bindings=self.candidate.copy(),
        )
        self.inv.sign_records()
        retained = native.retain_primary(self.state / INVENTORY_PRIMARY, packet, **self.inv.options)
        self.public = dict(
            cases=self.native_cases.copy(),
            source=packet["source"],
            fingerprint=packet["fingerprint"],
            status="pass",
            release_ready=False,
            scope=inventory.SCOPE,
            max_cli_seconds=0.05,
            candidate_reference=self.candidate["candidate_reference"],
            primary_sha256=retained["primary_sha256"],
            binding_sha256=retained["binding_sha256"],
        )
        self.hosted = self.enterContext(patch.object(gate, "hosted"))
        self.qualify = self.enterContext(patch.object(native, "qualify", return_value=self.public))
        self.run_outage = self.enterContext(
            patch.object(outage, "run", autospec=True, return_value=self.out.public)
        )
        self.inventory_pin = gate.capture_inventory(ROOT, self.state)
        self.outage_pin = gate.capture_outage(ROOT, self.state)

    def replay(self):
        return self.gate.replay(
            ROOT, self.state, inventory_pin=self.inventory_pin, outage_pin=self.outage_pin
        )

    def repin_inventory(self):
        self.inventory_pin = self.gate.capture_inventory(ROOT, self.state)

    def repin_outage(self):
        self.out.publish()
        self.outage_pin = self.gate.capture_outage(ROOT, self.state)

    def test_original_files_replay_after_teardown(self):
        self.qualify.assert_called_once_with(self.state, "trusted-mlsecops:dev")
        self.run_outage.assert_called_once_with(ROOT, self.state, proposal_pin=self.proposal_sha)
        self.assertEqual(self.outage_pin["proposal_sha256"], self.proposal_sha)
        del os.environ["M23_PROPOSAL_SHA256"]
        self.assertEqual(
            self.inventory_pin["public_sha256"],
            digest((self.state / INVENTORY_PUBLIC).read_bytes()),
        )
        self.assertEqual(
            self.outage_pin["public_sha256"], digest((self.state / outage.PUBLIC).read_bytes())
        )
        self.hosted.side_effect = self.qualify.side_effect = self.run_outage.side_effect = (
            AssertionError
        )
        report = self.replay()
        self.assertEqual(report["proposal_finished_at"], self.proposal["finished_at"])
        self.assertEqual(report["candidate"], self.candidate)
        self.assertEqual(report["release_subject"], self.out.binding["context"]["bundle_sha256"])
        self.assertEqual(report["routes"], {"promotion.denied": 5, "inventory.mismatch": 10})
        self.assertEqual(
            report["metrics"]["phase_windows"], dict(ready=1, outage=1, attempt=1, recover=1)
        )
        self.assertEqual(report["metrics"]["observations"], 4000)
        self.assertEqual(report["metrics"]["inventory_events"], 6)
        self.assertIn(self.proposal_sha, report["artifact_hashes"].values())
        cases = report["cases"]
        self.assertEqual(len(cases), len(set(cases)))
        self.assertEqual(
            len([n for n in cases if n.startswith("inventory:")]), len(self.native_cases)
        )
        self.assertTrue(all(":" in n for n in cases))
        self.assertTrue(any("controlled-authorization" in n for n in cases))
        self.assertIn(self.public["binding_sha256"], report["artifact_hashes"].values())
        self.assertNotIn(b"signatures", canonical(report))
        self.assertNotIn(b"private-canary", canonical(report))

    def test_missing_invalid_or_changed_proposal_pin_precedes_native_run(self):
        self.run_outage.reset_mock()
        for value in (None, "A" * 64, "0" * 64):
            if value is None:
                os.environ.pop("M23_PROPOSAL_SHA256")
            else:
                os.environ["M23_PROPOSAL_SHA256"] = value
            with self.subTest(value=value), self.assertRaises(Rejected):
                self.gate.capture_outage(ROOT, self.state)
        self.run_outage.assert_not_called()

    def test_original_proposal_bytes_and_all_actual_bindings_are_required(self):
        write_json(self.state / PROPOSAL, {**self.proposal, "source_dirty": True})
        with self.assertRaises(Rejected):
            self.replay()
        for name, value in (
            ("subject_sha256", "8" * 64),
            ("model_sha256", "8" * 64),
            ("proposal_reference", "8" * 64),
            ("campaign_id", self.out.primary["security_campaign_id"]),
            ("source", {}),
            ("source", {**self.proposal["source"], "unused": True}),
            ("finished_at", "2026-11-14T07:14:28"),
            ("finished_at", "private-canary"),
            ("source_dirty", True),
            ("release_ready", True),
            ("status", "inconclusive"),
        ):
            write_json(self.state / PROPOSAL, {**self.proposal, name: value})
            os.environ["M23_PROPOSAL_SHA256"] = digest((self.state / PROPOSAL).read_bytes())
            with self.subTest(field=name), self.assertRaises(Rejected):
                self.repin_outage()
                self.replay()

    def test_controlled_subject_cannot_be_used_as_release_subject(self):
        subject = self.out.primary["subject_sha256"]
        self.out.signed_recovery(bundle=subject, asset=subject)
        self.out.binding["boundary"]["fixture_bundle_sha256"] = subject
        self.repin_outage()
        with self.assertRaisesRegex(Rejected, "release_subject"):
            self.replay()

    def test_foreign_assurance_outcome_rejected(self):
        self.out.primary["actual_refusal"]["parent_refusal"] = "promotion_denial_audit_unconfirmed"
        self.repin_outage()
        with self.assertRaisesRegex(Rejected, "actual_refusal"):
            self.replay()

    def test_unrelated_signed_history_does_not_set_outage_latency(self):
        self.out.signed_recovery(routed_at_ms=4030)
        signed = self.out.binding["recovery"]["signed_evidence"]
        registry = self.out.fx.registry
        key = self.out.fx.keys["promoter"]
        box = Outbox(registry, key_identity(key), signed["outbox"]["snapshot"])
        book = Ledger(registry, signed["collector"]["snapshot"])
        record = box.enqueue(
            (
                dict(
                    kind="promotion.denied",
                    reason="policy",
                    correlation_id="8" * 32,
                    asset_sha256="5" * 64,
                    bundle_sha256="5" * 64,
                ),
                key,
            ),
            clock_ms=4038,
        )
        event = registry.verify(record["envelope"], clock_ms=4038)
        book.ingest(record["envelope"], clock_ms=4038)
        routed = book.route(
            (event.document()["event_id"], self.out.fx.keys["receipt"]), clock_ms=4040
        )
        box.acknowledge(routed["receipt"], clock_ms=4040)
        signed["outbox"]["snapshot"] = box.document()
        signed["collector"]["snapshot"] = book.document()
        self.repin_outage()
        self.assertEqual(self.replay()["routes"]["promotion.denied"], 0)

    def test_signed_cutoff_inclusive_and_illegal_receipt_intervals_rejected(self):
        signed = self.out.binding["recovery"]["signed_evidence"]
        record = copy.deepcopy(signed["outbox"]["snapshot"]["records"][0])
        registry = self.out.fx.registry
        expected = {self.out.binding["boundary"]["pending"]["event_id"]}
        receipt = decode(signing.decode64(record["receipt"]["payload"]))
        for delta in (60000, 60001, -1):
            receipt["routed_at_ms"] = receipt["ingested_at_ms"] + delta
            record["receipt"] = signing.sign(
                receipt, "security-event-receipt", self.out.fx.keys["receipt"]
            )

            def measure():
                return self.gate._route_ms(registry, [record], expected, "promotion.denied")

            if delta == 60000:
                self.assertEqual(measure(), 60000)
            else:
                with self.assertRaisesRegex(Rejected, "delivery_deadline"):
                    measure()

    def test_committed_source_does_not_accept_another_authorized_inventory_role(self):
        # The native fixture always wires the promoter. The registry also permits serving to emit mismatches.
        with patch.dict(self.inv.fx.keys, promoter=self.inv.fx.keys["serving"]):
            self.inv.producer = key_identity(self.inv.fx.keys["promoter"])
            self.inv.sign_records()
        retained = native.retain_primary(
            self.state / INVENTORY_PRIMARY, self.inv.packet, **self.inv.options
        )
        self.public.update(
            primary_sha256=retained["primary_sha256"], binding_sha256=retained["binding_sha256"]
        )
        self.repin_inventory()
        with self.assertRaisesRegex(Rejected, "inventory_producer"):
            self.replay()

    def test_missing_extra_and_same_length_substituted_legacy_cases(self):
        labels = self.native_cases
        for invalid in (labels[:-1], labels + [labels[0]], [labels[-1], *labels[1:]]):
            self.public["cases"] = invalid
            with self.assertRaises(Rejected):
                self.repin_inventory()
                self.replay()

    def test_capture_guard_precedes_both_native_calls(self):
        self.hosted.side_effect = Rejected("hosted")
        self.qualify.reset_mock()
        self.run_outage.reset_mock()
        for capture in (self.gate.capture_inventory, self.gate.capture_outage):
            with self.assertRaisesRegex(Rejected, "hosted"):
                capture(ROOT, self.state)
        self.qualify.assert_not_called()
        self.run_outage.assert_not_called()

    def test_replaced_retained_files_reject_with_original_pins(self):
        for path in (
            self.state / INVENTORY_PUBLIC,
            self.state / INVENTORY_PRIMARY,
            (self.state / INVENTORY_PRIMARY).with_suffix(".bindings.json"),
            self.state / outage.PUBLIC,
            self.state / outage.PRIVATE,
            self.out.directory / "binding.json",
        ):
            raw = path.read_bytes()
            path.write_bytes(raw + b" ")
            with self.subTest(name=path.name), self.assertRaises(Rejected):
                self.replay()
            path.write_bytes(raw)

    def test_public_replaced_between_pinned_read_and_native_reverify(self):
        verify = outage.reverify

        def replace_and_verify(root, state):
            # Different signed recovery still gives an identical green window summary.
            self.out.signed_recovery(routed_at_ms=4031)
            self.out.publish()
            return verify(root, state)

        with (
            patch.object(outage, "reverify", side_effect=replace_and_verify),
            self.assertRaises(Rejected),
        ):
            self.replay()

    def test_extra_recover_window_counts_and_receives_its_own_id(self):
        packet_module = window_fixtures.packet
        with patch.object(packet_module, "PHASES", (*packet_module.PHASES, "recover")):
            packet, reference, trace, golden = window_fixtures.fixture()
        campaign = self.out.primary["security_campaign_id"]
        self.out.packet = packet
        summary = packet_module.verify(
            packet,
            reference=reference,
            context=trace,
            golden=golden,
            campaign=campaign,
        )
        self.out.binding["summary"] = summary
        self.out.primary["native"].update(**summary, operator_retained_reverified=summary)
        operator = self.out.operator
        operator["timeline"]["finish"].update(started_at_ms=6020, started_ns=6020000000)
        operator["requests"]["finish"] = digest(
            canonical(
                dict(
                    phase="finish", campaign=campaign, payload=dict(packet=packet, summary=summary)
                )
            )
        )
        operator["results"]["finish"] = {"packet_sha256": summary["packet_sha256"]}
        self.out.public["observation"] = dict(
            **summary, retained_primary_reverified=True, full_M23="inconclusive"
        )
        self.repin_outage()
        report = self.replay()
        self.assertEqual(report["metrics"]["observations"], 5000)
        self.assertEqual(report["metrics"]["phase_windows"]["recover"], 2)
        self.assertIn("outage:recover:window:2", report["cases"])

    def test_rehashed_corrupt_window_rejects(self):
        self.out.packet["windows"][2]["http"][-1]["response"]["predictions"][-1]["score"] = 0.001
        self.repin_outage()
        with self.assertRaisesRegex(Rejected, "security_green_"):
            self.replay()

    def test_stale_public_cannot_be_pinned_at_capture(self):
        with patch.object(
            outage, "run", return_value={**self.out.public, "primary_sha256": "0" * 64}
        ):
            with self.assertRaises(Rejected):
                self.gate.capture_outage(ROOT, self.state)
        with patch.object(self.gate, "write_json"):
            self.public["primary_sha256"] = "0" * 64
            with self.assertRaises(Rejected):
                self.repin_inventory()

    def test_shared_candidate_and_binding_are_checked_after_repin(self):
        self.out.primary["candidate_reference"] = "8" * 64
        self.out.primary["actual_refusal"]["candidate"] = "8" * 64
        self.repin_outage()
        with self.assertRaises(Rejected):
            self.replay()

    def test_methods_recomputed_even_with_new_inventory_pins(self):
        packet = self.inv.packet
        name = inventory.METHODS[0]
        packet["methods"][name] = self.inv.options["expected_methods"][name] = "4" * 64
        result = native.retain_primary(self.state / INVENTORY_PRIMARY, packet, **self.inv.options)
        self.public.update(
            primary_sha256=result["primary_sha256"], binding_sha256=result["binding_sha256"]
        )
        self.repin_inventory()
        with self.assertRaises(Rejected):
            self.replay()
