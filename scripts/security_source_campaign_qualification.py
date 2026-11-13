"""Source-packet replay against actual decisions on controlled in-memory transport."""

import copy
import importlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, decode, digest, read_json
from mlsecops.security_source_evidence import SUBJECT_FIELDS, verify_delivery
from scripts import security_event_source_live_qualification as source
from scripts.security_source_capture_qualification import ControlledCollector


class SourceCampaign(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("scripts.security_source_campaign"),
            "retained source campaign replay is missing",
        )
        self.module = importlib.import_module("scripts.security_source_campaign")
        fixture = ControlledCollector()
        self.addCleanup(fixture.fx.doCleanups)
        retained_keys = tempfile.TemporaryDirectory()
        self.addCleanup(retained_keys.cleanup)
        self.keys, self.publics = {}, fixture.fx.publics.copy()
        for role in ("receipt", "intake"):
            target = Path(retained_keys.name) / (role + ".pem")
            target.write_bytes(fixture.fx.keys[role].read_bytes())
            target.chmod(0o600)
            self.keys[role] = target
        policy = read_json(Path(__file__).resolve().parents[1] / "policies/local-cpu.json")
        self.expected = dict(
            source="a" * 40,
            fingerprint="b" * 64,
            materials={"source.py": "c" * 64},
            root=fixture.fx.publics["root"],
            pin=fixture.registry.sha256,
            policy_sha256=digest(canonical(policy)),
            transport="controlled-in-memory",
        )
        primary = source.run_source_campaign(
            fixture, fixture.emitter, collector_snapshot=fixture.book.document
        )
        self.packet = dict(
            schema_version=1,
            source=self.expected["source"],
            fingerprint=self.expected["fingerprint"],
            method_materials=self.expected["materials"],
            source_after=self.expected["source"],
            fingerprint_after=self.expected["fingerprint"],
            materials_after=self.expected["materials"],
            source_clean=True,
            campaign=primary,
        )

    def reject(self, packet=None, expected=None):
        with self.assertRaisesRegex(Rejected, "^source_campaign_invalid$"):
            self.module.verify(packet or self.packet, expected=expected or self.expected)

    def test_exact_sources_exclude_manual_control_and_keep_controlled_scope(self):
        result = self.module.verify(self.packet, expected=self.expected)
        self.assertEqual(
            result["cases"],
            ["artifact-unsupported-format", "worker-output-schema", "offline-integrity"],
        )
        self.assertEqual(result["transport"], "controlled-in-memory")
        self.assertIs(result["release_ready"], False)
        self.assertEqual(result["scope"], "intake-controller-source-primary-not-full-M23")
        self.assertNotIn(b"PRIVATE-CANARY", canonical(result))

    def test_root_source_fingerprint_methods_and_policy_are_caller_pinned(self):
        for key, value in (
            ("root", "x" * 44),
            ("pin", "0" * 64),
            ("source", "0" * 40),
            ("fingerprint", "0" * 64),
            ("materials", {}),
            ("policy_sha256", "0" * 64),
            ("transport", "owned-linux-http"),
        ):
            self.reject(expected={**self.expected, key: value})

    def test_missing_unknown_duplicate_and_relabelled_source_cases_are_rejected(self):
        for operation in (
            lambda v: v.pop(),
            lambda v: v.append(copy.deepcopy(v[0])),
            lambda v: v[0].update(case_id="manual-event"),
            lambda v: v[0].update(reason="integrity"),
            lambda v: v[1].update(subject_kind="model"),
            lambda v: v[2].update(decision="model_intake_fail"),
            lambda v: v[0].update(event_id=v[1]["event_id"]),
            lambda v: v[0].update(trigger_sha256="f" * 64),
        ):
            packet = copy.deepcopy(self.packet)
            operation(packet["campaign"]["source_observations"])
            self.reject(packet)

    def test_cleanup_dirty_status_schema_and_primary_substitution_fail_closed(self):
        for key, value in (
            ("source_clean", False),
            ("schema_version", True),
            ("source_after", "0" * 40),
            ("fingerprint_after", "0" * 64),
            ("materials_after", {}),
        ):
            self.reject({**self.packet, key: value})
        for key, value in (
            ("cleanup", {"fixture_cleanups_confirmed": False}),
            ("release_ready", True),
            ("bundle", {"status": "pass"}),
            ("transport_controls", []),
            ("executor_scope", "real-worker"),
        ):
            packet = copy.deepcopy(self.packet)
            packet["campaign"][key] = value
            self.reject(packet)

    def test_timing_substitution_late_delivery_and_disconnected_retry_are_rejected(self):
        for operation in (
            lambda v: v.pop(),
            lambda v: v[0].update(event_id="0" * 64),
            lambda v: v[0].update(start_monotonic_ns=True),
            lambda v: v[0].update(end_monotonic_ns=v[0]["start_monotonic_ns"] - 1),
            lambda v: v[0].update(end_monotonic_ns=v[0]["start_monotonic_ns"] + 61_000_000_000),
            lambda v: v[0].update(start_utc_ns=v[0]["start_utc_ns"] - 10_000_000_000),
            lambda v: v[3].update(start_monotonic_ns=v[3]["start_monotonic_ns"] + 1),
        ):
            packet = copy.deepcopy(self.packet)
            operation(packet["campaign"]["source_timings"])
            self.reject(packet)

    def refresh_delivery(self, packet):
        primary = packet["campaign"]
        expected = {}
        for record in primary["bundle"]["collector"]["records"][:3]:
            value = decode(signing.decode64(record["envelope"]["payload"]))
            expected[value["event_id"]] = {k: value[k] for k in SUBJECT_FIELDS}
        primary["delivery_verification"] = verify_delivery(
            primary["bundle"],
            expected_root=self.expected["root"],
            expected_pin=self.expected["pin"],
            expected_events=expected,
        )

    def test_resigned_receipt_after_online_completion_does_not_prove_synchronous_delivery(self):
        packet = copy.deepcopy(self.packet)
        bundle = packet["campaign"]["bundle"]
        record = bundle["collector"]["records"][0]
        receipt = signing.verify(
            record["receipt"], "security-event-receipt", self.publics["receipt"]
        )
        receipt["routed_at_ms"] = receipt["ingested_at_ms"] + 60000
        signed = signing.sign(receipt, "security-event-receipt", self.keys["receipt"])
        for item in (record, bundle["incidents"][0], bundle["outboxes"][0]["records"][0]):
            item["receipt"] = signed
        bundle["registry"]["clock_ms"] = receipt["routed_at_ms"] + 1
        bundle["outboxes"][0]["updated_at_ms"] = receipt["routed_at_ms"] + 1
        bundle["collector"]["updated_at_ms"] = receipt["routed_at_ms"] + 1
        self.refresh_delivery(packet)
        self.reject(packet)

    def test_foreign_signed_control_without_source_outbox_does_not_prove_retry(self):
        from mlsecops import security_events as events

        packet = copy.deepcopy(self.packet)
        primary, bundle = packet["campaign"], packet["campaign"]["bundle"]
        record = bundle["collector"]["records"][3]
        original = decode(signing.decode64(record["envelope"]["payload"]))
        fields = {
            k: v
            for k, v in original.items()
            if k not in ("schema_version", "event_id", "action", "outcome")
        }
        fields.update(producer_id=digest(signing.decode64(self.publics["intake"])), sequence=1)
        value = events.create(**fields)
        record["envelope"] = signing.sign(value, "security-event", self.keys["intake"])
        receipt = signing.verify(
            record["receipt"], "security-event-receipt", self.publics["receipt"]
        )
        for field in ("event_id", "producer_id", "epoch", "sequence"):
            receipt[field] = value[field]
        record["receipt"] = signing.sign(receipt, "security-event-receipt", self.keys["receipt"])
        bundle["incidents"][3] = copy.deepcopy(record)
        bundle["outboxes"][0]["records"].pop()
        primary["transport_controls"][0]["event_id"] = value["event_id"]
        self.refresh_delivery(packet)
        self.reject(packet)

    def test_private_atomic_retention_replays_after_fixture_has_been_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.json"
            result = self.module.retain(self.packet, path, expected=self.expected)
            bindings = path.with_suffix(".bindings.json")
            self.assertTrue(bindings.is_file(), "owner pins must survive separately from primary")
            self.assertEqual(
                read_json(bindings),
                {"expected": self.expected, "primary_sha256": result["primary_file_sha256"]},
            )
            self.assertEqual(result["binding_sha256"], digest(bindings.read_bytes()))
            self.assertEqual(result["primary_file_sha256"], digest(path.read_bytes()))
            self.assertEqual(
                {k: v for k, v in result.items() if k != "binding_sha256"},
                self.module.replay(
                    path, expected=self.expected, expected_sha256=result["primary_file_sha256"]
                ),
            )
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaisesRegex(Rejected, "source_campaign_primary_changed"):
                self.module.replay(
                    path, expected=self.expected, expected_sha256=result["primary_file_sha256"]
                )

    def test_missing_and_invalid_primary_are_not_success_and_no_write_on_bad_packet(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.json"
            with self.assertRaises(Rejected):
                self.module.replay(path, expected=self.expected, expected_sha256="f" * 64)
            with self.assertRaises(Rejected):
                self.module.retain(
                    {**self.packet, "source_clean": False}, path, expected=self.expected
                )
            self.assertFalse(path.exists())

    def test_native_guard_runs_before_provisioning_on_windows(self):
        with (
            patch.object(self.module.sys, "platform", "win32"),
            patch.object(source.SourceLive, "setUp") as setup,
        ):
            with self.assertRaisesRegex(Rejected, "source_campaign_hosted_required"):
                self.module.qualify()
            setup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
