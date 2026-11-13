"""Controlled source calls and real signatures, without processes or Linux stores."""

import importlib
import time
import unittest
from unittest.mock import patch

from mlsecops import security_event_delivery as delivery
from mlsecops import security_event_ledger as ledger
from mlsecops import security_event_outbox as outbox
from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, digest
from scripts import security_event_source_live_qualification as source
from scripts import security_events_qualification as fixtures


class ControlledCollector:
    """Only transport/lifecycle is controlled; source, queue and ledger are real."""

    def __init__(self):
        self.fx = fixtures.EventContracts("runTest")
        self.fx.setUp()
        self.directory = self.fx.directory
        clock = self.now()
        self.fx.document.update(issued_at_ms=clock - 1000, expires_at_ms=clock + 600000)
        self.registry = self.fx.registry_for(clock=clock)
        envelope = signing.sign(self.fx.document, "security-event-config", self.fx.keys["root"])
        (self.directory / "registry.json").write_bytes(canonical(envelope))
        (self.directory / "collector.json").write_bytes(
            canonical(
                {
                    "registry_file": str(self.directory / "registry.json"),
                    "registry_root": self.fx.publics["root"],
                    "registry_sha256": self.registry.sha256,
                    "state_directory": str(self.directory / "unused-controlled-store"),
                    "state_sha256": "a" * 64,
                }
            )
        )
        self.box = outbox.Outbox.empty(
            self.registry, outbox.key_identity(self.fx.keys["controller"]), clock_ms=clock
        )
        self.box.snapshot = self.box.document
        self.book = ledger.Ledger.empty(self.registry, clock_ms=clock)
        self.online = False
        self.cleaned = False
        self.cleanup_result = True
        self.fail_final_stop = False
        self.stop_count = 0
        self.page_size = 32

    @staticmethod
    def now():
        return time.time_ns() // 1_000_000

    def start(self):
        self.online = True

    def stop(self):
        self.stop_count += 1
        self.online = False
        if self.fail_final_stop and self.stop_count >= 2:
            raise Rejected("controlled_stop_failed")

    def doCleanups(self):
        self.cleaned = True
        return self.fx.doCleanups() and self.cleanup_result

    def send(self, envelope):
        if not self.online:
            raise OSError("controlled offline")
        record = self.book.ingest(envelope, clock_ms=self.now())
        event = self.registry.verify(record["envelope"], clock_ms=record["ingested_at_ms"])
        return self.book.route(
            (event.document()["event_id"], self.fx.keys["receipt"]), clock_ms=self.now()
        )["receipt"]

    def emitter(self):
        # A fresh client permits lost-response patching without mutating the fixture.
        class Client:
            pass

        client = Client()
        client.send = self.send
        return delivery.Emitter(self.box, self.fx.keys["controller"], client)

    def exchange(self, method, path):
        if not self.online or method != "GET" or not path.startswith("/incidents/"):
            raise Rejected("controlled_exchange_invalid")
        offset = int(path.rsplit("/", 1)[1])
        records = self.book.document()["records"]
        end = offset + self.page_size
        return 200, {
            "incidents": records[offset:end],
            "next_offset": end if end < len(records) else None,
            "release_ready": False,
        }


class SourceCaptureContracts(unittest.TestCase):
    def setUp(self):
        self.fx = ControlledCollector()
        self.addCleanup(self.fx.fx.doCleanups)
        self.root = self.fx.fx.publics["root"]
        self.pin = self.fx.registry.sha256
        self.producer = self.fx.box.producer.identity

    def run_campaign(self):
        return source.run_source_campaign(
            self.fx, self.fx.emitter, collector_snapshot=self.fx.book.document
        )

    def packet(self):
        packet = self.run_campaign()
        self.assertIsInstance(packet, dict, "source campaign discarded private primary records")
        return packet

    def test_primary_bundle_survives_cleanup_and_replays_with_external_pins(self):
        packet = self.packet()
        self.assertTrue(self.fx.cleaned, "packet returned before confirmed cleanup")
        self.assertFalse(self.fx.directory.exists())
        bundle = packet["bundle"]
        self.assertEqual(set(bundle), {"registry", "outboxes", "collector", "incidents"})
        self.assertEqual(bundle["outboxes"], [self.fx.box.document()])
        self.assertEqual(bundle["collector"], self.fx.book.document())
        self.assertEqual(bundle["incidents"], bundle["collector"]["records"])
        self.assertEqual(len(bundle["incidents"]), 4)
        self.assertEqual(bundle["registry"]["root"], self.root)
        self.assertEqual(bundle["registry"]["pin"], self.pin)
        self.assertGreaterEqual(
            bundle["registry"]["clock_ms"], bundle["collector"]["updated_at_ms"]
        )
        from mlsecops.security_source_evidence import verify_delivery

        expected = {
            item["event_id"]: {
                **{
                    name: item[name] for name in ("kind", "reason", "asset_sha256", "bundle_sha256")
                },
                "producer_id": self.producer,
            }
            for item in packet["source_observations"]
        }
        result = verify_delivery(
            bundle, expected_root=self.root, expected_pin=self.pin, expected_events=expected
        )
        self.assertEqual(len(result["events"]), 3)
        self.assertEqual(result["scope"], "signed-delivery-not-source-decision-or-M23")

    def test_actual_decisions_exclude_manually_emitted_transport_control(self):
        packet = self.packet()
        observations = packet["source_observations"]
        self.assertEqual(
            [(x["kind"], x["reason"]) for x in observations],
            [
                ("artifact.rejected", "unsupported_format"),
                ("worker.policy_violation", "output_schema"),
                ("artifact.rejected", "integrity"),
            ],
        )
        self.assertEqual(
            [x["decision"] for x in observations],
            ["model_intake_fail", "model_intake_fail", "intake_security_audit_unavailable"],
        )
        for item in observations:
            self.assertEqual(
                set(item),
                {
                    "case_id",
                    "event_id",
                    "kind",
                    "reason",
                    "asset_sha256",
                    "bundle_sha256",
                    "subject_kind",
                    "decision",
                    "trigger_sha256",
                },
            )
            self.assertEqual(item["asset_sha256"], digest(source.CONTENT))
            self.assertIsNone(item["bundle_sha256"])
            self.assertRegex(item["trigger_sha256"], r"^[0-9a-f]{64}$")
        controls = packet["transport_controls"]
        self.assertEqual(len(controls), 1)
        self.assertEqual(controls[0]["case_id"], "lost-response")
        self.assertNotIn(controls[0]["event_id"], {x["event_id"] for x in observations})

    def test_intervals_bind_event_ids_and_separate_offline_wait_from_retry(self):
        packet = self.packet()
        intervals = packet["source_timings"]
        self.assertEqual(
            [x["phase"] for x in intervals],
            ["online", "online", "offline-decision", "offline-wait", "retry"],
        )
        ids = [x["event_id"] for x in packet["source_observations"]]
        self.assertEqual(
            [x["event_id"] for x in intervals], [ids[0], ids[1], ids[2], ids[2], ids[2]]
        )
        for value in intervals:
            self.assertGreaterEqual(value["end_monotonic_ns"], value["start_monotonic_ns"])
            self.assertGreaterEqual(value["end_utc_ns"], value["start_utc_ns"])
        self.assertEqual(intervals[3]["start_monotonic_ns"], intervals[2]["end_monotonic_ns"])
        self.assertLessEqual(intervals[3]["end_monotonic_ns"], intervals[4]["start_monotonic_ns"])

    def test_packet_contains_no_raw_input_keys_tokens_or_runtime_paths(self):
        packet = self.packet()
        raw = canonical(packet)
        for private in (
            b"PRIVATE-CANARY",
            b"PRIVATE KEY",
            b"ingress.token",
            b"operator.token",
            str(self.fx.directory).encode(),
        ):
            self.assertNotIn(private, raw)
        for record in packet["bundle"]["collector"]["records"]:
            self.assertNotIn(b"PRIVATE-CANARY", signing.decode64(record["envelope"]["payload"]))

    def test_cleanup_false_cannot_return_a_success_packet(self):
        self.fx.cleanup_result = False
        with self.assertRaisesRegex(Rejected, "source_capture_cleanup_failed"):
            self.run_campaign()
        self.assertTrue(self.fx.cleaned)

    def test_cleanup_true_without_removing_fixture_cannot_claim_cleanup(self):
        with patch.object(self.fx, "doCleanups", return_value=True):
            with self.assertRaisesRegex(Rejected, "source_capture_cleanup_failed"):
                self.run_campaign()
        self.assertTrue(self.fx.directory.exists())

    def test_real_source_never_predicts_or_executes_worker_for_digest_mismatch(self):
        execute = source.worker.execute
        actions = []

        def observed(request):
            actions.append(request["action"])
            return execute(request)

        with patch.object(source.worker, "execute", side_effect=observed):
            self.packet()
        self.assertEqual(actions, ["inspect"])

    def test_stop_failure_propagates_and_still_removes_fixture_secrets(self):
        self.fx.fail_final_stop = True
        with self.assertRaises(Rejected):
            self.run_campaign()
        self.assertTrue(self.fx.cleaned, "stop failure skipped fixture cleanup")
        self.assertFalse(self.fx.directory.exists())

    def test_source_success_cannot_be_reported_as_a_denial(self):
        with patch.object(
            source.pipeline, "evaluate_verified_candidate", return_value={"status": "pass"}
        ):
            with self.assertRaisesRegex(Rejected, "source_capture_decision"):
                self.run_campaign()
        self.assertTrue(self.fx.cleaned)

    def test_wrong_actual_event_subject_cannot_be_counted(self):
        original = self.fx.box.enqueue

        def changed(request, *, clock_ms):
            fields, key = request
            return original(({**fields, "asset_sha256": "f" * 64}, key), clock_ms=clock_ms)

        with patch.object(self.fx.box, "enqueue", side_effect=changed):
            with self.assertRaisesRegex(Rejected, "source_capture_decision"):
                self.run_campaign()
        self.assertTrue(self.fx.cleaned)

    def test_partial_incident_export_cannot_return_a_success_packet(self):
        self.fx.page_size = 2
        exchange = self.fx.exchange

        def truncated(method, path):
            status, page = exchange(method, path)
            page["next_offset"] = None
            return status, page

        with patch.object(self.fx, "exchange", side_effect=truncated):
            with self.assertRaises(Rejected):
                self.run_campaign()
        self.assertTrue(self.fx.cleaned)

    def test_paginated_incidents_are_exported_completely(self):
        self.fx.page_size = 2
        packet = self.packet()
        self.assertEqual(len(packet["bundle"]["incidents"]), 4)

    def test_capture_helper_never_starts_or_stops_supplied_fixture(self):
        name = "scripts.security_source_capture"
        self.assertIsNotNone(importlib.util.find_spec(name), "capture helper not implemented")
        helper = importlib.import_module(name)
        with (
            patch.object(self.fx, "start", side_effect=AssertionError("implicit startup")),
            patch.object(self.fx, "stop", side_effect=AssertionError("implicit shutdown")),
        ):
            bundle = helper.capture_delivery(
                self.fx, [self.fx.emitter()], incidents=[], collector_snapshot=self.fx.book.document
            )
        self.assertEqual(bundle["collector"], self.fx.book.document())
        self.assertFalse(self.fx.cleaned)

    def test_capture_rejects_clock_before_any_snapshot_update(self):
        from scripts.security_source_capture import capture_delivery

        with patch.object(
            self.fx, "now", return_value=self.fx.book.document()["updated_at_ms"] - 1
        ):
            with self.assertRaisesRegex(Rejected, "source_capture_incomplete"):
                capture_delivery(
                    self.fx,
                    [self.fx.emitter()],
                    incidents=[],
                    collector_snapshot=self.fx.book.document,
                )

    def test_capture_rejects_pending_outbox_even_with_empty_collector(self):
        from scripts.security_source_capture import capture_delivery

        emitter = self.fx.emitter()
        with self.assertRaises(Rejected):
            emitter.emit(
                dict(
                    kind="artifact.rejected",
                    reason="integrity",
                    correlation_id="e" * 32,
                    asset_sha256=digest(source.CONTENT),
                    bundle_sha256=None,
                )
            )
        with self.assertRaisesRegex(Rejected, "source_capture_incomplete"):
            capture_delivery(
                self.fx, [emitter], incidents=[], collector_snapshot=self.fx.book.document
            )

    def test_capture_rejects_pending_collector_without_hiding_the_record(self):
        from scripts.security_source_capture import capture_delivery

        fields = dict(
            kind="artifact.rejected",
            reason="integrity",
            correlation_id="e" * 32,
            asset_sha256=digest(source.CONTENT),
            bundle_sha256=None,
        )
        record = self.fx.box.enqueue(
            (fields, self.fx.fx.keys["controller"]), clock_ms=self.fx.now()
        )
        self.fx.book.ingest(record["envelope"], clock_ms=self.fx.now())
        with self.assertRaisesRegex(Rejected, "source_capture_incomplete"):
            capture_delivery(
                self.fx,
                [],
                incidents=self.fx.book.document()["records"],
                collector_snapshot=self.fx.book.document,
            )

    def test_repeating_pagination_cursor_refuses_instead_of_looping(self):
        from scripts.security_source_capture import read_incidents

        with patch.object(
            self.fx,
            "exchange",
            return_value=(
                200,
                {
                    "incidents": [],
                    "next_offset": 0,
                    "release_ready": False,
                },
            ),
        ):
            with self.assertRaisesRegex(Rejected, "source_capture_incidents"):
                read_incidents(self.fx)

    def test_bad_incident_status_or_page_shape_refuses(self):
        from scripts.security_source_capture import read_incidents

        cases = (
            (503, {"incidents": [], "next_offset": None, "release_ready": False}),
            (200, None),
            (200, {"incidents": []}),
            (200, {"incidents": [], "next_offset": None, "release_ready": True}),
            (200, {"incidents": {}, "next_offset": None, "release_ready": False}),
        )
        for response in cases:
            with (
                self.subTest(status=response[0]),
                patch.object(self.fx, "exchange", return_value=response),
            ):
                with self.assertRaisesRegex(Rejected, "source_capture_incidents"):
                    read_incidents(self.fx)

    def test_incident_limit_refuses_instead_of_exporting_unbounded_data(self):
        from scripts.security_source_capture import read_incidents

        with patch.object(
            self.fx,
            "exchange",
            return_value=(
                200,
                {
                    "incidents": [{}] * 1025,
                    "next_offset": None,
                    "release_ready": False,
                },
            ),
        ):
            with self.assertRaisesRegex(Rejected, "source_capture_incidents"):
                read_incidents(self.fx)

    def test_default_capture_reads_owned_store_with_exact_identity_pin(self):
        from scripts import security_source_capture as capture

        def controlled_store(root, pin, registry):
            if (
                root != str(self.fx.directory / "unused-controlled-store")
                or pin != "a" * 64
                or registry is not self.fx.registry
            ):
                raise Rejected("wrong_owned_store_binding")

            class Store:
                snapshot = self.fx.book.document

            return Store()

        with patch.object(capture.storage, "Store", side_effect=controlled_store):
            result = capture.capture_delivery(self.fx, [self.fx.emitter()], incidents=[])
        self.assertEqual(result["collector"], self.fx.book.document())
        self.assertEqual(result["outboxes"], [self.fx.box.document()])

    def test_tampered_incident_receipt_is_not_exported_as_complete(self):
        from scripts.security_source_capture import capture_delivery, read_incidents

        self.fx.start()
        emitter = self.fx.emitter()
        emitter.emit(
            dict(
                kind="artifact.rejected",
                reason="integrity",
                correlation_id="e" * 32,
                asset_sha256=digest(source.CONTENT),
                bundle_sha256=None,
            )
        )
        incidents = read_incidents(self.fx)
        incidents[0]["receipt"]["payload"] = "tampered"
        with self.assertRaisesRegex(Rejected, "source_capture_incomplete"):
            capture_delivery(
                self.fx, [emitter], incidents=incidents, collector_snapshot=self.fx.book.document
            )

    def test_integer_zero_cannot_replace_signed_incident_late_false(self):
        from scripts.security_source_capture import capture_delivery, read_incidents

        self.fx.start()
        emitter = self.fx.emitter()
        emitter.emit(
            dict(
                kind="artifact.rejected",
                reason="integrity",
                correlation_id="e" * 32,
                asset_sha256=digest(source.CONTENT),
                bundle_sha256=None,
            )
        )
        incidents = read_incidents(self.fx)
        self.assertIs(incidents[0]["late"], False)
        incidents[0]["late"] = 0
        with self.assertRaisesRegex(Rejected, "source_capture_incomplete"):
            capture_delivery(
                self.fx, [emitter], incidents=incidents, collector_snapshot=self.fx.book.document
            )

    def test_oversized_primary_files_refuse_before_loading_json_into_memory(self):
        from scripts import security_source_capture as capture

        decode = capture.decode

        def bounded_decode(content, limit=16 * 1024 * 1024):
            if len(content) > limit:
                raise AssertionError("oversized file was fully loaded before decode")
            return decode(content, limit)

        for name, limit in (("collector.json", 16384), ("registry.json", 32768)):
            target = self.fx.directory / name
            original = target.read_bytes()
            try:
                target.write_bytes(b" " * (limit + 1))
                with (
                    self.subTest(name=name),
                    patch.object(capture, "decode", side_effect=bounded_decode),
                ):
                    with self.assertRaisesRegex(Rejected, "^artifact_too_large$"):
                        capture.capture_delivery(
                            self.fx,
                            [self.fx.emitter()],
                            incidents=[],
                            collector_snapshot=self.fx.book.document,
                        )
            finally:
                target.write_bytes(original)

    def test_start_failure_cleans_fixture_and_returns_no_packet(self):
        with patch.object(self.fx, "start", side_effect=OSError("controlled start failure")):
            with self.assertRaises(OSError):
                self.run_campaign()
        self.assertTrue(self.fx.cleaned)
        self.assertFalse(self.fx.directory.exists())

    def test_snapshot_failure_cleans_fixture_and_returns_no_packet(self):
        with patch.object(self.fx.book, "document", side_effect=OSError("controlled read failure")):
            with self.assertRaises(OSError):
                self.run_campaign()
        self.assertTrue(self.fx.cleaned)
        self.assertFalse(self.fx.directory.exists())


if __name__ == "__main__":
    unittest.main()
