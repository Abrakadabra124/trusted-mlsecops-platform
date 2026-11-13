"""Pure inventory primary replay and retention checks. No native infrastructure."""

import contextlib
import copy
import importlib
import importlib.util
import io
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import asset_graph, security_event_delivery, security_inventory_events, signing
from mlsecops import security_event_ledger as ledger
from mlsecops import security_event_outbox as outbox
from mlsecops.contracts import Rejected, canonical, digest, read_json
from scripts import security_events_qualification as fixtures
from scripts.asset_graph_fixture import ENVIRONMENT, OWNERS, fixture

METHODS = (
    "scripts/security_inventory_events_native.py",
    "scripts/asset_graph_fixture.py",
    "scripts/security_source_capture.py",
    "mlsecops/security_inventory_evidence.py",
    "mlsecops/security_inventory_events.py",
    "mlsecops/security_source_evidence.py",
    "mlsecops/candidate_lineage.py",
    "mlsecops/asset_graph.py",
)
STEPS = (
    ("candidate-valid", None, 0),
    ("candidate-source-mismatch", "digest", 1),
    ("candidate-image-mismatch-offline", "digest", 2),
    ("candidate-blocked-pending", None, 2),
    ("candidate-valid-after-retry", None, 2),
    ("candidate-missing", None, 2),
    ("graph-valid", None, 2),
    ("graph-digest", "digest", 3),
    ("graph-owner", "owner", 4),
    ("graph-dangling", "dangling", 5),
    ("graph-cycle", "cycle", 6),
    ("candidate-request-pin", None, 6),
)


class InventoryPrimary(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.EventContracts("runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.producer = outbox.key_identity(self.fx.keys["promoter"])
        self.bindings = dict(
            candidate_reference="c" * 64,
            evaluation_reference="e" * 64,
            model_sha256="d" * 64,
            image_id="sha256:" + "a" * 64,
            source_revision="b" * 40,
            source_fingerprint="f" * 64,
        )
        graph, snapshot, revoked = fixture()
        base = dict(
            document=graph,
            snapshot=snapshot,
            revoked=revoked,
            trusted_owners=OWNERS,
            environment=ENVIRONMENT,
        )
        observations = []
        for index, (case, reason, count) in enumerate(STEPS):
            controlled = case.startswith("graph-")
            request = copy.deepcopy(base) if controlled else None
            projection = (
                None
                if controlled
                else {
                    "candidate_reference": self.bindings["candidate_reference"],
                    "evaluation_reference": self.bindings["evaluation_reference"],
                    "expected": {
                        k: self.bindings[k]
                        for k in ("image_id", "source_revision", "source_fingerprint")
                    },
                }
            )
            if case == "graph-digest":
                request["snapshot"]["deployments"][0]["model_sha256"] = "f" * 64
            elif case == "graph-owner":
                request["document"]["assets"][0]["owner"] = "private-canary"
            elif case == "graph-dangling":
                request["snapshot"]["deployments"].pop()
            elif case == "graph-cycle":
                asset = request["document"]["assets"][0]
                asset["dependencies"] = [dict(asset_id=asset["asset_id"], sha256=asset["sha256"])]
                request["snapshot"]["graph_sha256"] = digest(canonical(request["document"]))
            if case == "candidate-source-mismatch":
                projection["expected"]["source_revision"] = "0" * 40
            elif case in ("candidate-image-mismatch-offline", "candidate-blocked-pending"):
                projection["expected"]["image_id"] = "sha256:" + "f" * 64
            elif case == "candidate-missing":
                projection["candidate_reference"] = "0" * 64
            request_hash = digest(canonical(request if controlled else projection))
            accepted = case in ("candidate-valid", "candidate-valid-after-retry", "graph-valid")
            observations.append(
                dict(
                    case_id=case,
                    subject_kind="controlled-graph" if controlled else "actual-sql-candidate",
                    subject_sha256=request_hash
                    if controlled
                    else projection["candidate_reference"],
                    request_sha256=request_hash,
                    configured_request_sha256="0" * 64
                    if case == "candidate-request-pin"
                    else request_hash,
                    candidate_request=projection,
                    graph_request=request,
                    decision="verified" if accepted else "inventory_security_rejected",
                    returncode=0 if accepted else 1,
                    started_at_ms=2000 + index * 100,
                    finished_at_ms=2050 + index * 100,
                    elapsed_ns=50_000_000,
                    before_count=0 if index == 0 else STEPS[index - 1][2],
                    after_count=count,
                    event_id=None,
                )
            )
        sql = {
            key: dict(objects=2, digest="a" * 64)
            for key in ("manifests", "lineage", "candidates", "evaluations")
        }
        self.packet = dict(
            schema_version=1,
            scope="actual-candidate-sql-and-controlled-graph-not-full-M19-M23",
            source=self.bindings["source_revision"],
            fingerprint=self.bindings["source_fingerprint"],
            methods={name: "a" * 64 for name in METHODS},
            bindings=copy.deepcopy(self.bindings),
            observations=observations,
            cleanup=dict(
                collector_process_stopped=True,
                collector_port_closed=True,
                fixture_removed=True,
                confirmed_at_ms=4100,
            ),
            sql=dict(
                before=sql,
                after=copy.deepcopy(sql),
                owned_container_before="1" * 64,
                owned_container_after="1" * 64,
                source_sql_cleanup="caller-owned-not-performed",
            ),
        )
        self.sign_records()

    def sign_records(self):
        """Re-sign attacks too, so semantic tests cannot pass by signature failure alone."""
        queue = outbox.Outbox.empty(self.fx.registry, self.producer, clock_ms=1900)
        book = ledger.Ledger.empty(self.fx.registry, clock_ms=1900)
        pending = None
        for index, (item, (_, reason, _)) in enumerate(zip(self.packet["observations"], STEPS)):
            if index == 4:
                book.ingest(pending["envelope"], clock_ms=2350)
                event = self.fx.registry.verify(pending["envelope"], clock_ms=2350).document()
                receipt = book.route((event["event_id"], self.fx.keys["receipt"]), clock_ms=2360)
                queue.acknowledge(receipt["receipt"], clock_ms=2370)
            if reason is None:
                continue
            clock = item["started_at_ms"] + 10
            record = queue.enqueue(
                (
                    dict(
                        kind="inventory.mismatch",
                        reason=reason,
                        correlation_id=f"{index:032x}",
                        asset_sha256=item["subject_sha256"],
                        bundle_sha256=None,
                    ),
                    self.fx.keys["promoter"],
                ),
                clock_ms=clock,
            )
            event = self.fx.registry.verify(record["envelope"], clock_ms=clock).document()
            item["event_id"] = event["event_id"]
            if index == 2:
                pending = copy.deepcopy(record)
                continue
            book.ingest(record["envelope"], clock_ms=clock + 10)
            routed = book.route((event["event_id"], self.fx.keys["receipt"]), clock_ms=clock + 20)
            queue.acknowledge(routed["receipt"], clock_ms=clock + 30)
        self.packet["retry"] = dict(
            pending_record=pending,
            started_at_ms=2350,
            finished_at_ms=2380,
            elapsed_ns=30_000_000,
            delivered=1,
        )
        self.packet["bundle"] = dict(
            registry=dict(
                envelope=signing.sign(
                    self.fx.document, "security-event-config", self.fx.keys["root"]
                ),
                root=self.fx.publics["root"],
                pin=self.fx.registry.sha256,
                clock_ms=4000,
            ),
            outboxes=[queue.document()],
            collector=book.document(),
            incidents=book.document()["records"],
        )
        self.options = dict(
            expected_source=self.bindings["source_revision"],
            expected_fingerprint=self.bindings["source_fingerprint"],
            expected_methods=copy.deepcopy(self.packet["methods"]),
            expected_candidate=copy.deepcopy(self.bindings),
            expected_root=self.fx.publics["root"],
            expected_pin=self.fx.registry.sha256,
        )

    def module(self):
        name = "mlsecops.security_inventory_evidence"
        self.assertIsNotNone(importlib.util.find_spec(name), "inventory primary replay is missing")
        return importlib.import_module(name)

    def verify(self, packet=None, **changes):
        return self.module().verify(
            self.packet if packet is None else packet, **{**self.options, **changes}
        )

    def reject(self, packet=None, **changes):
        with self.assertRaisesRegex(Rejected, "^inventory_evidence_invalid$"):
            self.verify(packet, **changes)

    def test_complete_signed_packet_replays_and_public_result_excludes_primary(self):
        result = self.verify()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["scope"], self.packet["scope"])
        self.assertEqual(result["event_count"], 6)
        self.assertEqual(result["primary_sha256"], digest(canonical(self.packet)))
        self.assertFalse(result["release_ready"])
        for private in (b"private-canary", b"signatures", b"graph_request", b"root", b"incidents"):
            self.assertNotIn(private, canonical(result))

    def test_owner_source_fingerprint_methods_candidate_and_authority_are_external(self):
        for key, value in (
            ("expected_source", "0" * 40),
            ("expected_fingerprint", "0" * 64),
            ("expected_methods", {}),
            ("expected_root", self.fx.publics["worker"]),
            ("expected_pin", "0" * 64),
            ("expected_candidate", {**self.bindings, "candidate_reference": "0" * 64}),
            ("expected_candidate", {**self.bindings, "model_sha256": "0" * 64}),
        ):
            with self.subTest(key=key):
                self.reject(**{key: value})

    def test_signed_wrong_candidate_subject_and_wrong_subject_label_are_rejected(self):
        self.packet["observations"][1]["subject_sha256"] = "0" * 64
        self.sign_records()
        self.reject()
        self.packet["observations"][1]["subject_sha256"] = self.bindings["candidate_reference"]
        self.packet["observations"][1]["subject_kind"] = "controlled-graph"
        self.sign_records()
        self.reject()

    def test_rehashed_and_resigned_graph_with_wrong_actual_reason_is_rejected(self):
        target = self.packet["observations"][7]
        target["graph_request"] = copy.deepcopy(self.packet["observations"][8]["graph_request"])
        value = digest(canonical(target["graph_request"]))
        target.update(subject_sha256=value, request_sha256=value, configured_request_sha256=value)
        self.sign_records()
        self.reject()

    def test_rehashed_semantics_valid_candidate_cannot_explain_mismatch(self):
        item = self.packet["observations"][1]
        item["candidate_request"] = copy.deepcopy(
            self.packet["observations"][0]["candidate_request"]
        )
        item["request_sha256"] = digest(canonical(item["candidate_request"]))
        item["configured_request_sha256"] = item["request_sha256"]
        self.reject()

    def test_signature_receipt_missing_incident_or_outbox_never_replays(self):
        for target, mutate in (
            (
                "bundle",
                lambda v: v["outboxes"][0]["records"][0]["envelope"]["signatures"][0].update(
                    sig="AAAA"
                ),
            ),
            (
                "bundle",
                lambda v: v["collector"]["records"][0]["receipt"]["signatures"][0].update(
                    sig="AAAA"
                ),
            ),
            ("bundle", lambda v: v["incidents"].pop()),
            ("bundle", lambda v: v["outboxes"][0]["records"].pop()),
            ("bundle", lambda v: v.update(outboxes=[])),
        ):
            changed = copy.deepcopy(self.packet)
            mutate(changed[target])
            self.reject(changed)

    def test_incomplete_cleanup_changed_sql_or_container_and_fake_sql_cleanup_rejected(self):
        for key in ("collector_process_stopped", "collector_port_closed", "fixture_removed"):
            changed = copy.deepcopy(self.packet)
            changed["cleanup"][key] = False
            self.reject(changed)
        for key, value in (
            ("after", {}),
            ("owned_container_after", "2" * 64),
            ("source_sql_cleanup", "cleaned"),
        ):
            changed = copy.deepcopy(self.packet)
            changed["sql"][key] = value
            self.reject(changed)

    def test_duplicate_missing_observation_nonfinite_time_wrong_decision_and_request_pin(self):
        for field, value in (
            ("elapsed_ns", float("nan")),
            ("elapsed_ns", True),
            ("elapsed_ns", 31_000_000_000),
            ("returncode", 0),
            ("decision", "verified"),
            ("finished_at_ms", 1),
            ("configured_request_sha256", "0" * 64),
        ):
            changed = copy.deepcopy(self.packet)
            changed["observations"][1][field] = value
            self.reject(changed)
        for change in (lambda v: v.pop(), lambda v: v.append(copy.deepcopy(v[1]))):
            changed = copy.deepcopy(self.packet)
            change(changed["observations"])
            self.reject(changed)

    def test_pending_record_retry_cannot_be_replaced_by_terminal_receipt(self):
        changed = copy.deepcopy(self.packet)
        changed["retry"]["pending_record"] = copy.deepcopy(
            changed["bundle"]["outboxes"][0]["records"][1]
        )
        self.reject(changed)
        changed = copy.deepcopy(self.packet)
        changed["retry"]["delivered"] = 0
        self.reject(changed)

    def test_retention_rejects_before_write_and_verifies_disk_readback(self):
        from scripts import security_inventory_events_native as native

        retain = getattr(native, "retain_primary", None)
        self.assertTrue(callable(retain), "native primary retention is missing")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "primary.json"
            bad = copy.deepcopy(self.packet)
            bad["cleanup"]["fixture_removed"] = False
            with self.assertRaises(Rejected):
                retain(path, bad, **self.options)
            self.assertFalse(path.exists())
            result = retain(path, self.packet, **self.options)
            self.assertEqual(read_json(path), self.packet)
            self.assertEqual(result["primary_sha256"], digest(canonical(self.packet)))
            with patch.object(native, "read_json", return_value=bad):
                with self.assertRaises(Rejected):
                    retain(path, self.packet, **self.options)

    def test_extra_private_payload_fields_are_rejected_before_retention(self):
        for section in ("bindings", "sql", "cleanup"):
            changed = copy.deepcopy(self.packet)
            changed[section]["raw_config"] = "PRIVATE-CANARY"
            self.reject(changed)
        changed = copy.deepcopy(self.packet)
        changed["observations"][8]["graph_request"]["document"]["assets"][-1]["token"] = (
            "PRIVATE-CANARY"
        )
        self.reject(changed)

    def test_invalid_graph_shapes_pin_mismatch_and_untyped_failure_are_not_mismatches(self):
        for change in (
            lambda r: r.update(environment="/private/config"),
            lambda r: r["snapshot"].update(environment="other"),
            lambda r: r["document"]["assets"][0].update(owner="/private/key"),
            lambda r: r["document"]["assets"][-1]["dependencies"][0].update(
                asset_id="/private/path"
            ),
            lambda r: r["snapshot"]["deployments"][0].update(asset_id="/private/path"),
            lambda r: r["revoked"][0].update(asset_id="/private/path"),
        ):
            original = copy.deepcopy(self.packet)
            item = self.packet["observations"][8]
            change(item["graph_request"])
            sha = digest(canonical(item["graph_request"]))
            item.update(subject_sha256=sha, request_sha256=sha, configured_request_sha256=sha)
            self.sign_records()
            self.reject()
            self.packet = original
        changed = copy.deepcopy(self.packet)
        changed["observations"][7]["graph_request"]["snapshot"]["deployments"].pop()
        self.reject(changed)

    def test_validly_signed_unrelated_event_cannot_extend_inventory_campaign(self):
        book = ledger.Ledger(self.fx.registry, self.packet["bundle"]["collector"])
        event = self.fx.event(
            kind="artifact.rejected", role="intake", occurred_at_ms=3200, observed_at_ms=3200
        )
        envelope = signing.sign(event, "security-event", self.fx.keys["intake"])
        book.ingest(envelope, clock_ms=3210)
        book.route((event["event_id"], self.fx.keys["receipt"]), clock_ms=3220)
        self.packet["bundle"].update(
            collector=book.document(), incidents=book.document()["records"]
        )
        self.reject()

    def test_request_identity_is_stable_across_retry_and_pin_control(self):
        for index in (3, 4, 11):
            changed = copy.deepcopy(self.packet)
            changed["observations"][index]["request_sha256"] = "9" * 64
            if index != 11:
                changed["observations"][index]["configured_request_sha256"] = "9" * 64
            self.reject(changed)

    def test_distinct_candidate_requests_cannot_share_one_request_hash(self):
        changed = copy.deepcopy(self.packet)
        original = changed["observations"][0]["request_sha256"]
        changed["observations"][1].update(
            request_sha256=original, configured_request_sha256=original
        )
        self.reject(changed)

    def test_real_signed_receipt_for_another_event_is_not_delivery_evidence(self):
        wrong = self.packet["bundle"]["outboxes"][0]["records"][1]["receipt"]
        for records in (
            self.packet["bundle"]["outboxes"][0]["records"],
            self.packet["bundle"]["collector"]["records"],
            self.packet["bundle"]["incidents"],
        ):
            records[0]["receipt"] = copy.deepcopy(wrong)
        self.reject()

    def retime_receipt(self, packet, index, *, ingested=None, routed=None):
        record = packet["bundle"]["outboxes"][0]["records"][index]
        event = self.fx.registry.verify(record["envelope"], clock_ms=record["queued_at_ms"])
        receipt = self.fx.registry.receipt(record["receipt"], event)
        if ingested is not None:
            receipt["ingested_at_ms"] = ingested
        if routed is not None:
            receipt["routed_at_ms"] = routed
        signed = signing.sign(receipt, "security-event-receipt", self.fx.keys["receipt"])
        self.fx.registry.receipt(signed, event)
        for records in (
            packet["bundle"]["outboxes"][0]["records"],
            packet["bundle"]["collector"]["records"],
            packet["bundle"]["incidents"],
        ):
            records[index]["receipt"] = copy.deepcopy(signed)
            if "ingested_at_ms" in records[index]:
                records[index]["ingested_at_ms"] = receipt["ingested_at_ms"]
        for document in (packet["bundle"]["outboxes"][0], packet["bundle"]["collector"]):
            document["updated_at_ms"] = max(document["updated_at_ms"], receipt["routed_at_ms"])
        outbox.Outbox(self.fx.registry, self.producer, packet["bundle"]["outboxes"][0])
        ledger.Ledger(self.fx.registry, packet["bundle"]["collector"])

    def test_online_signed_receipt_after_cli_finish_is_rejected(self):
        for record, observation in ((0, 1), (2, 7), (3, 8), (4, 9), (5, 10)):
            with self.subTest(case=self.packet["observations"][observation]["case_id"]):
                changed = copy.deepcopy(self.packet)
                end = changed["observations"][observation]["finished_at_ms"]
                self.retime_receipt(changed, record, routed=end + 1)
                self.reject(changed)

    def test_same_host_ingest_cannot_precede_event_enqueue(self):
        changed = copy.deepcopy(self.packet)
        queued = changed["bundle"]["outboxes"][0]["records"][0]["queued_at_ms"]
        self.retime_receipt(changed, 0, ingested=queued - 1)
        self.reject(changed)

    def test_online_delivery_boundaries_are_inclusive_and_retry_stays_separate(self):
        changed = copy.deepcopy(self.packet)
        for record, observation in ((0, 1), (2, 7), (3, 8), (4, 9), (5, 10)):
            queued = changed["bundle"]["outboxes"][0]["records"][record]["queued_at_ms"]
            end = changed["observations"][observation]["finished_at_ms"]
            self.retime_receipt(changed, record, ingested=queued, routed=end)
        self.assertEqual(self.verify(changed)["status"], "pass")
        offline = changed["bundle"]["outboxes"][0]["records"][1]
        event = self.fx.registry.verify(offline["envelope"], clock_ms=offline["queued_at_ms"])
        receipt = self.fx.registry.receipt(offline["receipt"], event)
        self.assertGreater(receipt["routed_at_ms"], changed["observations"][2]["finished_at_ms"])

    def test_retention_binds_independent_owner_inputs_and_checks_sidecar_readback(self):
        from scripts import security_inventory_events_native as native

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "primary.json"
            result = native.retain_primary(path, self.packet, **self.options)
            binding_path = path.with_name("primary.bindings.json")
            self.assertTrue(
                binding_path.exists(), "owner inputs were discarded with fixture cleanup"
            )
            sidecar = read_json(binding_path)
            self.assertEqual(sidecar["expected"], self.options)
            self.assertEqual(result["binding_sha256"], digest(canonical(sidecar)))
            self.assertEqual(
                self.module().verify(read_json(path), **sidecar["expected"])["primary_sha256"],
                result["primary_sha256"],
            )
            original_read = read_json

            def altered_read(target):
                value = original_read(target)
                if Path(target) == binding_path:
                    value["expected"]["expected_root"] = self.fx.publics["worker"]
                return value

            with patch.object(native, "read_json", side_effect=altered_read):
                with self.assertRaises(Rejected):
                    native.retain_primary(path, self.packet, **self.options)


class NativeCLIPrivacy(unittest.TestCase):
    def test_raw_exception_and_argument_details_are_not_printed(self):
        from scripts import security_inventory_events_native as native

        main = getattr(native, "main", None)
        self.assertTrue(callable(main), "native failures still expose raw exceptions")
        for failure in (OSError("PRIVATE-CANARY/config"), KeyboardInterrupt()):
            with (
                patch.object(native, "qualify", side_effect=failure),
                contextlib.redirect_stdout(io.StringIO()) as output,
                contextlib.redirect_stderr(io.StringIO()) as error,
            ):
                result = main(["--state", "PRIVATE-CANARY"])
            self.assertIn(result, (1, 130))
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(error.getvalue(), "inventory_security_native_rejected\n")
        with contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(main(["--unknown=PRIVATE-CANARY"]), 1)
        self.assertNotIn("PRIVATE-CANARY", error.getvalue())


class ControlledNative:
    """Real source capture, signing, outbox and ledger; fake OS/SQL boundaries only."""

    def __init__(self):
        self.fx = fixtures.EventContracts("runTest")
        self.fx.setUp()
        self.directory = self.fx.directory
        now = self.now()
        self.fx.document.update(issued_at_ms=now - 1000, expires_at_ms=now + 600000)
        self.registry = self.fx.registry_for(clock=now)
        self.box = outbox.Outbox.empty(
            self.registry, outbox.key_identity(self.fx.keys["promoter"]), clock_ms=now
        )
        self.box.snapshot = self.box.document
        self.book = ledger.Ledger.empty(self.registry, clock_ms=now)
        self.audit_config = self.directory / "audit.json"
        self.write("audit.json", canonical(dict(schema_version=2)))
        self.write(
            "registry.json",
            canonical(
                signing.sign(self.fx.document, "security-event-config", self.fx.keys["root"])
            ),
        )
        self.write(
            "collector.json",
            canonical(
                dict(
                    registry_file=str(self.directory / "registry.json"),
                    registry_root=self.fx.publics["root"],
                    registry_sha256=self.registry.sha256,
                    state_directory=str(self.directory / "state"),
                    state_sha256="a" * 64,
                )
            ),
        )
        self.start()
        self.fail_cleanup = False
        self.fail_stop = False
        self.stop_count = 0
        self.page_mode = "normal"
        self.expected = dict(
            image_id="sha256:" + "a" * 64, source_revision="b" * 40, source_fingerprint="f" * 64
        )

    @staticmethod
    def now():
        return time.time_ns() // 1_000_000

    def write(self, name, body):
        (self.directory / name).write_bytes(body)

    def start(self):
        self.process = object()

    def stop(self):
        self.stop_count += 1
        self.process = None
        if self.fail_stop and self.stop_count == 2:
            raise Rejected("controlled_stop_failed")

    @contextmanager
    def live(self):
        try:
            yield self
        finally:
            self.stop()
            if self.fail_cleanup:
                raise Rejected("controlled_cleanup_failed")
            self.fx.doCleanups()

    def send(self, envelope):
        if self.process is None:
            raise OSError("controlled_offline")
        record = self.book.ingest(envelope, clock_ms=self.now())
        event = self.registry.verify(record["envelope"], clock_ms=record["ingested_at_ms"])
        return self.book.route(
            (event.document()["event_id"], self.fx.keys["receipt"]), clock_ms=self.now()
        )["receipt"]

    def emitter(self, *args):
        return security_event_delivery.Emitter(
            self.box, self.fx.keys["promoter"], SimpleNamespace(send=self.send)
        )

    def exchange(self, method, path):
        if method != "GET" or self.process is None:
            raise Rejected("controlled_http")
        offset = int(path.rsplit("/", 1)[-1])
        records = self.book.document()["records"]
        page = dict(
            incidents=records[offset : offset + 2],
            next_offset=offset + 2 if offset + 2 < len(records) else None,
            release_ready=False,
        )
        if self.page_mode == "bad-offset":
            page["next_offset"] = offset
        elif self.page_mode == "omit-record":
            page["incidents"] = []
            page["next_offset"] = None
        return 200, page

    def run(self, argv, **kwargs):
        config = read_json(argv[-1])
        request = read_json(config["request_file"])
        try:
            if digest(canonical(request)) != config["request_sha256"]:
                raise Rejected("controlled_pin")

            def operation():
                if config["mode"] == "graph":
                    return asset_graph.assess(**request)
                if request["context"]["candidate_reference"] == "0" * 64:
                    raise Rejected("storage_object_missing")
                if request["context"]["expected"] != self.expected:
                    raise asset_graph.InventoryMismatch(
                        "inventory_candidate_build_binding", "digest"
                    )

            subject = (
                config["request_sha256"]
                if config["mode"] == "graph"
                else request["context"]["candidate_reference"]
            )
            security_inventory_events.capture(
                operation, audit=self.emitter(), subject=lambda: subject
            )
            return SimpleNamespace(
                returncode=0,
                stderr=b"",
                stdout=canonical(
                    dict(
                        state="verified",
                        subject_sha256=subject,
                        scope="controlled-cli-transport",
                        full_M19="inconclusive",
                        release_ready=False,
                    )
                ),
            )
        except Rejected:
            return SimpleNamespace(
                returncode=1, stderr=b"inventory_security_rejected\n", stdout=b""
            )


class NativeRetention(unittest.TestCase):
    def setUp(self):
        self.fx = ControlledNative()
        self.addCleanup(self.fx.fx.doCleanups)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        self.sql = {
            name: dict(objects=2, digest="a" * 64)
            for name in ("manifests", "lineage", "candidates", "evaluations")
        }
        self.sql_changed = False
        self.container_changed = False

    def campaign(self):
        from scripts import security_inventory_events_native as native

        actual_read = read_json

        def read(path):
            if Path(path).name == "storage-demo.json":
                return dict(
                    candidate=dict(candidate_reference="c" * 64), evaluation_reference="e" * 64
                )
            if Path(path).name in ("storage-trust.json", "local-cpu.json"):
                return {}  # SQL boundary is replaced; no credential or policy file access.
            return actual_read(path)

        after = copy.deepcopy(self.sql)
        if self.sql_changed:
            after["candidates"]["digest"] = "9" * 64
        with (
            patch.object(native.sys, "platform", "linux"),
            patch.dict(
                native.os.environ, GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted"
            ),
            patch.object(
                native, "command", side_effect=lambda args: "b" * 40 if args[-1] == "HEAD" else ""
            ),
            patch.object(native, "source_fingerprint", return_value="f" * 64),
            patch.object(native, "resolve_image", return_value="sha256:" + "a" * 64),
            patch.object(
                native,
                "validate",
                side_effect=[
                    dict(container_id="1" * 64),
                    dict(container_id=("2" if self.container_changed else "1") * 64),
                ],
            ),
            patch.object(native, "metadata_snapshot", side_effect=[self.sql, after]),
            patch.object(native, "read_json", side_effect=read),
            patch.object(
                native.candidate_lineage,
                "collect",
                return_value=dict(graph=dict(assets=[dict(kind="model", sha256="d" * 64)])),
            ),
            patch.object(native.audit_fixture, "live", self.fx.live),
            patch.object(native.security_event_delivery, "configured", self.fx.emitter),
            patch.object(
                native.security_source_capture.storage,
                "Store",
                return_value=SimpleNamespace(snapshot=self.fx.book.document),
            ),
            patch.object(native.subprocess, "run", self.fx.run),
        ):
            return native.qualify(self.state, "controlled-image")

    def test_native_orchestration_retains_after_cleanup_with_full_primary_not_public(self):
        result = self.campaign()
        self.assertFalse(self.fx.directory.exists())
        primary = read_json(self.state / "evidence/security-inventory-primary.json")
        self.assertEqual(result["primary_sha256"], digest(canonical(primary)))
        self.assertEqual(len(primary["observations"]), 12)
        self.assertEqual(len(primary["bundle"]["incidents"]), 6)
        self.assertEqual(primary["sql"]["source_sql_cleanup"], "caller-owned-not-performed")
        self.assertNotIn(str(self.fx.directory), canonical(primary).decode())
        self.assertNotIn(str(self.state), canonical(primary).decode())
        self.assertNotIn(b"PRIVATE KEY", canonical(primary))
        self.assertNotIn(b"signatures", canonical(result))
        sidecar = read_json(self.state / "evidence/security-inventory-primary.bindings.json")
        self.assertEqual(digest(canonical(sidecar)), result["binding_sha256"])
        self.assertEqual(sidecar["expected"]["expected_root"], self.fx.fx.publics["root"])
        self.assertNotIn(str(self.state), canonical(sidecar).decode())
        self.assertNotIn(str(self.fx.directory), canonical(sidecar).decode())

    def test_failed_fixture_cleanup_never_writes_artifact(self):
        self.fx.fail_cleanup = True
        with self.assertRaisesRegex(Rejected, "controlled_cleanup_failed"):
            self.campaign()
        self.assertFalse((self.state / "evidence").exists())

    def test_failed_collector_stop_never_writes_artifact(self):
        self.fx.fail_stop = True
        with self.assertRaisesRegex(Rejected, "controlled_stop_failed"):
            self.campaign()
        self.assertFalse((self.state / "evidence").exists())

    def test_changed_sql_or_container_never_writes_artifact(self):
        self.sql_changed = True
        with self.assertRaisesRegex(Rejected, "source-sql-unchanged-and-owned"):
            self.campaign()
        self.assertFalse((self.state / "evidence").exists())

    def test_changed_container_never_writes_artifact(self):
        self.container_changed = True
        with self.assertRaisesRegex(Rejected, "source-sql-unchanged-and-owned"):
            self.campaign()
        self.assertFalse((self.state / "evidence").exists())

    def test_missing_incident_or_nonprogressing_pages_reject_before_retention(self):
        from scripts import security_inventory_events_native as native

        for mode in ("bad-offset", "omit-record"):
            self.fx.start()
            self.fx.page_mode = mode
            self.fx.emitter().emit(
                dict(
                    kind="inventory.mismatch",
                    reason="owner",
                    asset_sha256="c" * 64,
                    bundle_sha256=None,
                    correlation_id="1" * 32,
                )
            )
            with self.assertRaisesRegex(Rejected, "source_capture_(incidents|incomplete)"):
                native.capture_delivery(
                    self.fx, self.fx.emitter, collector_snapshot=self.fx.book.document
                )


if __name__ == "__main__":
    unittest.main()
