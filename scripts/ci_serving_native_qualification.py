"""Orchestrate real driver code against strict local, non-infrastructure boundaries."""

import copy
import importlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops.contracts import Rejected, atomic_write, bounded_read, canonical, decode, digest
from scripts import ci_validation_transfer as validation
from scripts import frozen_candidate_transfer as transfer
from scripts import m18_delivery_freeze, release_native
from scripts.ci_producer_cluster_qualification import OWNER, SOURCE

GATES = ("M13", "M14", "M15")
ADMISSIONS = {
    "M13": "evidence/privacy-gate-private.json",
    "M14": "evidence/M14-frozen-private.json",
    "M15": "evidence/M15-frozen-private.json",
}
PIN_NAMES = (
    "M13_PROPOSAL_SHA256",
    "M13_DEMO_SHA256",
    "M14_PROPOSAL_SHA256",
    "M14_DEMO_SHA256",
    "M14_KEYS_SHA256",
    "M14_TRUST_SHA256",
    "M15_PROPOSAL_SHA256",
    "M15_DEMO_SHA256",
    "M15_KEYS_SHA256",
    "M15_TRUST_SHA256",
    "SERVING_RETENTION",
)


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("scripts.ci_serving_native"), "driver missing"
        )
        self.m = importlib.import_module("scripts.ci_serving_native")
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.producer = self.root / ".runtime"
        self.producer.mkdir()
        self.events, self.faults = [], {}
        self.state, self.attached, self.created = None, False, False
        self.cleaned = False
        self.cleanup_result = dict.fromkeys((*GATES, "SQL"), True)
        self.marker = dict(workspace_id="a" * 32, container_id="1" * 64, port=15439)
        self.consumer_marker = dict(workspace_id="b" * 32, container_id="2" * 64, port=15440)
        self.expected = {k: SOURCE.get(k, digest(k.encode())) for k in transfer.IDENTITY}
        self.values = self.expected | dict(integrity_snapshot={"manifest": "f" * 64})
        self.original = dict(status="pass", source=SOURCE, source_dirty=False)
        self.freeze = {}
        for name in transfer.delivery.FILES:
            raw = (
                canonical(self.original if name == transfer.delivery.PROPOSAL else {"name": name})
                + b"\n"
            )
            self.freeze[name] = digest(raw)
            if name != transfer.delivery.PROPOSAL:
                atomic_write(self.producer / name, raw)
        self.owner = dict(
            freeze_pin="e" * 64, freeze=self.freeze, expected=self.expected, run_owner=OWNER
        )
        self.upstream = {}
        self.upstream_bytes = {}
        for gate in ("M02", "M03", "M07"):
            raw = canonical(dict(gate=gate, status="pass", exit_code=0)) + b"\n"
            atomic_write(self.producer / f"evidence/{gate}.json", raw)
            self.upstream[gate] = digest(raw)
            self.upstream_bytes[gate] = raw
        self.envelopes = {
            name: dict(
                envelope=("PRIVATE-" + name).encode(),
                context={"phase": name + "M13"},
                ciphertext_sha256=digest(name.encode()),
                manifest_sha256="d" * 64,
            )
            for name in ("candidate", "upstream", "validation")
        }
        self.validation = canonical([{"original": "validation"}])
        self.key = b"K" * 32
        self.offline = "c" * 64
        self.retention_args = None
        self.gate_change = None
        self.gates_done = []
        self.enterContext(patch.dict(os.environ, {name: "previous-" + name for name in PIN_NAMES}))
        self.enterContext(
            patch.dict(os.environ, {"GITHUB_OUTPUT": str(self.root / "public-output")})
        )
        self.before_env = dict(os.environ)
        for target in ("subprocess.run", "subprocess.Popen", "socket.socket"):
            self.enterContext(patch(target, side_effect=AssertionError("no infrastructure")))
        self.mock(self.m.driver, "hosted", lambda: self.event("hosted"))
        self.mock(self.m.driver, "source", lambda root, image: self.source(root, image))
        self.mock(self.m.driver, "run_owner", lambda: OWNER.copy())
        self.mock(
            self.m.producer_cluster, "cleanup", lambda producer: self.event("producer_cleanup")
        )
        self.mock(self.m.storage_bootstrap, "validate", self.marker_for)
        self.mock(release_native, "qualify", self.proposal)
        self.mock(m18_delivery_freeze, "capture", self.freeze_capture)
        self.mock(transfer.delivery, "pinned", lambda *a: {"freeze": self.freeze})
        self.mock(transfer.delivery, "frozen", lambda *a: (self.values, {}, {}))
        self.enterContext(
            patch.object(
                self.m,
                "secrets",
                SimpleNamespace(
                    token_bytes=lambda size: self.key if size == 32 else self.fail("key length")
                ),
            )
        )
        self.mock(self.m.bridge, "seal", lambda *a, **kw: self.seal("candidate", *a, **kw))
        self.mock(self.m.upstream, "seal", lambda *a, **kw: self.seal("upstream", *a, **kw))
        self.mock(validation, "seal", lambda *a, **kw: self.seal("validation", *a, **kw))
        self.mock(
            validation,
            "_descriptor",
            lambda state, values: {"sha256": digest(self.validation)},
        )
        self.mock(validation, "retain", self.validation_retain)
        self.mock(self.m.storage, "get", self.validation_get)
        self.mock(self.m.bridge, "_fresh", self.fresh)
        self.mock(self.m.bridge, "_window", lambda context, values, now: self.event("window"))
        self.mock(
            self.m.m17_recovery_native,
            "stop_owned",
            lambda state: (
                self.event("producer_stop")
                if state == self.producer
                else self.fail("consumer stop bypasses lifecycle")
            ),
        )
        self.mock(self.m.shared_serving_receipt, "offline_pin", self.offline_pin)
        self.mock(self.m.consumer_candidate_state, "materialize", self.materialize)
        self.mock(self.m.upstream, "materialize", self.attach)
        self.mock(self.m.storage_pki, "initialize", lambda state: self.event("tls"))
        self.mock(self.m.lifecycle.Lifecycle, "begin", self.begin)
        self.mock(self.m.lifecycle.Lifecycle, "load", self.load)
        self.mock(self.m.candidate_storage, "import_candidate", self.import_candidate)
        self.mock(self.m.validation_storage, "import_validation", self.import_validation)
        self.mock(self.m.serving_retention, "retain", self.retention_start)
        self.mock(self.m.serving_retention, "preflight", self.preflight)
        self.mock(self.m.acceptance, "report", self.gate)
        self.mock(self.m.exporter, "retain", self.export)
        self.mock(self.m.exporter, "replay", self.replay)

    def mock(self, obj, name, action):
        return self.enterContext(patch.object(obj, name, side_effect=action))

    def event(self, name):
        self.events.append(name)
        fault = self.faults.get(name)
        if fault:
            raise fault

    def source(self, root, image):
        self.assertEqual((root, image), (self.root, "trusted-mlsecops:dev"))
        self.event("source")
        return SOURCE.copy()

    def marker_for(self, state):
        self.event("target")
        return self.marker if state == self.producer else self.consumer_marker

    def proposal(self, root, producer, image):
        self.assertIn("producer_cleanup", self.events)
        self.assertEqual(self.events.count("proposal"), 0)
        self.event("proposal")
        return self.original

    def freeze_capture(self, root, state, freeze, revision):
        self.assertEqual(
            (state, freeze, revision), (self.producer, self.freeze, SOURCE["source_revision"])
        )
        self.event("freeze")
        return self.owner["freeze_pin"]

    def authority(self, args):
        self.assertEqual({k: args[k] for k in self.owner}, self.owner)

    def seal(self, name, root, state, *args, **kw):
        self.authority(kw)
        self.assertIs(kw["key"], self.key)
        self.assertEqual(kw["phase"], "M13")
        self.assertEqual(state, self.producer)
        self.assertNotIn("producer_stop", self.events)
        if name == "upstream":
            self.assertEqual(kw["reports"], self.upstream)
        if name == "validation":
            self.assertEqual(args, (b"retained-validation",))
        self.event("seal_" + name)
        return self.envelopes[name].copy()

    def validation_get(self, client, namespace, reference):
        self.assertEqual(
            (client, namespace, reference),
            (self.producer / "storage-clients/publisher", "validation", digest(self.validation)),
        )
        self.event("validation_get")
        return self.validation

    def validation_retain(self, root, state, raw, **kw):
        self.authority(kw)
        self.assertEqual(raw, self.validation)
        self.event("validation_retain")
        return b"retained-validation"

    def fresh(self, root, state, owner):
        self.assertEqual(owner, self.owner)
        self.event("fresh")
        return self.values, 1000

    def transport(self, name, raw, kw):
        self.authority(kw)
        expected = self.envelopes[name]
        self.assertIs(kw["key"], self.key)
        self.assertEqual(
            (raw, kw["phase"], kw["expected_context"], kw["ciphertext_pin"]),
            (expected["envelope"], "M13", expected["context"], expected["ciphertext_sha256"]),
        )

    @contextmanager
    def materialize(self, root, envelope, **kw):
        self.transport("candidate", envelope, kw)
        self.assertEqual(kw["manifest_pin"], self.envelopes["candidate"]["manifest_sha256"])
        self.assertEqual(kw["trust_key_path"], self.producer / "keys/trust.pem")
        self.assertIn("producer_stop", self.events)
        self.event("materialize")
        try:
            with tempfile.TemporaryDirectory(dir=self.root) as temporary:
                self.state = Path(temporary)
                yield self.state, dict(workspace_id="b" * 32)
        finally:
            self.event("context_exit")

    @contextmanager
    def attach(self, root, state, envelope, **kw):
        self.transport("upstream", envelope, kw)
        self.assertEqual(kw["workspace_id"], "b" * 32)
        self.assertEqual(kw["reports"], self.upstream)
        self.event("attach")
        self.attached = True
        try:
            for gate in self.upstream:
                atomic_write(
                    state / f"evidence/{gate}.json",
                    self.upstream_bytes[gate],
                )
            yield state, dict(reports=self.upstream)
        finally:
            self.attached = False
            self.event("attach_exit")

    def begin(self, producer, state, **kw):
        self.assertEqual(kw, dict(run_owner=OWNER, source=SOURCE))
        self.assertEqual((producer, state), (self.producer, self.state))
        self.assertIn("tls", self.events)
        self.event("begin")
        self.created = True
        return self

    def load(self, producer, **kw):
        self.assertEqual(kw, dict(run_owner=OWNER, source=SOURCE))
        self.event("load")
        if not self.created:
            raise Rejected("no witness")
        return self

    def bootstrap_sql(self, state):
        self.event("sql")
        atomic_write(state / "storage.json", canonical(self.consumer_marker) + b"\n")
        self.storage_pin = digest(bounded_read(state / "storage.json"))
        return self.storage_pin

    def import_candidate(self, root, state, **kw):
        self.authority(kw)
        self.assertEqual(
            (kw["expected_workspace_id"], kw["storage_pin"]), ("b" * 32, self.storage_pin)
        )
        self.assertFalse(self.gates_done)
        self.event("import_candidate")
        return dict(
            status="pass",
            proposal_reference=self.expected["proposal_reference"],
            workspace_id="b" * 32,
            storage_pin=self.storage_pin,
        )

    def import_validation(self, root, state, envelope, **kw):
        self.transport("validation", envelope, kw)
        self.assertEqual(
            (kw["expected_workspace_id"], kw["storage_pin"]), ("b" * 32, self.storage_pin)
        )
        self.assertFalse(self.gates_done)
        self.event("import_validation")
        return dict(
            status="pass",
            validation_sha256=digest(self.validation),
            workspace_id="b" * 32,
            storage_pin=self.storage_pin,
        )

    def retention_start(self, root, state, **kw):
        self.assertEqual(
            kw,
            dict(
                freeze_pin=self.owner["freeze_pin"],
                source_pin=self.storage_pin,
                pins=self.freeze,
                revision=SOURCE["source_revision"],
            ),
        )
        self.event("retention_start")
        return "a" * 64

    def start(self, state, pin):
        self.assertEqual(pin, self.storage_pin)
        self.assertIn("import_validation", self.events)
        self.event("start")

    def preflight(self, root, state, pin, revision, phase):
        self.assertEqual((pin, revision), ("a" * 64, SOURCE["source_revision"]))
        self.event("preflight_" + phase)

    def gate(self, gate, profile, root, *, state):
        self.assertEqual(self.events[-1], "preflight_" + gate)
        self.assertEqual(profile, "local-cpu")
        self.assertEqual(gate, GATES[len(self.gates_done)])
        for label, name in (
            ("PROPOSAL", transfer.delivery.PROPOSAL),
            ("DEMO", "storage-demo.json"),
        ):
            self.assertEqual(os.environ[gate + "_" + label + "_SHA256"], self.freeze[name])
        if gate != "M13":
            for label, name in (("KEYS", "trusted-keys.json"), ("TRUST", "storage-trust.json")):
                self.assertEqual(os.environ[gate + "_" + label + "_SHA256"], self.freeze[name])
        self.event(gate)
        self.assertTrue(self.attached)
        self.assertFalse(self.cleaned)
        self.gates_done.append(gate)
        atomic_write(state / ADMISSIONS[gate], canonical({"gate": gate}) + b"\n")
        print("PRIVATE-PYTHON", file=sys.stderr)
        os.write(1, b"PRIVATE-FD-OUT\n")
        os.write(2, b"PRIVATE-FD-ERR\n")
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as out:
            out.write("PRIVATE-OUTPUT\n")
        os.environ["NEW_GATE_PIN"] = "PRIVATE-ENV"
        report = dict(gate=gate, status="pass", exit_code=0, cases=[{"id": "ordinary"}])
        if self.gate_change:
            report.update(self.gate_change)
        return report

    def transition(self, state, phase, pin):
        self.assertEqual(pin, self.storage_pin)
        self.assertEqual(phase, self.gates_done[-1])
        self.assertFalse(self.cleaned)
        self.event("transition_" + phase)
        return dict(
            before={"phase": phase}, after={"phase": GATES[GATES.index(phase) + 1]}, source_sql=pin
        )

    def cleanup(self):
        self.event("cleanup")
        self.cleaned = True
        return self.cleanup_result.copy()

    def offline_pin(self, state):
        self.assertEqual(state, self.producer)
        self.event("offline")
        return self.offline

    def export(self, root, state, destination, **kw):
        self.authority(kw)
        self.assertTrue(self.attached and self.cleaned and state.exists())
        self.assertEqual(kw["consumer_storage_pin"], self.storage_pin)
        self.assertEqual(kw["report_pins"].keys(), {*self.upstream, *GATES})
        for gate, pin in kw["report_pins"].items():
            self.assertEqual(pin, digest(bounded_read(state / f"evidence/{gate}.json")))
        for gate, pin in kw["admission_pins"].items():
            self.assertEqual(pin, digest(bounded_read(state / ADMISSIONS[gate])))
        self.assertEqual([p["before"]["phase"] for p in kw["transitions"]], ["M13", "M14"])
        self.retention_args = copy.deepcopy(kw)
        self.event("export")
        return dict(index_pin="9" * 64, release_ready=False)

    def replay(self, root, destination, *, index_pin, **kw):
        self.assertFalse(self.attached or self.state.exists())
        self.assertEqual(index_pin, "9" * 64)
        self.assertEqual(kw, self.retention_args)
        self.event("replay")
        return dict(release_ready=False)

    def execute(self, **kw):
        result = self.m.execute(self.root, **kw)
        self.assertEqual(dict(os.environ), self.before_env)
        self.assertEqual(set(result), {"status", "stage", "gate_counts", "cleanup_counts"})
        self.assertNotIn("PRIVATE", canonical(result).decode())
        self.assertFalse((self.root / "public-output").exists())
        return result

    def test_gate_failure_stops_same_pipeline_and_preserves_stage_during_cleanup(self):
        self.gate_change = dict(status="pass", exit_code=1)
        result = self.execute()
        self.assertEqual((result["status"], result["stage"]), ("fail", "M13"))
        self.assertEqual(self.gates_done, ["M13"])
        self.assertTrue(self.cleaned)
        self.assertNotIn("export", self.events)

    def test_full_sequence_retains_before_exit_replays_after_and_imports_only_once(self):
        result = self.execute()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["gate_counts"], dict.fromkeys(GATES, 1))
        self.assertEqual(result["cleanup_counts"], dict(required=4, verified=4))
        for name in (
            "proposal",
            "import_candidate",
            "import_validation",
            "transition_M13",
            "transition_M14",
        ):
            self.assertEqual(self.events.count(name), 1)
        for left, right in (
            ("producer_cleanup", "proposal"),
            ("seal_validation", "producer_stop"),
            ("cleanup", "export"),
            ("export", "attach_exit"),
            ("context_exit", "replay"),
        ):
            self.assertLess(self.events.index(left), self.events.index(right))

    def test_failures_at_every_boundary_never_advance_or_skip_outer_cleanup(self):
        for stage in (
            "seal_candidate",
            "seal_upstream",
            "validation_retain",
            "seal_validation",
            "materialize",
            "attach",
            "tls",
            "begin",
            "sql",
            "import_candidate",
            "import_validation",
            "retention_start",
            "start",
            "preflight_M13",
            "M13",
            "transition_M13",
            "preflight_M14",
            "M14",
            "transition_M14",
            "preflight_M15",
            "M15",
            "export",
            "attach_exit",
            "context_exit",
            "replay",
        ):
            with self.subTest(stage=stage):
                case = DriverTests(
                    "test_full_sequence_retains_before_exit_replays_after_and_imports_only_once"
                )
                case.setUp()
                try:
                    case.faults[stage] = Rejected("PRIVATE-" + stage)
                    result = case.execute()
                    self.assertEqual(result["status"], "fail")
                    self.assertIn("load", case.events)
                    self.assertIn("producer_stop", case.events)
                    if case.created:
                        self.assertIn("cleanup", case.events)
                    self.assertEqual(case.events.count("proposal"), 1)
                finally:
                    case.doCleanups()

    def test_partial_cleanup_blocks_export_even_with_all_gates_pass(self):
        self.cleanup_result["M14"] = False
        result = self.execute()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["cleanup_counts"]["verified"], 3)
        self.assertNotIn("export", self.events)

    def test_original_upstream_pins_not_refreshed_from_mutable_producer(self):
        def initialize(state):
            self.event("tls")
            atomic_write(self.producer / "evidence/M02.json", b"changed-after-seal")

        with patch.object(self.m.storage_pki, "initialize", initialize):
            result = self.execute()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(
            {g: self.retention_args["report_pins"][g] for g in self.upstream}, self.upstream
        )

    def test_gate_failure_cleans_before_context_exit_then_outer_retry(self):
        self.faults["M14"] = Rejected("private-gate-failure")
        result = self.execute()
        self.assertEqual((result["status"], result["stage"]), ("fail", "M14"))
        self.assertLess(self.events.index("cleanup"), self.events.index("attach_exit"))
        self.assertGreater(self.events.count("cleanup"), 1)

    def test_stale_before_gate_does_not_renew_or_run_later_phase(self):
        self.faults["preflight_M14"] = Rejected("remaining=599")
        result = self.execute()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(self.gates_done, ["M13"])
        self.assertEqual(self.events.count("proposal"), 1)

    def test_existing_proposal_refuses_before_new_authority(self):
        atomic_write(self.producer / transfer.delivery.PROPOSAL, b"original")
        result = self.execute()
        self.assertEqual(result["status"], "fail")
        self.assertNotIn("proposal", self.events)

    def test_wrong_new_sql_owner_or_port_prevents_all_imports(self):
        self.consumer_marker["container_id"] = self.marker["container_id"]
        result = self.execute()
        self.assertEqual(result["status"], "fail")
        self.assertNotIn("import_candidate", self.events)

    def test_private_output_environment_restored_and_no_memory_key_persisted(self):
        self.assertEqual(self.execute()["status"], "pass")
        raw = b"\n".join(p.read_bytes() for p in self.producer.rglob("*") if p.is_file())
        for value in (b"PRIVATE-PYTHON", b"PRIVATE-FD-OUT", b"PRIVATE-FD-ERR", b"PRIVATE-OUTPUT"):
            self.assertIn(value, raw)
        self.assertNotIn(self.key, raw)
        self.assertNotIn(b"PRIVATE-candidate", raw)

    def test_clean_source_failure_never_proposes_or_adopts_resources(self):
        self.faults["source"] = Rejected("dirty")
        result = self.execute()
        self.assertEqual(result["status"], "fail")
        self.assertNotIn("proposal", self.events)
        self.assertNotIn("begin", self.events)

    def test_cli_arguments_closed_and_stdout_contains_only_projection(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = self.m.main(["PRIVATE-invalid"])
        self.assertEqual(code, 1)
        result = decode(out.getvalue().encode())
        self.assertEqual(result["stage"], "arguments")
        self.assertNotIn("PRIVATE", out.getvalue())

    def test_cleanup_cli_reloads_external_binding_after_view_deleted(self):
        self.assertEqual(self.execute()["status"], "pass")
        self.assertFalse(self.state.exists())
        before = self.events.count("proposal")
        with patch.object(self.m, "__file__", str(self.root / "scripts/ci_serving_native.py")):
            out = io.StringIO()
            with redirect_stdout(out), patch.object(sys, "argv", ["ci_serving_native", "cleanup"]):
                code = self.m.main()
        self.assertEqual(code, 0)
        self.assertEqual(decode(out.getvalue().encode())["cleanup_counts"]["verified"], 4)
        self.assertEqual(before, self.events.count("proposal"))
        self.assertEqual(dict(os.environ), self.before_env)

    def test_missing_cleanup_witness_and_changed_offline_owner_never_pass(self):
        result = self.execute(cleanup=True)
        self.assertEqual((result["status"], result["cleanup_counts"]["verified"]), ("fail", 0))
        self.assertNotIn("begin", self.events)
        self.assertEqual(self.execute()["status"], "pass")
        record = decode(bounded_read(self.producer / self.m.OFFLINE))
        record["run_owner"]["run_attempt"] += 1
        atomic_write(self.producer / self.m.OFFLINE, canonical(record))
        self.assertEqual(self.execute(cleanup=True)["status"], "fail")

    def test_cleanup_wrong_source_or_run_refused_by_durable_loader(self):
        self.assertEqual(self.execute()["status"], "pass")

        def foreign_load(producer, **kw):
            if kw != dict(source=SOURCE, run_owner=OWNER):
                raise Rejected("foreign durable owner")
            return self

        with patch.object(self.m.lifecycle.Lifecycle, "load", foreign_load):
            with patch.object(self.m.driver, "run_owner", return_value=OWNER | {"run_attempt": 99}):
                self.assertEqual(self.execute(cleanup=True)["status"], "fail")
            with patch.object(
                self.m.driver, "source", return_value=SOURCE | {"image_id": "sha256:" + "f" * 64}
            ):
                self.assertEqual(self.execute(cleanup=True)["status"], "fail")

    def test_actual_fractional_boundary_after_bootstrap_blocks_m13_without_renewal(self):
        moment = [1000.0]
        values = dict(proposal_issued_at=900, captured_at=900, proposal_expires_at=1800)

        def fresh(root, state, owner):
            self.assertEqual(owner, self.owner)
            current = self.m.serving_retention.window(values, None)
            return self.values, current

        def start(state, pin):
            self.start(state, pin)
            moment[0] = 1200.01

        with (
            patch.object(self.m.bridge, "_fresh", fresh),
            patch.object(self, "start", wraps=self.start) as mocked,
        ):
            # Use a separate closure so advancing time is part of the real driver call order.
            original_start = mocked._mock_wraps

            def delayed_start(state, pin):
                original_start(state, pin)
                moment[0] = 1200.01

            mocked.side_effect = delayed_start
            with patch.object(self.m.serving_retention.time, "time", side_effect=lambda: moment[0]):
                result = self.execute()
        self.assertEqual((result["status"], result["stage"]), ("fail", "M13"))
        self.assertFalse(self.gates_done)
        self.assertEqual(self.events.count("proposal"), 1)
        self.assertTrue(self.cleaned)

    def test_primary_exception_survives_cleanup_and_offline_failures(self):
        primary = KeyboardInterrupt("PRIVATE-primary")
        self.faults.update(M14=primary, cleanup=OSError("PRIVATE-cleanup"))
        original_offline = self.offline_pin

        def offline(state):
            if "M14" in self.events:
                raise Rejected("PRIVATE-offline")
            return original_offline(state)

        progress = dict(stage="preflight", gate_counts={}, cleanup={})
        with (
            self.m.driver.private_output(self.producer, "test-error"),
            self.m.environment(self.producer),
        ):
            with patch.object(self.m.shared_serving_receipt, "offline_pin", offline):
                with self.assertRaises(KeyboardInterrupt) as raised:
                    self.m.run(self.root, self.producer, progress)
        self.assertIs(raised.exception, primary)
        self.assertIn("producer_offline_unverified", primary.__notes__)
        self.assertIn("serving_cleanup_unverified", primary.__notes__)
        self.assertEqual(progress["stage"], "M14")

    def test_public_status_stays_fail_when_private_output_exit_fails(self):
        original = self.m.driver.private_output

        @contextmanager
        def failing(producer, action):
            with original(producer, action):
                yield
                raise OSError("PRIVATE-flush")

        with patch.object(self.m.driver, "private_output", failing):
            result = self.execute()
        self.assertEqual((result["status"], result["stage"]), ("fail", "output"))
        self.assertTrue(self.cleaned)

    def test_module_entry_point_emits_closed_cleanup_result(self):
        self.assertEqual(self.execute()["status"], "pass")
        path = Path(self.m.__file__)
        out = io.StringIO()
        with redirect_stdout(out), patch.object(sys, "argv", [str(path), "cleanup"]):
            with self.assertRaises(SystemExit) as raised:
                exec(
                    compile(path.read_text(encoding="utf-8"), str(path), "exec"),
                    {
                        "__name__": "__main__",
                        "__file__": str(self.root / "scripts/ci_serving_native.py"),
                    },
                )
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(decode(out.getvalue().encode())["status"], "pass")

    def test_projection_never_serializes_unknown_fields_or_invalid_counts(self):
        result = self.m.projection(
            dict(
                stage="PRIVATE-stage",
                gate_counts={"M13": True, "M14": -1, "M15": "PRIVATE-count"},
                cleanup={"M13": "PRIVATE-owner"},
                extra="PRIVATE-payload",
            ),
            False,
        )
        self.assertEqual(
            result,
            dict(
                status="fail",
                stage="preflight",
                gate_counts=dict.fromkeys(GATES, 0),
                cleanup_counts=dict(required=4, verified=0),
            ),
        )


if __name__ == "__main__":
    unittest.main()
