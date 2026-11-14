"""Aggregate acceptance must fail on missing routes, mixed source or incomplete cleanup."""

import copy
import io
import os
import runpy
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import mlsecops
from mlsecops import security_gate as gate
from mlsecops.contracts import Rejected, canonical, decode, digest, read_json, write_json
from mlsecops.security_events import RULES


class GateResults(unittest.TestCase):
    def setUp(self):
        self.source = dict(source_revision="a" * 40, source_fingerprint="b" * 64)
        self.subject = dict(
            **self.source,
            image_id="sha256:" + "c" * 64,
            candidate_reference="d" * 64,
            evaluation_reference="e" * 64,
            model_sha256="f" * 64,
        )
        self.sources = dict(
            cases=["sequence:duplicate-no-incident"],
            routes={kind: 60000 for kind in RULES if kind not in gate.CANDIDATE_KINDS},
            sequence_notice_seconds={"ingest-hole": 120, "heartbeat-head-only": 119.8},
            heartbeat_notice_seconds=119.5,
            artifact_hashes={"intake-primary": "a" * 64},
        )
        self.candidate = dict(
            cases=["outage:refusal-and-recovery"],
            routes={kind: 0 for kind in gate.CANDIDATE_KINDS},
            candidate=self.subject,
            release_subject="1" * 64,
            artifact_hashes={"outage-primary": "b" * 64},
            metrics={"observations": 20000},
        )


class Acceptance(GateResults):
    def report(self):
        return gate.reconcile(self.sources, self.candidate, self.source)

    def test_input_digests_follow_the_replayed_release_subject_and_model(self):
        for release, model in (("1" * 64, "f" * 64), ("2" * 64, "3" * 64)):
            with self.subTest(release=release, model=model):
                self.candidate["release_subject"] = release
                self.subject["model_sha256"] = model
                self.assertEqual(
                    self.report()["input_digests"],
                    {**self.subject, "release_subject": release, "model": model},
                )

    def test_malformed_release_or_model_digest_rejects(self):
        for target, field in (
            (self.candidate, "release_subject"),
            (self.subject, "model_sha256"),
        ):
            with self.subTest(field=field), patch.dict(target, {field: "g" * 64}):
                with self.assertRaises(Rejected):
                    self.report()

    def test_seven_routes_and_inclusive_cutoffs(self):
        result = self.report()
        self.assertEqual(set(result["metrics"]["routes"]), set(RULES))
        self.assertEqual(result["input_digests"]["candidate_reference"], "d" * 64)
        self.assertEqual(
            result["metrics"]["routes"]["artifact.rejected"],
            {"route": "security.artifacts", "max_delivery_ms": 60000},
        )
        self.assertEqual(len(result["cases"]), len({case["id"] for case in result["cases"]}))

    def test_missing_mixed_late_or_duplicated_evidence_rejects(self):
        for change in (
            lambda: self.sources["routes"].pop("identity.denied"),
            lambda: self.sources["routes"].update({"promotion.denied": 0}),
            lambda: self.candidate["routes"].update({"promotion.denied": True}),
            lambda: self.candidate["routes"].update({"inventory.mismatch": 60001}),
            lambda: self.sources["sequence_notice_seconds"].update({"ingest-hole": 120.001}),
            lambda: self.sources.update(heartbeat_notice_seconds=float("nan")),
            lambda: self.subject.update(source_fingerprint="0" * 64),
            lambda: self.sources.update(cases=[]),
            lambda: self.candidate.update(cases=copy.copy(self.sources["cases"])),
            lambda: self.sources.update(artifact_hashes={"x": "no-hash"}),
        ):
            self.setUp()
            change()
            with self.assertRaises(Rejected):
                self.report()

    def test_cleanup_fails_on_running_sql_or_named_cluster(self):
        for running, clusters in ((True, ""), (False, "other\ntrusted-mlsecops")):
            with (
                patch.object(gate, "validate", return_value={"container_id": "f" * 64}),
                patch.object(gate, "inspect", return_value={"State": {"Running": running}}),
                patch.object(gate, "command", return_value=clusters),
                self.assertRaises(Rejected),
            ):
                gate.confirm_cleanup("unused")

    def test_cleanup_checks_original_container_id_and_all_cluster_names(self):
        with (
            patch.object(gate, "validate", return_value={"container_id": "f" * 64}),
            patch.object(gate, "inspect", return_value={"State": {"Running": False}}) as inspect,
            patch.object(gate, "command", return_value="another-cluster") as command,
        ):
            gate.confirm_cleanup("unused")
        inspect.assert_called_once_with("container", "f" * 64)
        command.assert_called_once_with(["kind", "get", "clusters"])


class StageWorkflow(GateResults):
    def setUp(self):
        super().setUp()
        self.candidate["proposal_finished_at"] = self.at(0)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.state = self.root / ".runtime"
        for name in (
            "uv.lock",
            "data.lock",
            "pyproject.toml",
            ".python-version",
            "Dockerfile",
            "policies/local-cpu.json",
        ):
            path = self.root / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(name.encode())
        self.source["source_fingerprint"] = gate.source_fingerprint(self.root)
        self.subject.update(self.source)
        self.owner = {"GITHUB_RUN_ID": "74", "GITHUB_RUN_ATTEMPT": "2"}
        self.enterContext(patch.dict(os.environ, self.owner))
        self.enterContext(patch.object(gate, "hosted"))
        self.dirty = ""
        self.clusters = "another-cluster"
        self.enterContext(patch.object(gate, "command", side_effect=self.command))
        self.validate = self.enterContext(
            patch.object(gate, "validate", return_value={"container_id": "4" * 64})
        )
        self.inspect = self.enterContext(
            patch.object(gate, "inspect", return_value={"State": {"Running": False}})
        )
        self.enterContext(patch.object(gate, "now", return_value=self.at(6)))
        # The wrapper treats each capture result as opaque and sends it to its own replayer.
        self.bindings = {name: {"primary": digest(name.encode())} for name in gate.STAGES}
        self.operations = {
            name: Mock(return_value=binding) for name, binding in self.bindings.items()
        }
        self.sources_replay = Mock(return_value=self.sources)
        self.candidate_replay = Mock(return_value=self.candidate)
        boundaries = {
            "security_gate_sources": SimpleNamespace(
                capture=self.operations["sources"], replay=self.sources_replay
            ),
            "security_gate_candidate": SimpleNamespace(
                capture_inventory=self.operations["inventory"],
                capture_outage=self.operations["outage"],
                replay=self.candidate_replay,
            ),
        }
        for name, module in boundaries.items():
            self.enterContext(patch.object(mlsecops, name, module, create=True))

    def command(self, args):
        if args == ["git", "-C", str(self.root), "status", "--porcelain"]:
            return self.dirty
        if args == ["git", "-C", str(self.root), "rev-parse", "HEAD"]:
            return self.source["source_revision"]
        if args == ["kind", "get", "clusters"]:
            return self.clusters
        self.fail("unexpected external command")

    @staticmethod
    def at(second):
        return f"2026-11-14T10:00:{second:02d}+00:00"

    def path(self, name):
        return self.state / "evidence" / f"M23-{name}.json"

    def stages(self):
        pins = {}
        # Consecutive captures can meet exactly at a timestamp.
        with patch.object(gate, "now", side_effect=map(self.at, (1, 2, 2, 3, 4, 5))):
            for name in gate.STAGES:
                pins[name] = gate.capture(self.root, self.state, name, self.operations[name])
        self.enterContext(
            patch.dict(os.environ, {"M23_" + k.upper() + "_SHA256": v for k, v in pins.items()})
        )
        return pins

    def rejected_before_replay(self):
        with self.assertRaises(Rejected):
            gate.qualify(self.root, self.state)
        self.sources_replay.assert_not_called()
        self.candidate_replay.assert_not_called()

    def test_capture_pins_exact_file_and_read_stage_checks_external_bindings(self):
        name = "inventory"
        pin = gate.capture(self.root, self.state, name, self.operations[name])
        expected = dict(
            schema_version=1,
            stage=name,
            owner=self.owner,
            source=self.source,
            methods=digest(canonical(gate.materials(self.root))),
            binding=self.bindings[name],
            started_at=self.at(6),
            finished_at=self.at(6),
        )
        content = self.path(name).read_bytes()
        self.assertEqual(content, canonical(expected) + b"\n")
        self.assertEqual(pin, digest(content))
        self.assertEqual(
            gate.read_stage(self.state, name, pin, self.source, expected["methods"], self.owner),
            expected,
        )
        self.operations[name].assert_called_once_with(self.root, self.state)

    def test_dirty_source_or_drift_during_capture_cannot_publish_stage(self):
        name = "sources"
        operation = self.operations[name]
        self.dirty = " M Dockerfile"
        with self.assertRaises(Rejected):
            gate.capture(self.root, self.state, name, operation)
        operation.assert_not_called()
        self.assertFalse(self.path(name).exists())
        self.dirty = ""
        for filename in ("Dockerfile", "data.lock"):
            with self.subTest(filename=filename):
                # data.lock contributes only to method materials, not the source fingerprint.
                path = self.root / filename
                operation.side_effect = lambda root, state: path.write_bytes(b"changed")
                with self.assertRaises(Rejected):
                    gate.capture(self.root, self.state, name, operation)
                self.assertFalse(self.path(name).exists())

    def test_qualify_replays_original_bindings_and_reports_inputs_metrics_and_pins(self):
        pins = self.stages()
        result = gate.qualify(self.root, self.state)
        self.sources_replay.assert_called_once_with(self.root, self.state, self.bindings["sources"])
        self.candidate_replay.assert_called_once_with(
            self.root,
            self.state,
            inventory_pin=self.bindings["inventory"],
            outage_pin=self.bindings["outage"],
        )
        self.assertEqual(result["status"], "pass")
        self.assertIs(result["release_ready"], False)
        self.assertIs(result["source_dirty"], False)
        self.assertEqual((result["started_at"], result["finished_at"]), (self.at(1), self.at(6)))
        self.assertEqual(result["checks"], 2)
        self.assertEqual(
            result["cases"],
            [
                dict(id=case, status="pass", expected=True, actual=True)
                for case in sorted(self.sources["cases"] + self.candidate["cases"])
            ],
        )
        self.assertEqual(
            result["input_digests"],
            {
                **self.subject,
                "release_subject": self.candidate["release_subject"],
                "model": self.subject["model_sha256"],
            },
        )
        self.assertEqual(result["metrics"]["outage"], self.candidate["metrics"])
        self.assertEqual(set(result["metrics"]["routes"]), set(RULES))
        self.assertEqual(
            result["artifact_hashes"],
            {
                **{"stage-" + k: v for k, v in pins.items()},
                "method_materials": digest(canonical(gate.materials(self.root))),
                "sources-intake-primary": "a" * 64,
                "candidate-outage-primary": "b" * 64,
            },
        )
        self.assertTrue(result["limitations"])

    def test_changed_stage_pins_run_owner_source_and_methods_reject_before_replay(self):
        pins = self.stages()
        for name, original in pins.items():
            replacement = digest(original.encode())
            with (
                self.subTest(stage=name),
                patch.dict(os.environ, {"M23_" + name.upper() + "_SHA256": replacement}),
            ):
                self.rejected_before_replay()
        for field in self.owner:
            with self.subTest(owner=field), patch.dict(os.environ, {field: "75"}):
                self.rejected_before_replay()
        for filename in ("Dockerfile", "data.lock"):
            with self.subTest(filename=filename):
                path = self.root / filename
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                self.rejected_before_replay()
                path.write_bytes(original)
        path = self.path("inventory")
        path.write_bytes(path.read_bytes() + b" ")
        self.rejected_before_replay()
        self.validate.assert_not_called()

    def test_shared_delivery_rechecks_frozen_bytes_stage_owner_and_signed_subject(self):
        demo = dict(
            candidate=dict(
                candidate_reference=self.subject["candidate_reference"],
                metadata=dict(model_digest=self.subject["model_sha256"]),
            ),
            evaluation_reference=self.subject["evaluation_reference"],
        )
        proposal = dict(
            source={**self.source, "image_id": self.subject["image_id"]},
            proposal_reference="3" * 64,
            model_sha256=self.subject["model_sha256"],
            subject_sha256=self.candidate["release_subject"],
        )
        demo_path = self.state / "storage-demo.json"
        proposal_path = self.state / "evidence/release-native.json"
        write_json(demo_path, demo)
        write_json(proposal_path, proposal)
        env = dict(
            M23_DEMO_SHA256=digest(demo_path.read_bytes()),
            M23_PROPOSAL_SHA256=digest(proposal_path.read_bytes()),
        )
        self.enterContext(patch.dict(os.environ, env))
        hashes = self.candidate["artifact_hashes"]
        hashes["outage-proposal_sha256"] = env["M23_PROPOSAL_SHA256"]
        self.stages()
        result = gate.qualify(self.root, self.state)
        self.assertEqual(result["artifact_hashes"]["frozen_demo"], env["M23_DEMO_SHA256"])
        self.assertEqual(
            result["input_digests"]["proposal_reference"], proposal["proposal_reference"]
        )
        for obj, changes in (
            (hashes, {"outage-proposal_sha256": "0" * 64}),
            (self.subject, {"evaluation_reference": "0" * 64}),
        ):
            with patch.dict(obj, changes), self.assertRaises(Rejected):
                gate.qualify(self.root, self.state)
        write_json(demo_path, {**demo, "evaluation_reference": "0" * 64})
        with self.assertRaises(Rejected):
            gate.qualify(self.root, self.state)
        with (
            patch.dict(os.environ, M23_DEMO_SHA256=digest(demo_path.read_bytes())),
            self.assertRaises(Rejected),
        ):
            gate.qualify(self.root, self.state)

    def test_proposal_must_be_frozen_before_the_first_measurement(self):
        self.stages()
        for stamp in (self.at(2), self.at(0).removesuffix("+00:00")):
            with self.subTest(stamp=stamp), patch.dict(self.candidate, proposal_finished_at=stamp):
                with self.assertRaises(Rejected):
                    gate.qualify(self.root, self.state)

    def test_rehashed_malformed_or_mislabelled_stage_primary_fails_before_cleanup(self):
        self.stages()
        path = self.path("inventory")
        record = read_json(path)
        for label, raw in (
            ("broken JSON", b"{"),
            ("missing binding", canonical({k: v for k, v in record.items() if k != "binding"})),
            ("boolean version", canonical({**record, "schema_version": True})),
            ("another stage", canonical({**record, "stage": "sources"})),
        ):
            with self.subTest(label=label):
                path.write_bytes(raw)
                with patch.dict(os.environ, {"M23_INVENTORY_SHA256": digest(raw)}):
                    self.rejected_before_replay()
        self.validate.assert_not_called()

    def test_rehashed_capture_times_must_be_aware_ordered_and_no_later_than_replay(self):
        self.stages()
        for name, field, value in (
            ("inventory", "finished_at", self.at(1)),
            ("outage", "started_at", self.at(2)),
            ("outage", "finished_at", self.at(7)),
            ("sources", "started_at", self.at(1).removesuffix("+00:00")),
        ):
            with self.subTest(name=name, field=field, value=value):
                path = self.path(name)
                original = read_json(path)
                write_json(path, {**original, field: value})
                with patch.dict(
                    os.environ, {"M23_" + name.upper() + "_SHA256": digest(path.read_bytes())}
                ):
                    self.rejected_before_replay()
                write_json(path, original)
        self.validate.assert_not_called()

    def test_cleanup_failure_never_calls_either_replayer(self):
        self.stages()
        self.validate.side_effect = Rejected("unverified_owner")
        self.rejected_before_replay()
        self.inspect.assert_not_called()
        self.validate.side_effect = None
        self.inspect.return_value = {"State": {"Running": True}}
        self.rejected_before_replay()
        self.inspect.return_value = {"State": {"Running": False}}
        self.clusters = "other\n" + gate.cluster.NAME
        self.rejected_before_replay()

    def test_primary_rejected_by_either_replayer_cannot_produce_a_report(self):
        self.stages()
        for label, replay in (
            ("sources", self.sources_replay),
            ("candidate", self.candidate_replay),
        ):
            with self.subTest(boundary=label):
                replay.side_effect = Rejected("malformed_primary")
                with self.assertRaisesRegex(Rejected, "^malformed_primary$"):
                    gate.qualify(self.root, self.state)
                replay.assert_called_once()
                if label == "sources":
                    self.candidate_replay.assert_not_called()
                replay.side_effect = None

    def test_cli_dispatches_each_capture_and_appends_only_its_retained_hash(self):
        output = self.root / "outputs"
        output.write_text("prior=keep\n", encoding="utf-8")
        expected = ["prior=keep"]
        with (
            patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
            patch.object(gate, "__file__", str(self.root / "mlsecops/security_gate.py")),
        ):
            for name in gate.STAGES:
                with (
                    self.subTest(stage=name),
                    patch.object(sys, "argv", ["gate", name]),
                    redirect_stdout(io.StringIO()) as stdout,
                    redirect_stderr(io.StringIO()) as stderr,
                ):
                    self.assertEqual(gate.main(), 0)
                    stage = self.path(name)
                    pin = digest(stage.read_bytes())
                    self.assertEqual(read_json(stage)["binding"], self.bindings[name])
                    self.assertEqual(
                        decode(stdout.getvalue().encode()),
                        dict(stage=name, primary_manifest_sha256=pin),
                    )
                    self.assertEqual(stderr.getvalue(), "")
                    expected.append("sha256=" + pin)
                    self.assertEqual(output.read_text(encoding="utf-8").splitlines(), expected)

    def test_cli_capture_failure_does_not_publish_or_disclose_private_path(self):
        name = "inventory"
        output = self.root / "outputs"
        canary = (self.root / "private-client.json").as_posix()
        self.operations[name].side_effect = OSError(canary)
        with (
            patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
            patch.object(gate, "__file__", str(self.root / "mlsecops/security_gate.py")),
            patch.object(sys, "argv", ["gate", name]),
            redirect_stdout(io.StringIO()) as stdout,
            redirect_stderr(io.StringIO()) as stderr,
        ):
            self.assertEqual(gate.main(), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertFalse(canary in stderr.getvalue(), "public diagnostic disclosed private path")
        diagnostic = decode(stderr.getvalue().encode())
        self.assertEqual(set(diagnostic), {"stage", "status", "site"})
        self.assertEqual((diagnostic["stage"], diagnostic["status"]), (name, "fail"))
        self.assertEqual(set(diagnostic["site"]), {"module", "line"})
        self.assertFalse(output.exists())
        self.assertFalse(self.path(name).exists())

    def test_outage_cli_preserves_bounded_request_and_caller_diagnostics(self):
        self.operations["outage"].side_effect = Rejected("kubernetes_request_failed:get:timeout")
        with (
            patch.object(gate, "__file__", str(self.root / "mlsecops/security_gate.py")),
            patch.object(sys, "argv", ["gate", "outage"]),
            redirect_stderr(io.StringIO()) as stderr,
        ):
            self.assertEqual(gate.main(), 1)
        result = decode(stderr.getvalue().encode())
        self.assertEqual(result["request"], {"operation": "get", "category": "timeout"})
        self.assertTrue(result["callers"])
        self.assertNotIn(str(self.root), stderr.getvalue())

    def test_module_entrypoint_rejects_unowned_host_before_capture(self):
        with (
            patch("scripts.kube_trust_native.hosted", side_effect=Rejected("unowned")),
            patch.object(sys, "argv", ["gate", "outage"]),
            redirect_stdout(io.StringIO()) as stdout,
            redirect_stderr(io.StringIO()) as stderr,
            self.assertRaises(SystemExit) as stopped,
        ):
            runpy.run_path(gate.__file__, run_name="__main__")
        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(decode(stderr.getvalue().encode())["status"], "fail")
        self.operations["outage"].assert_not_called()

    def test_cli_argument_errors_do_not_disclose_private_path(self):
        canary = (self.root / "private-client.json").as_posix()
        for label, arguments in (
            ("unknown stage", [canary]),
            ("extra argument", ["sources", canary]),
        ):
            with (
                self.subTest(case=label),
                patch.object(sys, "argv", ["gate", *arguments]),
                redirect_stdout(io.StringIO()) as stdout,
                redirect_stderr(io.StringIO()) as stderr,
            ):
                try:
                    result = gate.main()
                except SystemExit as stopped:
                    result = stopped.code
                self.assertIn(result, (1, 2))
                self.assertTrue(stderr.getvalue().strip())
                self.assertFalse(
                    canary in stdout.getvalue() + stderr.getvalue(),
                    "argument error disclosed private path",
                )
                self.operations["sources"].assert_not_called()
