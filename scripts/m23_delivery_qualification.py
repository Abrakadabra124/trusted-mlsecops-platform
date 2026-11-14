"""Strict delivery schemas and phase ordering, with no native services."""

import copy
import io
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest, write_json
from scripts import m23_delivery as delivery

OPERATIONS = delivery.operations


class DeliveryContracts(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.state = self.root / ".runtime"
        self.source = dict(source_revision="a" * 40, source_fingerprint="b" * 64)
        self.image = "sha256:" + "c" * 64
        self.proposal = dict(
            source=self.source | dict(image_id=self.image),
            status="pass",
            source_dirty=False,
            release_ready=False,
            proposal_reference="d" * 64,
            model_sha256="e" * 64,
            subject_sha256="f" * 64,
        )
        self.demo = dict(
            candidate=dict(
                candidate_reference="1" * 64,
                metadata=dict(
                    **self.proposal["source"], model_digest="e" * 64, policy_digest="2" * 64
                ),
            ),
            evaluation_reference="3" * 64,
        )
        self.env = {
            "GITHUB_SHA": self.source["source_revision"],
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "2",
        }
        for name, value, key in (
            ("storage-demo.json", self.demo, "M23_DEMO_SHA256"),
            ("evidence/release-native.json", self.proposal, "M23_PROPOSAL_SHA256"),
            ("trusted-keys.json", {"key": "public"}, "M23_KEYS_FILE_SHA256"),
            ("storage-trust.json", {"trust": "public"}, "M23_TRUST_SHA256"),
            ("storage.json", {"container_id": "owned"}, "M23_SQL_SHA256"),
        ):
            write_json(self.state / name, value)
            self.env[key] = digest(canonical(value) + b"\n")
        self.enterContext(patch.dict(delivery.os.environ, self.env))
        self.enterContext(
            patch.object(delivery.security_gate, "source_state", return_value=self.source)
        )
        self.enterContext(
            patch.object(delivery.security_gate, "materials", return_value={"method": "pin"})
        )
        self.enterContext(patch.object(delivery.security_gate, "hosted"))
        self.enterContext(
            patch.object(delivery.security_gate, "now", return_value="2026-11-14T10:00:00+00:00")
        )
        self.enterContext(
            patch.object(
                delivery,
                "operations",
                return_value={
                    stage: lambda root, state: {"primary": "4" * 64} for stage in delivery.STAGES
                },
            )
        )

    def capture_all(self):
        for stage in delivery.STAGES:
            pins = delivery.capture(self.root, self.state, stage, self.env)
            self.env["M23_" + stage.upper() + "_SHA256"] = pins["sha256"]
            self.env["M23_" + stage.upper() + "_DELIVERY_SHA256"] = pins["delivery"]

    def test_capture_refuses_missing_owner_pin_before_operation(self):
        for key in delivery.FILES:
            with self.subTest(key=key):
                env = self.env.copy()
                env.pop(key)
                with (
                    patch.object(delivery.security_gate, "capture") as native,
                    self.assertRaises((Rejected, KeyError)),
                ):
                    delivery.capture(self.root, self.state, "sources", env)
                native.assert_not_called()

    def test_inventory_cannot_precede_sources(self):
        with (
            patch.object(delivery.security_gate, "capture") as native,
            self.assertRaises((Rejected, KeyError)),
        ):
            delivery.capture(self.root, self.state, "inventory", self.env)
        native.assert_not_called()

    def test_same_original_inputs_and_ordered_stage_chain(self):
        self.capture_all()
        chain = delivery.chain(self.root, self.state, self.env)
        self.assertEqual(set(chain), set(delivery.STAGES))
        self.assertEqual(chain["outage"]["inputs"], delivery.inputs(self.state, self.env))

    def test_bool_schema_extra_missing_fields_and_resealed_chain_reject(self):
        self.capture_all()
        path = delivery.path(self.state, "inventory")
        original = path.read_bytes()
        document = delivery.decode(original)
        changes = [
            lambda p: p.update(schema_version=True),
            lambda p: p.update(extra="private"),
            lambda p: p.pop("inputs"),
            lambda p: p.update(previous="0" * 64),
            lambda p: p["owner"].update(GITHUB_RUN_ATTEMPT="1"),
            lambda p: p["inputs"].update(candidate_reference="0" * 64),
        ]
        for change in changes:
            changed = copy.deepcopy(document)
            change(changed)
            write_json(path, changed)
            env = self.env | {"M23_INVENTORY_DELIVERY_SHA256": digest(path.read_bytes())}
            with self.subTest(change=change), self.assertRaises(Rejected):
                delivery.chain(self.root, self.state, env)
        path.write_bytes(original)

    def test_gate_inventory_keeps_all_22_children_and_m18_separate(self):
        from mlsecops.final_evidence import CHILDREN

        self.assertEqual(len(CHILDREN), 22)
        self.assertNotIn("M18", CHILDREN)
        self.assertEqual(
            set(delivery.gates("M11-M12")),
            set(delivery.controller_delivery.intake_gates("M11-M12")) | {"M23"},
        )
        self.assertIn("M22", set(CHILDREN) - set(delivery.gates("M11-M12")))

    def test_capture_never_replaces_existing_evidence(self):
        self.capture_all()
        with patch.object(delivery.security_gate, "capture") as native, self.assertRaises(Rejected):
            delivery.capture(self.root, self.state, "sources", self.env)
        native.assert_not_called()
        with self.assertRaises(Rejected):
            delivery.capture(self.root, self.state, "unknown", self.env)

    def test_changed_input_during_native_capture_cannot_emit_sidecar(self):
        operation = delivery.security_gate.capture

        def changing(*args):
            result = operation(*args)
            write_json(self.state / "storage-trust.json", {"changed": True})
            return result

        with (
            patch.object(delivery.security_gate, "capture", side_effect=changing),
            self.assertRaises(Rejected),
        ):
            delivery.capture(self.root, self.state, "sources", self.env)
        self.assertFalse(delivery.path(self.state, "sources").exists())

    def test_raw_stage_pin_and_strict_stage_schema_and_time(self):
        self.capture_all()
        path = delivery.security_gate.stage_path(self.state, "outage")
        original = delivery.decode(path.read_bytes())
        sidecar = delivery.path(self.state, "outage")
        record = delivery.decode(sidecar.read_bytes())
        for change in (
            lambda p: p.update(schema_version=True),
            lambda p: p.update(extra="payload"),
            lambda p: p["owner"].update(GITHUB_RUN_ID="other"),
            lambda p: p.update(started_at="2026-11-14T09:59:59+00:00"),
            lambda p: p.update(finished_at="2026-11-14T10:00:00"),
            lambda p: p.update(methods="0" * 64),
        ):
            changed = copy.deepcopy(original)
            change(changed)
            write_json(path, changed)
            pin = digest(path.read_bytes())
            write_json(sidecar, record | {"stage_sha256": pin})
            env = self.env | {
                "M23_OUTAGE_SHA256": pin,
                "M23_OUTAGE_DELIVERY_SHA256": digest(sidecar.read_bytes()),
            }
            with self.subTest(change=change), self.assertRaises(Rejected):
                delivery.chain(self.root, self.state, env)

    def test_noncanonical_sidecar_rejected_even_with_matching_pin(self):
        self.capture_all()
        path = delivery.path(self.state, "outage")
        path.write_bytes(path.read_bytes() + b" ")
        env = self.env | {"M23_OUTAGE_DELIVERY_SHA256": digest(path.read_bytes())}
        with self.assertRaises(Rejected):
            delivery.chain(self.root, self.state, env)

    def test_original_candidate_source_model_policy_and_pin_required(self):
        for change in (
            lambda p: p["source"].update(source_revision="0" * 40),
            lambda p: p["source"].update(source_fingerprint="invalid"),
            lambda p: p["source"].update(image_id="c" * 64),
            lambda p: p.update(release_ready=0),
            lambda p: p.update(status="inconclusive"),
            lambda p: p.update(source_dirty=True),
            lambda p: p.update(model_sha256="0" * 64),
            lambda p: p.update(proposal_reference="invalid"),
        ):
            proposal = copy.deepcopy(self.proposal)
            change(proposal)
            write_json(self.state / "evidence/release-native.json", proposal)
            env = self.env | {"M23_PROPOSAL_SHA256": digest(canonical(proposal) + b"\n")}
            with self.subTest(change=change), self.assertRaises(Rejected):
                delivery.inputs(self.state, env)

    def make_transition(self):
        self.capture_all()
        self.movement = dict(
            before=dict(namespace="6" * 64, volume="7" * 64),
            after=dict(namespace="8" * 64, volume="9" * 64),
            source_sql=self.env["M23_SQL_SHA256"],
        )
        for name in delivery.OWNER_FILES:
            write_json(self.state / "kubernetes-security" / name, {"M23": name})

        def move(state, retired, pin):
            self.assertEqual(pin, self.env["M23_SQL_SHA256"])
            retired.mkdir()
            (state / "kubernetes-security").rename(retired / "kubernetes-security")
            return self.movement

        with patch.object(delivery.serving_campaign, "transition", side_effect=move):
            pins = delivery.transition(self.root, self.state, self.env)
        self.env["M23_TRANSITION_SHA256"] = pins["sha256"]
        for name in delivery.OWNER_FILES:
            write_json(self.state / "kubernetes-security" / name, {"late": name})

    def test_transition_reuses_owned_existing_mechanism_and_keeps_pins(self):
        self.make_transition()
        record = delivery.pinned(
            self.state / "evidence/M23-delivery-transition.json", self.env["M23_TRANSITION_SHA256"]
        )
        self.assertEqual(record["transition"], self.movement)
        with (
            patch.object(delivery.serving_campaign, "transition") as native,
            self.assertRaises(Rejected),
        ):
            delivery.transition(self.root, self.state, self.env)
        native.assert_not_called()

    def test_occupied_retirement_directory_prevents_any_cluster_mutation(self):
        self.capture_all()
        (self.state / "M23-retired-serving").mkdir()
        with (
            patch.object(delivery.serving_campaign, "transition") as native,
            self.assertRaises(Rejected),
        ):
            delivery.transition(self.root, self.state, self.env)
        native.assert_not_called()

    def make_receipt(self):
        self.make_transition()
        original = delivery.inputs(self.state, self.env)
        self.parent = dict(
            candidate={
                k: original[k]
                for k in (
                    "source_revision",
                    "source_fingerprint",
                    "image_id",
                    "candidate_reference",
                    "evaluation_reference",
                    "proposal_reference",
                )
            }
            | dict(
                qualified_candidate_model=original["model_sha256"],
                qualified_candidate_subject=original["release_subject"],
            ),
            reports={},
            proposal_packet=self.env["M23_PROPOSAL_SHA256"],
            release_ready=False,
        )
        for gate in delivery.controller_delivery.intake_gates("M11-M12"):
            # The parent reconciler's semantics are tested by its own suite.
            raw = canonical(dict(gate=gate)) + b"\n"
            (self.state / "evidence" / (gate + ".json")).write_bytes(raw)
            self.parent["reports"][gate] = digest(raw)
        self.replayed = dict(
            input_digests={
                k: original[k]
                for k in (
                    "source_revision",
                    "source_fingerprint",
                    "image_id",
                    "candidate_reference",
                    "evaluation_reference",
                    "model_sha256",
                    "release_subject",
                )
            }
            | dict(model=original["model_sha256"]),
            artifact_hashes={"candidate-outage-proposal_sha256": self.env["M23_PROPOSAL_SHA256"]},
            cases=[dict(id="source-negative", status="pass", expected=True, actual=True)],
            checks=1,
            metrics={"test": 1},
            limitations=["synthetic-only"],
            started_at="2026-11-14T10:00:00+00:00",
            finished_at="2026-11-14T10:15:00+00:00",
        )
        self.report = {
            k: self.replayed[k]
            for k in ("input_digests", "artifact_hashes", "cases", "started_at", "finished_at")
        }
        self.report.update(
            schema_version=1,
            gate="M23",
            status="pass",
            profile="local-cpu",
            policy_digest=original["policy_digest"],
            source_revision=original["source_revision"],
            exit_code=0,
            redaction_version=1,
            source_dirty=False,
            metrics=dict(checks=1, **self.replayed["metrics"]),
            residual_risks=self.replayed["limitations"],
        )
        self.publish_report(self.report)
        self.env["SOURCE_OFFLINE_SHA256"] = "5" * 64
        self.offline = self.enterContext(
            patch.object(delivery.shared_serving_receipt, "offline_pin", return_value="5" * 64)
        )
        self.replay = self.enterContext(
            patch.object(delivery.security_gate, "qualify", return_value=self.replayed)
        )
        self.cleanup_check = self.enterContext(
            patch.object(delivery.security_gate, "confirm_cleanup")
        )

    def publish_report(self, report):
        write_json(self.state / "evidence/M23.json", report)
        self.env["M23_REPORT_SHA256"] = digest(canonical(report) + b"\n")

    def receipt(self):
        return delivery.receipt(self.root, self.state, self.parent, self.env)

    def test_receipt_adds_only_verified_m23_and_preserves_original_candidate(self):
        self.make_receipt()
        result = self.receipt()
        self.assertEqual(set(result["reports"]), set(delivery.gates("M11-M12")))
        self.assertEqual(result["candidate"], self.parent["candidate"])
        self.assertEqual(result["reports"]["M23"], self.env["M23_REPORT_SHA256"])
        self.assertIs(result["release_ready"], False)
        self.replay.assert_called_once_with(self.root, self.state)
        self.assertEqual(self.offline.call_count, 4)

    def test_strict_report_rejects_resealed_schema_types_fields_and_semantics(self):
        self.make_receipt()
        changes = [
            lambda r: r.update(schema_version=True),
            lambda r: r.update(redaction_version=True),
            lambda r: r.update(extra="private"),
            lambda r: r.pop("source_dirty"),
            lambda r: r.update(exit_code=False),
            lambda r: r.update(exit_code=0.0),
            lambda r: r.update(status="inconclusive"),
            lambda r: r.update(source_dirty=0),
            lambda r: r.update(source_revision="0" * 40),
            lambda r: r.update(policy_digest="0" * 64),
            lambda r: r["input_digests"].update(candidate_reference="0" * 64),
            lambda r: r["artifact_hashes"].update(extra="0" * 64),
            lambda r: r["cases"][0].update(actual=1),
            lambda r: r["cases"][0].update(status="skipped"),
            lambda r: r.update(cases=[]),
            lambda r: r["metrics"].update(checks=True),
            lambda r: r.update(residual_risks=[]),
            lambda r: r.update(finished_at="2026-11-14T09:59:59+00:00"),
            lambda r: r.update(finished_at="2026-11-14T10:16:00+00:00"),
            lambda r: r.update(finished_at="2026-11-14T10:15:00"),
        ]
        for change in changes:
            report = copy.deepcopy(self.report)
            change(report)
            self.publish_report(report)
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.receipt()

    def test_source_offline_witness_detects_restart_before_or_during_replay(self):
        self.make_receipt()
        for observations in (("0" * 64,), ("5" * 64, "0" * 64), ("5" * 64, "5" * 64, "0" * 64)):
            self.offline.side_effect = observations
            with self.subTest(observations=observations), self.assertRaises(Rejected):
                self.receipt()

    def test_native_replay_rejection_and_foreign_proposal_never_produce_receipt(self):
        self.make_receipt()
        self.replay.side_effect = Rejected("signed_primary_changed")
        with self.assertRaises(Rejected):
            self.receipt()
        self.replay.side_effect = None
        for section, key in (
            ("input_digests", "candidate_reference"),
            ("artifact_hashes", "candidate-outage-proposal_sha256"),
        ):
            changed = copy.deepcopy(self.replayed)
            changed[section][key] = "0" * 64
            self.replay.return_value = changed
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.receipt()

    def test_parent_cannot_mix_revisions_candidates_or_drop_children(self):
        self.make_receipt()
        original = copy.deepcopy(self.parent)
        for change in (
            lambda p: p["candidate"].update(source_revision="0" * 40),
            lambda p: p["candidate"].update(qualified_candidate_model="0" * 64),
            lambda p: p.update(release_ready=0),
            lambda p: p["reports"].pop("M11"),
            lambda p: p["reports"].update(M23="0" * 64),
            lambda p: p.update(proposal_packet="0" * 64),
            lambda p: p["reports"].update(M12="0" * 64),
        ):
            self.parent = copy.deepcopy(original)
            change(self.parent)
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.receipt()

    def test_transition_resealed_same_cluster_or_foreign_owner_is_rejected(self):
        self.make_receipt()
        path = self.state / "evidence/M23-delivery-transition.json"
        original = delivery.decode(path.read_bytes())
        for change in (
            lambda r: r.update(schema_version=True),
            lambda r: r.update(extra=True),
            lambda r: r["transition"]["after"].update(namespace="6" * 64),
            lambda r: r["transition"]["after"].update(volume="7" * 64),
            lambda r: r["transition"].update(source_sql="0" * 64),
            lambda r: r.update(outage_delivery="0" * 64),
        ):
            record = copy.deepcopy(original)
            change(record)
            write_json(path, record)
            self.env["M23_TRANSITION_SHA256"] = digest(path.read_bytes())
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.receipt()

    def test_legacy_delivery_modes_do_not_silently_add_m23(self):
        for mode in ("M12", "M13"):
            self.assertEqual(delivery.gates(mode), delivery.controller_delivery.intake_gates(mode))

    def test_existing_operations_are_reused_without_executing_native_code(self):
        from mlsecops import security_gate_candidate, security_gate_sources

        self.assertEqual(
            OPERATIONS(),
            dict(
                sources=security_gate_sources.capture,
                inventory=security_gate_candidate.capture_inventory,
                outage=security_gate_candidate.capture_outage,
            ),
        )

    def test_original_owner_is_used_only_offline_and_late_owner_is_restored_on_failure(self):
        self.make_receipt()
        for fail in (False, True):

            def replay(root, state):
                for name in delivery.OWNER_FILES:
                    self.assertEqual(
                        delivery.decode((state / "kubernetes-security" / name).read_bytes()),
                        {"M23": name},
                    )
                if fail:
                    raise Rejected("invalid_signature")
                return self.replayed

            self.replay.side_effect = replay
            if fail:
                with self.assertRaises(Rejected):
                    self.receipt()
            else:
                self.receipt()
            for name in delivery.OWNER_FILES:
                self.assertEqual(
                    delivery.decode((self.state / "kubernetes-security" / name).read_bytes()),
                    {"late": name},
                )
        self.cleanup_check.side_effect = Rejected("cluster_still_running")
        with self.assertRaises(Rejected):
            self.receipt()

    def test_owner_file_substitution_rejected_before_swap(self):
        self.make_receipt()
        retired = self.state / "M23-retired-serving/kubernetes-security/resources.json"
        retired.write_bytes(b"{}\n")
        with self.assertRaises(Rejected):
            self.receipt()
        self.replay.assert_not_called()
        for name in delivery.OWNER_FILES:
            self.assertEqual(
                delivery.decode((self.state / "kubernetes-security" / name).read_bytes()),
                {"late": name},
            )

    def test_partial_public_swap_restores_all_late_owner_bytes(self):
        self.make_receipt()
        write = delivery.atomic_write
        calls = 0

        def fail_once(path, raw):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("controlled-write-failure")
            return write(path, raw)

        with (
            patch.object(delivery, "atomic_write", side_effect=fail_once),
            self.assertRaises(OSError),
        ):
            self.receipt()
        for name in delivery.OWNER_FILES:
            self.assertEqual(
                delivery.decode((self.state / "kubernetes-security" / name).read_bytes()),
                {"late": name},
            )

    def test_failed_restore_attempts_every_owner_file_and_never_returns_receipt(self):
        self.make_receipt()
        write = delivery.atomic_write
        attempted = []

        def fail_first_restore(path, raw):
            value = delivery.decode(raw)
            if "late" in value:
                attempted.append(value["late"])
                if value["late"] == delivery.OWNER_FILES[0]:
                    raise OSError("private filesystem detail")
            return write(path, raw)

        with (
            patch.object(delivery, "atomic_write", side_effect=fail_first_restore),
            self.assertRaisesRegex(Rejected, "^M23_delivery_owner_restore$"),
        ):
            self.receipt()
        self.assertEqual(attempted, list(delivery.OWNER_FILES))
        for name in delivery.OWNER_FILES[1:]:
            self.assertEqual(
                delivery.decode((self.state / "kubernetes-security" / name).read_bytes()),
                {"late": name},
            )

    def test_cli_gate_uses_ordinary_acceptance_and_refuses_inconclusive(self):
        from contextlib import nullcontext

        from mlsecops import acceptance

        # main resolves its checkout from __file__; keep every output in this fixture.
        fake_script = self.root / "scripts/m23_delivery.py"
        with (
            patch.object(delivery, "__file__", str(fake_script)),
            patch.object(delivery, "hosted"),
            patch.dict(os.environ, GITHUB_OUTPUT=str(self.root / "output")),
            patch.object(sys, "argv", ["m23_delivery", "gate"]),
            patch.object(delivery, "authority", side_effect=lambda *args: nullcontext()),
            patch.object(acceptance, "report") as report,
        ):
            for status, code in (("pass", 0), ("inconclusive", 2), ("fail", 1), ("pass", False)):
                report.return_value = dict(status=status, exit_code=code)
                if status == "pass" and type(code) is int:
                    delivery.main()
                    self.assertEqual(
                        (self.root / "output").read_text(),
                        "sha256=" + digest(canonical(report.return_value) + b"\n") + "\n",
                    )
                else:
                    with self.assertRaises(Rejected):
                        delivery.main()
            report.assert_called_with("M23", "local-cpu", self.root, self.state)

    def test_workflow_preserves_online_capture_offline_replay_and_original_pins(self):
        workflow = (
            Path(delivery.__file__).resolve().parents[1] / ".github/workflows/storage-recovery.yml"
        ).read_text()
        chunks = re.split(r"(?=^      - )", workflow, flags=re.MULTILINE)
        steps = {}
        for index, chunk in enumerate(chunks):
            match = re.search(r"^        id: (\w+)$", chunk, re.MULTILINE)
            if match:
                self.assertNotIn(match[1], steps)
                steps[match[1]] = (index, chunk)
        ordered = (
            "source",
            "m23_sources",
            "m23_inventory",
            "m23_outage",
            "m23_transition",
            "joint_actual",
            "recovery",
            "stop_sql",
            "m23_offline",
            "joint_controlled",
            "joint_gates",
            "stop_cluster",
            "joint_receipt",
            "m23_gate",
            "delivery",
        )
        self.assertEqual([steps[s][0] for s in ordered], sorted(steps[s][0] for s in ordered))
        self.assertLess(
            workflow.index("-m scripts.controller_serving_handoff"),
            workflow.index("id: m23_sources"),
        )
        for stage in (
            "m23_sources",
            "m23_inventory",
            "m23_outage",
            "m23_transition",
            "m23_gate",
            "delivery",
        ):
            body = steps[stage][1]
            for key, output in (
                ("DEMO", "demo"),
                ("PROPOSAL", "proposal"),
                ("KEYS_FILE", "keys_file"),
                ("TRUST", "trust"),
                ("SQL", "sql"),
            ):
                self.assertIn(
                    "M23_" + key + "_SHA256: ${{ steps.source.outputs." + output + " }}", body
                )
        self.assertIn("steps.stop_sql.outcome == 'success'", steps["m23_offline"][1])
        self.assertIn("-m scripts.m23_delivery gate", steps["m23_gate"][1])
        self.assertIn("-m scripts.m23_delivery receipt", steps["delivery"][1])
        self.assertEqual(
            workflow.count("from scripts.m23_delivery import gates as intake_gates"), 2
        )
        self.assertIn("-m scripts.m18_delivery_freeze replay-m04", workflow)
        self.assertIn('test "$result" -eq 2', workflow)
        self.assertIn("set(CHILDREN) - set(gates)", workflow)

    def test_cli_modes_emit_only_hashes_or_public_receipt(self):
        env = self.env | dict(
            GITHUB_OUTPUT=str(self.root / "outputs"),
            M17_DEMO_SHA256="a" * 64,
            M17_PROPOSAL_SHA256="b" * 64,
            M17_KEYS_SHA256="c" * 64,
        )
        with (
            patch.dict(os.environ, env),
            patch.object(delivery, "hosted"),
            patch.object(delivery, "capture", return_value=dict(sha256="d" * 64)),
            patch.object(delivery, "transition", return_value=dict(sha256="e" * 64)),
            patch.object(delivery.shared_serving_receipt, "offline_pin", return_value="f" * 64),
        ):
            for args in (["capture", "sources"], ["transition"], ["offline"]):
                with patch.object(sys, "argv", ["m23_delivery", *args]):
                    delivery.main()
            self.assertEqual(
                (self.root / "outputs").read_text().splitlines(),
                ["sha256=" + c * 64 for c in "def"],
            )
            with (
                patch.object(sys, "argv", ["m23_delivery", "invalid"]),
                self.assertRaises(Rejected),
            ):
                delivery.main()
            for mode in ("M11-M12", "M12", "M13"):
                stream = io.StringIO()
                with (
                    patch.dict(os.environ, DELIVERY_SERVING_GATE=mode),
                    patch.object(sys, "argv", ["m23_delivery", "receipt"]),
                    patch.object(delivery.controller_delivery, "reconcile", return_value={}),
                    patch.object(
                        delivery.controller_delivery,
                        "intake_delivery",
                        return_value={"parent": True},
                    ),
                    patch.object(delivery, "receipt", return_value={"joint": True}) as joint,
                    redirect_stdout(stream),
                ):
                    delivery.main()
                self.assertEqual(
                    delivery.decode(stream.getvalue().encode()),
                    {"joint": True} if mode == "M11-M12" else {"parent": True},
                )
                self.assertEqual(joint.call_count, int(mode == "M11-M12"))


if __name__ == "__main__":
    unittest.main()
