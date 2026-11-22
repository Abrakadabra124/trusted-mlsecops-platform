"""Original-byte collection and object-only replay; native measurements are mocked."""

import copy
import io
import os
import runpy
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from mlsecops import load_gate, monitoring_gate, privacy_gate
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, write_json
from scripts import m18_serving_retention as collector
from scripts import performance_delivery_qualification as fixtures


class ServingPrimaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.DeliveryContracts.setUpClass()
        cls.addClassCleanup(fixtures.DeliveryContracts.doClassCleanups)

    def setUp(self):
        fx = fixtures.DeliveryContracts()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        self.fixture = fx
        self.root, self.state = fx.root, fx.state
        self.methods = {"scripts/example.py": digest(b"same source")}
        self.enterContext(patch.object(collector, "materials", return_value=self.methods))
        self.clean = self.enterContext(patch.object(collector.final, "clean"))
        self.packets, self.metrics, self.values = {}, {}, {}
        self.reports, self.admissions = {}, {}
        # Keep real frozen signatures, permit verification and normal delivery replay.
        # Only native observation mathematics / POSIX audit reads use controlled fixtures.
        self.load = self.enterContext(
            patch.object(
                load_gate,
                "reconcile",
                return_value={
                    k: {"pass": True} for k in ("measurement", "overload", "operator", "monitoring")
                },
            )
        )
        self.enterContext(
            patch.object(
                load_gate, "retained", side_effect=lambda state, value: self.packets["M14"]
            )
        )
        self.enterContext(patch.object(monitoring_gate, "reconcile"))
        self.enterContext(
            patch.object(
                monitoring_gate,
                "retained",
                side_effect=lambda state, value, files: (
                    self.metrics["M15"],
                    self.packets["M15"],
                    {},
                ),
            )
        )
        self.enterContext(
            patch.object(privacy_gate, "reconcile", return_value={"observations": 1014})
        )
        self.enterContext(
            patch.object(
                privacy_gate,
                "retained_windows",
                side_effect=lambda state, value: self.packets["M13"],
            )
        )
        self.enterContext(
            patch.object(
                collector.serving_campaign.audit_snapshot,
                "load_packet",
                side_effect=lambda path: bounded_read(path / "packet.json"),
            )
        )
        self.audit = self.enterContext(
            patch.object(
                collector.serving_campaign.audit_evidence, "verify", return_value={"verified": True}
            )
        )
        for gate, mode in collector.MODES.items():
            fx.campaign = {"M13": "a", "M14": "b", "M15": "c"}[gate] * 32
            index, value = fx.runtime("M15" if gate == "M15" else "M14")
            if gate == "M13":
                value["privacy_campaign_id"] = value.pop("load_campaign_id")
            value.update(
                scope="actual-candidate-kubernetes-inference",
                source_dirty=False,
                method_materials=digest(canonical(self.methods)),
                native={"verified": True},
            )
            self.index = index
            self.metrics[gate] = {
                "M13": {"observations": 1014},
                "M14": self.load.return_value,
                "M15": {"observations": 12000},
            }[gate]
            if gate == "M13":
                value["native"] = dict(
                    audit={"verified": True},
                    monitoring_proof={"signed": "monitoring"},
                    operator_observation={"service_observations": {}},
                )
                self.packets[gate] = self.privacy(value)
            for filename in privacy_gate.ARTIFACTS:
                if filename not in value["artifact_hashes"]:
                    body = value["native"] if filename == "probe.json" else {"fixture": filename}
                    value["artifact_hashes"][filename] = self.file(
                        "candidate-inference/" + fx.campaign + "/" + filename, body
                    )
            if gate != "M13":
                self.packets[gate] = {
                    "candidate-" + k: v for k, v in value["artifact_hashes"].items()
                }
                if gate == "M14":
                    for filename in ("start-request.json", "finish-request.json", "resources.json"):
                        self.packets[gate][filename] = self.file(
                            "evidence/load/" + fx.campaign + "/" + filename, {"fixture": filename}
                        )
                else:
                    for filename in ("binding.json", "packet.json", "feedback/proof.json"):
                        self.packets[gate][filename] = self.file(
                            "evidence/monitoring/" + fx.campaign + "/" + filename,
                            {"fixture": filename},
                        )
                    self.packets[gate]["public"] = self.file(
                        "evidence/kubernetes-monitoring-public.json", {"fixture": "public"}
                    )
            controls = dict(
                cases=[dict(id="controlled", status="pass", expected=True, actual=True)]
            )
            self.file("evidence/" + mode + "-contracts.json", controls)
            component = dict(
                status="pass",
                release_ready=False,
                checks=1,
                cases=controls["cases"],
                source_revision=fx.fx.source["source_revision"],
                metrics=self.metrics[gate],
                input_digests={
                    **fx.fx.source,
                    **{
                        k: value[k]
                        for k in (*collector.delivery.IDENTITY, "qualification_permit_sha256")
                    },
                },
                artifact_hashes=dict(
                    method_materials=digest(canonical(self.methods)),
                    controlled_contracts=digest(canonical(controls)),
                ),
            )
            private = self.file("evidence/kubernetes-" + mode + "-private.json", value)
            if gate == "M13":
                component["artifact_hashes"].update(
                    proposal_packet=fx.pins[collector.delivery.PROPOSAL],
                    frozen_demo=fx.pins[collector.delivery.DEMO],
                )
                self.admissions[gate] = self.file(
                    "evidence/privacy-gate-private.json",
                    dict(private_observation=private, retained_packets=self.packets[gate]),
                )
            else:
                if gate == "M14":
                    component["artifact_hashes"].update(
                        private_observation=private,
                        **{
                            "retained_" + k.replace("-", "_").replace(".", "_"): v
                            for k, v in self.packets[gate].items()
                        },
                    )
                collector.delivery.seal(
                    self.root,
                    self.state,
                    gate,
                    index,
                    value,
                    private,
                    self.packets[gate],
                    component,
                )
                self.admissions[gate] = digest(
                    bounded_read(self.state / f"evidence/{gate}-frozen-private.json")
                )
                if gate == "M15":
                    self.file(
                        "evidence/monitoring-gate-private.json",
                        dict(private_observation=private, retained_packets=self.packets[gate]),
                    )
            self.file("evidence/" + mode + "-gate.json", component)
            wrapper = dict(
                component,
                gate=gate,
                source_dirty=False,
                exit_code=0,
                started_at=value["started_at"],
                finished_at=value["finished_at"],
                metrics=dict(checks=1, **self.metrics[gate]),
            )
            self.reports[gate] = self.file("evidence/" + gate + ".json", wrapper)
            self.values[gate] = value
            for name in ("permit.pem", "ref.pem"):
                (self.state / name).unlink()
        self.freeze = self.file(collector.FREEZE, self.index)
        self.pins = dict(freeze_pin=self.freeze, reports=self.reports, admissions=self.admissions)

    def file(self, name, value):
        write_json(self.state / name, value)
        return digest(bounded_read(self.state / name))

    def privacy(self, value):
        path = "evidence/privacy/" + self.fixture.campaign
        cli = "evidence/cli-privacy/" + "d" * 32
        value["controlled_cli"] = dict(privacy_campaign_id="d" * 32, service_windows={})
        pins = dict(
            actual_audit=self.file(path + "/audit-evidence/packet.json", {"fixture": "actual"}),
            controlled_cli_packet=self.file(
                cli + "/closed-window/packet.json", {"fixture": "control"}
            ),
            monitoring=digest(canonical(value["native"]["monitoring_proof"])),
        )
        self.file(cli + "/context.json", {"fixture": "context"})
        source = self.file(path + "/feedback/source-service/packet.json", {"fixture": "source"})
        pins["feedback_privacy"] = self.file(
            path + "/feedback/privacy.json", dict(service=dict(sha256=source))
        )
        for prefix, directory, windows in (
            ("actual", path, value["native"]["operator_observation"]["service_observations"]),
            ("controlled_cli", cli, value["controlled_cli"]["service_windows"]),
        ):
            for namespace in ("serving", "trust"):
                pin = self.file(
                    directory + "/services/" + namespace + "/packet.json",
                    {"fixture": prefix + namespace},
                )
                windows[namespace] = dict(sha256=pin)
                pins[prefix + "_" + namespace] = pin
        return pins

    def capture(self):
        return collector.capture(self.root, self.state, **self.pins)

    def replay(self, pin):
        return collector.replay(self.root, self.state, pin, **self.pins)

    def draft_inputs(self):
        final_path = self.state / collector.final.INDEX
        original = bounded_read(final_path)
        self.addCleanup(lambda: self.assertEqual(bounded_read(final_path), original))
        # Keep the other 19 inventories from the final-evidence fixture. This trio has new reports.
        name = "evidence/M18-plan.json"
        plan = decode(collector.final.pinned(self.state / name, self.fixture.fx.index["plan"]))
        for gate, pin in self.reports.items():
            report = decode(collector.final.pinned(self.state / f"evidence/{gate}.json", pin))
            plan["cases"][gate] = digest(canonical(sorted(case["id"] for case in report["cases"])))
            plan["artifacts"][gate] = digest(canonical(sorted(report["artifact_hashes"])))
        for field in ("cases", "artifacts"):
            self.assertEqual(set(plan[field]), set(collector.final.CHILDREN))
        return self.capture(), dict(
            self.pins,
            plan_pin=self.file(name, plan),
            proposal_reference=self.values["M13"]["proposal_reference"],
        )

    def test_draft_rejects_foreign_proposal_and_freeze(self):
        receipt, args = self.draft_inputs()
        other_freeze = dict(self.index, source_fingerprint=digest(b"other source"))
        for change in (
            {"proposal_reference": digest(b"other proposal")},
            {"freeze_pin": collector.put(self.state, canonical(other_freeze) + b"\n")},
        ):
            with self.subTest(field=next(iter(change))), self.assertRaises(Rejected):
                collector.assemble_draft(self.root, self.state, receipt, **(args | change))

    def test_draft_requires_original_plan_bytes_and_matching_source(self):
        receipt, args = self.draft_inputs()
        name = "evidence/M18-plan.json"
        path = self.state / name
        raw = bounded_read(path)
        plan = decode(raw)
        path.write_bytes(raw + b" ")
        with self.assertRaises(Rejected):
            collector.assemble_draft(self.root, self.state, receipt, **args)
        for field, value in (
            ("source_revision", "e" * 40),
            ("source_fingerprint", digest(b"another source")),
            ("schema_version", 2),
        ):
            changed = self.file(name, {**plan, field: value})
            with self.subTest(field=field), self.assertRaises(Rejected):
                collector.assemble_draft(
                    self.root, self.state, receipt, **(args | {"plan_pin": changed})
                )

    def test_draft_rejects_repinned_plan_with_wrong_serving_inventory(self):
        receipt, args = self.draft_inputs()
        name = "evidence/M18-plan.json"
        plan = decode(bounded_read(self.state / name))
        for field, gate in (("cases", "M13"), ("artifacts", "M15")):
            changed = copy.deepcopy(plan)
            changed[field][gate] = digest(canonical(["unexpected-entry"]))
            pin = self.file(name, changed)
            self.assertNotEqual(pin, args["plan_pin"])
            with self.subTest(field=field, gate=gate), self.assertRaises(Rejected):
                collector.assemble_draft(
                    self.root, self.state, receipt, **(args | {"plan_pin": pin})
                )

    def test_draft_is_inconclusive_private_and_byte_reproducible(self):
        receipt, args = self.draft_inputs()
        result = collector.assemble_draft(self.root, self.state, receipt, **args)
        # Only this small receipt can leave the private store. The index blob holds the references.
        self.assertEqual(set(result), {"status", "release_ready", "index_sha256"})
        self.assertEqual(result["status"], "inconclusive")
        self.assertIs(result["release_ready"], False)
        pin = result["index_sha256"]
        raw = collector.final.blob(self.state, pin)
        draft = decode(raw)
        self.assertEqual(pin, digest(raw))
        for field in (
            "source_revision",
            "source_fingerprint",
            "image_id",
            "policy_reference",
            "freeze",
        ):
            self.assertEqual(draft[field], self.index[field], field)
        self.assertEqual(draft["schema_version"], 1)
        self.assertIsInstance(draft["scope"], str)
        self.assertTrue(draft["scope"])
        self.assertEqual(draft["status"], "inconclusive")
        self.assertIs(draft["release_ready"], False)
        self.assertIs(draft.get("production_authorized", False), False)
        self.assertEqual(draft["proposal_reference"], args["proposal_reference"])
        self.assertEqual(draft["plan"], args["plan_pin"])
        self.assertEqual(draft["reports"], self.reports)
        self.assertEqual(
            draft["retained"],
            {
                "M13": self.admissions["M13"],
                "M15": digest(bounded_read(self.state / "evidence/monitoring-gate-private.json")),
            },
        )
        repeated = collector.assemble_draft(self.root, self.state, receipt, **args)
        self.assertEqual(repeated["index_sha256"], pin)
        self.assertEqual(collector.final.blob(self.state, repeated["index_sha256"]), raw)

    def test_trio_draft_keeps_original_plan_contract_without_upstream_rejections(self):
        receipt, args = self.draft_inputs()
        name = "evidence/M18-plan.json"
        plan = decode(collector.final.pinned(self.state / name, args["plan_pin"]))
        del plan["rejections"]
        args["plan_pin"] = self.file(name, plan)
        result = collector.assemble_draft(self.root, self.state, receipt, **args)
        draft = decode(collector.final.blob(self.state, result["index_sha256"]))
        self.assertEqual(draft["reports"], self.reports)
        self.assertEqual(result["status"], "inconclusive")
        self.assertIs(result["release_ready"], False)

    def test_draft_merges_m02_without_overwriting_base(self):
        receipt, args = self.draft_inputs()
        first = collector.assemble_draft(self.root, self.state, receipt, **args)
        serving = decode(collector.final.blob(self.state, first["index_sha256"]))
        m02 = collector.put(self.state, bounded_read(self.state / "evidence/M02.json"))
        base = dict(serving, reports={"M02": m02}, retained={})
        base_bytes = canonical(base) + b"\n"
        base_pin = collector.put(self.state, base_bytes)
        result = collector.assemble_draft(self.root, self.state, receipt, base_pin=base_pin, **args)
        self.assertNotEqual(result["index_sha256"], base_pin)
        merged = decode(collector.final.blob(self.state, result["index_sha256"]))
        self.assertEqual(merged["reports"], {"M02": m02, **self.reports})
        self.assertEqual(merged["retained"], serving["retained"])
        self.assertEqual(collector.final.blob(self.state, base_pin), base_bytes)
        object_path = self.state / "evidence/M18-objects" / m02
        object_path.write_bytes(b"damaged preexisting M02")
        with self.assertRaises(Rejected):
            collector.assemble_draft(self.root, self.state, receipt, base_pin=base_pin, **args)
        self.assertEqual(collector.final.blob(self.state, base_pin), base_bytes)

    def test_draft_rejects_digest_conflicts_without_overwriting_base(self):
        receipt, args = self.draft_inputs()
        first = collector.assemble_draft(self.root, self.state, receipt, **args)
        draft = decode(collector.final.blob(self.state, first["index_sha256"]))
        for field, change in (
            ("reports", {"M13": self.reports["M14"]}),
            ("retained", {"M15": draft["retained"]["M13"]}),
        ):
            base = {**draft, field: draft[field] | change}
            raw = canonical(base) + b"\n"
            pin = collector.put(self.state, raw)
            with self.subTest(field=field), self.assertRaises(Rejected):
                collector.assemble_draft(self.root, self.state, receipt, base_pin=pin, **args)
            self.assertEqual(collector.final.blob(self.state, pin), raw)
        # A valid plan with a new external pin cannot be merged into a draft of the old plan.
        name = "evidence/M18-plan.json"
        path = self.state / name
        path.write_bytes(bounded_read(path) + b" ")
        changed = dict(args, plan_pin=digest(bounded_read(path)))
        with self.assertRaises(Rejected):
            collector.assemble_draft(
                self.root, self.state, receipt, base_pin=first["index_sha256"], **changed
            )

    def test_draft_rejects_corrupt_blobs_without_repairing_them(self):
        receipt, args = self.draft_inputs()
        first = collector.assemble_draft(self.root, self.state, receipt, **args)
        for pin in (receipt, self.packets["M15"]["packet.json"], first["index_sha256"]):
            path = self.state / "evidence/M18-objects" / pin
            original = bounded_read(path)
            path.write_bytes(b"corrupt")
            try:
                with self.subTest(pin=pin), self.assertRaises(Rejected):
                    collector.assemble_draft(self.root, self.state, receipt, **args)
                self.assertEqual(bounded_read(path), b"corrupt")
            finally:
                path.write_bytes(original)

    def test_draft_base_cannot_authorize_release_or_switch_proposal(self):
        receipt, args = self.draft_inputs()
        first = collector.assemble_draft(self.root, self.state, receipt, **args)
        draft = decode(collector.final.blob(self.state, first["index_sha256"]))
        for change in (
            {"status": "pass"},
            {"release_ready": True},
            {"proposal_reference": digest(b"another candidate proposal")},
        ):
            raw = canonical(draft | change) + b"\n"
            base_pin = collector.put(self.state, raw)
            with self.subTest(field=next(iter(change))), self.assertRaises(Rejected):
                collector.assemble_draft(self.root, self.state, receipt, base_pin=base_pin, **args)
            self.assertEqual(collector.final.blob(self.state, base_pin), raw)

    def test_missing_and_corrupt_originals_never_produce_a_receipt(self):
        for name in (
            "evidence/M13.json",
            "evidence/M14-frozen-private.json",
            "evidence/monitoring-gate-private.json",
            "candidate-inference/" + "a" * 32 + "/config.json",
            "evidence/privacy/" + "a" * 32 + "/audit-evidence/packet.json",
            "evidence/load/" + "b" * 32 + "/resources.json",
            "evidence/monitoring/" + "c" * 32 + "/packet.json",
        ):
            path = self.state / name
            original = bounded_read(path)
            for corrupted in (None, b"corrupted"):
                if corrupted is None:
                    path.unlink()
                else:
                    path.write_bytes(corrupted)
                with (
                    self.subTest(name=name, corrupted=corrupted is not None),
                    self.assertRaises((Rejected, OSError, KeyError)),
                ):
                    self.capture()
                self.assertFalse((self.state / collector.RECEIPT).exists())
                path.write_bytes(original)

    def test_swapped_admissions_reports_and_owner_pins_are_rejected(self):
        for table in ("reports", "admissions"):
            changed = copy.deepcopy(self.pins)
            changed[table]["M13"], changed[table]["M15"] = (
                changed[table]["M15"],
                changed[table]["M13"],
            )
            with self.subTest(table=table), self.assertRaises(Rejected):
                collector.capture(self.root, self.state, **changed)
        with self.assertRaises(Rejected):
            collector.capture(self.root, self.state, **dict(self.pins, freeze_pin="0" * 64))
        with self.assertRaises(Rejected):
            collector.capture(
                self.root, self.state, **dict(self.pins, reports={"M13": self.reports["M13"]})
            )

    def test_capture_preserves_all_original_bytes_and_native_admissions(self):
        pin = self.capture()
        record = decode(collector.final.blob(self.state, pin))
        self.assertEqual(
            record["retained"],
            {
                "M13": self.admissions["M13"],
                "M15": digest(bounded_read(self.state / "evidence/monitoring-gate-private.json")),
            },
        )
        self.assertNotEqual(record["retained"]["M15"], self.admissions["M15"])
        for name, ref in record["files"].items():
            self.assertEqual(collector.final.blob(self.state, ref), bounded_read(self.state / name))
        self.assertEqual(self.capture(), pin)
        self.assertEqual(self.replay(pin)["reports"], self.reports)

    def test_offline_replay_survives_deletion_of_all_original_captured_files(self):
        pin = self.capture()
        record = decode(collector.final.blob(self.state, pin))
        for name in record["files"]:
            (self.state / name).unlink()
        (self.state / collector.RECEIPT).unlink()
        result = self.replay(pin)
        self.assertFalse(result["release_ready"])
        self.assertEqual(result["retained"], record["retained"])
        self.assertEqual(set(result["reports"]), set(collector.GATES))
        self.assertFalse(list(self.state.glob("m18-serving-*")))

    def test_missing_corrupt_objects_fail_and_capture_does_not_repair_corruption(self):
        pin = self.capture()
        record = decode(collector.final.blob(self.state, pin))
        for ref in (
            self.reports["M14"],
            self.admissions["M13"],
            self.packets["M13"]["actual_audit"],
            self.packets["M15"]["packet.json"],
        ):
            path = self.state / "evidence/M18-objects" / ref
            raw = bounded_read(path)
            path.unlink()
            with self.assertRaises((Rejected, OSError)):
                self.replay(pin)
            path.write_bytes(b"corrupt")
            with self.assertRaises(Rejected):
                self.replay(pin)
            with self.assertRaises(Rejected):
                self.capture()
            self.assertEqual(path.read_bytes(), b"corrupt")
            path.write_bytes(raw)
        self.assertEqual(record["reports"], self.replay(pin)["reports"])

    def test_resealed_report_for_a_different_candidate_cannot_change_the_frozen_owner(self):
        for gate, mode in collector.MODES.items():
            report_name, component_name = (
                "evidence/" + gate + ".json",
                "evidence/" + mode + "-gate.json",
            )
            original = {p: bounded_read(self.state / p) for p in (report_name, component_name)}
            report, component = (decode(original[p]) for p in (report_name, component_name))
            report["input_digests"]["candidate_reference"] = "0" * 64
            self.reports[gate] = self.file(report_name, report)
            component["input_digests"] = report["input_digests"]
            component_pin = self.file(component_name, component)
            if gate != "M13":
                name = "evidence/" + gate + "-frozen-private.json"
                original[name] = bounded_read(self.state / name)
                admission = decode(original[name])
                admission["component_sha256"] = component_pin
                self.admissions[gate] = self.file(name, admission)
            with self.subTest(gate=gate), self.assertRaises(Rejected):
                self.capture()
            self.assertFalse((self.state / collector.RECEIPT).exists())
            for name, raw in original.items():
                (self.state / name).write_bytes(raw)
            self.reports[gate] = digest(original[report_name])
            if gate != "M13":
                self.admissions[gate] = digest(
                    original["evidence/" + gate + "-frozen-private.json"]
                )

    def test_original_permit_window_is_checked_without_renewal(self):
        name = "evidence/kubernetes-privacy-private.json"
        original = bounded_read(self.state / name)
        value = decode(original)
        value["finished_at"] = "2100-01-01T00:00:00+00:00"
        private = self.file(name, value)
        admission_name = "evidence/privacy-gate-private.json"
        admission_raw = bounded_read(self.state / admission_name)
        admission = decode(admission_raw)
        admission["private_observation"] = private
        self.admissions["M13"] = self.file(admission_name, admission)
        with self.assertRaises(Rejected):
            self.capture()
        (self.state / name).write_bytes(original)
        (self.state / admission_name).write_bytes(admission_raw)
        self.admissions["M13"] = digest(admission_raw)
        pin = self.capture()
        with patch.object(collector.final, "now", return_value="2100-01-01T00:00:00+00:00"):
            self.assertFalse(self.replay(pin)["release_ready"])

    def test_object_limits_and_original_receipt_are_immutable(self):
        for raw in (b"", b"x" * (collector.LIMIT + 1)):
            with self.subTest(size=len(raw)), self.assertRaises(Rejected):
                collector.put(self.state, raw)
        self.capture()
        path = self.state / collector.RECEIPT
        path.write_bytes(b"changed")
        with self.assertRaises(Rejected):
            self.capture()
        self.assertEqual(path.read_bytes(), b"changed")

    def test_m15_native_admission_must_match_the_original_frozen_admission(self):
        path = "evidence/monitoring-gate-private.json"
        native = decode(bounded_read(self.state / path))
        native["private_observation"] = self.admissions["M13"]
        self.file(path, native)
        with self.assertRaises(Rejected):
            self.capture()

    def test_resealed_receipt_cannot_swap_inputs_admissions_or_add_files(self):
        pin = self.capture()
        original = decode(collector.final.blob(self.state, pin))
        mutations = [
            dict(original, freeze_sha256="0" * 64),
            dict(original, retained={"M13": self.admissions["M13"]}),
        ]
        mutations.append(
            dict(
                original, files=dict(original["files"], **{"keys/private.pem": digest(b"private")})
            )
        )
        changed = copy.deepcopy(original)
        changed["files"]["evidence/M13.json"] = self.reports["M15"]
        mutations.append(changed)
        for changed in mutations:
            forged = collector.put(self.state, canonical(changed) + b"\n")
            with self.subTest(keys=changed.keys()), self.assertRaises((Rejected, KeyError)):
                self.replay(forged)

    def test_normal_verifier_failure_and_changed_methods_are_not_overridden(self):
        for verifier in (self.audit, self.load, monitoring_gate.reconcile):
            verifier.side_effect = Rejected("controlled verifier rejection")
            with self.assertRaises(Rejected):
                self.capture()
            verifier.side_effect = None
        with (
            patch.object(collector, "materials", return_value={"changed": "source"}),
            self.assertRaises(Rejected),
        ):
            self.capture()
        self.clean.side_effect = Rejected("dirty source")
        with self.assertRaises(Rejected):
            self.capture()

    def test_cli_publishes_only_receipt_pin_and_public_summary(self):
        env = {
            "M18_FREEZE_SHA256": self.freeze,
            "GITHUB_OUTPUT": str(self.root / "outputs"),
            **{g + "_REPORT": p for g, p in self.reports.items()},
            **{g + "_ADMISSION": p for g, p in self.admissions.items()},
        }
        with (
            patch.dict(os.environ, env),
            patch.object(
                collector, "__file__", str(self.root / "scripts/m18_serving_retention.py")
            ),
            redirect_stdout(io.StringIO()) as output,
        ):
            collector.main(["capture"])
            pin = (self.root / "outputs").read_text().strip().split("=", 1)[1]
            with patch.dict(os.environ, M18_SERVING_PRIMARY_SHA256=pin):
                collector.main(["replay"])
            self.assertIn("::add-mask::" + pin, output.getvalue())
            self.assertNotIn('"retained"', output.getvalue())
            self.assertNotIn("monitoring_proof", output.getvalue())
        with (
            patch.object(sys, "argv", [collector.__file__, "invalid"]),
            self.assertRaisesRegex(SystemExit, "M18 serving primary verification failed"),
        ):
            runpy.run_path(collector.__file__, run_name="__main__")


if __name__ == "__main__":
    unittest.main()
