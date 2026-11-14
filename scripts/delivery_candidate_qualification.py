"""Reconcile the gate files from one proposal and refuse mixed attempts or candidates."""

import io
import os
import runpy
import sys
import unittest
from contextlib import chdir, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, write_json
from scripts.delivery_candidate import reconcile


class Delivery(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(TemporaryDirectory())
        self.enterContext(chdir(directory))
        self.root = Path(".runtime")
        self.dir = self.root / "evidence"

        def h(label):
            return digest(label.encode())

        self.source = dict(
            source_fingerprint=h("tree"), source_revision="c" * 40, image_id="sha256:" + h("image")
        )
        self.proposal = dict(
            source=self.source,
            status="pass",
            release_ready=False,
            source_dirty=False,
            model_sha256=h("model"),
            subject_sha256=h("subject"),
            proposal_reference=h("proposal"),
        )
        demo = dict(
            candidate=dict(
                candidate_reference=h("candidate"),
                metadata=dict(
                    model_digest=h("model"), policy_digest=h("policy"), input_digest=h("training")
                ),
            ),
            evaluation_reference=h("evaluation"),
        )
        demo["dataset"] = dict(dataset_reference=h("dataset"))
        self.original = self.dir / "release-native.json"
        self.demo = self.root / "storage-demo.json"
        write_json(self.original, self.proposal)
        write_json(self.demo, demo)
        self.keys = dict(curator="owned-curator", evaluator="owned-evaluator")
        write_json(self.root / "trusted-keys.json", self.keys)
        write_json(self.root / "storage-trust.json", self.keys)
        pin = digest(bounded_read(self.original))
        self.env = dict(
            GITHUB_SHA=self.source["source_revision"],
            M17_PROPOSAL_SHA256=pin,
            M17_DEMO_SHA256=digest(bounded_read(self.demo)),
            M17_KEYS_SHA256=digest(canonical(self.keys)),
            M19_TRUST_SHA256=digest(bounded_read(self.root / "storage-trust.json")),
            T19_PRIMARY_SHA256=h("canary-packet"),
            T19_ROLLBACK_SHA256=h("rollback-packet"),
            M17_PRIMARY_SHA256=h("recovery-packet"),
            M19_PRIMARY_SHA256=h("inventory-packet"),
            M19_FLEET_INPUTS_SHA256=h("inventory-inputs"),
        )
        self.enterContext(patch.dict(os.environ, self.env))
        self.reports = {}
        write_json(Path("data.lock"), dict(output=dict(sha256=h("data"))))
        lock = digest(bounded_read(Path("data.lock")))
        for gate in (
            "M01",
            "M02",
            "M03",
            "M06",
            "M07",
            "M08",
            "M09",
            "M10",
            "M12",
            "M16",
            "M17",
            "M19",
        ):
            common = dict(
                candidate_reference=h("candidate"),
                evaluation_reference=h("evaluation"),
                source_fingerprint=h("tree"),
            )
            result = dict(
                gate=gate,
                profile="local-cpu",
                source_dirty=False,
                source_revision=self.source["source_revision"],
                status="pass",
                exit_code=0,
                policy_digest=h("policy"),
            )
            if gate in ("M16", "M17", "M19"):
                result.update(release_ready=False, artifact_hashes=dict(proposal_packet=pin))
                inputs = dict(
                    **self.source,
                    qualified_candidate_model=h("model"),
                    qualified_candidate_subject=h("subject"),
                    proposal_reference=h("proposal"),
                )
                artifacts = result["artifact_hashes"]
                if gate in ("M17", "M19"):
                    artifacts.update(
                        demo=self.env["M17_DEMO_SHA256"], public_keys=self.env["M17_KEYS_SHA256"]
                    )
                if gate in ("M16", "M19"):
                    artifacts.update(
                        {
                            k: h(gate + k)
                            for k in (
                                "traffic_rows",
                                "candidate_source",
                                "candidate_journal",
                                "stable_journal",
                            )
                        }
                    )
                if gate == "M16":
                    artifacts.update(
                        traffic_packet=self.env["T19_PRIMARY_SHA256"],
                        rollback_packet=self.env["T19_ROLLBACK_SHA256"],
                    )
                elif gate == "M17":
                    artifacts["recovery_packet"] = self.env["M17_PRIMARY_SHA256"]
                else:
                    inputs.update(release_subject=h("subject"), model=h("model"))
                    artifacts.update(
                        primary=self.env["M19_PRIMARY_SHA256"],
                        fleet_inputs=self.env["M19_FLEET_INPUTS_SHA256"],
                        source_trust=self.env["M19_TRUST_SHA256"],
                    )
            elif gate in ("M10", "M12"):
                if gate == "M10":
                    result.update(
                        release_ready=False, artifact_hashes=dict(actual_proposal_report=pin)
                    )
                inputs = dict(
                    **self.source,
                    model=h("model"),
                    release_subject=h("subject"),
                    proposal_reference=h("proposal"),
                )
            elif gate == "M01":
                common = dict(source_fingerprint=h("tree"))
                inputs = dict(worker_image=self.source["image_id"])
            elif gate == "M02":
                common = dict(source_fingerprint=h("tree"))
                inputs = dict(data_lock=lock, source=h("data"))
            elif gate == "M03":
                inputs = dict(
                    data_lock=lock,
                    source=h("data"),
                    worker_image=self.source["image_id"],
                    dataset_reference=h("dataset"),
                )
            elif gate == "M06":
                inputs = dict(
                    frozen_demo=self.env["M17_DEMO_SHA256"],
                    worker_image=self.source["image_id"],
                    dataset_reference=h("dataset"),
                    model_digest=h("model"),
                    candidate_training_input=h("training"),
                )
            elif gate == "M07":
                inputs = dict(
                    data_lock=lock,
                    dataset_source=h("data"),
                    model=h("model"),
                    training_request=h("training"),
                    worker_image=self.source["image_id"],
                    dataset_reference=h("dataset"),
                )
            else:
                inputs = {
                    "image" if gate == "M08" else "image_id": self.source["image_id"],
                    "candidate_training_input": h("training"),
                    "model_digest": h("model"),
                }
            result["input_digests"] = common | inputs
            self.reports[gate] = result
            write_json(self.path(gate), result)

    def path(self, gate):
        return self.dir / (gate + ".json")

    def run_cli(self):
        with redirect_stdout(io.StringIO()) as out, patch.dict(sys.modules):
            sys.modules.pop("scripts.delivery_candidate", None)
            runpy.run_module("scripts.delivery_candidate", run_name="__main__")
        return decode(out.getvalue().encode())

    def test_fixed_historical_profiles_and_frozen_m06(self):
        from scripts.delivery_candidate import BASE7, PARENT11, frozen_reports

        pins = dict(
            demo_pin=self.env["M17_DEMO_SHA256"],
            proposal_pin=self.env["M17_PROPOSAL_SHA256"],
            revision=self.source["source_revision"],
        )
        for profile, required in (
            ("base7", BASE7),
            ("parent11", PARENT11),
            ("m06-checkpoint", ("M06",)),
        ):
            with self.subTest(profile=profile):
                receipt = frozen_reports(self.root, profile=profile, **pins)
                self.assertEqual(set(receipt["reports"]), set(required))
                self.assertIs(receipt["release_ready"], False)
                gate = required[0]
                write_json(self.path(gate), self.reports[gate] | {"source_revision": "b" * 40})
                with self.assertRaises(Rejected):
                    frozen_reports(self.root, profile=profile, **pins)
                write_json(self.path(gate), self.reports[gate])

    def test_combined_parent12_requires_early_capture_and_all_fifteen_hashes(self):
        from scripts import controller_delivery as collector
        from scripts.m12_pinned_native import PACKET

        capture = self.root / PACKET
        write_json(capture, {"attempt": "one"})
        capture_pin = digest(bounded_read(capture))
        report = self.reports["M12"] | {"artifact_hashes": {"pinned_actual": capture_pin}}
        write_json(self.path("M12"), report)
        scoped = {g: digest(bounded_read(self.path(g))) for g in ("M03", "M07")}
        scoped.update({g: digest(g.encode()) for g in ("M04", "M05", "M20")})
        with (
            patch.object(collector, "reconcile", return_value=scoped),
            patch.object(sys, "argv", ["controller_delivery", "--include-recovery", "parent12"]),
            patch.dict(os.environ, M12_EARLY_SHA256=capture_pin),
            redirect_stdout(io.StringIO()) as buffer,
        ):
            collector.main()
            result = decode(buffer.getvalue().encode())
            self.assertEqual(set(result["reports"]), set(collector.GATES))
            self.assertEqual(len(result["reports"]), 15)
            self.assertIs(result["release_ready"], False)
            self.assertEqual(result["reports"]["M12"], digest(bounded_read(self.path("M12"))))
            with patch.dict(os.environ, M19_PRIMARY_SHA256=self.env["M17_PRIMARY_SHA256"]):
                with self.assertRaisesRegex(Rejected, "capture_reused"):
                    collector.main()
            write_json(self.path("M12"), report | {"artifact_hashes": {"pinned_actual": "a" * 64}})
            with self.assertRaisesRegex(Rejected, "m12_capture_mismatch"):
                collector.main()
            write_json(self.path("M12"), report)
            write_json(capture, {"attempt": "two"})
            with self.assertRaises(Rejected):
                collector.main()

    def test_cli_hashes_all_original_bytes(self):
        direct = reconcile(
            self.root,
            demo_pin=self.env["M17_DEMO_SHA256"],
            proposal_pin=self.env["M17_PROPOSAL_SHA256"],
            revision=self.source["source_revision"],
            keys_pin=self.env["M17_KEYS_SHA256"],
            trust_pin=self.env["M19_TRUST_SHA256"],
            captures={
                "canary": self.env["T19_PRIMARY_SHA256"],
                "rollback": self.env["T19_ROLLBACK_SHA256"],
                "recovery": self.env["M17_PRIMARY_SHA256"],
                "inventory": self.env["M19_PRIMARY_SHA256"],
                "fleet": self.env["M19_FLEET_INPUTS_SHA256"],
            },
        )
        result = self.run_cli()
        self.assertEqual(result, direct)
        self.assertIs(result["release_ready"], False)
        self.assertEqual(len(result["reports"]), 12)
        self.assertEqual(
            result["reports"], {g: digest(bounded_read(self.path(g))) for g in self.reports}
        )
        self.assertEqual(result["proposal_packet"], self.env["M17_PROPOSAL_SHA256"])

    def test_mixed_inputs_and_incomplete_gates_refuse(self):
        for gate, result in self.reports.items():
            inputs = result["input_digests"]
            for key in inputs:
                with self.subTest(gate=gate, key=key), patch.dict(inputs, {key: "foreign"}):
                    write_json(self.path(gate), result)
                    with self.assertRaisesRegex(Rejected, "candidate_mismatch"):
                        self.run_cli()
            for change in (
                dict(exit_code=False),
                dict(status="inconclusive"),
                dict(source_dirty=True),
                dict(policy_digest="other"),
            ):
                with self.subTest(gate=gate, change=change), patch.dict(result, change):
                    write_json(self.path(gate), result)
                    with self.assertRaisesRegex(Rejected, "candidate_mismatch"):
                        self.run_cli()
            if gate in ("M16", "M17", "M19"):
                with patch.dict(result["artifact_hashes"], proposal_packet="9" * 64):
                    write_json(self.path(gate), result)
                    with self.assertRaisesRegex(Rejected, "recovery_proposal_mismatch"):
                        self.run_cli()
            if gate == "M10":
                for change in [
                    dict(release_ready=True),
                    dict(artifact_hashes={"actual_proposal_report": "9" * 64}),
                ]:
                    with patch.dict(result, change):
                        write_json(self.path(gate), result)
                        with self.assertRaisesRegex(Rejected, "promotion_proposal_mismatch"):
                            self.run_cli()
            write_json(self.path(gate), result)

    def test_changed_originals_or_foreign_revision_refuse(self):
        for key in (
            "M17_DEMO_SHA256",
            "M17_PROPOSAL_SHA256",
            "M17_KEYS_SHA256",
            "M19_TRUST_SHA256",
            "GITHUB_SHA",
        ):
            with (
                self.subTest(key=key),
                patch.dict(os.environ, {key: "9" * 64}),
                self.assertRaises(Rejected),
            ):
                self.run_cli()
        self.proposal["model_sha256"] = "9" * 64
        write_json(self.original, self.proposal)
        with (
            patch.dict(os.environ, M17_PROPOSAL_SHA256=digest(bounded_read(self.original))),
            self.assertRaisesRegex(Rejected, "original_proposal_mismatch"),
        ):
            self.run_cli()

    def test_missing_report_does_not_emit_a_summary(self):
        self.path("M08").unlink()
        with self.assertRaisesRegex(Rejected, "artifact_unavailable"):
            self.run_cli()

    def test_m19_report_is_required(self):
        self.path("M19").unlink()
        with self.assertRaises(Rejected):
            self.run_cli()

    def test_foreign_source_hashes_and_capture_pins_refused(self):
        fields = {
            "M16": ("traffic_packet", "rollback_packet"),
            "M17": ("demo", "public_keys", "recovery_packet"),
            "M19": ("demo", "public_keys", "source_trust", "primary", "fleet_inputs"),
        }
        for gate, keys in fields.items():
            report = self.reports[gate]
            for key in keys:
                with self.subTest(gate=gate, key=key):
                    with patch.dict(report["artifact_hashes"], {key: "f" * 64}):
                        write_json(self.path(gate), report)
                        with self.assertRaises(Rejected):
                            self.run_cli()
                    write_json(self.path(gate), report)

    def test_m19_canary_sidecars_cannot_substitute_m16_observations(self):
        inventory = self.reports["M19"]["artifact_hashes"]
        canary = self.reports["M16"]["artifact_hashes"]
        for key in ("traffic_rows", "candidate_source", "candidate_journal", "stable_journal"):
            with self.subTest(key=key):
                with patch.dict(canary, {key: inventory[key]}):
                    write_json(self.path("M16"), self.reports["M16"])
                    with self.assertRaises(Rejected):
                        self.run_cli()
                write_json(self.path("M16"), self.reports["M16"])

    def test_duplicate_capture_and_wrong_key_newline_convention_refused(self):
        for changes in (
            dict(M19_PRIMARY_SHA256=self.env["T19_PRIMARY_SHA256"]),
            dict(M17_KEYS_SHA256=digest(bounded_read(self.root / "trusted-keys.json"))),
        ):
            with patch.dict(os.environ, changes), self.assertRaises(Rejected):
                self.run_cli()


class Workflow(unittest.TestCase):
    def test_inventory_runs_on_fresh_proposal_and_all_replays_follow_cleanup(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / ".github/workflows/storage-recovery.yml").read_text()
        blocks = text.split("\n      - name: ")

        def step(command):
            matches = [b for b in blocks if command in b]
            self.assertEqual(len(matches), 1, command)
            return blocks.index(matches[0]), matches[0]

        source, _ = step("-m scripts.release_native --state")
        materials, prepare = step("-m scripts.inventory_fleet_materials --existing")
        capture, inventory = step("-m scripts.inventory_deployment_native")
        promotion, _ = step("--gate M10 --output")
        canary, traffic = step("-m scripts.canary_rollout_native capture")
        rollback, durable = step("-m scripts.canary_rollout_native rollback")
        recovery, _ = step("-m scripts.m17_recovery_native capture")
        stop, _ = step("-m scripts.m17_recovery_native stop")
        cluster, _ = step("kind delete cluster")
        replay, public = step("--gate M19 --output")
        self.assertEqual(
            [
                source,
                materials,
                capture,
                promotion,
                canary,
                rollback,
                recovery,
                stop,
                cluster,
                replay,
            ],
            sorted(
                {
                    source,
                    materials,
                    capture,
                    promotion,
                    canary,
                    rollback,
                    recovery,
                    stop,
                    cluster,
                    replay,
                }
            ),
        )
        for block in (prepare, inventory, public):
            for key, value in (
                ("M19_PROPOSAL_SHA256", "steps.source.outputs.proposal"),
                ("M19_DEMO_SHA256", "steps.source.outputs.demo"),
                ("M19_KEYS_SHA256", "steps.source.outputs.keys"),
                ("M19_TRUST_SHA256", "steps.source.outputs.trust"),
                ("M19_WORKSPACE_ID", "steps.sql.outputs.workspace"),
            ):
                self.assertIn(key + ": ${{ " + value + " }}", block)
        self.assertIn("id: inventory_inputs", prepare)
        self.assertIn("id: inventory_capture", inventory)
        self.assertIn(
            "M19_FLEET_INPUTS_SHA256: ${{ steps.inventory_inputs.outputs.sha256 }}", inventory
        )
        self.assertIn("M19_PRIMARY_SHA256: ${{ steps.inventory_capture.outputs.sha256 }}", public)
        self.assertIn("T19_PRIMARY_SHA256: ${{ steps.canary.outputs.sha256 }}", public)
        self.assertIn("T19_ROLLBACK_SHA256: ${{ steps.rollback.outputs.sha256 }}", public)
        self.assertIn("T19_PRIMARY_SHA256: ${{ steps.canary.outputs.sha256 }}", durable)
        self.assertIn("id: canary", traffic)
        self.assertLess(
            public.index("--gate M19 --output"),
            public.index("-m scripts.controller_delivery --include-recovery parent12"),
        )
        self.assertIn("from scripts.controller_delivery import GATES", public)
        self.assertIn("for gate in GATES:", public)

    def test_normal_entrypoints_write_distinct_private_packets(self):
        from scripts import canary_rollout_native as canary
        from scripts import inventory_deployment_native as inventory

        root = Path(self.enterContext(TemporaryDirectory()))
        state = root / ".runtime"
        records = {
            inventory.gate.PACKET: dict(campaign="inventory"),
            canary.PACKET: dict(campaign="canary"),
            canary.ROLLBACK_PACKET: dict(campaign="canary", rollback=True),
        }
        self.assertEqual(len(records), 3)
        with (
            patch.dict(os.environ, GITHUB_OUTPUT=str(root / "outputs")),
            patch.object(canary, "hosted"),
            patch.object(canary, "__file__", str(root / "scripts/canary_rollout_native.py")),
            patch.object(inventory, "capture", return_value=records[inventory.gate.PACKET]),
            patch.object(canary, "traffic", return_value=records[canary.PACKET]),
            patch.object(
                canary, "controlled_rollback", return_value=records[canary.ROLLBACK_PACKET]
            ),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(inventory.main(root), 0)
            for stage in ("capture", "rollback"):
                with patch.object(sys, "argv", ["canary_rollout_native", stage]):
                    self.assertEqual(canary.main(), 0)
        self.assertEqual({name: decode(bounded_read(state / name)) for name in records}, records)
