"""Expiry, immutable retention and same-candidate joins without native services."""

import copy
import io
import os
import runpy
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime
from unittest.mock import patch

from mlsecops.contracts import Rejected, bounded_read, digest, write_json
from scripts import final_evidence_qualification as fixtures
from scripts import serving_retention as retention


class RetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.FinalEvidenceContracts.setUpClass()
        cls.addClassCleanup(fixtures.FinalEvidenceContracts.tearDownClass)

    def setUp(self):
        fx = fixtures.FinalEvidenceContracts()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        fx.build()
        self.fx = fx
        self.root, self.state = fx.root, fx.state
        self.revision = fx.source["source_revision"]
        self.clock = fx.values["captured_at"] + 1
        self.freeze = fx.pinfile(retention.FREEZE, fx.index)
        self.sql = {"workspace_id": "original", "container_id": "source"}
        self.source_pin = fx.pinfile("storage.json", self.sql)
        self.enterContext(patch.object(retention.final_evidence, "clean"))
        self.validate = self.enterContext(
            patch.object(retention.storage_bootstrap, "validate", return_value=self.sql)
        )
        self.inspect = self.enterContext(
            patch.object(
                retention.storage_bootstrap,
                "inspect",
                return_value={"State": {"Running": True, "Status": "running"}},
            )
        )

    def capture(self):
        return retention.retain(
            self.root,
            self.state,
            freeze_pin=self.freeze,
            source_pin=self.source_pin,
            pins=self.fx.freeze,
            revision=self.revision,
            clock=self.clock,
        )

    def test_expired_future_and_insufficient_source_window_refused_before_retention(self):
        for clock in (
            self.fx.values["proposal_issued_at"] - 1,
            self.fx.values["proposal_expires_at"],
            self.fx.values["proposal_expires_at"] - 599,
        ):
            self.clock = clock
            with self.subTest(clock=clock), self.assertRaises(Rejected):
                self.capture()
            self.assertFalse((self.state / retention.RECEIPT).exists())

    def test_owner_pins_revision_source_and_running_state_cannot_be_substituted(self):
        for field in self.fx.freeze:
            original = self.fx.freeze[field]
            self.fx.freeze[field] = "0" * 64
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.capture()
            self.fx.freeze[field] = original
        self.revision = "0" * 40
        with self.assertRaises(Rejected):
            self.capture()
        self.revision = self.fx.source["source_revision"]
        self.source_pin = "0" * 64
        with self.assertRaises(Rejected):
            self.capture()
        self.source_pin = self.fx.pinfile("storage.json", self.sql)
        for running, status in ((False, "exited"), (True, "restarting")):
            self.inspect.return_value = {"State": {"Running": running, "Status": status}}
            with self.subTest(status=status), self.assertRaises(Rejected):
                self.capture()
        self.inspect.return_value = {"State": {"Running": True, "Status": "running"}}
        self.validate.return_value = dict(self.sql, container_id="other")
        with self.assertRaises(Rejected):
            self.capture()

    def test_original_capture_is_idempotent_and_replay_does_not_renew_validity(self):
        pin = self.capture()
        original = bounded_read(self.state / retention.RECEIPT)
        self.clock += 1
        self.assertEqual(self.capture(), pin)
        self.assertEqual(bounded_read(self.state / retention.RECEIPT), original)
        with patch.object(
            retention.time, "time", return_value=self.fx.values["proposal_expires_at"]
        ):
            retained, values = retention.load(self.root, self.state, pin, self.revision)
            self.assertEqual(values["proposal_reference"], self.fx.values["proposal_reference"])
            self.assertEqual(retained["captured_at"], self.clock - 1)
            with self.assertRaises(Rejected):
                retention.preflight(self.root, self.state, pin, self.revision, "M13")

    def test_capture_cannot_overwrite_existing_retention_or_launder_expired_capture(self):
        pin = self.capture()
        receipt, _ = retention.load(self.root, self.state, pin, self.revision)
        for field, changed in (
            ("source_sql", "0" * 64),
            ("freeze_sha256", "0" * 64),
            ("captured_at", self.fx.values["proposal_expires_at"]),
            ("captured_at", self.fx.values["captured_at"] - 1),
        ):
            altered = dict(receipt, **{field: changed})
            changed_pin = self.fx.pinfile(retention.RECEIPT, altered)
            with self.subTest(field=field), self.assertRaises(Rejected):
                retention.load(self.root, self.state, changed_pin, self.revision)
        write_json(self.state / retention.RECEIPT, dict(receipt, source_sql="0" * 64))
        with self.assertRaises(Rejected):
            self.capture()

    def test_each_native_phase_requires_full_remaining_permit_window(self):
        pin = self.capture()
        expiry = self.fx.values["proposal_expires_at"]
        for phase in retention.PHASES:
            result = retention.preflight(
                self.root, self.state, pin, self.revision, phase, clock=expiry - 600
            )
            self.assertEqual(result["remaining_seconds"], 600)
            with self.subTest(phase=phase), self.assertRaises(Rejected):
                retention.preflight(
                    self.root, self.state, pin, self.revision, phase, clock=expiry - 599
                )
        with self.assertRaises(Rejected):
            retention.preflight(self.root, self.state, pin, self.revision, "M22", clock=self.clock)

    def parent(self):
        values = self.fx.values
        candidate = {k: values[k] for k in retention.CANDIDATE}
        parent = dict(
            candidate=candidate,
            release_ready=False,
            proposal_packet=self.fx.freeze[retention.delivery.PROPOSAL],
            reports={g: digest(g.encode()) for g in retention.PARENT_GATES},
            security_transition=digest(b"transition"),
            source_offline="f" * 64,
            security_capture={s: digest(s.encode()) for s in ("sources", "inventory", "outage")},
        )
        summary = dict(
            **{k: values[k] for k in (*retention.delivery.SOURCE, *retention.delivery.IDENTITY)},
            release_ready=False,
            reports={
                g: parent["reports"].get(g, digest(g.encode())) for g in retention.campaign.GATES
            },
        )
        return parent, summary

    def test_join_refuses_missing_gates_changed_proposal_candidate_and_report_overlap(self):
        parent, summary = self.parent()
        result = retention.join(parent, summary, self.fx.values, self.fx.freeze)
        self.assertEqual(
            set(result["reports"]), set(retention.PARENT_GATES) | {"M13", "M14", "M15"}
        )
        self.assertFalse(result["release_ready"])
        mutations = []
        for key in retention.CANDIDATE:
            bad = copy.deepcopy(parent)
            bad["candidate"][key] = "other"
            mutations.append(bad)
        for gate in ("M04", "M05", "M11", "M12", "M21", "M23"):
            bad = copy.deepcopy(parent)
            del bad["reports"][gate]
            mutations.append(bad)
        mutations += [dict(parent, proposal_packet="0" * 64), dict(parent, release_ready=True)]
        for bad in mutations:
            with self.subTest(parent=bad.keys()), self.assertRaises(Rejected):
                retention.join(bad, summary, self.fx.values, self.fx.freeze)
        for gate in ("M02", "M03", "M07"):
            bad = dict(summary, reports=dict(summary["reports"], **{gate: "0" * 64}))
            with self.subTest(gate=gate), self.assertRaises(Rejected):
                retention.join(parent, bad, self.fx.values, self.fx.freeze)

    def replay_fixture(self):
        pin = self.capture()
        parent, summary = self.parent()
        for gate in retention.PARENT_GATES:
            inputs = dict(
                self.fx.values, proposal_packet=self.fx.freeze[retention.delivery.PROPOSAL]
            )
            report = dict(
                gate=gate,
                status="pass",
                exit_code=0,
                source_dirty=False,
                source_revision=self.revision,
                input_digests=inputs,
                cases=[dict(id="negative", status="pass", expected="reject", actual="reject")],
            )
            parent["reports"][gate] = self.fx.pinfile("evidence/" + gate + ".json", report)
        summary["reports"].update({g: parent["reports"][g] for g in ("M02", "M03", "M07")})
        admissions = {}
        for gate in ("M14", "M15"):
            admissions[gate] = self.fx.pinfile(
                f"evidence/{gate}-frozen-private.json", dict(index=self.fx.index)
            )
        nodes = [
            dict(namespace=digest(bytes([i])), volume=digest(bytes([10 + i]))) for i in range(4)
        ]
        security = dict(
            inputs=dict(files=self.fx.freeze | {"storage.json": self.source_pin}),
            transition=dict(
                source_sql=self.source_pin,
                after=nodes[0],
                before=dict(namespace=digest(b"security-ns"), volume=digest(b"security-vol")),
            ),
        )
        parent["security_transition"] = self.fx.pinfile(
            "evidence/M23-delivery-transition.json", security
        )
        args = dict(
            retention_pin=pin,
            parent_pin=self.fx.pinfile("evidence/delivery-candidate.json", parent),
            reports=summary["reports"],
            admissions=admissions,
            revision=self.revision,
            transitions=[
                dict(before=nodes[i], after=nodes[i + 1], source_sql=self.source_pin)
                for i in range(3)
            ],
        )
        replay = self.enterContext(
            patch.object(retention.campaign, "replay", return_value=(summary, []))
        )
        return args, parent, replay

    def test_offline_join_rechecks_original_bytes_and_never_contacts_live_sql(self):
        args, parent, native = self.replay_fixture()
        self.validate.reset_mock()
        self.inspect.reset_mock()
        with patch.object(
            retention.time, "time", return_value=self.fx.values["proposal_expires_at"] + 1
        ):
            result = retention.replay(self.root, self.state, **args)
        self.assertEqual(len(result["reports"]), 21)
        self.assertEqual(set(result["reports"]), set(retention.final_evidence.CHILDREN) - {"M22"})
        self.assertEqual(result["reports"]["M04"], parent["reports"]["M04"])
        self.validate.assert_not_called()
        self.inspect.assert_not_called()
        native.assert_called_once()
        (self.state / "evidence/M04.json").write_bytes(b"substituted")
        with self.assertRaises(Rejected):
            retention.replay(self.root, self.state, **args)

    def test_replay_rejects_reused_cluster_volume_broken_transition_and_wrong_policy(self):
        args, _, native = self.replay_fixture()
        mutations = []
        mutations.append(dict(args, transitions=args["transitions"][:2]))
        for key in ("namespace", "volume"):
            bad = copy.deepcopy(args)
            bad["transitions"][2]["after"][key] = bad["transitions"][0]["before"][key]
            mutations.append(bad)
        bad = copy.deepcopy(args)
        bad["transitions"][2]["source_sql"] = "0" * 64
        mutations.append(bad)
        bad = copy.deepcopy(args)
        bad["transitions"][2]["before"] = bad["transitions"][0]["before"]
        mutations.append(bad)
        for changed in mutations:
            with self.subTest(transitions=changed["transitions"]), self.assertRaises(Rejected):
                retention.replay(self.root, self.state, **changed)
        for index in (
            dict(self.fx.index, policy_reference="0" * 64),
            dict(self.fx.index, freeze={}),
        ):
            bad = copy.deepcopy(args)
            bad["admissions"]["M15"] = self.fx.pinfile(
                "evidence/M15-frozen-private.json", dict(index=index)
            )
            with self.assertRaises(Rejected):
                retention.replay(self.root, self.state, **bad)
        native.assert_not_called()

    def test_join_rejects_resealed_m05_on_another_proposal(self):
        args, parent, _ = self.replay_fixture()
        path = self.state / "evidence/M05.json"
        report = retention.decode(bounded_read(path))
        report["input_digests"]["proposal_packet"] = "0" * 64
        parent["reports"]["M05"] = self.fx.pinfile("evidence/M05.json", report)
        args["parent_pin"] = self.fx.pinfile("evidence/delivery-candidate.json", parent)
        with self.assertRaises(Rejected):
            retention.replay(self.root, self.state, **args)

    def test_trio_replay_requires_ordered_windows_and_distinct_phase_permits(self):
        campaign = retention.campaign
        public, pins = {}, {}
        for number, gate in enumerate(campaign.GATES):
            public[gate] = dict(
                gate=gate,
                status="pass",
                exit_code=0,
                source_dirty=False,
                source_revision=self.revision,
                input_digests=dict(
                    self.fx.values, qualification_permit_sha256=digest(gate.encode())
                ),
                cases=[dict(id="negative", status="pass", expected="reject", actual="reject")],
                started_at=datetime.fromtimestamp(self.clock + number * 10, UTC).isoformat(),
                finished_at=datetime.fromtimestamp(self.clock + number * 10 + 1, UTC).isoformat(),
            )
            pins[gate] = self.fx.pinfile("evidence/" + gate + ".json", public[gate])
        admission = self.fx.pinfile("evidence/M14-frozen-private.json", dict(index=self.fx.index))
        nodes = [
            dict(namespace=digest(bytes([i])), volume=digest(bytes([10 + i]))) for i in range(3)
        ]
        args = dict(
            pins=self.fx.freeze,
            reports=pins,
            admissions={g: admission for g in ("M13", "M14", "M15")},
            transitions=[
                dict(before=nodes[i], after=nodes[i + 1], source_sql=self.source_pin)
                for i in range(2)
            ],
            source_pin=self.source_pin,
            revision=self.revision,
        )
        with (
            patch.object(
                campaign.delivery,
                "replay",
                side_effect=lambda root, state, gate, **kwargs: dict(report=public[gate]),
            ),
            patch.object(campaign, "privacy", return_value=digest(b"M13")) as privacy,
        ):
            summary, proofs = campaign.replay(self.root, self.state, **args)
            self.assertEqual(summary["reports"], pins)
            self.assertEqual(len(proofs), 6)
            privacy.return_value = public["M14"]["input_digests"]["qualification_permit_sha256"]
            with self.assertRaises(Rejected):
                campaign.replay(self.root, self.state, **args)
            privacy.return_value = digest(b"M13")
            public["M15"]["started_at"] = public["M13"]["started_at"]
            pins["M15"] = self.fx.pinfile("evidence/M15.json", public["M15"])
            with self.assertRaises(Rejected):
                campaign.replay(self.root, self.state, **args)

    def cli(self):
        from mlsecops import security_gate
        from scripts import kube_trust_native, shared_serving_receipt

        self.enterContext(
            patch.object(retention, "__file__", str(self.root / "scripts/serving_retention.py"))
        )
        hosted = self.enterContext(patch.object(kube_trust_native, "hosted"))
        cleanup = self.enterContext(patch.object(security_gate, "confirm_cleanup"))
        offline = self.enterContext(
            patch.object(shared_serving_receipt, "offline_pin", return_value="f" * 64)
        )
        env = dict(
            GITHUB_SHA=self.revision,
            GITHUB_OUTPUT=str(self.root / "outputs"),
            M18_FREEZE_SHA256=self.freeze,
            SOURCE_SQL=self.source_pin,
            SOURCE_OFFLINE_SHA256="f" * 64,
            **{label: self.fx.freeze[p] for p, label in retention.delivery.FILES.items()},
        )
        self.enterContext(patch.dict(os.environ, env))
        self.enterContext(redirect_stdout(io.StringIO()))
        return hosted, cleanup, offline

    def test_cli_masks_retention_pins_and_requires_hosted_context(self):
        hosted, _, _ = self.cli()
        retention.main(["retain"])
        pin = (self.root / "outputs").read_text().strip().split("=", 1)[1]
        with patch.dict(os.environ, SERVING_RETENTION=pin):
            retention.main(["check", "M13"])
        with self.assertRaises(Rejected):
            retention.main(["unknown"])
        hosted.side_effect = Rejected("hosted_only")
        with self.assertRaises(Rejected):
            retention.main(["retain"])

    def test_module_entrypoint_refuses_local_execution_before_any_native_call(self):
        from scripts import kube_trust_native

        with patch.object(kube_trust_native, "hosted", side_effect=Rejected("hosted_only")):
            with self.assertRaisesRegex(Rejected, "hosted_only"):
                runpy.run_path(retention.__file__, run_name="__main__")
        self.validate.assert_not_called()
        self.inspect.assert_not_called()

    def test_cli_requires_cleanup_and_unchanged_stop_witness_before_publishing(self):
        args, _, _ = self.replay_fixture()
        # M13 admission is consumed by the independently tested trio verifier.
        args["admissions"]["M13"] = "e" * 64
        _, cleanup, offline = self.cli()
        env = dict(
            SERVING_RETENTION=args["retention_pin"],
            PARENT_RECEIPT=args["parent_pin"],
            **{g + "_REPORT": p for g, p in args["reports"].items()},
            **{g + "_ADMISSION": p for g, p in args["admissions"].items()},
            **{
                k: retention.canonical(v).decode()
                for k, v in zip(
                    ("PRIVACY_TO_LOAD", "LOAD_TO_MONITORING", "MONITORING_TO_JOINT"),
                    args["transitions"],
                    strict=True,
                )
            },
        )
        self.enterContext(patch.dict(os.environ, env))
        original = bounded_read(self.state / "evidence/delivery-candidate.json")
        for witnesses in (["0" * 64], ["f" * 64, "0" * 64]):
            offline.side_effect = witnesses
            with self.assertRaises(Rejected):
                retention.main(["replay"])
            self.assertEqual(
                bounded_read(self.state / "evidence/delivery-candidate.json"), original
            )
            self.assertFalse((self.root / "outputs").exists())
        offline.side_effect = None
        cleanup.side_effect = Rejected("cleanup_missing")
        with self.assertRaises(Rejected):
            retention.main(["replay"])
        cleanup.side_effect = None
        retention.main(["replay"])
        self.assertIn("receipt=", (self.root / "outputs").read_text())
        self.assertEqual(
            len(
                retention.decode(bounded_read(self.state / "evidence/delivery-candidate.json"))[
                    "reports"
                ]
            ),
            21,
        )

    def test_security_transition_and_offline_witness_cannot_be_dropped_or_substituted(self):
        args, parent, _ = self.replay_fixture()
        original = retention.decode(
            bounded_read(self.state / "evidence/M23-delivery-transition.json")
        )
        for key in ("before", "after", "source_sql"):
            changed = copy.deepcopy(original)
            changed["transition"][key] = (
                args["transitions"][-1]["after"] if key != "source_sql" else "0" * 64
            )
            parent["security_transition"] = self.fx.pinfile(
                "evidence/M23-delivery-transition.json", changed
            )
            args["parent_pin"] = self.fx.pinfile("evidence/delivery-candidate.json", parent)
            with self.subTest(key=key), self.assertRaises(Rejected):
                retention.replay(self.root, self.state, **args)
        changed = copy.deepcopy(original)
        changed["inputs"]["files"]["storage.json"] = "0" * 64
        parent["security_transition"] = self.fx.pinfile(
            "evidence/M23-delivery-transition.json", changed
        )
        args["parent_pin"] = self.fx.pinfile("evidence/delivery-candidate.json", parent)
        with self.assertRaises(Rejected):
            retention.replay(self.root, self.state, **args)


if __name__ == "__main__":
    unittest.main()
