"""Owner pins, signed package replay and isolation of two frozen performance gates."""

import os
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from mlsecops import performance_delivery as delivery
from mlsecops import signing
from mlsecops.candidate_serving_reader import KIND
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from scripts import (
    candidate_lineage_qualification,
    final_evidence_qualification,
    monitoring_qualification,
)


class DeliveryContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        final_evidence_qualification.FinalEvidenceContracts.setUpClass()
        cls.addClassCleanup(final_evidence_qualification.FinalEvidenceContracts.tearDownClass)

    def setUp(self):
        fx = final_evidence_qualification.FinalEvidenceContracts()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        self.rows = [
            {"entity_id": 1000 + i, "features": [0.5] * 6, "label": i % 2} for i in range(1000)
        ]
        cls = candidate_lineage_qualification.CandidateLineageContracts
        with (
            patch.object(cls, "split_contents", {"validation": canonical(self.rows)}, create=True),
            patch.object(
                cls, "policy", {**cls.policy, "rows": 1464, "split_counts": [64, 1000, 400]}
            ),
        ):
            fx.build()
        self.fx = fx
        self.state, self.root = fx.state, fx.root
        self.pins = fx.freeze.copy()
        self.campaign = "a" * 32
        self.proposal_campaign = fx.verified["manifest"]["release_id"]
        fx.proposal["campaign_id"] = self.proposal_campaign
        self.pins[delivery.PROPOSAL] = fx.pinfile(delivery.PROPOSAL, fx.proposal)
        write_json(
            self.state / "release-proposals" / self.proposal_campaign / "policy-envelope.json",
            fx.release.policy_envelope,
        )
        self.verified = self.enterContext(
            patch.object(
                delivery,
                "verified_materials",
                return_value=(
                    fx.release.bundle.materials.context,
                    fx.verified,
                    fx.package,
                    fx.keys["approver"],
                ),
            )
        )

    def test_mixed_owner_pins_and_signature_or_model_mutations(self):
        self.assertIsNone(delivery.owner("M14", None))
        with patch.dict(os.environ, {"M15_PROPOSAL_SHA256": "1" * 64}):
            with self.assertRaises(Rejected):
                delivery.owner("M15", None)
        for path in self.pins:
            with self.subTest(path=path), self.assertRaises(Rejected):
                delivery.capture(
                    self.root, self.state, self.fx.source, {**self.pins, path: "9" * 64}
                )
        index = delivery.capture(self.root, self.state, self.fx.source, self.pins)
        self.assertEqual(index["freeze"], self.pins)
        self.assertEqual(index["policy_reference"], self.fx.index["policy_reference"])
        demo = read_json(self.state / "storage-demo.json")
        demo["evaluation"]["report"]["auprc"] = 0
        self.pins["storage-demo.json"] = self.fx.pinfile("storage-demo.json", demo)
        with self.assertRaises(Rejected):
            delivery.capture(self.root, self.state, self.fx.source, self.pins)

    def runtime(self, gate):
        fx = self.fx
        index = delivery.start(self.root, self.state, fx.source, self.pins)
        values = fx.values
        key = self.state / "permit.pem"
        pub = signing.create_key(key)
        reference_key = self.state / "ref.pem"
        ref_public = signing.create_key(reference_key)
        issued = values["captured_at"]

        def window(seconds):
            return datetime.fromtimestamp(issued + seconds, UTC).isoformat()

        permit = dict(
            schema_version=1,
            purpose=KIND,
            campaign_id=self.campaign,
            environment="local-cpu",
            proposal_sha256=values["proposal_reference"],
            subject_sha256=values["release_subject"],
            model_sha256=values["model"],
            **fx.source,
            issued_at=issued,
            expires_at=issued + 120,
        )
        self.config = dict(
            context=fx.release.bundle.materials.context,
            publisher_public=fx.keys["approver"],
            expected_campaign=self.campaign,
            expected_permit=digest(canonical(permit)),
            permit_public=pub,
            permit_envelope=signing.sign(permit, KIND, key),
            proposal_reference=values["proposal_reference"],
        )
        reference = {
            **monitoring_qualification.reference(),
            "model_sha256": values["model"],
            "bundle_sha256": values["release_subject"],
            "evaluation_sha256": values["evaluation_reference"],
            "dataset_sha256": values["dataset_reference"],
            "source_fingerprint": values["source_fingerprint"],
        }
        request = dict(
            model=values["model"],
            bundle=values["release_subject"],
            monitoring=dict(
                reference=signing.sign(reference, "monitor-reference", reference_key),
                reference_public=ref_public,
                rows=self.rows,
            ),
        )
        value = {k: values[k] for k in delivery.IDENTITY}
        value.update(
            source=fx.source,
            started_at=window(0),
            finished_at=window(45),
            proposal_issued_at=values["proposal_issued_at"],
            qualification_campaign_id=self.campaign,
            qualification_permit_sha256=self.config["expected_permit"],
            actual_refusal=dict(
                campaign_id=self.proposal_campaign,
                candidate=values["candidate_reference"],
                model=values["model"],
                proposal=values["proposal_reference"],
                parent_refusal="release_assurance_required",
                job_outcome="rejected",
            ),
            artifact_hashes={},
            **{delivery.MODES[gate] + "_campaign_id": self.campaign},
        )
        for name, item in (("config.json", self.config), ("request.json", request)):
            value["artifact_hashes"][name] = fx.pinfile(
                "candidate-inference/" + self.campaign + "/" + name, item
            )
        return index, value

    def test_historical_verifier_checks_signed_identity_permit_window_and_owner_bytes(self):
        root, state = self.root, self.state
        index, value = self.runtime("M14")

        def signed(observation):
            return delivery.signed_inputs(root, state, "M14", index, observation)

        self.assertEqual(
            signed(value)["evaluation_reference"], self.fx.values["evaluation_reference"]
        )
        for name in (
            *delivery.IDENTITY,
            "qualification_campaign_id",
            "qualification_permit_sha256",
            "proposal_issued_at",
            "source",
        ):
            with self.subTest(name=name), self.assertRaises(Rejected):
                signed({**value, name: "0" * 64})
        with self.assertRaises(Rejected):
            signed({**value, "finished_at": "2100-02-01T00:00:00+00:00"})
        for field, bad in (
            ("job_outcome", "admitted"),
            ("candidate", "0" * 64),
            ("model", "0" * 64),
        ):
            with self.assertRaises(Rejected):
                signed({**value, "actual_refusal": {**value["actual_refusal"], field: bad}})
        permit = signing.verify(self.config["permit_envelope"], KIND, self.config["permit_public"])
        permit["subject_sha256"] = "0" * 64
        self.config.update(
            permit_envelope=signing.sign(permit, KIND, state / "permit.pem"),
            expected_permit=digest(canonical(permit)),
        )
        value["qualification_permit_sha256"] = self.config["expected_permit"]
        value["artifact_hashes"]["config.json"] = self.fx.pinfile(
            "candidate-inference/" + self.campaign + "/config.json", self.config
        )
        with self.assertRaises(Rejected):
            signed(value)
        with self.assertRaises(Rejected):
            delivery.pinned(state / delivery.PROPOSAL, "0" * 64)
        (state / "kubernetes-security").mkdir()
        with self.assertRaises(Rejected):
            delivery.start(root, state, self.fx.source, self.pins)

    def test_offline_replay_uses_both_owner_outputs_and_recomputes_each_primary(self):
        from mlsecops import load_gate, monitoring_gate

        for gate in ("M14", "M15"):
            with self.subTest(gate=gate):
                index, value = self.runtime(gate)
                native = {
                    k: {"checked": True}
                    for k in ("measurement", "overload", "operator", "monitoring")
                }
                mode = delivery.MODES[gate]
                metrics = native if gate == "M14" else {"observations": 12000}
                component = dict(
                    status="pass",
                    release_ready=False,
                    metrics=metrics,
                    cases=[],
                    checks=0,
                    source_revision=self.fx.source["source_revision"],
                    input_digests={
                        **self.fx.source,
                        **{
                            k: value[k] for k in (*delivery.IDENTITY, "qualification_permit_sha256")
                        },
                    },
                    artifact_hashes={},
                )
                private = self.fx.pinfile(f"evidence/kubernetes-{mode}-private.json", value)
                packets = {"test": "b" * 64}
                delivery.seal(
                    self.root, self.state, gate, index, value, private, packets, component
                )
                self.fx.pinfile(f"evidence/{mode}-gate.json", component)
                wrapper = {
                    **component,
                    "gate": gate,
                    "source_dirty": False,
                    "exit_code": 0,
                    "started_at": value["started_at"],
                    "finished_at": value["finished_at"],
                    "metrics": {"checks": 0, **metrics},
                }
                report_path = f"evidence/{gate}.json"
                report_pin = self.fx.pinfile(report_path, wrapper)
                adm_path = f"evidence/{gate}-frozen-private.json"
                admission = read_json(self.state / adm_path)
                admission_pin = digest((self.state / adm_path).read_bytes())

                def replay(report=report_pin, adm=admission_pin):
                    return delivery.replay(
                        self.root,
                        self.state,
                        gate,
                        pins=self.pins,
                        report_pin=report,
                        admission_pin=adm,
                    )

                with (
                    patch.object(load_gate, "reconcile", return_value=native),
                    patch.object(load_gate, "retained", return_value=packets) as load,
                    patch.object(monitoring_gate, "reconcile"),
                    patch.object(monitoring_gate, "artifacts"),
                    patch.object(
                        monitoring_gate, "retained", return_value=(metrics, packets, {})
                    ) as monitor,
                ):
                    self.assertEqual(replay()["report_sha256"], report_pin)
                    (load if gate == "M14" else monitor).assert_called_once()
                    (monitor if gate == "M14" else load).assert_not_called()
                    for item in (
                        "metrics",
                        "input_digests",
                        "cases",
                        "artifact_hashes",
                        "gate",
                        "status",
                    ):
                        change = self.fx.pinfile(report_path, {**wrapper, item: "invalid"})
                        with self.assertRaises(Rejected):
                            replay(change)
                        self.fx.pinfile(report_path, wrapper)
                    for item in (
                        "private_observation",
                        "retained_packets",
                        "component_sha256",
                        "gate",
                    ):
                        forged = self.fx.pinfile(adm_path, {**admission, item: "0" * 64})
                        for supplied in (forged, admission_pin):
                            with self.assertRaises(Rejected):
                                replay(adm=supplied)
                        self.fx.pinfile(adm_path, admission)
                for p in ("permit.pem", "ref.pem"):
                    (self.state / p).unlink()

    def test_native_propagates_owner_proposal_to_existing_prepare(self):
        from scripts import kube_load_native, kube_monitoring_native

        self.assertIsNone(delivery.start(self.root, self.state, self.fx.source, None))
        self.assertIsNone(delivery.seal(self.root, self.state, "M14", None, {}, None, None, {}))
        self.assertTrue(delivery.diagnostic(lambda: True)())

        def refused():
            raise Rejected("only private to caller")

        with (
            self.assertRaisesRegex(Rejected, "only private to caller"),
            patch("builtins.print") as output,
        ):
            delivery.diagnostic(refused)()
        self.assertNotIn("only private to caller", str(output.call_args))
        self.assertEqual(delivery.prepare_args(None), {})
        self.assertEqual(
            delivery.prepare_args({"freeze": self.pins}),
            {"proposal_pin": self.pins[delivery.PROPOSAL]},
        )
        for module in (kube_load_native, kube_monitoring_native):
            with (
                patch.object(module, "hosted"),
                patch.object(module.promotion_state, "install"),
                patch.object(module, "prepare", side_effect=Rejected("stop")) as prepare,
                self.assertRaises(Rejected),
            ):
                module.run(self.root, self.state, proposal_pin=self.pins[delivery.PROPOSAL])
            prepare.assert_called_once_with(
                self.root,
                self.state,
                "trusted-mlsecops:dev",
                proposal_pin=self.pins[delivery.PROPOSAL],
            )
