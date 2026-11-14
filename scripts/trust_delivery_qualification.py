"""Frozen M11 bindings with genuine signed proposal and evaluation fixtures."""

import copy
import os
import tempfile
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from mlsecops import signing, trust_acceptance, trust_delivery, trust_gate
from mlsecops.candidate_serving_reader import KIND
from mlsecops.contracts import Rejected, canonical, digest, read_json, write_json
from scripts import release_bundle_qualification, trust_gate_fixtures, trust_gate_qualification


class FrozenContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        release_bundle_qualification.ReleaseBundleContracts.setUpClass()
        cls.addClassCleanup(release_bundle_qualification.ReleaseBundleContracts.tearDownClass)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.fx = release_bundle_qualification.ReleaseBundleContracts()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.package = self.fx.create()
        self.verified = self.fx.check(self.package)
        self.context = self.fx.materials.context
        self.source = self.context["expected"]
        self.demo = {
            "candidate": {
                "candidate_reference": self.context["candidate_reference"],
                "metadata": self.fx.materials.fixture.metadata,
            },
            "evaluation_reference": self.context["evaluation_reference"],
            "evaluation": self.fx.materials.fixture.bound,
        }
        self.report = dict(
            schema_version=1,
            status="pass",
            release_ready=False,
            source_dirty=False,
            scope="release-proposal-and-authorization-denial-not-full-M10",
            source=self.source,
            campaign_id=self.verified["manifest"]["release_id"],
            proposal_reference=digest(canonical(self.package["envelope"])),
            subject_sha256=self.verified["subject_sha256"],
            model_sha256=digest(self.verified["model"]),
        )
        for name, value in (
            ("storage-demo.json", self.demo),
            ("evidence/release-native.json", self.report),
            ("trusted-keys.json", {"approver": self.fx.materials.public}),
            ("storage-trust.json", self.context["trust"]),
        ):
            write_json(self.state / name, value)
        self.proposal_pin = digest((self.state / "evidence/release-native.json").read_bytes())
        self.demo_pin = digest((self.state / "storage-demo.json").read_bytes())

    def freeze(self):
        with patch.object(
            trust_delivery,
            "verified_materials",
            return_value=(self.context, self.verified, self.package, self.fx.materials.public),
        ):
            return trust_delivery.freeze(
                Path.cwd(), self.state, self.source, self.proposal_pin, self.demo_pin
            )

    def test_frozen_proposal_requires_same_signed_evaluation_even_with_rehashed_demo(self):
        record = self.freeze()
        self.assertEqual(record["evaluation_reference"], self.context["evaluation_reference"])
        self.assertEqual(record["subject_sha256"], self.report["subject_sha256"])
        self.demo["evaluation"]["report"]["auprc"] = 0.123
        write_json(self.state / "storage-demo.json", self.demo)
        self.demo_pin = digest((self.state / "storage-demo.json").read_bytes())
        with self.assertRaises(Rejected):
            self.freeze()

    def test_changed_owner_pin_and_substituted_candidate_are_rejected(self):
        with patch.object(self, "proposal_pin", "0" * 64), self.assertRaises(Rejected):
            self.freeze()
        self.demo["candidate"]["candidate_reference"] = "b" * 64
        write_json(self.state / "storage-demo.json", self.demo)
        self.demo_pin = digest((self.state / "storage-demo.json").read_bytes())
        with self.assertRaises(Rejected):
            self.freeze()

    def runtime(self):
        binding = self.freeze()
        native, _ = trust_gate_fixtures.fixture()
        actual = native["actual_inference"]
        actual.update(
            {
                k: binding[k]
                for k in (
                    "candidate_reference",
                    "evaluation_reference",
                    "proposal_reference",
                    "subject_sha256",
                    "model_sha256",
                )
            }
        )
        actual.update(
            source=binding["source"],
            qualification_campaign_id="a" * 32,
            started_at="1970-01-01T00:33:20+00:00",
            finished_at="1970-01-01T00:34:20+00:00",
        )
        observation = dict(
            existing_process=True,
            release_ready=False,
            pod_uid="pod",
            cases=[
                "existing-HTTP-process-live",
                "unapproved-or-revoked-ready-503",
                "unapproved-or-revoked-predict-503",
                "no-inference-worker",
            ],
        )
        native["actual"].update(
            candidate=binding["candidate_reference"],
            proposal=binding["proposal_reference"],
            model=binding["model_sha256"],
            serving_before_admission=dict(
                release_ready=False,
                pod_uid="pod",
                heartbeat_before=0,
                heartbeat_after=1,
                elapsed_seconds=1.0,
                observation=observation,
            ),
        )
        actual["actual_refusal"] = copy.deepcopy(native["actual"])
        key = self.state / "qualification.pem"
        public = signing.create_key(key)
        permit = dict(
            schema_version=1,
            purpose=KIND,
            campaign_id="a" * 32,
            environment=binding["context"]["policy"]["environment"],
            proposal_sha256=binding["proposal_reference"],
            subject_sha256=binding["subject_sha256"],
            model_sha256=binding["model_sha256"],
            **binding["source"],
            issued_at=2000,
            expires_at=2600,
        )
        envelope = signing.sign(permit, KIND, key)
        pin = digest(canonical(permit))
        config = dict(
            context=binding["context"],
            publisher_public=binding["publisher_public"],
            proposal_reference=binding["proposal_reference"],
            permit_envelope=envelope,
            permit_public=public,
            expected_permit=pin,
        )
        actual["qualification_permit_sha256"] = pin
        actual["native"]["cases"] = [
            dict(id=k, expected=v, actual=v, status="pass")
            for k, v in {
                "qualification-permit-payload": pin,
                "qualification-permit-envelope": digest(canonical(envelope)),
            }.items()
        ]
        return binding, native, config

    def retain(self, native, config):
        actual = native["actual_inference"]
        directory = self.state / "candidate-inference" / actual["qualification_campaign_id"]
        for name, value in (("config.json", config), ("probe.json", actual["native"])):
            write_json(directory / name, value)
        actual["artifact_hashes"] = {
            name: digest((directory / name).read_bytes()) for name in ("config.json", "probe.json")
        }

    def test_signed_permit_joins_same_evaluation_and_distinguishes_controlled_subjects(self):
        binding, native, config = self.runtime()
        self.retain(native, config)
        result = trust_delivery.retained(self.state, native, binding)
        self.assertEqual(result["actual_release_authorization"], "inconclusive")
        self.assertEqual(result["actual_production_refusal"], "release_assurance_required")
        self.assertNotIn(binding["subject_sha256"], result["controlled_subjects"])
        self.assertIs(result["release_ready"], False)
        for field in (
            "candidate_reference",
            "evaluation_reference",
            "proposal_reference",
            "subject_sha256",
            "model_sha256",
        ):
            damaged = copy.deepcopy(native)
            damaged["actual_inference"][field] = "1" * 64
            with self.subTest(field=field), self.assertRaises(Rejected):
                trust_gate.delivery(damaged, binding, config)

        for field in ("subject_sha256", "proposal_reference"):
            damaged = copy.deepcopy(native)
            damaged["authorized_rollback"]["target_receipt"][field] = binding[field]
            with self.subTest(controlled=field), self.assertRaises(Rejected):
                trust_gate.delivery(damaged, binding, config)

    def test_joint_retention_checks_original_bytes_window_and_separate_authority_histories(self):
        from scripts import kube_authority_pair_qualification as pair
        from scripts import shared_serving_native as shared

        binding, native, config = self.runtime()
        actual = native["actual_inference"]
        directory = shared.directory(self.state, actual)
        base = pair.states()
        model, key = binding["model_sha256"], digest(signing.decode64(binding["publisher_public"]))
        with patch.multiple(pair, MODEL=model, KEY=key):
            after_model = pair.revoked(base, pair.Target.MODEL_REVOCATION)
            after_key = pair.revoked(after_model, pair.Target.PRIMARY)
        actual["independent_authorities"]["states"] = dict(
            before=base, after_model=after_model, after_key=after_key
        )
        actual["native"].update(pair.isolation(pair.Target.PRIMARY, base))
        actual["model_revocation"].update(pair.isolation(pair.Target.MODEL_REVOCATION, base))
        snapshot = {"objects": [], "promotion": []}
        sha = digest(canonical(snapshot))
        for r in actual["trust_lifecycle"].values():
            r["snapshot_sha256"] = sha
        actual.update(
            key_revocation_snapshot_sha256=sha,
            model_revocation_snapshot_sha256=sha,
            base_snapshot_sha256=sha,
            revoked_key_sha256=key,
        )
        actual["root_rotation"].update(next_public=pair.PUBLIC, model_snapshot_sha256=sha)
        config.update(
            trust_root=pair.PUBLIC,
            expected_campaign=actual["qualification_campaign_id"],
            kubernetes_worker={},
        )
        # Sign against the genuine fixture proposal's original clock.
        issued = binding["proposal_issued_at"]
        permit = signing.verify(config["permit_envelope"], KIND, config["permit_public"])
        config["permit_envelope"] = signing.sign(
            {**permit, "issued_at": issued + 10, "expires_at": issued + 610},
            KIND,
            self.state / "qualification.pem",
        )
        config["expected_permit"] = actual["qualification_permit_sha256"] = digest(
            canonical(signing.verify(config["permit_envelope"], KIND, config["permit_public"]))
        )
        actual.update(
            proposal_issued_at=issued,
            started_at=datetime.fromtimestamp(issued + 1, UTC).isoformat(),
            finished_at=datetime.fromtimestamp(issued + 300, UTC).isoformat(),
            trust_lifecycle_ownership_return=dict(
                transfer=dict(before="one", after="two", release_ready=False),
                observation=None,
                heartbeat_before=1,
                heartbeat_after=2,
                identity_events_delivered=0,
                return_seconds=0.1,
                outbox_retained=True,
                release_ready=False,
            ),
        )
        files = {
            "config.json": config,
            "request.json": dict(
                model=model,
                bundle=binding["subject_sha256"],
                clock_cache=True,
                independent_authorities=True,
            ),
            "reference.json": {"receipt": {"model_digest": model}},
            "probe.json": actual["native"],
            "root-rotation.json": actual["root_rotation"],
            "independent-authorities.json": actual["independent_authorities"],
            "key-revocation.json": actual["key_revocation"],
            "model-revocation.json": actual["model_revocation"],
            **{k + ".json": v["probe"] for k, v in actual["trust_lifecycle"].items()},
        }
        for name, value in files.items():
            write_json(directory / name, value)
        actual["artifact_hashes"] = {
            name: digest((directory / name).read_bytes()) for name in files
        }
        packet = dict(
            binding=binding,
            actual=actual,
            prepared=dict(actual=native["actual"], profile={}),
            owner=dict(source=binding["source"]),
            sql_snapshot=snapshot,
        )
        self.assertEqual(shared.retained(self.state, packet), config)
        for filename in files:
            raw = (directory / filename).read_bytes()
            (directory / filename).write_bytes(raw + b" ")
            with self.subTest(filename=filename), self.assertRaises(Rejected):
                shared.retained(self.state, packet)
            (directory / filename).write_bytes(raw)
        for change in (
            dict(finished_at=datetime.fromtimestamp(issued + 610, UTC).isoformat()),
            dict(model_sha256="0" * 64),
            dict(base_snapshot_sha256="0" * 64),
        ):
            with self.subTest(change=change), self.assertRaises(Rejected):
                shared.retained(self.state, {**packet, "actual": {**actual, **change}})
        after_model["primary"]["version"] += 1
        write_json(directory / "independent-authorities.json", actual["independent_authorities"])
        actual["artifact_hashes"]["independent-authorities.json"] = digest(
            (directory / "independent-authorities.json").read_bytes()
        )
        with self.assertRaisesRegex(Rejected, "candidate_authority_revoke_transition"):
            shared.retained(self.state, packet)

    def test_retention_and_current_owner_inputs_reject_substitution_after_native_run(self):
        binding, native, config = self.runtime()
        self.retain(native, config)
        for field, value in (("qualification_campaign_id", "../escape"), ("native", {})):
            damaged = copy.deepcopy(native)
            damaged["actual_inference"][field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                trust_delivery.retained(self.state, damaged, binding)
        config["context"] = {**config["context"], "evaluation_reference": "f" * 64}
        self.retain(native, config)
        with self.assertRaises(Rejected):
            trust_delivery.retained(self.state, native, binding)
        write_json(self.state / "storage-demo.json", {})
        with self.assertRaises(Rejected):
            trust_delivery.retained(self.state, native, binding)

    def test_signed_different_permit_and_false_refusal_never_join(self):
        binding, native, config = self.runtime()
        for field, value in (
            ("subject_sha256", "0" * 64),
            ("issued_at", 1999),
            ("expires_at", 2601),
        ):
            changed = copy.deepcopy(config)
            payload = signing.verify(changed["permit_envelope"], KIND, changed["permit_public"])
            payload[field] = value
            changed["permit_envelope"] = signing.sign(
                payload, KIND, self.state / "qualification.pem"
            )
            with self.subTest(field=field), self.assertRaises(Rejected):
                trust_gate.delivery(native, binding, changed)
        for field, value in (
            ("job_outcome", "recorded-not-activated"),
            ("parent_refusal", "other"),
        ):
            altered = copy.deepcopy(native)
            altered["actual"][field] = value
            altered["actual_inference"]["actual_refusal"][field] = value
            with self.subTest(refusal=field), self.assertRaises(Rejected):
                trust_gate.delivery(altered, binding, config)
        broken = copy.deepcopy(native)
        broken["actual"]["serving_before_admission"]["observation"]["cases"] = []
        broken["actual_inference"]["actual_refusal"] = copy.deepcopy(broken["actual"])
        with self.assertRaises(Rejected):
            trust_gate.delivery(broken, binding, config)

    def test_clean_cluster_and_explicit_pin_pair_are_required(self):
        trust_delivery.check_pins(None, None)
        trust_delivery.check_pins(self.proposal_pin, self.demo_pin)
        for proposal, demo in (
            (None, self.demo_pin),
            (self.proposal_pin, None),
            ("", self.demo_pin),
        ):
            with self.subTest(proposal=proposal), self.assertRaises(Rejected):
                trust_delivery.check_pins(proposal, demo)
        trust_delivery.clean_campaign(self.state)
        for name in (
            "kubernetes-trust",
            "kubernetes-trust-model",
            "kubernetes-security",
            "kubernetes-serving-service",
        ):
            path = self.state / name
            path.mkdir()
            with self.assertRaisesRegex(Rejected, "fresh_cluster_required"):
                trust_delivery.clean_campaign(self.state)
            path.rmdir()

    def test_frozen_runner_passes_pin_and_finishes_rotations_in_separate_owned_storage(self):
        native, source = trust_gate_fixtures.fixture()
        native["actual_inference"]["started_at"] = "1970-01-01T00:03:20+00:00"
        native["actual_inference"]["artifact_hashes"] = {}
        binding = {
            "evaluation_reference": "4" * 64,
            "subject_sha256": "1" * 64,
            "model_sha256": "f" * 64,
        }
        signers, _ = trust_gate_qualification.TrustGateContracts().signer()
        rotation = dict(
            status="pass",
            release_ready=False,
            source_revision=source["source_revision"],
            source_fingerprint=source["source_fingerprint"],
            cases=[str(i) for i in range(37)],
            head_sequence=4,
            policy_version=4,
            rotations=["1" * 64, "2" * 64, "3" * 64],
        )
        isolated = self.state / "isolated"
        fail_cleanup = False

        @contextmanager
        def disposable(*args):
            isolated.mkdir()
            try:
                yield isolated
            finally:
                isolated.rmdir()
                if fail_cleanup:
                    raise Rejected("cleanup-unconfirmed")

        with (
            patch.dict(
                os.environ,
                {"M11_PROPOSAL_SHA256": self.proposal_pin, "M11_DEMO_SHA256": self.demo_pin},
            ),
            patch.object(trust_acceptance, "hosted"),
            patch.object(trust_acceptance, "materials", return_value={}),
            patch.object(
                trust_acceptance,
                "command",
                side_effect=lambda args: "" if "status" in args else source["source_revision"],
            ),
            patch.object(
                trust_acceptance, "source_fingerprint", return_value=source["source_fingerprint"]
            ),
            patch.object(trust_acceptance, "now", return_value="1970-01-01T00:03:20+00:00"),
            patch.object(trust_acceptance.serving_output_native, "source", return_value=source),
            patch.object(trust_delivery, "freeze", return_value=binding),
            patch.object(
                trust_delivery,
                "retained",
                return_value={"actual_release_authorization": "inconclusive"},
            ),
            patch.object(
                trust_acceptance.kube_serving_native,
                "prepare",
                return_value={**source, "profile": {"image_id": source["image_id"]}},
            ) as prepare,
            patch.object(trust_acceptance.kube_serving_native, "qualify", return_value=native),
            patch.object(trust_acceptance, "controlled_contracts", return_value={"cases": []}),
            patch.object(trust_acceptance, "disposable", side_effect=disposable),
            patch.object(
                trust_acceptance.release_key_native, "qualify", return_value=rotation
            ) as rotate,
            patch.object(
                trust_acceptance.release_key_serving_native, "qualify", return_value=signers
            ) as serve,
        ):
            result = trust_acceptance.qualify(self.state, self.state)
            self.assertEqual(prepare.call_args.kwargs, {"proposal_pin": self.proposal_pin})
            self.assertEqual(rotate.call_args.args[1], isolated)
            self.assertEqual(serve.call_args.args[1], isolated)
            self.assertFalse(isolated.exists())
            self.assertEqual(result["artifact_hashes"]["proposal_packet"], self.proposal_pin)
            self.assertEqual(result["input_digests"]["evaluation_reference"], "4" * 64)
            self.assertEqual(result["input_digests"]["qualified_candidate_subject"], "1" * 64)
            self.assertEqual(result["metrics"]["actual_release_authorization"], "inconclusive")
            from scripts import shared_serving_native as shared

            joint_binding = {
                **binding,
                "source": source,
                "input_files": {
                    "evidence/release-native.json": self.proposal_pin,
                    "storage-demo.json": self.demo_pin,
                },
            }
            native["started_at"] = native["actual_inference"]["started_at"]
            with patch.dict(os.environ, {"M11_M12_ACTUAL_SHA256": "7" * 64}):
                with self.assertRaisesRegex(Rejected, "M11_joint_native_required"):
                    trust_acceptance.qualify(self.state, self.state)
                with (
                    patch.dict(os.environ, {shared.PIN: "8" * 64}),
                    patch.object(
                        shared, "lookup", return_value=(joint_binding, native, {})
                    ) as lookup,
                ):
                    joint = trust_acceptance.qualify(self.state, self.state)
                    lookup.assert_called_once()
                    prepare.assert_called_once()
                    self.assertEqual(joint["artifact_hashes"]["shared_native"], "8" * 64)
                    self.assertEqual(joint["artifact_hashes"]["pinned_actual"], "7" * 64)
                    self.assertEqual(joint["checks"], result["checks"])
                    with self.assertRaises(Rejected):
                        trust_acceptance.qualify(self.state, self.state, proposal_pin="0" * 64)
            fail_cleanup = True
            with self.assertRaises(Rejected):
                trust_acceptance.qualify(
                    self.state, self.state, proposal_pin=self.proposal_pin, demo_pin=self.demo_pin
                )
            self.assertEqual(
                read_json(self.state / "evidence/trust-gate.json")["status"], "inconclusive"
            )


if __name__ == "__main__":
    unittest.main()
