"""Private shared retention contracts; synthetic observations, real signed closure."""

import copy
import importlib.util
import io
import os
import shutil
import subprocess
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from mlsecops import final_evidence as final
from mlsecops import inference_gate, signing, trust_acceptance, trust_delivery, trust_gate
from mlsecops.candidate_serving_reader import KIND
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, write_json
from scripts import frozen_candidate_transfer as transfer
from scripts import frozen_candidate_transfer_qualification as fixtures
from scripts import kube_authority_pair_qualification as pair
from scripts import shared_serving_native as shared
from scripts import trust_gate_fixtures, trust_gate_qualification

ROOT = Path(__file__).resolve().parents[1]


def replace(value, replacements):
    if isinstance(value, dict):
        return {k: replace(v, replacements) for k, v in value.items()}
    if isinstance(value, list):
        return [replace(v, replacements) for v in value]
    return replacements.get(value, value) if isinstance(value, str) else value


def method_maps(root):
    paths = [m.replace(".", "/") + ".py" for m in inference_gate.inference_contracts.MODULES]
    paths += [
        "scripts/inference_contracts.py",
        "scripts/evaluation_contracts.py",
        "scripts/kube_candidate_native.py",
        "scripts/kube_serving_native.py",
        "scripts/candidate_serving_reader.py",
        "scripts/kube_promotion_native.py",
        "data.lock",
    ]
    return trust_acceptance.materials(root), {p: digest(bounded_read(root / p)) for p in paths}


class SharedRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.TransferTests.setUpClass()
        cls.addClassCleanup(fixtures.TransferTests.doClassCleanups)

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("scripts.m18_shared_retention"))
        from scripts import m18_shared_retention as collector

        self.collector = collector
        fx = fixtures.TransferTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        self.fx, self.root, self.state = fx, fx.root, fx.state
        consumer = self.state / "consumer"
        consumer.mkdir()
        for path in list(self.state.iterdir()):
            if path != consumer:
                path.rename(consumer / path.name)
        self.state = fx.state = fx.fx.state = consumer
        self.pins = copy.deepcopy(fx.owner)
        self.destination = self.root / ".runtime/retained-shared"
        for directory in ("mlsecops", "scripts"):
            for path in (ROOT / directory).glob("*.py"):
                target = self.root / directory / path.name
                target.parent.mkdir(exist_ok=True)
                shutil.copyfile(path, target)
        for name in ("uv.lock", "pyproject.toml", ".python-version", "Dockerfile"):
            target = self.root / name
            if not target.exists():
                shutil.copyfile(ROOT / name, target)
        self.build()

    def file(self, name, value):
        write_json(self.state / name, value)
        return digest(bounded_read(self.state / name))

    def build(self):
        fx = self.fx.fx
        source = fx.source
        expected = self.pins["expected"]
        binding = dict(
            context=fx.release.bundle.materials.context,
            publisher_public=fx.keys["approver"],
            source=source,
            **{k: expected[k] for k in transfer.delivery.IDENTITY},
            proposal_issued_at=fx.values["proposal_issued_at"],
            proposal_expires_at=fx.values["proposal_expires_at"],
            input_files=self.pins["freeze"],
        )
        native, old_source = trust_gate_fixtures.fixture()
        old = native["actual_inference"]
        changes = {
            old[k]: expected[k]
            for k in ("candidate_reference", "proposal_reference", "model_sha256", "subject_sha256")
        }
        changes.update({old_source[k]: source[k] for k in source})
        native = replace(native, changes)
        actual = native["actual_inference"]
        issued = binding["proposal_issued_at"]

        def stamp(offset):
            return datetime.fromtimestamp(issued + offset, UTC).isoformat()

        key = self.state / "qualification.pem"
        public = signing.create_key(key)
        permit = dict(
            schema_version=1,
            purpose=KIND,
            campaign_id="a" * 32,
            environment="local-cpu",
            proposal_sha256=expected["proposal_reference"],
            subject_sha256=expected["subject_sha256"],
            model_sha256=expected["model_sha256"],
            **source,
            issued_at=issued + 10,
            expires_at=issued + 610,
        )
        envelope = signing.sign(permit, KIND, key)
        permit_pin = digest(canonical(permit))
        native = replace(native, {actual["qualification_permit_sha256"]: permit_pin})
        actual = native["actual_inference"]
        actual.update(
            evaluation_reference=expected["evaluation_reference"],
            qualification_campaign_id="a" * 32,
            proposal_issued_at=issued,
            started_at=stamp(1),
            finished_at=stamp(300),
        )
        native["started_at"] = stamp(0)
        native["actual"]["serving_before_admission"] = dict(
            release_ready=False,
            pod_uid="pod",
            heartbeat_before=0,
            heartbeat_after=1,
            elapsed_seconds=1.0,
            observation=dict(
                existing_process=True,
                release_ready=False,
                pod_uid="pod",
                cases=[
                    "existing-HTTP-process-live",
                    "unapproved-or-revoked-ready-503",
                    "unapproved-or-revoked-predict-503",
                    "no-inference-worker",
                ],
            ),
        )
        actual["actual_refusal"] = native["actual"]
        with patch.multiple(
            pair,
            POLICY=permit_pin,
            MODEL=expected["model_sha256"],
            KEY=actual["revoked_key_sha256"],
        ):
            before = pair.states()
            model = pair.revoked(before, pair.Target.MODEL_REVOCATION)
            after = pair.revoked(model, pair.Target.PRIMARY)
        actual["independent_authorities"]["states"] = dict(
            before=before, after_model=model, after_key=after
        )
        actual["native"].update(pair.isolation(pair.Target.PRIMARY, before))
        actual["model_revocation"].update(pair.isolation(pair.Target.MODEL_REVOCATION, before))
        snapshot = {"objects": [], "promotion": []}
        native = replace(native, {actual["base_snapshot_sha256"]: digest(canonical(snapshot))})
        actual = native["actual_inference"]
        actual["root_rotation"]["next_public"] = pair.PUBLIC
        actual["trust_lifecycle_ownership_return"] = dict(
            transfer=dict(before="one", after="two", release_ready=False),
            observation=None,
            heartbeat_before=1,
            heartbeat_after=2,
            identity_events_delivered=0,
            return_seconds=0.1,
            outbox_retained=True,
            release_ready=False,
        )
        config = dict(
            context=binding["context"],
            publisher_public=binding["publisher_public"],
            proposal_reference=expected["proposal_reference"],
            permit_envelope=envelope,
            permit_public=public,
            expected_permit=permit_pin,
            trust_root=pair.PUBLIC,
            expected_campaign="a" * 32,
            kubernetes_worker={},
        )
        grouped = {
            200: "verified-ready golden-status 64KiB-accepted 100-rows-status outside-support-status ready-after-invalid",
            401: "unauthorized-401",
            413: "413-over-64KiB",
            429: "429-busy",
            100: "100-rows-count",
            503: "stopped-worker-503 stopped-worker-not-ready",
            expected["subject_sha256"]: "golden-bundle ready-bundle",
            expected["model_sha256"]: "golden-model ready-model",
            "abstain": "outside-support-abstains",
            "candidate-qualification": "qualification-audit-context",
            "unexpected_fields": "unsigned-permit-signature-reason",
            "invalid_signature_count": "unsigned-proposal-signature-reason",
            permit_pin: "qualification-permit-payload",
            digest(canonical(envelope)): "qualification-permit-envelope",
            None: "outside-support-no-score",
        }
        observed = {n: v for v, names in grouped.items() for n in names.split()}
        observed.update(
            {
                "initial-worker-absence": 0,
                "final-worker-absence": 0,
                "one-persistent-worker": 1,
                "actual-candidate-not-release": False,
                "golden-parity-1e-6": True,
                "finite-bounded-scores": True,
            }
        )
        for name in inference_gate.NATIVE_CASES - observed.keys():
            if name.startswith("422-"):
                observed[name] = 422
            elif name.endswith("-503"):
                observed[name] = 503
            else:
                observed[name] = int(name == "malformed-model-worker-constructions")
        actual["native"]["cases"] = [
            c for c in actual["native"]["cases"] if c["id"] not in observed
        ] + trust_gate_fixtures.typed(**observed)
        for phase in ("before_approval", "after_revocation"):
            native[phase]["cases"].append("unapproved-or-revoked-predict-503")
        native["approved"]["cases"] += [
            "response-model-and-bundle-binding",
            "same-worker-UID-across-requests",
            "stopped-worker-503",
        ]
        data = {
            "config.json": config,
            "request.json": dict(
                model=expected["model_sha256"],
                bundle=expected["subject_sha256"],
                clock_cache=True,
                independent_authorities=True,
            ),
            "reference.json": {"receipt": {"model_digest": expected["model_sha256"]}},
            "probe.json": actual["native"],
            "root-rotation.json": actual["root_rotation"],
            "independent-authorities.json": actual["independent_authorities"],
            "key-revocation.json": actual["key_revocation"],
            "model-revocation.json": actual["model_revocation"],
            **{k + ".json": v["probe"] for k, v in actual["trust_lifecycle"].items()},
        }
        actual["artifact_hashes"] = {
            n: self.file("candidate-inference/" + "a" * 32 + "/" + n, v) for n, v in data.items()
        }
        owner = dict(
            source=source,
            proposal_sha256=self.pins["freeze"][transfer.delivery.PROPOSAL],
            inputs={
                k: v for k, v in self.pins["freeze"].items() if k != transfer.delivery.PROPOSAL
            },
            runner=dict(GITHUB_RUN_ID="123456", GITHUB_RUN_ATTEMPT="1", GITHUB_JOB="consumer"),
            workspace="owned-workspace",
            cluster="owned-cluster",
        )
        early = dict(
            binding=binding,
            actual=actual,
            prepared=dict(actual=native["actual"], profile={}),
            owner=owner,
            sql_snapshot=snapshot,
        )
        full = {k: v for k, v in native.items() if k != "actual_inference"}
        self.pins["actual_pin"] = self.file(shared.EARLY, early)
        self.pins["native_pin"] = self.file(
            shared.FULL, dict(early_sha256=self.pins["actual_pin"], controlled=full)
        )
        self.assertEqual(shared.retained(self.state, early), config)
        metrics = trust_gate.reconcile(native, source)
        joins = trust_delivery.retained(self.state, native, binding)
        signers, _ = trust_gate_qualification.TrustGateContracts().signer()
        signers.update(source)
        metrics["signer_first_503_seconds"] = trust_gate.release_signers(signers, source)
        rotation = dict(
            status="pass",
            release_ready=False,
            source_revision=source["source_revision"],
            source_fingerprint=source["source_fingerprint"],
            cases=[str(i) for i in range(37)],
            head_sequence=4,
            policy_version=4,
            rotations=["one", "two", "three"],
        )
        controls = dict(status="pass", checks=1, cases=trust_gate_fixtures.typed(control=True))
        common = dict(
            **actual["artifact_hashes"],
            shared_native=self.pins["native_pin"],
            pinned_actual=self.pins["actual_pin"],
            proposal_packet=self.pins["freeze"][transfer.delivery.PROPOSAL],
        )
        maps = method_maps(self.root)
        artifacts = dict(
            M11=dict(
                common,
                method_materials=digest(canonical(maps[0])),
                frozen_binding=self.file(
                    "evidence/trust-frozen.json", dict(binding=binding, joins=joins)
                ),
                storage_demo=self.pins["freeze"]["storage-demo.json"],
                signed_evaluation=expected["evaluation_reference"],
                **{
                    n: self.file("evidence/" + n + ".json", v)
                    for n, v in (
                        ("kubernetes-serving", native),
                        ("release-key-native", rotation),
                        ("release-key-serving", signers),
                        ("trust-contracts", controls),
                    )
                },
            ),
            M12=dict(
                common,
                native=self.file("evidence/inference-native.json", native),
                contracts=self.file("evidence/inference-contracts.json", controls),
                contract_materials=digest(canonical(maps[1])),
            ),
        )
        selected = inference_gate.joint_cases(actual, envelope)
        inference_gate.reconcile(
            dict(
                native, actual_inference=dict(actual, native=dict(actual["native"], cases=selected))
            ),
            source,
        )
        self.pins["report_pins"] = {}
        for gate in ("M11", "M12"):
            criteria = {
                "actual-candidate-binding",
                "five-clock-cache-faults",
                "still-valid-trust-version-replay",
                "independent-key-model-authorities",
                "signed-approval-expiry",
                "still-valid-release-sequence-replay",
                "authorized-and-denied-whole-bundle-rollback",
                "signer-sql-policy-history",
                "frozen-proposal-signed-evaluation",
                "production-refusal-controlled-subject-separation",
                "isolated-rotation-cleanup",
                *metrics["first_503_seconds"],
                "signer-publisher",
                "signer-assessor",
                "signer-approver",
            }
            cases = controls["cases"] + (
                selected
                if gate == "M12"
                else [
                    dict(id="M11-" + name, status="pass", expected=True, actual=True)
                    for name in sorted(criteria)
                ]
            )
            measured = (
                dict(metrics, **joins)
                if gate == "M11"
                else dict(
                    qualification_permit_sha256=permit_pin, native_cases=62, max_golden_error=0.0
                )
            )
            report = dict(
                gate=gate,
                status="pass",
                exit_code=0,
                source_dirty=False,
                source_revision=source["source_revision"],
                started_at=stamp(0),
                finished_at=stamp(800),
                input_digests=dict(
                    source,
                    model=expected["model_sha256"],
                    release_subject=expected["subject_sha256"],
                    **{
                        k: expected[k]
                        for k in (
                            "candidate_reference",
                            "evaluation_reference",
                            "proposal_reference",
                        )
                    },
                ),
                artifact_hashes=artifacts[gate],
                cases=cases,
                metrics=dict(checks=len(cases), **measured),
            )
            self.pins["report_pins"][gate] = self.file("evidence/" + gate + ".json", report)

    def retain(self, **changes):
        return self.collector.retain(
            self.root, self.state, self.destination, **(self.pins | changes)
        )

    def replay(self, index_pin, **changes):
        return self.collector.replay(
            self.root, self.destination, index_pin=index_pin, **(self.pins | changes)
        )

    def test_offline_roundtrip_keeps_every_original_preimage_after_source_view_deleted(self):
        original = {
            p.relative_to(self.state).as_posix(): p.read_bytes()
            for p in self.state.rglob("*")
            if p.is_file()
        }
        output = io.StringIO()
        with redirect_stdout(output):
            pin = self.retain()
            for name in (shared.EARLY, shared.FULL, "evidence/M11.json", "evidence/M12.json"):
                (self.state / name).unlink()
            result = self.replay(pin)
        self.assertEqual(output.getvalue(), "")
        self.assertIs(result["release_ready"], False)
        record = decode(bounded_read(self.destination / "evidence/M18-objects" / pin))
        for name, ref in record["files"].items():
            self.assertEqual(bounded_read(self.destination / transfer.CAS / ref), original[name])
        for gate in ("M11", "M12"):
            report = decode(original["evidence/" + gate + ".json"])
            for ref in report["artifact_hashes"].values():
                self.assertEqual(digest(bounded_read(self.destination / transfer.CAS / ref)), ref)
        self.assertNotIn("qualification.pem", record["files"])

    def test_missing_tampered_and_noncanonical_originals_fail_without_destination(self):
        path = self.state / shared.EARLY
        raw = path.read_bytes()
        for replacement in (None, raw + b" ", canonical(decode(raw))):
            if replacement is None:
                path.unlink()
            else:
                path.write_bytes(replacement)
            with self.subTest(missing=replacement is None), self.assertRaises((Rejected, OSError)):
                self.retain()
            self.assertFalse(self.destination.exists())
            path.write_bytes(raw)

    def test_external_pins_and_identity_cannot_be_taken_from_receipt(self):
        pin = self.retain()
        for changes in (
            dict(freeze_pin="0" * 64),
            dict(actual_pin="0" * 64),
            dict(native_pin="0" * 64),
            dict(report_pins={"M11": "0" * 64, "M12": self.pins["report_pins"]["M12"]}),
            dict(expected=self.pins["expected"] | {"model_sha256": "0" * 64}),
            dict(run_owner=self.pins["run_owner"] | {"run_attempt": 2}),
        ):
            with self.subTest(fields=tuple(changes)), self.assertRaises(Rejected):
                self.replay(pin, **changes)

    def report_change(self, gate, change):
        name = "evidence/" + gate + ".json"
        value = decode(bounded_read(self.state / name))
        change(value)
        self.pins["report_pins"][gate] = self.file(name, value)

    def test_repinned_m11_report_cannot_omit_reconciled_case(self):
        def omit(report):
            report["cases"].pop()
            report["metrics"]["checks"] -= 1

        self.report_change("M11", omit)
        with self.assertRaises(Rejected):
            self.retain()

    def resave_shared(self, early):
        full = decode(bounded_read(self.state / shared.FULL))
        self.pins["actual_pin"] = self.file(shared.EARLY, early)
        full["early_sha256"] = self.pins["actual_pin"]
        self.pins["native_pin"] = self.file(shared.FULL, full)
        native = dict(full["controlled"], actual_inference=early["actual"])
        for gate, name, field in (
            ("M11", "kubernetes-serving", "kubernetes-serving"),
            ("M12", "inference-native", "native"),
        ):
            ref = self.file("evidence/" + name + ".json", native)
            self.report_change(
                gate,
                lambda r: r["artifact_hashes"].update(
                    {
                        field: ref,
                        "pinned_actual": self.pins["actual_pin"],
                        "shared_native": self.pins["native_pin"],
                    }
                ),
            )

    def test_repinned_expired_original_permit_time_is_still_denied(self):
        early = decode(bounded_read(self.state / shared.EARLY))
        config = decode(
            bounded_read(self.state / "candidate-inference" / ("a" * 32) / "config.json")
        )
        permit = signing.verify(config["permit_envelope"], KIND, config["permit_public"])
        early["actual"]["finished_at"] = datetime.fromtimestamp(
            permit["expires_at"], UTC
        ).isoformat()
        self.resave_shared(early)
        with self.assertRaisesRegex(Rejected, "shared_serving_actual_binding"):
            self.retain()
        self.assertFalse(self.destination.exists())

    def test_repinned_foreign_attempt_is_rejected_by_original_owner_binding(self):
        early = decode(bounded_read(self.state / shared.EARLY))
        early["owner"]["runner"]["GITHUB_RUN_ATTEMPT"] = "2"
        self.resave_shared(early)
        with self.assertRaisesRegex(Rejected, "shared-run-attempt"):
            self.retain()

    def test_noncanonical_rehashed_report_and_secret_fields_are_denied(self):
        path = self.state / "evidence/M11.json"
        raw = path.read_bytes()
        path.write_bytes(raw.rstrip(b"\n"))
        self.pins["report_pins"]["M11"] = digest(path.read_bytes())
        with self.assertRaisesRegex(Rejected, "producer-json"):
            self.retain()
        path.write_bytes(raw)
        self.report_change("M11", lambda r: r.update(password="private-sentinel"))
        with self.assertRaisesRegex(Rejected, "frozen-transfer-rejected"):
            self.retain()

    def test_actual_artifact_allowlist_rejects_extra_entry_before_read(self):
        early = decode(bounded_read(self.state / shared.EARLY))
        early["actual"]["artifact_hashes"]["../secret"] = "0" * 64
        self.resave_shared(early)
        with self.assertRaisesRegex(Rejected, "unexpected_fields"):
            self.retain()

    def test_signed_original_policy_tamper_cannot_be_hidden_by_report_summary(self):
        ref = self.fx.index["policy_reference"]
        path = self.state / transfer.CAS / ref
        raw = path.read_bytes()
        path.write_bytes(raw + b" ")
        with self.assertRaises(Rejected):
            self.retain()

    def test_signature_tamper_is_rejected_even_with_repinned_config(self):
        early = decode(bounded_read(self.state / shared.EARLY))
        path = self.state / "candidate-inference" / ("a" * 32) / "config.json"
        config = decode(path.read_bytes())
        config["permit_envelope"]["signatures"][0]["sig"] = signing.encode64(b"x" * 64)
        write_json(path, config)
        ref = digest(path.read_bytes())
        early["actual"]["artifact_hashes"]["config.json"] = ref
        self.resave_shared(early)
        for gate in ("M11", "M12"):
            self.report_change(gate, lambda r: r["artifact_hashes"].update({"config.json": ref}))
        with self.assertRaises(Rejected):
            self.retain()

    def test_expired_operational_window_is_historical_only_and_no_infra_is_called(self):
        expired = datetime.fromtimestamp(self.fx.fx.values["proposal_expires_at"] + 86400, UTC)
        with (
            patch.object(final, "now", return_value=expired.isoformat()),
            patch.object(transfer, "window", side_effect=AssertionError("operational window")),
            patch.object(subprocess, "run", side_effect=AssertionError("external process")),
            patch.object(shared, "lookup", side_effect=AssertionError("live owner")),
        ):
            pin = self.retain()
            shutil.rmtree(self.state)
            result = self.replay(pin)
        self.assertFalse(result["release_ready"])
        self.assertEqual(
            {p.name for p in (self.root / ".runtime").iterdir()}, {self.destination.name}
        )

    def test_missing_required_external_arguments_are_not_inferred(self):
        for name in self.pins:
            reduced = self.pins.copy()
            del reduced[name]
            with self.subTest(name=name), self.assertRaises(TypeError):
                self.collector.retain(self.root, self.state, self.destination, **reduced)
            with self.subTest(name=name), self.assertRaises(TypeError):
                self.collector.replay(self.root, self.destination, index_pin="0" * 64, **reduced)

    def test_source_checks_before_collection_and_after_semantics(self):
        for responses in ([Rejected("dirty")], [None, Rejected("changed")]):
            with patch.object(final, "clean", side_effect=responses), self.assertRaises(Rejected):
                self.retain()
            self.assertFalse(self.destination.exists())
            self.assertFalse(list((self.root / ".runtime").glob("shared-replay-*")))

    def test_method_map_changed_source_and_wrong_raw_lf_reference_fail(self):
        script = self.root / "scripts/kube_candidate_native.py"
        raw = script.read_bytes()
        script.write_bytes(raw + b"\n# changed\n")
        with self.assertRaises(Rejected):
            self.retain()
        script.write_bytes(raw)
        self.report_change(
            "M11",
            lambda r: r["artifact_hashes"].update(
                method_materials=digest(canonical(method_maps(self.root)[0]) + b"\n")
            ),
        )
        with self.assertRaises(Rejected):
            self.retain()

    def test_extra_artifact_reference_and_missing_expected_reference_fail(self):
        name = "evidence/M12.json"
        original = bounded_read(self.state / name)
        for change in (
            lambda r: r["artifact_hashes"].update(extra=digest(b"extra")),
            lambda r: r["artifact_hashes"].pop("contracts"),
        ):
            (self.state / name).write_bytes(original)
            self.report_change("M12", change)
            with self.subTest(change=change), self.assertRaises((Rejected, KeyError)):
                self.retain()
        self.assertFalse(self.destination.exists())

    def test_failure_after_destination_creation_removes_only_owned_output(self):
        sibling = self.root / ".runtime/sibling"
        sibling.mkdir()
        (sibling / "keep").write_bytes(b"owned by another caller")
        with patch.object(self.collector, "replay", side_effect=OSError("disk failure")):
            with self.assertRaises(OSError):
                self.retain()
        self.assertFalse(self.destination.exists())
        self.assertEqual((sibling / "keep").read_bytes(), b"owned by another caller")

    def test_unallowlisted_keys_logs_and_kubeconfig_are_not_read(self):
        for name in ("keys/trust.pem", "kubeconfig", "raw.log", "train.json", "holdout.json"):
            path = self.state / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"unrelated private sentinel")
        ordinary = self.collector.bounded_read

        def guarded(path, *args):
            if Path(path).name in {
                "trust.pem",
                "kubeconfig",
                "raw.log",
                "train.json",
                "holdout.json",
            }:
                self.fail("forbidden input read")
            return ordinary(path, *args)

        with patch.object(self.collector, "bounded_read", side_effect=guarded):
            pin = self.retain()
        record = decode(bounded_read(self.destination / transfer.CAS / pin))
        self.assertTrue(
            all(
                "private sentinel"
                not in bounded_read(self.destination / transfer.CAS / ref).decode(errors="replace")
                for ref in record["objects"]
            )
        )

    def test_existing_outside_and_consumer_destinations_fail_without_overwrite(self):
        self.destination.mkdir()
        marker = self.destination / "keep"
        marker.write_bytes(b"old")
        for destination in (
            self.destination,
            self.state / "inside",
            self.root / "public",
            self.root / ".runtime",
        ):
            with self.subTest(destination=destination), self.assertRaises((Rejected, ValueError)):
                self.collector.retain(self.root, self.state, destination, **self.pins)
        self.assertEqual(marker.read_bytes(), b"old")

    def test_limits_reject_before_persistent_output(self):
        for constant, limit in (("LIMIT", 128), ("TOTAL", final.LIMIT + 128), ("MAX_FILES", 1)):
            with patch.object(self.collector, constant, limit), self.assertRaises(Rejected):
                self.retain()
            self.assertFalse(self.destination.exists())

    def rewrite_index(self, pin, mutate):
        path = self.destination / transfer.CAS / pin
        record = decode(path.read_bytes())
        mutate(record)
        raw = canonical(record) + b"\n"
        replacement = digest(raw)
        path.unlink()
        (self.destination / transfer.CAS / replacement).write_bytes(raw)
        return replacement

    def test_repinned_index_cannot_add_missing_extra_or_traversal_entries(self):
        pin = self.retain()
        original = bounded_read(self.destination / transfer.CAS / pin)
        for change in (
            lambda r: r["files"].pop(shared.EARLY),
            lambda r: r["files"].update({"../escape": self.pins["actual_pin"]}),
            lambda r: r["objects"].update({"f" * 64: 5}),
            lambda r: r["objects"].update({self.pins["actual_pin"]: 1}),
            lambda r: r["objects"].update({self.pins["actual_pin"]: True}),
            lambda r: r.update(scope="M18-pass"),
            lambda r: r.update(classification="public"),
        ):
            forged = self.rewrite_index(pin, change)
            with self.subTest(change=change), self.assertRaises((Rejected, KeyError)):
                self.replay(forged)
            (self.destination / transfer.CAS / forged).unlink()
            (self.destination / transfer.CAS / pin).write_bytes(original)

    def test_missing_or_corrupt_canonical_map_is_not_reconstructed_on_replay(self):
        pin = self.retain()
        ref = digest(canonical(method_maps(self.root)[0]))
        path = self.destination / transfer.CAS / ref
        original = path.read_bytes()
        for value in (None, original + b"\n"):
            if value is None:
                path.unlink()
            else:
                path.write_bytes(value)
            with self.subTest(missing=value is None), self.assertRaises((Rejected, OSError)):
                self.replay(pin)
            path.write_bytes(original)

    def test_extra_output_files_and_oversized_declared_total_fail(self):
        pin = self.retain()
        for name in ("extra", "evidence/extra", transfer.CAS + "f" * 64):
            path = self.destination / name
            path.write_bytes(b"extra")
            with self.subTest(name=name), self.assertRaises(Rejected):
                self.replay(pin)
            path.unlink()
        with patch.object(self.collector, "TOTAL", 1), self.assertRaises(Rejected):
            self.replay(pin)

    def test_source_or_destination_symlink_is_denied(self):
        source = self.state / shared.EARLY
        other = self.state / "original-early.json"
        source.rename(other)
        os.symlink(other, source)
        with self.assertRaises(Rejected):
            self.retain()
        source.unlink()
        other.rename(source)
        outside = self.root / "outside"
        outside.mkdir()
        os.symlink(outside, self.destination, target_is_directory=True)
        with self.assertRaises(Rejected):
            self.retain()

    def test_collector_has_separate_explicit_replay_api(self):
        spec = importlib.util.find_spec("scripts.m18_shared_retention")
        self.assertIsNotNone(spec, "bounded private shared collector is missing")
        from scripts import m18_shared_retention as collector

        self.assertTrue(callable(collector.retain))
        self.assertTrue(callable(collector.replay))


if __name__ == "__main__":
    unittest.main()
