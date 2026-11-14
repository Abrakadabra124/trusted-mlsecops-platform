"""T19 candidate wiring against signed materials and controlled storage/worker transports."""

import asyncio
import copy
import importlib.metadata
import shutil
import tempfile
import time
import unittest
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import (
    canary_native_evidence,
    prediction_protocol,
    serving,
    serving_audit,
    serving_http,
    signing,
    storage,
    trust,
)
from mlsecops.contracts import Rejected, canonical, decode, digest, write_json
from mlsecops.datasets import FEATURES
from scripts import canary_candidate_native as candidate
from scripts import release_authorization_qualification as fixtures
from scripts import serving_http_qualification as http_tests


class ActualCandidate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.ReleaseAuthorizationContracts.setUpClass()
        cls.addClassCleanup(fixtures.ReleaseAuthorizationContracts.tearDownClass)
        cls.fixture = fixtures.ReleaseAuthorizationContracts()
        cls.fixture.setUp()
        cls.addClassCleanup(cls.fixture.doCleanups)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.state = self.root / ".runtime"
        self.authority = self.state / "evidence" / "isolated"
        fixture = self.fixture
        self.package = copy.deepcopy(fixture.package)
        self.context = fixture.bundle.materials.context
        trained = fixture.bundle.materials.fixture
        write_json(
            self.state / "storage-demo.json",
            {
                "candidate": {
                    "candidate_reference": self.context["candidate_reference"],
                    "metadata": trained.metadata,
                },
                "evaluation_reference": self.context["evaluation_reference"],
                "evaluation": trained.bound,
                "dataset": dict(
                    dataset_reference=trained.dataset_ref,
                    source_approval_digest=trained.trust["source_approval_digest"],
                ),
            },
        )
        self.source = self.context["expected"]
        self.campaign = "c" * 32
        self.features = [[0.1] * len(FEATURES)]
        self.report = {
            "scope": "release-proposal-and-authorization-denial-not-full-M10",
            "status": "pass",
            "source_dirty": False,
            "release_ready": False,
            "source": self.source,
            "proposal_reference": digest(canonical(self.package["envelope"])),
            "model_sha256": digest(fixture.release["model"]),
            "subject_sha256": fixture.release["subject_sha256"],
            "campaign_id": fixture.release["manifest"]["release_id"],
            "policy_sha256": fixture.policy_hash,
        }
        self.report_path = self.state / "evidence/release-native.json"
        write_json(self.report_path, self.report)
        self.pin = digest(self.report_path.read_bytes())
        write_json(self.root / "policies/local-cpu.json", self.context["policy"])
        write_json(self.state / "storage-trust.json", self.context["trust"])
        write_json(
            self.state / "trusted-keys.json",
            {
                "approver": fixture.bundle.materials.public,
                "trust": fixture.authorities.public["root"],
            },
        )
        write_json(
            self.state / "release-proposals" / self.report["campaign_id"] / "policy-envelope.json",
            fixture.policy_envelope,
        )
        self.mock(candidate, "hosted")
        self.source_check = self.mock(candidate, "source", return_value=self.source)
        self.marker = self.mock(
            candidate.storage_bootstrap, "validate", return_value={"name": "source"}
        )
        self.ledger = self.mock(
            candidate.storage_restore, "ledger", return_value={"source": "original"}
        )
        self.load = self.mock(candidate.release_bundle, "load", return_value=self.package)
        self.mock(storage, "connection_parameters", return_value={"user": "ml_serving"})
        self.worker = self.mock(candidate.sandbox, "run_worker", side_effect=self.predict)
        self.disposable = self.mock(candidate, "disposable", side_effect=self.open_trust)
        self.install = self.mock(candidate.trust_authority, "install")
        self.update = self.mock(candidate.trust_authority, "update", side_effect=self.update_trust)
        self.read = self.mock(candidate.trust_authority, "read", side_effect=self.read_trust)
        self.versions = []

    def mock(self, target, name, **options):
        return self.enterContext(patch.object(target, name, **options))

    @contextmanager
    def open_trust(self, root, state, campaign, suffix, port):
        self.assertEqual(
            (root, state, campaign, port), (self.root, self.state, self.campaign, 15446)
        )
        self.authority.mkdir(parents=True)
        try:
            yield self.authority
        finally:
            shutil.rmtree(self.authority)

    def update_trust(self, state, policy_sha256, key, *, revoked_artifacts=()):
        self.assertEqual(state, self.authority)
        self.assertTrue(key.is_relative_to(self.authority))
        clock = int(time.time())
        payload = dict(
            schema_version=1,
            environment="local-cpu",
            version=len(self.versions) + 1,
            promotion_policy_sha256=policy_sha256,
            issued_at=clock,
            expires_at=clock + 3600,
            revoked_keys=[],
            revoked_artifacts=list(revoked_artifacts),
        )
        envelope = signing.sign(payload, "trust-policy", key)
        self.versions.append(envelope)
        return {
            "version": payload["version"],
            "document_sha256": digest(canonical(envelope)),
            "reused": False,
        }

    def read_trust(self, client, environment, public):
        self.assertEqual(client, self.authority / "storage-clients/serving")
        self.install.assert_called_once_with(self.authority, environment, public)
        return self.versions[-1], int(time.time())

    def predict(self, image, request, *, timeout):
        self.assertEqual(image, self.source["image_id"])
        self.assertEqual(request["features"], self.features)
        self.assertEqual(
            prediction_protocol.validate_request(request), self.fixture.release["model"]
        )
        scan = dict(
            format="onnx",
            policy_version="linear-onnx-v2",
            inspected_nodes=2,
            unsupported=0,
            skipped=0,
            errors=0,
            onnx_version=importlib.metadata.version("onnx"),
        )
        return prediction_protocol.response(request, [0.25], scan), {"image_id": image}

    def open(self, **overrides):
        return candidate.actual_candidate(
            self.root,
            self.state,
            "test-image",
            **{
                "campaign": self.campaign,
                "proposal_pin": self.pin,
                "features": self.features,
                **overrides,
            },
        )

    def test_original_proposal_independent_golden_and_offline_revocation(self):
        with self.open() as (engine, golden, binding, revoke):
            self.assertIsInstance(engine, serving.Engine)
            self.assertIsNone(engine.worker_factory)
            self.assertIsNone(engine.worker)
            self.assertIsNone(engine.reader.current)
            self.assertEqual(engine.reader.client, self.state / "storage-clients/serving")
            self.assertEqual(
                (golden.model, golden.bundle, golden.score),
                (self.report["model_sha256"], self.report["subject_sha256"], 0.25),
            )
            self.assertEqual(
                decode(golden.body)["instances"],
                [dict(zip(FEATURES, self.features[0], strict=True))],
            )
            reader = engine.reader
            sidecar = (
                self.state
                / "evidence"
                / ("canary-native-" + self.campaign)
                / "candidate-source.json"
            )
            raw = sidecar.read_bytes()
            source_evidence = decode(raw)
            self.assertEqual(source_evidence["permit"], reader.permit)
            self.assertEqual(
                source_evidence["storage_demo_sha256"],
                digest((self.state / "storage-demo.json").read_bytes()),
            )
            self.assertEqual(
                binding,
                {
                    **self.source,
                    "candidate_reference": self.context["candidate_reference"],
                    "evaluation_reference": self.context["evaluation_reference"],
                    "model_sha256": golden.model,
                    "subject_sha256": golden.bundle,
                    "proposal_reference": self.report["proposal_reference"],
                    "permit_sha256": digest(canonical(reader.permission())),
                    "trust_root": reader.public,
                    "source_evidence_sha256": digest(raw),
                },
            )
            loaded = reader.load()
            self.assertEqual(source_evidence["lineage"], asdict(loaded.lineage))
            self.assertFalse(loaded.release_ready)
            self.assertEqual(loaded.model, self.fixture.release["model"])
            self.assertEqual(reader.check(loaded)["version"], 1)
            proof = revoke()
            with self.assertRaisesRegex(Rejected, "trust_artifact_revoked"):
                reader.check(loaded)
            with self.assertRaises(Rejected):
                revoke()
        self.assertFalse(self.authority.exists())
        self.assertEqual(sidecar.read_bytes(), raw)
        lineage, issued = canary_native_evidence.candidate_source(
            self.state, sidecar.parent, self.campaign, binding, int(time.time()) + 1
        )
        self.assertEqual(lineage, asdict(loaded.lineage))
        self.assertEqual(
            issued, signing.verify(reader.permit, candidate.KIND, reader.public)["issued_at"]
        )
        with self.assertRaises(Rejected):
            revoke()
        self.assertEqual(self.update.call_count, 2)
        self.assertEqual(set(proof), {"root", "before", "after"})
        self.assertEqual(proof["root"], binding["trust_root"])
        first, last = [
            trust.validate(proof[k], binding["trust_root"], "local-cpu")
            for k in ("before", "after")
        ]
        trust.successor(first, last)
        self.assertEqual(
            [first["revoked_artifacts"], last["revoked_artifacts"]], [[], [golden.model]]
        )
        self.assertEqual(first["promotion_policy_sha256"], binding["permit_sha256"])
        self.assertEqual(last["promotion_policy_sha256"], binding["permit_sha256"])
        self.worker.assert_called_once()
        self.assertEqual(self.ledger.call_count, 2)

    def test_early_rejections_do_not_touch_infrastructure(self):
        for overrides in (
            {"proposal_pin": None},
            {"proposal_pin": "A" * 64},
            {"proposal_pin": digest(canonical(self.report))},
            {"campaign": "../foreign"},
            {"features": self.features * 2},
            {"features": [[True] * len(FEATURES)]},
        ):
            with (
                self.subTest(overrides=overrides),
                self.assertRaises(Rejected),
                self.open(**overrides),
            ):
                self.fail("unexpected yield")
        for operation in (self.marker, self.source_check, self.load, self.worker, self.disposable):
            operation.assert_not_called()

    def test_http_lifespan_activates_candidate_and_returns_503_after_signed_revocation(self):
        worker = Mock(
            image=self.source["image_id"], binding={"model_sha256": self.report["model_sha256"]}
        )
        worker.predict.return_value = [0.25]
        with (
            self.open() as (engine, golden, _, revoke),
            patch.object(serving, "Worker", return_value=worker) as create,
        ):
            harness = http_tests.ServingHttpContracts()
            harness.token = "f" * 64
            journal = serving_audit.Journal(self.state / "candidate.jsonl")
            journal.start()
            self.addCleanup(journal.close, timeout=5)
            harness.app = serving_http.create_app(engine, harness.token, audit=journal)

            async def traffic():
                async with harness.app.router.lifespan_context(harness.app):
                    status, reply, _ = await harness.invoke(body=decode(golden.body))
                    self.assertEqual(status, 200)
                    self.assertTrue(golden.valid(reply))
                    revoke()
                    status, reply, _ = await harness.invoke(body=decode(golden.body))
                    self.assertEqual((status, reply["error"]), (503, {"code": "model_unavailable"}))

            asyncio.run(traffic())
            create.assert_called_once_with(self.fixture.release["model"], self.source["image_id"])
            worker.start.assert_called_once()
            worker.close.assert_called_once()

    def test_cannot_attribute_measurement_after_permit_expiry_to_revocation(self):
        with (
            self.assertRaisesRegex(Rejected, "release_expired_or_future_document"),
            self.open() as (engine, _, _, revoke),
        ):
            revoke()
            expires = engine.reader.permission()["expires_at"]
            self.mock(candidate, "time", time=Mock(return_value=expires))

    def test_signed_wrong_policy_or_model_and_changed_update_receipt_are_rejected(self):
        for change in ("policy", "model", "receipt", "old"):
            with self.subTest(change=change), self.open() as (_, _, _, revoke):

                def substitute(state, policy, key, *, revoked_artifacts):
                    receipt = self.update_trust(
                        state,
                        "0" * 64 if change == "policy" else policy,
                        key,
                        revoked_artifacts=["1" * 64] if change == "model" else revoked_artifacts,
                    )
                    if change == "receipt":
                        receipt["document_sha256"] = "0" * 64
                    if change == "old":
                        self.versions.pop()
                    return receipt

                self.update.side_effect = substitute
                with self.assertRaisesRegex(Rejected, "canary_candidate_trust_readback"):
                    revoke()
            self.update.side_effect = self.update_trust
            self.versions.clear()
            self.install.reset_mock()

    def test_pinned_report_still_requires_verified_materials_and_right_campaign(self):
        for change in (
            {"status": "inconclusive"},
            {"model_sha256": "0" * 64},
            {"source": {}},
            {"campaign_id": "e" * 32},
        ):
            write_json(self.report_path, {**self.report, **change})
            with (
                self.subTest(change=change),
                self.assertRaises(Rejected),
                self.open(proposal_pin=digest(self.report_path.read_bytes())),
            ):
                self.fail("unexpected yield")
        self.disposable.assert_not_called()

    def test_demo_references_must_match_the_original_signed_package_before_worker(self):
        for changes in (
            {"candidate": {"candidate_reference": "0" * 64}},
            {"evaluation_reference": "0" * 64},
        ):
            write_json(
                self.state / "storage-demo.json",
                {
                    "candidate": {"candidate_reference": self.context["candidate_reference"]},
                    "evaluation_reference": self.context["evaluation_reference"],
                    **changes,
                },
            )
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(Rejected, "canary_candidate_storage_demo"),
                self.open(),
            ):
                self.fail("unexpected yield")
        self.disposable.assert_not_called()
        self.worker.assert_not_called()

    def test_foreign_worker_image_or_replayed_response_cannot_supply_golden(self):
        def substitution(image, request, *, timeout):
            response, execution = self.predict(image, request, timeout=timeout)
            (response if wrong_batch else execution).update(
                {"batch_id": "unrelated"} if wrong_batch else {"image_id": "wrong-image"}
            )
            return response, execution

        self.worker.side_effect = substitution
        for wrong_batch in (True, False):
            with self.assertRaises(Rejected), self.open():
                self.fail("unexpected yield")
        self.disposable.assert_not_called()

    def test_ordinary_release_must_deny_for_missing_assurance(self):
        for effect in (None, Rejected("wrong_denial")):
            with (
                patch.object(candidate.release_authorization, "verify", side_effect=effect),
                self.assertRaises(Rejected),
                self.open(),
            ):
                self.fail("unexpected yield")
        self.worker.assert_not_called()
        self.disposable.assert_not_called()

    def test_exit_rechecks_report_ledger_checkout_and_source_files_after_cleanup(self):
        for changed in ("report", "ledger", "source", "trust", "storage"):
            with self.subTest(changed=changed), self.assertRaises(Rejected), self.open():
                if changed in ("report", "trust"):
                    path = (
                        self.report_path
                        if changed == "report"
                        else self.state / "storage-trust.json"
                    )
                    original = path.read_bytes()
                    path.write_bytes(original + b" ")
                elif changed == "ledger":
                    self.ledger.return_value = {}
                elif changed == "storage":
                    self.marker.return_value = {"name": "replaced"}
                else:
                    self.source_check.return_value = {**self.source, "source_revision": "0" * 40}
            self.assertFalse(self.authority.exists())
            if changed in ("report", "trust"):
                path.write_bytes(original)
            self.ledger.return_value = {"source": "original"}
            self.marker.return_value = {"name": "source"}
            self.source_check.return_value = self.source
            self.versions.clear()
            self.install.reset_mock()

    def test_caller_error_closes_authority_and_invalidates_unused_callback(self):
        with (
            self.assertRaisesRegex(RuntimeError, "traffic stopped"),
            self.open() as (_, _, _, revoke),
        ):
            raise RuntimeError("traffic stopped")
        self.assertFalse(self.authority.exists())
        with self.assertRaises(Rejected):
            revoke()
        self.assertEqual(self.update.call_count, 1)
        self.assertEqual(self.ledger.call_count, 2)
