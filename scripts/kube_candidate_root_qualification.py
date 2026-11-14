import copy
import unittest
from unittest.mock import patch

from mlsecops import kube_security_rotation, signing, trust_rotation
from mlsecops.contracts import Rejected, canonical, digest
from mlsecops.trust_targets import Target
from scripts import kube_candidate_root as native
from scripts import trust_rotation_qualification as fixtures


class CandidateRootContracts(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RotationContracts()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture
        self.previous = self.f.fixture.envelope()
        self.metadata = {
            "environment": "local-cpu",
            "root_public": self.f.old_public,
            "version": 1,
            "sha256": digest(canonical(self.previous)),
            "envelope": self.previous,
            "clock": self.f.clock,
        }
        self.states = {}
        self.receipts = {}
        self.fault = None
        self.phases = []
        self.config = {
            "trust_root": self.f.old_public,
            "minimum_trust_version": 1,
            "permit_public": signing.encode64(b"p" * 32),
            "permit_envelope": {"fixed": True},
            "expected_permit": self.f.fixture.payload["promotion_policy_sha256"],
        }
        self.expected = {"model": "a" * 64, "bundle": "b" * 64}
        for target in Target:
            self.states[target.value] = {
                "authority": {
                    "identity": {
                        "root_sha256": trust_rotation.key_id(self.f.old_public),
                        "volume": target.value,
                    },
                    "version": 1,
                    "policy_sha256": self.config["expected_permit"],
                    "revoked_artifacts": self.f.fixture.payload["revoked_artifacts"],
                    "revoked_keys": self.f.fixture.payload["revoked_keys"],
                },
                "records": {
                    "migrations": ["v1", "v2"],
                    "documents": [[1, self.metadata["sha256"]]],
                    "rotations": [],
                },
            }
        self.enterContext(
            patch.object(native.trust_root_store, "migrate", return_value={"reused": True})
        )
        self.enterContext(
            patch.object(native.trust_authority, "current", return_value=("owned", self.metadata))
        )
        self.enterContext(patch.object(native.trust_root_store, "rotate", side_effect=self.rotate))
        self.enterContext(patch.object(native.rotation, "snapshot", side_effect=self.snapshot))
        self.enterContext(
            patch.object(
                native,
                "snapshot",
                side_effect=lambda state: {
                    "models": "changed"
                    if self.fault == "models" and len(self.receipts) == 2
                    else "fixed"
                },
            )
        )
        self.enterContext(patch.object(native, "invoke", side_effect=self.invoke))
        self.enterContext(patch.object(native.time, "time", return_value=self.f.clock))
        self.observers = []
        self.enterContext(patch.object(kube_security_rotation, "update", side_effect=self.observe))

    def observe(self, state, package, *, next_root):
        self.assertEqual(self.phases, ["primary-rotated-while-live"])
        self.assertEqual(self.states[Target.PRIMARY.value]["authority"]["version"], 2)
        self.assertEqual(self.states[Target.MODEL_REVOCATION.value]["authority"]["version"], 1)
        self.assertEqual(next_root, self.f.new_public)
        self.assertEqual(
            digest(canonical(package)), self.receipts[Target.PRIMARY.value]["rotation_sha256"]
        )
        self.observers.append(next_root)
        if self.fault == "observer":
            raise Rejected("observer_transition_failed")
        return {"release_ready": False, "reused": False}

    def test_observer_updates_primary_after_live_probe_before_separate_peer(self):
        report = self.exercise()
        self.assertEqual(self.observers, [self.f.new_public])
        self.assertEqual(report["observer_transition"], {"release_ready": False, "reused": False})

    def test_observer_failure_does_not_rotate_peer_or_restore_primary(self):
        self.fault = "observer"
        with self.assertRaisesRegex(Rejected, "observer_transition_failed"):
            self.exercise()
        self.assertEqual(self.states[Target.PRIMARY.value]["authority"]["version"], 2)
        self.assertEqual(self.states[Target.MODEL_REVOCATION.value]["authority"]["version"], 1)

    def snapshot(self, state, *, target=Target.PRIMARY):
        return copy.deepcopy(self.states[target.value])

    def rotate(self, state, package, *, current_root, next_root, backend):
        target = getattr(backend, "keywords", {}).get("target", Target.PRIMARY)
        trust_rotation.verify(
            package,
            previous=self.previous,
            environment="local-cpu",
            current_root=current_root,
            next_root=next_root,
            clock=self.f.clock,
        )
        if target.value in self.receipts:
            return {**self.receipts[target.value], "reused": self.fault != "retry"}
        if self.fault == "write-failed" or (
            self.fault == "peer-write-failed" and target is Target.MODEL_REVOCATION
        ):
            raise Rejected("injected_write_failure")
        payload = signing.verify(package["document"], "trust-policy", next_root)
        receipt = {
            "state": "rotated-not-activated",
            "version": 2,
            "document_sha256": digest(canonical(package["document"])),
            "rotation_sha256": digest(canonical(package)),
            "root_sha256": trust_rotation.key_id(next_root),
            "reused": False,
            "release_ready": False,
        }
        self.receipts[target.value] = receipt
        row = self.states[target.value]
        row["authority"].update(version=2, revoked_keys=payload["revoked_keys"])
        row["authority"]["identity"]["root_sha256"] = receipt["root_sha256"]
        row["records"]["documents"].append([2, receipt["document_sha256"]])
        row["records"]["rotations"].append([2, receipt["rotation_sha256"]])
        if self.fault == "peer-change" and target is Target.PRIMARY:
            self.states[Target.MODEL_REVOCATION.value]["authority"]["version"] = 99
        if self.fault == "receipt":
            return {**receipt, "release_ready": True}
        return receipt

    def invoke(self, state, profile, config, expected, *, coordinator, candidate_probe):
        self.assertEqual(config, self.config)
        self.assertTrue(candidate_probe)
        self.assertEqual(expected["fault"], "root-rotation")
        if self.fault == "wrong-phase":
            coordinator("denied")
        coordinator("ready")
        self.phases.append("primary-rotated-while-live")
        self.assertEqual(self.states["primary"]["authority"]["version"], 2)
        if self.fault != "missing-phase":
            coordinator("denied")
        if self.fault == "duplicate-phase":
            coordinator("denied")
        wanted = {
            "qualification-permit-payload": self.config["expected_permit"],
            "qualification-permit-envelope": digest(canonical(self.config["permit_envelope"])),
            "root-recovery-permit-payload": self.config["expected_permit"],
            "root-recovery-permit-envelope": digest(canonical(self.config["permit_envelope"])),
            "golden-status": 200,
            "trust-fault-initial-prediction": True,
            "cold-reader-root-rotation": True,
            "no-automatic-reactivation": True,
            "trust-fault-readiness-503": True,
            "trust-fault-complete-trace": True,
            "root-recovery-golden-status": 200,
            "root-recovery-golden-model": self.expected["model"],
            "root-recovery-golden-bundle": self.expected["bundle"],
            "root-recovery-golden-parity-1e-6": True,
            "root-recovery-worker-absence": 0,
            "root-recovery-worker-cleanup": 0,
            "final-worker-absence": 0,
        }
        report = {
            "status": "pass",
            "release_ready": False,
            "authority_target": "primary",
            "model_sha256": self.expected["model"],
            "subject_sha256": self.expected["bundle"],
            "max_golden_error": 0.0,
            "root_recovery": {**expected["root_recovery"], "max_golden_error": 0.0},
            "cases": [
                {"id": k, "actual": v, "expected": v, "status": "pass"} for k, v in wanted.items()
            ],
            "lifecycle": {
                "fault": "root-rotation",
                "first_503_seconds": 1.1,
                "observations": 2,
                "trace": [
                    {"start_seconds": 1.0, "end_seconds": 1.1, "http_status": 503},
                    {"start_seconds": 2.0, "end_seconds": 2.1, "http_status": 503},
                ],
            },
        }
        if self.fault == "wrong-model":
            report["model_sha256"] = "c" * 64
        if self.fault == "missing-cold":
            report["cases"] = report["cases"][:2]
        if self.fault == "false-green":
            report["cases"][0]["actual"] = 503
        if self.fault == "late-denial":
            report["lifecycle"]["first_503_seconds"] = 61
        if self.fault == "late-ML":
            report["lifecycle"]["trace"][-1]["http_status"] = 200
        if self.fault == "nonfinite":
            report["lifecycle"]["trace"][-1]["end_seconds"] = float("inf")
        if self.fault == "wrong-recovery":
            report["root_recovery"]["trust_root"] = self.f.old_public
        if self.fault == "changed-permit":
            case = next(c for c in report["cases"] if c["id"] == "root-recovery-permit-envelope")
            case.update(actual="f" * 64, expected="f" * 64)
        if self.fault == "initial-200":
            report["lifecycle"]["trace"].insert(
                0, {"start_seconds": 0.1, "end_seconds": 0.2, "http_status": 200}
            )
            report["lifecycle"]["observations"] = 3
        return report

    def exercise(self, **options):
        return native.exercise(
            "state",
            "profile",
            self.config,
            self.expected,
            old_key=self.f.old_key,
            new_key=self.f.new_key,
            expires_at=self.f.clock + 600,
            **options,
        )

    def test_outer_owner_injects_raw_probe_without_nested_handoff(self):
        with patch.object(native, "invoke", side_effect=AssertionError("nested handoff")):
            report = self.exercise(probe=self.invoke)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(self.observers, [self.f.new_public])

    def test_failed_peer_does_not_restore_primary_or_observer(self):
        self.fault = "peer-write-failed"
        with self.assertRaisesRegex(Rejected, "injected_write_failure"):
            self.exercise()
        self.assertEqual(self.observers, [self.f.new_public])
        self.assertEqual(self.states[Target.PRIMARY.value]["authority"]["version"], 2)
        self.assertEqual(self.states[Target.MODEL_REVOCATION.value]["authority"]["version"], 1)

    def test_failed_live_trace_does_not_update_observer_or_peer(self):
        self.fault = "late-denial"
        with self.assertRaisesRegex(Rejected, "candidate_root_trace"):
            self.exercise()
        self.assertEqual(self.observers, [])
        self.assertEqual(self.states[Target.PRIMARY.value]["authority"]["version"], 2)
        self.assertEqual(self.states[Target.MODEL_REVOCATION.value]["authority"]["version"], 1)

    def test_live_primary_then_explicit_peer_rotation_preserves_one_permit(self):
        before = copy.deepcopy(self.config)
        report = self.exercise()
        self.assertEqual(report["status"], "pass")
        self.assertFalse(report["release_ready"])
        self.assertEqual(self.config, before)
        self.assertEqual(report["next_public"], self.f.new_public)
        self.assertEqual(report["minimum_trust_version"], 2)
        self.assertEqual(set(report["authorities"]), {"primary", "model-revocation"})
        self.assertEqual(self.phases, ["primary-rotated-while-live"])

    def test_failed_trace_or_binding_cannot_be_published_as_success(self):
        for fault in (
            "wrong-model",
            "missing-cold",
            "false-green",
            "late-denial",
            "late-ML",
            "nonfinite",
            "wrong-recovery",
            "peer-change",
            "wrong-phase",
            "duplicate-phase",
            "write-failed",
            "receipt",
            "retry",
            "models",
            "missing-phase",
            "changed-permit",
        ):
            case = CandidateRootContracts()
            case.setUp()
            try:
                case.fault = fault
                with self.subTest(fault=fault), self.assertRaises(Rejected):
                    case.exercise()
            finally:
                case.doCleanups()

    def test_valid_trace_can_include_a_pre_denial_prediction(self):
        self.fault = "initial-200"
        self.assertEqual(self.exercise()["probe"]["lifecycle"]["observations"], 3)

    def test_same_permit_root_and_short_lifetime_reject_before_mutation(self):
        with patch.object(native.trust_root_store, "migrate") as migrate:
            self.config["permit_public"] = self.config["trust_root"]
            with self.assertRaisesRegex(Rejected, "candidate_root_key_separation"):
                self.exercise()
            self.config["permit_public"] = signing.encode64(b"p" * 32)
            with self.assertRaisesRegex(Rejected, "candidate_root_window"):
                native.exercise(
                    "state",
                    "profile",
                    self.config,
                    self.expected,
                    old_key=self.f.old_key,
                    new_key=self.f.new_key,
                    expires_at=self.f.clock + 179,
                )
            migrate.assert_not_called()


class SuspendedObserverContracts(unittest.TestCase):
    """Real marker/signature/resource validators over an in-memory cluster."""

    def setUp(self):
        from mlsecops import kube_serving_handoff as handoff
        from scripts import kube_observer_profile_qualification as profiles
        from scripts import kube_security_events_qualification as audit
        from scripts.kube_promotion_native import configuration
        from scripts.kube_serving_runtime_qualification import PROFILE

        self.handoff = handoff
        self.fx = audit.AuditBootstrap()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.rotation = profiles.ObserverProfile()
        self.rotation.setUp()
        self.addCleanup(self.rotation.doCleanups)
        self.fx.world()
        self.fx.profile = PROFILE
        self.fx.context["initial_root"] = self.rotation.fx.old_public
        self.audit = self.fx.bootstrap()
        self.state = self.fx.directory
        service = handoff.service
        promotion = configuration(
            "/client",
            "/trust-client",
            dict(
                context={"policy": {"environment": "local-cpu"}},
                trusted_root="root",
                expected_policy="a" * 64,
                expected_serving_image=PROFILE["image_id"],
            ),
            self.rotation.fx.old_public,
        )
        config = service.configuration(promotion, PROFILE)
        documents = service.documents(self.fx.workspace, PROFILE, config)
        for document in documents:
            document["metadata"]["uid"] = "serving-" + document["kind"]
            if document["kind"] == "Deployment":
                document["spec"]["replicas"] = 0
            self.fx.objects[service.kube_storage.reference(document)] = copy.deepcopy(document)
        self.serving = dict(
            schema_version=1,
            ready=False,
            handoff="f" * 32,
            workspace_id=self.fx.workspace,
            profile=PROFILE,
            config=config,
            config_sha256=digest(canonical(config)),
            audit_pin=self.audit["pins"]["serving"],
            resources={service.kube_storage.reference(d): d["metadata"]["uid"] for d in documents},
        )
        self.fx.subject.save(service.directory(self.state), self.serving)
        self.ticket = dict(
            nonce=self.serving["handoff"],
            marker_sha256=digest(canonical(self.serving)),
            previous="old-serving-pod",
        )
        self.enterContext(patch.object(service, "workspace_id", return_value=self.fx.workspace))
        self.enterContext(
            patch.object(kube_security_rotation.io, "history", return_value=self.rotation.history)
        )
        self.enterContext(
            patch.object(
                kube_security_rotation.io,
                "outbox",
                return_value={"pin": self.audit["pins"]["trust"]},
            )
        )
        self.enterContext(
            patch.object(
                kube_security_rotation.io, "pod", return_value={"metadata": {"uid": "old-observer"}}
            )
        )

        def replace(state, marker, before, after):
            key = service.kube_storage.reference(before)
            service.kube_storage.verify_resource(
                before, self.fx.objects[key], marker["resources"][key]
            )
            document = copy.deepcopy(after)
            document["metadata"]["uid"] = marker["resources"][key]
            self.fx.objects[key] = document

        self.enterContext(patch.object(kube_security_rotation, "replace", side_effect=replace))
        self.enterContext(patch.object(kube_security_rotation, "wait_empty"))
        self.observed = self.enterContext(
            patch.object(
                kube_security_rotation,
                "wait_observed",
                return_value={"first_source_check_confirmed": True},
            )
        )
        self.assertEqual(handoff.ticket_marker(self.state, self.ticket), self.serving)

    def update(self):
        return kube_security_rotation.update(
            self.state, self.rotation.package, next_root=self.rotation.fx.new_public
        )

    def test_observer_updates_with_suspended_serving_and_preserves_exact_return_ticket(self):
        before = canonical(self.serving)
        report = self.update()
        self.assertTrue(report["first_source_check_confirmed"])
        self.assertFalse(report["release_ready"])
        # Real audit.validate checks collector/observer and their owned resources,
        # not a live persistent serving Pod. The original root remains authorized.
        after = self.handoff.ticket_marker(self.state, self.ticket)
        self.assertEqual(canonical(after), before)
        self.assertEqual(self.fx.state_marker()["pins"], self.audit["pins"])
        self.assertTrue(self.fx.state_marker()["ready"])

    def test_interrupted_observer_blocks_return_without_repairing_ready_or_old_root(self):
        self.observed.side_effect = Rejected("observer_delivery_unconfirmed")
        with self.assertRaisesRegex(Rejected, "observer_delivery_unconfirmed"):
            self.update()
        self.assertFalse(self.fx.state_marker()["ready"])
        self.assertEqual(
            self.fx.state_marker()["observer"]["history"]["root_public"],
            self.rotation.fx.new_public,
        )
        with self.assertRaisesRegex(Rejected, "kube_security_profile_incomplete_or_changed"):
            self.handoff.ticket_marker(self.state, self.ticket)


if __name__ == "__main__":
    unittest.main()
