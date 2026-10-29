import copy
import unittest
from unittest.mock import patch

from mlsecops import signing, trust_rotation
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
        if self.fault == "write-failed":
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

    def exercise(self):
        return native.exercise(
            "state",
            "profile",
            self.config,
            self.expected,
            old_key=self.f.old_key,
            new_key=self.f.new_key,
            expires_at=self.f.clock + 600,
        )

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


if __name__ == "__main__":
    unittest.main()
