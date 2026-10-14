import unittest
from datetime import UTC, datetime

from mlsecops import release_authorization
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.signing import sign
from mlsecops.signing import verify as verified_payload
from scripts import release_bundle_qualification as bundle_fixtures
from scripts import release_policy_qualification as policy_fixtures
from scripts.candidate_lineage_qualification import evaluation_quality, examples


class ReleaseAuthorizationContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        bundle_fixtures.ReleaseBundleContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        bundle_fixtures.ReleaseBundleContracts.tearDownClass()

    def setUp(self):
        self.bundle = bundle_fixtures.ReleaseBundleContracts()
        self.bundle.setUp()
        self.authorities = policy_fixtures.ReleasePolicyContracts()
        self.authorities.setUp()
        self.addCleanup(self.authorities.doCleanups)
        self.clock = self.bundle.clock
        self.policy = self.authorities.policy
        self.policy.update(issued_at=self.clock - 60, expires_at=self.clock + 3600)
        self.policy["identities"]["publisher"]["public_key"] = self.bundle.materials.public
        self.policy_hash = digest(canonical(self.policy))
        self.policy_envelope = sign(self.policy, "promotion-policy", self.authorities.keys["root"])
        self.package = self.bundle.create()
        self.release = self.bundle.check(self.package)
        timestamp = datetime.fromtimestamp(self.clock, UTC).isoformat()
        self.reports = {
            gate: canonical(
                {
                    "schema_version": 1,
                    "gate": gate,
                    "status": "pass",
                    "exit_code": 0,
                    "profile": "local-cpu",
                    "source_revision": self.release["manifest"]["source_commit"],
                    "source_dirty": False,
                    "policy_digest": self.release["manifest"]["materials"]["evaluation_policy"],
                    "started_at": timestamp,
                    "finished_at": timestamp,
                    "input_digests": {
                        "release_subject": self.release["subject_sha256"],
                        "model": digest(self.bundle.materials.fixture.model),
                    },
                    "cases": [
                        {
                            "id": "controlled:contract-case",
                            "status": "pass",
                            "expected": "reject",
                            "actual": "reject",
                        }
                    ],
                    "artifact_hashes": {"controlled-fixture": "1" * 64},
                }
            )
            for gate in self.policy["required_gates"]
        }
        self.assurance = {
            "schema_version": 1,
            "issuer": "lab-assessor",
            "subject_sha256": self.release["subject_sha256"],
            "environment": "local-cpu",
            "policy_sha256": self.policy_hash,
            "issued_at": self.clock,
            "expires_at": self.clock + 1800,
            "reports": {gate: digest(content) for gate, content in self.reports.items()},
        }
        self.approval = {
            "schema_version": 1,
            "issuer": "lab-approver",
            "subject_sha256": self.release["subject_sha256"],
            "environment": "local-cpu",
            "policy_sha256": self.policy_hash,
            "issued_at": self.clock,
            "expires_at": self.clock + 1800,
            "assurance_sha256": digest(canonical(self.assurance)),
            "sequence": 1,
            "action": "promote",
        }

    def check(self, **changes):
        arguments = {
            "package": self.package,
            "policy_envelope": self.policy_envelope,
            "assurance_envelope": sign(
                self.assurance, "release-assurance", self.authorities.keys["assessor"]
            ),
            "approval_envelope": sign(
                self.approval, "release-approval", self.authorities.keys["approver"]
            ),
            "reports": self.reports,
            "context": self.bundle.materials.context,
            "trusted_root": self.authorities.public["root"],
            "expected_policy": self.policy_hash,
            "expected_serving_image": self.bundle.arguments["expected_serving_image"],
            "clock": self.clock,
        }
        return release_authorization.verify(**{**arguments, **changes})

    def test_bound_authorization_is_not_activation_or_release_readiness(self):
        result = self.check()
        self.assertTrue(result["authorization_valid"])
        self.assertFalse(result["release_ready"])
        self.assertEqual(result["state"], "authorized-not-activated")
        self.assertEqual(result, self.check())

    def test_failed_signed_model_quality_cannot_be_overridden_by_all_pass_reports(self):
        fixture = self.bundle.materials.fixture
        rows, _ = examples()
        fixture.bound["report"].update(
            evaluation_quality.summarize(
                rows, [0.5] * 400, evaluation_quality.freeze(fixture.policy)
            )
        )
        fixture.rebound_candidate()
        self.bundle.materials.context["evaluation_reference"] = fixture.evaluation_ref
        self.bundle.capsule = self.bundle.materials.create()
        package = self.bundle.create()
        self.assertEqual(self.bundle.check(package)["quality_component"], "fail")
        with self.assertRaisesRegex(Rejected, "publisher_or_quality_rejected"):
            self.check(package=package)

    def test_curator_cannot_be_release_approver_and_publisher_claim_is_bound(self):
        policy = {
            **self.policy,
            "identities": {
                **self.policy["identities"],
                "approver": {
                    "issuer": "lab-approver",
                    "public_key": self.bundle.materials.fixture.public["curator"],
                },
            },
        }
        with self.assertRaisesRegex(Rejected, "authority_not_separated"):
            self.check(
                policy_envelope=sign(policy, "promotion-policy", self.authorities.keys["root"]),
                expected_policy=digest(canonical(policy)),
            )
        payload = verified_payload(
            self.package["envelope"], "model-release", self.bundle.materials.public
        )
        invalid = {
            **self.package,
            "envelope": sign(
                {**payload, "issuer": "foreign-publisher"},
                "model-release",
                self.bundle.materials.key,
            ),
        }
        with self.assertRaisesRegex(Rejected, "publisher_or_quality_rejected"):
            self.check(package=invalid)

    def test_missing_failed_inconclusive_or_zero_check_gate_never_authorizes(self):
        for gate in self.reports:
            absent = {key: value for key, value in self.reports.items() if key != gate}
            with self.subTest(gate=gate), self.assertRaises(Rejected):
                self.check(reports=absent)
        for status in ("fail", "inconclusive", "skipped"):
            invalid = decode(self.reports["M08"])
            invalid["status"] = status
            reports = {**self.reports, "M08": canonical(invalid)}
            assurance = {
                **self.assurance,
                "reports": {gate: digest(content) for gate, content in reports.items()},
            }
            with self.subTest(status=status), self.assertRaisesRegex(Rejected, "gate_not_accepted"):
                self.check(
                    reports=reports,
                    assurance_envelope=sign(
                        assurance, "release-assurance", self.authorities.keys["assessor"]
                    ),
                )

    def test_report_semantics_remain_checked_after_hash_and_signature_update(self):
        original = decode(self.reports["M18"])
        case = original["cases"][0]
        mutations = (
            ("schema_version", True),
            ("source_dirty", True),
            ("exit_code", False),
            ("input_digests", {}),
            ("cases", []),
            ("artifact_hashes", {}),
            ("cases", [{**case, "status": "inconclusive"}]),
            ("cases", [case] * 2),
            ("cases", [{**case, "id": "invalid\ncase"}]),
            ("cases", [{**case, "actual": "allowed"}]),
            ("cases", [{**case, "actual": True, "expected": 1}]),
            ("finished_at", "not-a-time"),
            ("started_at", "2000-01-01T00:00:00+00:00"),
        )
        for field, value in mutations:
            reports = {**self.reports, "M18": canonical({**original, field: value})}
            assurance = {
                **self.assurance,
                "reports": {gate: digest(content) for gate, content in reports.items()},
            }
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.check(
                    reports=reports,
                    assurance_envelope=sign(
                        assurance, "release-assurance", self.authorities.keys["assessor"]
                    ),
                )

    def test_missing_assurance_oversized_and_wrong_report_digest_rejected(self):
        for changes, reason in (
            ({"assurance_envelope": None}, "release_assurance_required"),
            ({"reports": {**self.reports, "M18": b"x" * (1024 * 1024 + 1)}}, "reports_size_limit"),
            ({"reports": {**self.reports, "M18": b"{}"}}, "report_digest"),
        ):
            with self.assertRaisesRegex(Rejected, reason):
                self.check(**changes)
        for content in (canonical([]), canonical({})):
            reports = {**self.reports, "M18": content}
            assurance = {
                **self.assurance,
                "reports": {gate: digest(value) for gate, value in reports.items()},
            }
            with self.assertRaises(Rejected):
                self.check(
                    reports=reports,
                    assurance_envelope=sign(
                        assurance, "release-assurance", self.authorities.keys["assessor"]
                    ),
                )

    def test_authorization_windows_cannot_outlive_ancestors_or_precede_assurance(self):
        for body, kind, role in (
            ({**self.assurance, "issued_at": self.clock - 1}, "release-assurance", "assessor"),
            ({**self.approval, "expires_at": self.clock + 1801}, "release-approval", "approver"),
        ):
            with self.assertRaisesRegex(Rejected, "time_binding"):
                self.check(
                    **{
                        ("assurance_envelope" if role == "assessor" else "approval_envelope"): sign(
                            body, kind, self.authorities.keys[role]
                        )
                    }
                )
        shortened = {**self.assurance, "expires_at": self.clock + 1700}
        approval = {**self.approval, "assurance_sha256": digest(canonical(shortened))}
        with self.assertRaisesRegex(Rejected, "approval_time_binding"):
            self.check(
                assurance_envelope=sign(
                    shortened, "release-assurance", self.authorities.keys["assessor"]
                ),
                approval_envelope=sign(
                    approval, "release-approval", self.authorities.keys["approver"]
                ),
            )

    def test_assurance_cannot_precede_policy_validity(self):
        policy = {**self.policy, "issued_at": self.clock + 1}
        policy_hash = digest(canonical(policy))
        assurance = {**self.assurance, "policy_sha256": policy_hash}
        approval = {
            **self.approval,
            "policy_sha256": policy_hash,
            "assurance_sha256": digest(canonical(assurance)),
        }
        with self.assertRaisesRegex(Rejected, "time_binding"):
            self.check(
                clock=self.clock + 1,
                policy_envelope=sign(policy, "promotion-policy", self.authorities.keys["root"]),
                expected_policy=policy_hash,
                assurance_envelope=sign(
                    assurance, "release-assurance", self.authorities.keys["assessor"]
                ),
                approval_envelope=sign(
                    approval, "release-approval", self.authorities.keys["approver"]
                ),
            )

    def test_approval_cannot_change_subject_environment_policy_sequence_or_action(self):
        for field, value in (
            ("subject_sha256", "0" * 64),
            ("environment", "production"),
            ("policy_sha256", "0" * 64),
            ("assurance_sha256", "0" * 64),
            ("sequence", 2),
            ("action", "rollback"),
            ("issuer", "lab-publisher"),
            ("expires_at", self.clock),
        ):
            envelope = sign(
                {**self.approval, field: value},
                "release-approval",
                self.authorities.keys["approver"],
            )
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.check(approval_envelope=envelope)
        with self.assertRaises(Rejected):
            self.check(
                approval_envelope=sign(self.approval, "release-approval", self.bundle.materials.key)
            )


if __name__ == "__main__":
    unittest.main()
