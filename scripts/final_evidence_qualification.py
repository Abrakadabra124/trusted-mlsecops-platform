"""Offline M18 tests. Fixtures attest only their own simulated observations."""

import copy
import os
import shutil
import unittest
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mlsecops import acceptance, data_source
from mlsecops import final_evidence as final
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest, now, write_json
from mlsecops.signing import create_key, sign
from scripts import release_authorization_qualification as releases
from scripts.image_audit_qualification import fixtures as image_fixture

ROOT = Path(__file__).resolve().parents[1]


class FinalEvidenceContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        releases.ReleaseAuthorizationContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        releases.ReleaseAuthorizationContracts.tearDownClass()

    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.state = self.root / ".runtime"
        self.enterContext(patch.dict(os.environ))
        os.environ.pop("M18_INDEX_SHA256", None)
        os.environ.pop("M18_PLAN_SHA256", None)
        os.environ.pop("M18_DELIVERY_SHA256", None)

    def put(self, document):
        return final.retain(self.state, canonical(document))

    def pinfile(self, path, document):
        write_json(self.state / path, document)
        return digest(bounded_read(self.state / path))

    def build(self):
        self.release = releases.ReleaseAuthorizationContracts()
        self.release.setUp()
        self.addCleanup(self.release.doCleanups)
        bundle = self.release.bundle
        fixture = bundle.materials.fixture
        for name in data_source.INPUTS:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        write_json(self.root / "policies/local-cpu.json", fixture.policy)
        lock = dict(
            schema_version=1,
            stage="synthetic-source-v1",
            inputs=data_source.inputs(self.root),
            output=dict(sha256=digest(b"controlled source"), bytes=17),
        )
        write_json(self.root / "data.lock", lock)
        fixture.lineage.update(
            source_sha256=lock["output"]["sha256"],
            lock_sha256=digest(bounded_read(self.root / "data.lock")),
            inputs=lock["inputs"],
        )
        fixture.lineage_id = digest(canonical(fixture.lineage))
        fixture.statement.update(
            lineage_id=fixture.lineage_id,
            quarantine_object=lock["output"]["sha256"],
            lineage_object=fixture.signed("lineage", fixture.lineage, "data-lineage", "curator"),
        )
        fixture.dataset_ref = fixture.signed(
            "manifests", fixture.statement, "stored-dataset", "curator"
        )
        fixture.record["dataset_reference"] = fixture.dataset_ref
        fixture.metadata["lineage_id"] = fixture.lineage_id
        fixture.bound.update(dataset_reference=fixture.dataset_ref, lineage_id=fixture.lineage_id)
        fixture.rebound_candidate()
        bundle.materials.context.update(
            candidate_reference=fixture.candidate_ref, evaluation_reference=fixture.evaluation_ref
        )
        bundle.capsule = bundle.materials.create()
        bundle.attributes["issued_at"] -= 60
        self.package = bundle.create()
        self.verified = bundle.check(self.package)
        final.retain_package(self.state, self.package)
        self.source = fixture.expected.copy()
        self.time = now()
        self.latest = final.timestamp(self.time)
        self.keys = {
            **fixture.public,
            "approver": bundle.materials.public,
            "trust": self.release.authorities.public["root"],
        }
        self.proposal = dict(
            schema_version=1,
            scope="release-proposal-and-authorization-denial-not-full-M10",
            status="pass",
            full_M10="inconclusive",
            release_ready=False,
            source_dirty=False,
            source=self.source,
            started_at=self.time,
            finished_at=self.time,
            cases=[
                "actual-candidate-without-assurance-denied",
                "actual-promotion-admission-without-assurance-denied",
            ],
            proposal_reference=digest(canonical(self.package["envelope"])),
            subject_sha256=self.verified["subject_sha256"],
            model_sha256=digest(fixture.model),
            policy_sha256=self.release.policy_hash,
        )
        self.freeze = {
            "evidence/release-native.json": self.pinfile(
                "evidence/release-native.json", self.proposal
            ),
            "trusted-keys.json": self.pinfile("trusted-keys.json", self.keys),
            "storage-trust.json": self.pinfile("storage-trust.json", fixture.trust),
            "storage-demo.json": self.pinfile(
                "storage-demo.json",
                dict(
                    candidate=dict(
                        candidate_reference=fixture.candidate_ref, metadata=fixture.metadata
                    ),
                    evaluation=fixture.bound,
                    evaluation_reference=fixture.evaluation_ref,
                    dataset=dict(
                        dataset_reference=fixture.dataset_ref,
                        dataset_id=fixture.dataset_id,
                        lineage_id=fixture.lineage_id,
                        source_approval_digest=fixture.trust["source_approval_digest"],
                    ),
                ),
            ),
        }
        self.index = dict(
            schema_version=1,
            **self.source,
            freeze=self.freeze,
            reports={},
            policy_reference=self.put(self.release.policy_envelope),
        )
        self.values, _, _ = final.frozen(
            self.root,
            self.state,
            self.index,
            self.source["source_revision"],
            self.source["source_fingerprint"],
        )
        self.review_key = self.root / "reviewer.pem"
        reviewer = create_key(self.review_key)
        self.plan = dict(
            schema_version=1,
            source_revision=self.source["source_revision"],
            source_fingerprint=self.source["source_fingerprint"],
            reviewer_key=reviewer,
            modules=["mlsecops/final_evidence.py"],
            cases={},
            artifacts={},
            rejections={"M02": {}, "M03": {}},
            image_packages={
                "debian/" + role: ["libc6", "postgresql-18"]
                for role in ("storage", "tracking", "worker")
            },
        )
        self.reports = {}
        self.primaries = {}
        self.placeholder = self.put({"controlled": "artifact"})
        for gate in final.CHILDREN:
            cases = [dict(id="controlled-check", expected=True, actual=True, status="pass")]
            inputs = {
                k: self.values[k] for k in ("source_fingerprint", *final.BINDINGS[gate].split())
            }
            if gate in {"M08", "M22"}:
                inputs["source"] = self.values["source_fingerprint"]
            if gate == "M06":
                inputs["source"] = digest(
                    canonical(
                        {k: self.values[k] for k in ("source_fingerprint", "source_revision")}
                    )
                )
            inputs.update({k: self.placeholder for k in final.OTHER_INPUTS.get(gate, "").split()})
            if gate == "M06":
                inputs["mutated_worker_image"] = "sha256:" + self.placeholder
            self.reports[gate] = dict(
                schema_version=1,
                gate=gate,
                profile="local-cpu",
                source_revision=self.source["source_revision"],
                policy_digest=self.values["policy"],
                redaction_version=1,
                status="pass",
                exit_code=0,
                source_dirty=False,
                release_ready=False,
                started_at=self.time,
                finished_at=self.time,
                residual_risks=["Controlled unit fixture"],
                cases=cases,
                input_digests=inputs,
                artifact_hashes={
                    k: self.placeholder for k in final.REQUIRED_ARTIFACTS.get(gate, "").split()
                },
                metrics=dict(checks=1, rows=fixture.policy["rows"], independent_challenges=2),
            )
            self.primaries[gate] = dict(status="pass", cases=cases)
        self.primaries["M01"].update(
            inventory=dict(
                **{k: v for k, v in self.source.items() if k != "image_id"}, source_dirty=False
            ),
            materials={"controlled": True},
            pods=[dict(image_id=self.source["image_id"])],
            images={"worker": dict(image_id=self.source["image_id"])},
        )
        self.reports["M01"]["input_digests"].update(
            {k: digest(canonical(self.primaries["M01"][k])) for k in ("inventory", "materials")}
        )
        self.primaries["M02"].update(
            source_sha256=self.values["source"],
            source_lock_digest=self.values["data_lock"],
            policy_digest=self.values["policy"],
            rows=fixture.policy["rows"],
        )
        self.primaries["M03"].update(
            source_sha256=self.values["source"],
            source_lock_digest=self.values["data_lock"],
            candidate_reference=self.values["candidate_reference"],
            dataset_reference=self.values["dataset_reference"],
            execution=dict(image_id=self.values["image_id"]),
            storage_inputs=dict(config_digest=self.placeholder),
        )
        self.primaries["M04"].update(
            dataset_reference=self.values["dataset_reference"], cluster_namespace_uid="cluster"
        )
        self.primaries["M05"].update(
            candidate_reference=self.values["candidate_reference"],
            model_sha256=self.values["model"],
            serving_under_fault=dict(
                bundle_sha256=self.values["release_subject"], model_sha256=self.values["model"]
            ),
        )
        self.reports["M06"]["artifact_hashes"]["model:repeat-1"] = self.values["model"]
        self.reports["M06"]["input_digests"]["dataset"] = self.placeholder
        replay = dict(
            candidate=dict(
                model_digest=self.values["model"],
                auprc=self.values["evaluation_auprc"],
                run_id="actual",
                inputs={
                    **{
                        k: self.reports["M06"]["input_digests"][k]
                        for k in ("request", "policy", "source", "environment", "golden")
                    },
                    "dataset": self.values["dataset"],
                },
            ),
            protocol=self.values["prediction_protocol"],
            split_materials=self.values["split_materials"],
            reference_runs=["repeat1", "repeat2", "repeat3"],
        )
        self.reports["M06"]["artifact_hashes"]["candidate_replay"] = self.put(replay)
        self.reports["M06"]["cases"].append(
            dict(
                id="signed-candidate-three-fresh-repeats",
                expected=dict(probability_max=1e-6, auprc_max=1e-4),
                actual=dict(probability=1e-7, auprc=1e-5),
                status="pass",
            )
        )
        self.reports["M06"]["metrics"]["checks"] = 2
        self.reports["M20"]["artifact_hashes"].update(
            {k: self.placeholder for k in ("access", "controller", "isolation")}
        )
        self.primaries["M22"].update(scope="M22-absolute-matrix-and-frozen-review")
        self.make_challenges()
        for gate, key in final.PRIMARY.items():
            self.reports[gate]["artifact_hashes"][key] = self.put(self.primaries[gate])
        first = dict(
            subject_sha256=self.placeholder,
            proposal_reference=self.placeholder,
            sequence=1,
            release_ready=False,
            state="recorded-not-activated",
        )
        m10 = dict(
            scope="T13-pre-promotion-mechanism-actual-refusal-separate-controlled-authorization",
            actual_subject=self.values["release_subject"],
            actual_model=self.values["model"],
            actual_proposal=self.package["envelope"],
            actual_policy=self.release.policy_envelope,
            input_files=self.freeze,
            actual=dict(
                request=dict(
                    proposal_reference=self.values["proposal_reference"],
                    policy_reference=self.values["policy_reference"],
                    approval_reference=None,
                    assurance_reference=None,
                ),
                reason="release_assurance_required",
                before=dict(head=dict(sequence=0)),
                after=dict(head=dict(sequence=0)),
            ),
            controlled=dict(
                subject=self.placeholder,
                request=dict(proposal_reference=self.placeholder),
                first=first,
                retry=first,
                committed=dict(head=dict(sequence=1)),
            ),
        )
        self.reports["M10"]["artifact_hashes"]["promotion_primary"] = self.put(m10)
        self.reports["M10"]["metrics"].update(
            actual_release_authorization="inconclusive", actual_sequence=0, controlled_sequence=1
        )
        for gate, key in (
            ("M10", "actual_proposal_report"),
            ("M16", "proposal_packet"),
            ("M17", "proposal_packet"),
            ("M19", "proposal"),
            ("M23", "candidate-outage-proposal_sha256"),
        ):
            self.reports[gate]["artifact_hashes"][key] = self.freeze["evidence/release-native.json"]
            # File hashes are also retained as raw preimages.
        for path in self.freeze:
            final.retain(self.state, bounded_read(self.state / path))
        for gate in ("M17", "M19"):
            self.reports[gate]["artifact_hashes"]["demo"] = self.freeze["storage-demo.json"]
        self.reports["M17"]["artifact_hashes"]["public_keys"] = self.put(self.keys)
        self.reports["M19"]["artifact_hashes"]["public_keys"] = self.freeze["trusted-keys.json"]
        fleet = {"controlled": "four deployments"}
        self.reports["M19"]["artifact_hashes"].update(
            primary=self.put(dict(schema_version=2, fleet=fleet)), fleet=self.put(fleet)
        )
        self.reports["M17"]["artifact_hashes"]["backup_id"] = self.placeholder
        authority = self.reports["M20"]["artifact_hashes"]
        self.reports["M04"]["artifact_hashes"].update(
            authority=authority[final.PRIMARY["M20"]],
            **{k: authority[k] for k in ("access", "controller", "isolation")},
        )
        self.reports["M05"]["artifact_hashes"].update(
            access=self.put(self.primaries["M04"]), isolation=self.placeholder
        )
        self.make_governance()
        self.index["retained"] = {}
        for gate in ("M13", "M15"):
            private = dict(
                scope="actual-candidate-kubernetes-inference",
                source_dirty=False,
                source=self.source,
                **{
                    k: self.values[k]
                    for k in (
                        "candidate_reference",
                        "proposal_reference",
                        "model_sha256",
                        "subject_sha256",
                    )
                },
                started_at=self.time,
                finished_at=self.time,
                artifact_hashes=dict(observation=self.placeholder),
            )
            self.index["retained"][gate] = self.put(
                dict(
                    private_observation=self.put(private),
                    retained_packets=dict(trace=self.placeholder),
                )
            )
        self.seal()
        self.enterContext(patch.object(acceptance, "command", side_effect=self.git))
        self.enterContext(
            patch.object(
                acceptance, "source_fingerprint", return_value=self.source["source_fingerprint"]
            )
        )
        self.enterContext(patch.object(final, "command", side_effect=self.git))
        self.enterContext(
            patch.object(
                final, "source_fingerprint", return_value=self.source["source_fingerprint"]
            )
        )

    def git(self, arguments):
        self.assertEqual(arguments[0], "git")
        return "" if "status" in arguments else self.source["source_revision"]

    def make_challenges(self):
        inputs = {
            k: v
            for k, v in self.reports["M22"]["input_digests"].items()
            if k != "source_fingerprint"
        }
        snapshot = self.put({"run.json": self.placeholder})
        refs = self.reports["M22"]["artifact_hashes"]
        refs["primary_materials"] = snapshot
        from scripts.absolute_poisoning import matrix as prescribed_matrix

        records = [
            dict(id=c["id"], metrics=dict(status="pass"), run_id=c["id"])
            for c in prescribed_matrix()
        ]
        matrix = self.put(dict(input_digests=inputs, records=records))
        cases = [dict(id=c["id"], status="pass") for c in records] + [
            dict(id="review-" + f, status="pass") for f in ("label-flip", "backdoor")
        ]
        self.reports["M22"]["cases"] = cases
        self.reports["M22"]["metrics"]["checks"] = len(cases)
        self.primaries["M22"]["cases"] = cases
        binding = dict(
            inputs=inputs,
            revision=self.source["source_revision"],
            campaign_id="campaign",
            primary_sha256=snapshot,
            matrix_report_sha256=matrix,
            policy_sha256=self.values["policy"],
        )
        methods = {
            f + ext: self.put(dict(method=f, extension=ext))
            for f in ("label-flip", "backdoor")
            for ext in (".md", ".json")
        }
        freeze = sign(
            dict(binding=binding, reviewer="external-reviewer", frozen_at=self.time, files=methods),
            "m22-freeze",
            self.review_key,
        )
        intake = dict(
            campaign_id="campaign",
            reviewer_key=self.plan["reviewer_key"],
            owner="owner",
            received_at=self.time,
            freeze=freeze,
        )
        key = self.release.bundle.materials.key
        refs["review_intake"] = self.put(sign(intake, "m22-intake", key))
        approval = sign(
            dict(
                intake_sha256=refs["review_intake"],
                matches_frozen_methods=True,
                checked_at=self.time,
            ),
            "m22-methods",
            self.review_key,
        )
        refs["review_primary"] = self.put({**methods, "methods.dsse.json": self.put(approval)})
        observations = dict(
            intake_sha256=refs["review_intake"],
            primary_sha256=refs["review_primary"],
            outcomes=[
                dict(id="review-" + f, run_id=f, metrics=dict(status="pass"))
                for f in ("label-flip", "backdoor")
            ],
            finished_at=self.time,
        )
        refs["review_observations"] = self.put(sign(observations, "m22-observations", key))
        decision = dict(
            observations_sha256=digest(canonical(observations)),
            decided_at=self.time,
            findings={
                f: dict(
                    decision="pass", hard_boundary_bypass=False, result_md_sha256=self.placeholder
                )
                for f in ("label-flip", "backdoor")
            },
        )
        refs["review_decision"] = self.put(sign(decision, "m22-decision", self.review_key))

    def make_images(self):
        from scripts import image_audit as audit

        sbom, scan, _, _, _ = image_fixture()
        image = self.values["image_id"]
        sbom["source"]["metadata"]["imageID"] = image
        scan["source"]["target"]["imageID"] = image
        scan["descriptor"]["db"]["status"]["built"] = self.time
        result = audit.assess(sbom, scan, image, {"libc6", "postgresql-18"}, 0, self.latest)
        components = [
            dict(
                **result,
                name=name,
                scan_executed=True,
                sbom_validated=True,
                image_config_id=image,
                runtime_image_id=image,
                catalogued_packages=2,
                coverage_profile=name if name in ("worker", "storage", "tracking") else "worker",
                sbom_digest=self.put(sbom),
                report_digest=self.put(scan),
            )
            for name in ("worker", "storage", "tracking", "runtime-000")
        ]
        snapshot = dict(
            **{k: v for k, v in self.source.items() if k != "image_id"},
            schema_version=1,
            workspace_id="workspace",
            cluster_uid="cluster",
            controller_profile=self.source,
            containers=[
                dict(role=role, image_id=image)
                for role in ("workspace", "kind-node", "tracking-pg", "tracking-server")
            ],
            pods=[dict(image_id=image)],
            targets=[dict(name="runtime-000", reference=image, config_id=image)],
        )
        self.snapshot = snapshot

        def control(package, version, kind, advisory):
            c = copy.deepcopy(scan)
            c["matches"] = [
                dict(
                    artifact=dict(name=package, version=version, type=kind),
                    vulnerability=dict(id=advisory, severity="High"),
                )
            ]
            if kind == "apk":
                c["distro"] = dict(name="wolfi", version="20230201")
            return self.put(c)

        policy = {
            **audit.POLICY,
            "id": "observed-runtime-images-v1",
            "scope": [*audit.POLICY["scope"], "owned-runtime"],
        }
        self.audit = dict(
            **{k: v for k, v in self.source.items() if k != "image_id"},
            scope="observed-runtime-image-audit-only",
            status="pass",
            source_dirty=False,
            release_ready=False,
            policy=policy,
            policy_digest=digest(canonical(policy)),
            scanner_images=dict(syft=audit.SYFT_IMAGE, grype=audit.GRYPE_IMAGE),
            started_at=self.time,
            completed_at=self.time,
            detection_control="pass",
            wolfi_detection_control="pass",
            detection_control_digest=control("urllib3", "1.26.7", "python", "GHSA-v845-jxx5-vc9f"),
            control_observation=dict(exit_code=2),
            wolfi_detection_control_digest=control("openssl", "3.0.7-r0", "apk", "CVE-2023-0286"),
            wolfi_control_observation=dict(exit_code=2),
            components=components,
            runtime_scope=audit.image_scope.coverage(snapshot, components),
            vulnerability_count=0,
            go_detection_controls={
                kind: dict(
                    status="pass",
                    exit_code=2,
                    report_digest=control(
                        package, version, "go-module", sorted(audit.GO_CONTROL_ADVISORIES)[0]
                    ),
                )
                for kind, (package, version) in audit.GO_CONTROLS.items()
            },
        )
        return dict(
            runtime_before=self.put(snapshot),
            runtime_after=self.put(snapshot),
            image_audit=self.put(self.audit),
        )

    def make_governance(self):
        refs = self.make_images()
        self.cov = dict(
            meta=dict(branch_coverage=True),
            files={
                "mlsecops/final_evidence.py": dict(
                    summary=dict(num_branches=2, covered_branches=2, missing_branches=0),
                    executed_branches=[[1, 2], [1, 3]],
                    missing_branches=[],
                )
            },
        )
        refs["coverage"] = self.put(self.cov)
        for card in final.CARDS:
            path = self.root / card
            path.parent.mkdir(exist_ok=True, parents=True)
            shutil.copyfile(ROOT / card, path)
            refs[card] = digest(bounded_read(path))
        for kind in final.REVIEWS:
            note = dict(
                kind=kind,
                subject_sha256=self.values["release_subject"],
                decision="pass",
                observation="Controlled unit fixture observation",
                evidence=[self.placeholder],
            )
            if kind == "teardown":
                note.update(
                    before=self.put(
                        dict(
                            workspace_id="workspace",
                            owned=["container"],
                            observed_at=(self.latest - timedelta(seconds=1)).isoformat(),
                        )
                    ),
                    after=self.put(dict(workspace_id="workspace", owned=[], observed_at=self.time)),
                )
            if kind == "retention":
                note["inventory"] = self.put(
                    dict(
                        subject_sha256=self.values["release_subject"],
                        backup_id=self.placeholder,
                        observed_at=self.time,
                        retain_until=(self.latest + timedelta(days=1)).isoformat(),
                    )
                )
            if kind == "expiry":
                note["proposal_expires_at"] = self.values["proposal_expires_at"]
            refs[kind] = self.put(note)
        self.index["governance"] = refs

    def seal(self):
        for gate, report in self.reports.items():
            self.index["reports"][gate] = self.pinfile("evidence/" + gate + ".json", report)
            self.plan["cases"][gate] = digest(canonical(sorted(c["id"] for c in report["cases"])))
            self.plan["artifacts"][gate] = digest(canonical(sorted(report["artifact_hashes"])))
        self.index["plan"] = self.pinfile("evidence/M18-plan.json", self.plan)
        os.environ["M18_PLAN_SHA256"] = self.index["plan"]
        refs = self.index["governance"]
        self.review = dict(
            scope="local-cpu",
            decision="pass",
            plan=self.index["plan"],
            reports=self.index["reports"],
            retained=self.index["retained"],
            source_revision=self.values["source_revision"],
            subject_sha256=self.values["release_subject"],
            model_sha256=self.values["model"],
            governance={k: v for k, v in refs.items() if k != "review"},
            reviewed_at=self.time,
        )
        refs["review"] = self.put(sign(self.review, "final-evidence-review", self.review_key))
        self.repin_index()

    def repin_index(self):
        os.environ["M18_INDEX_SHA256"] = self.pinfile(final.INDEX, self.index)

    def run_report(self):
        return acceptance.report("M18", "local-cpu", self.root, self.state)

    def test_missing_owner_pin_reports_inconclusive_without_running_child_gates(self):
        report = acceptance.report("M18", "local-cpu", ROOT, self.state)
        self.assertEqual((report["status"], report["exit_code"]), ("inconclusive", 2))
        self.assertIn("M18_INDEX_SHA256", report["residual_risks"][0])
        self.assertIs(report["release_ready"], False)

    def test_substituted_owner_index_fails_without_echoing_contents(self):
        self.pinfile(final.INDEX, {"private": "do-not-echo"})
        os.environ["M18_INDEX_SHA256"] = digest(b"original")
        report = acceptance.report("M18", "local-cpu", ROOT, self.state)
        self.assertEqual(report["status"], "fail")
        self.assertNotIn("do-not-echo", str(report))
        self.assertIn("index", report["residual_risks"][0])

    def test_complete_real_signatures_and_native_shapes_are_lab_only(self):
        self.build()
        report = self.run_report()
        self.assertEqual(report["status"], "pass", report["residual_risks"])
        self.assertEqual(report["metrics"]["verified_gates"], 22)
        self.assertFalse(report["release_ready"])
        self.assertFalse(report["production_authorized"])
        self.assertNotIn("M18", self.index["reports"])
        self.assertEqual(report["artifact_hashes"]["M02"], self.index["reports"]["M02"])

    def test_missing_and_foreign_children_are_all_diagnosed(self):
        self.build()
        for gate in ("M01", "M04"):
            del self.index["reports"][gate]
        self.reports["M12"]["status"] = "fail"
        self.index["reports"]["M12"] = self.pinfile("evidence/M12.json", self.reports["M12"])
        self.repin_index()
        report = self.run_report()
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["metrics"]["verified_gates"], 19)
        errors = " ".join(report["residual_risks"])
        for gate in ("M01", "M04", "M12"):
            self.assertIn(gate + "/", errors)
        self.assertFalse(report["production_authorized"])

    def test_missing_files_inconclusive_and_changed_bytes_fail(self):
        self.build()
        path = self.state / "evidence/M07.json"
        original = path.read_bytes()
        path.unlink()
        self.assertEqual(self.run_report()["status"], "inconclusive")
        path.write_bytes(original + b" ")
        self.assertEqual(self.run_report()["status"], "fail")
        path.write_bytes(original)
        ref = self.reports["M01"]["artifact_hashes"][final.PRIMARY["M01"]]
        artifact = self.state / "evidence/M18-objects" / ref
        saved = artifact.read_bytes()
        artifact.unlink()
        self.assertEqual(self.run_report()["status"], "inconclusive")
        artifact.write_bytes(saved + b" ")
        self.assertEqual(self.run_report()["status"], "fail")

    def test_plan_cannot_come_from_index_and_cannot_skip_gates(self):
        self.build()
        pin = os.environ.pop("M18_PLAN_SHA256")
        self.assertIn("M18_PLAN_SHA256", " ".join(self.run_report()["residual_risks"]))
        os.environ["M18_PLAN_SHA256"] = pin
        self.index["reports"]["M18"] = self.placeholder
        self.repin_index()
        self.assertIn("index-gates", " ".join(self.run_report()["residual_risks"]))
        del self.index["reports"]["M18"]
        self.plan["cases"].pop("M01")
        self.index["plan"] = self.pinfile("evidence/M18-plan.json", self.plan)
        os.environ["M18_PLAN_SHA256"] = self.index["plan"]
        self.repin_index()
        self.assertIn("plan-gates", " ".join(self.run_report()["residual_risks"]))

    def test_independent_cases_artifacts_and_negative_reasons_are_frozen(self):
        self.build()
        report = self.reports["M02"]
        report["cases"].append(
            dict(id="negative", expected="reject", actual="source_tampered", status="pass")
        )
        self.plan["rejections"]["M02"] = {"negative": "source_tampered"}
        self.primaries["M02"]["cases"] = report["cases"]
        report["artifact_hashes"][final.PRIMARY["M02"]] = self.put(self.primaries["M02"])
        self.seal()
        self.assertEqual(self.run_report()["status"], "pass")
        report["cases"][-1]["actual"] = "different_rejection"
        self.index["reports"]["M02"] = self.pinfile("evidence/M02.json", report)
        self.repin_index()
        self.assertIn("negative-observations", " ".join(self.run_report()["residual_risks"]))
        report["cases"][-1]["actual"] = "source_tampered"
        report["cases"].pop()
        self.index["reports"]["M02"] = self.pinfile("evidence/M02.json", report)
        self.repin_index()
        self.assertIn("case-inventory", " ".join(self.run_report()["residual_risks"]))
        report["cases"].append(
            dict(id="negative", expected="reject", actual="source_tampered", status="pass")
        )
        report["artifact_hashes"]["extra"] = self.placeholder
        self.index["reports"]["M02"] = self.pinfile("evidence/M02.json", report)
        self.repin_index()
        self.assertIn("artifact-inventory", " ".join(self.run_report()["residual_risks"]))

    def test_each_native_binding_rejects_other_candidate_even_with_rehashed_report(self):
        self.build()
        for gate, fields in final.BINDINGS.items():
            for key in fields.split():
                report = copy.deepcopy(self.reports[gate])
                report["input_digests"][key] = "sha256:" + "0" * 64 if "image" in key else "0" * 64
                with self.subTest(gate=gate, key=key), self.assertRaises(Rejected):
                    final.check_gate(
                        gate, report, self.values, final.timestamp(now()), self.plan["cases"][gate]
                    )
        for gate in ("M02", "M03", "M06", "M07", "M08", "M09", "M16", "M17"):
            final.check_gate(
                gate,
                self.reports[gate],
                self.values,
                final.timestamp(now()),
                self.plan["cases"][gate],
            )

    def test_report_shape_status_policy_and_time_fail_closed(self):
        self.build()
        base = self.reports["M07"]
        mutations = [
            lambda r: r.update(schema_version=True),
            lambda r: r.update(exit_code=False),
            lambda r: r.update(source_dirty=True),
            lambda r: r.update(release_ready=True),
            lambda r: r.update(policy_digest="0" * 64),
            lambda r: r.update(profile="production"),
            lambda r: r.update(source_revision="0" * 40),
            lambda r: r.update(gate="M08"),
            lambda r: r.update(redaction_version=2),
            lambda r: r.update(started_at="invalid"),
            lambda r: r.update(finished_at="2099-01-01T00:00:00+00:00"),
            lambda r: r.update(started_at="2020-01-01"),
            lambda r: r.update(residual_risks=[]),
            lambda r: r.update(residual_risks=[""]),
            lambda r: r["metrics"].update(checks=0),
            lambda r: r["metrics"].update(skipped=1),
            lambda r: r.update(artifact_hashes={}),
            lambda r: r["input_digests"].update(unexpected="not-digest"),
            lambda r: r["input_digests"].update(model_sha256="0" * 64),
            lambda r: r.pop("source_dirty"),
            lambda r: r["input_digests"].update(source_revision="broken"),
            lambda r: r.update(status="fail", exit_code=1),
        ]
        for change in mutations:
            r = copy.deepcopy(base)
            change(r)
            with self.subTest(change=mutations.index(change)), self.assertRaises(Rejected):
                final.checked_at(
                    "M07",
                    final.check_gate,
                    "M07",
                    r,
                    self.values,
                    final.timestamp(now()),
                    self.plan["cases"]["M07"],
                )
        r = {**base, "status": "inconclusive", "exit_code": 2}
        with self.assertRaises(final.Missing):
            final.check_gate(
                "M07", r, self.values, final.timestamp(now()), self.plan["cases"]["M07"]
            )
        for gate in ("M01", "M03", "M04", "M05", "M20"):
            r = copy.deepcopy(self.reports[gate])
            del r["source_dirty"]
            final.check_gate(gate, r, self.values, final.timestamp(now()), self.plan["cases"][gate])

    def test_native_case_variants_and_rejected_skips(self):
        c = dict(id="probe", status="pass", expected=True, actual=True)
        for gate in ("M08", "M09", "M22"):
            self.assertEqual(final.check_cases(gate, [dict(id="probe", status="pass")]), {"probe"})
        for gate in ("M02", "M03"):
            final.check_cases(gate, [dict(c, expected="reject", actual="source_tamper")])
        for name in ("three-run-numeric-repeat", "signed-candidate-three-fresh-repeats"):
            final.check_cases(
                "M06",
                [
                    dict(
                        c,
                        id=name,
                        expected=dict(probability_max=1e-6, auprc_max=1e-4),
                        actual=dict(probability=1e-7, auprc=0),
                    )
                ],
            )
        invalid = [
            [],
            [c, c],
            [dict(c, status="inconclusive")],
            [dict(c, actual=False)],
            [dict(c, actual="skipped")],
            [dict(c, expected="reject", actual="accepted")],
            [dict(c, expected="reject", actual="bad reason")],
            [dict(c, id="")],
            [dict(c, extra=True)],
            [dict(c, actual="inconclusive")],
        ]
        for cases in invalid:
            with self.subTest(cases=cases), self.assertRaises(Rejected):
                final.check_cases("M02", cases)
        numeric = dict(
            c,
            id="three-run-numeric-repeat",
            expected=dict(probability_max=1e-6, auprc_max=1e-4),
            actual=dict(probability=1e-5, auprc=0),
        )
        with self.assertRaises(Rejected):
            final.check_cases("M06", [numeric])

    def test_cryptographic_freeze_and_original_files_cannot_be_substituted(self):
        self.build()
        arguments = (
            self.root,
            self.state,
            self.index,
            self.source["source_revision"],
            self.source["source_fingerprint"],
        )
        good = copy.deepcopy(self.index)
        for path in self.freeze:
            original = (self.state / path).read_bytes()
            (self.state / path).write_bytes(original + b" ")
            with self.subTest(path=path), self.assertRaises(Rejected):
                final.checked_at("freeze", final.frozen, *arguments)
            (self.state / path).write_bytes(original)
        envelope = copy.deepcopy(self.package["envelope"])
        envelope["payload"] = envelope["payload"][:-4] + "AAAA"
        self.proposal["proposal_reference"] = self.put(envelope)
        self.index["freeze"]["evidence/release-native.json"] = self.pinfile(
            "evidence/release-native.json", self.proposal
        )
        with self.assertRaises(Rejected):
            final.checked_at("freeze", final.frozen, *arguments)
        self.index = good
        with self.assertRaises(Rejected):
            final.checked_at(
                "freeze",
                final.frozen,
                self.root,
                self.state,
                self.index,
                "0" * 40,
                self.source["source_fingerprint"],
            )

    def test_governance_requires_independent_signature_complete_materials_and_bindings(self):
        self.build()
        args = (
            self.root,
            self.index,
            self.plan,
            self.reports,
            lambda ref: final.blob(self.state, ref, 64 * final.LIMIT),
            self.values,
            self.keys,
            self.release.policy,
            final.timestamp(now()),
        )
        original = copy.deepcopy(self.index["governance"])
        self.index["governance"]["review"] = self.put(
            sign(self.review, "final-evidence-review", self.release.bundle.materials.key)
        )
        with self.assertRaises(Rejected):
            final.checked_at("governance", final.governance, *args)
        self.index["governance"] = copy.deepcopy(original)
        reviewer = self.plan["reviewer_key"]
        self.plan["reviewer_key"] = self.keys["approver"]
        with self.assertRaisesRegex(Rejected, "separation"):
            final.governance(*args)
        self.plan["reviewer_key"] = reviewer
        review = copy.deepcopy(self.review)
        review["subject_sha256"] = "0" * 64
        self.index["governance"]["review"] = self.put(
            sign(review, "final-evidence-review", self.review_key)
        )
        with self.assertRaisesRegex(Rejected, "review-subject"):
            final.governance(*args)
        self.index["governance"] = copy.deepcopy(original)
        self.index["governance"].pop("coverage")
        with self.assertRaisesRegex(Rejected, "governance-inventory"):
            final.governance(*args)

    def test_branch_coverage_and_image_exceptions_are_rejected(self):
        self.build()
        final.coverage(canonical(self.cov), self.plan["modules"])
        for mutation in (
            lambda c: c["meta"].update(branch_coverage=False),
            lambda c: c["files"]["mlsecops/final_evidence.py"]["summary"].update(
                covered_branches=1
            ),
            lambda c: c["files"]["mlsecops/final_evidence.py"]["executed_branches"].append([1, 2]),
            lambda c: c["files"]["mlsecops/final_evidence.py"].update(
                executed_branches=[],
                missing_branches=[[1, 2], [1, 3]],
                summary=dict(num_branches=2, covered_branches=0, missing_branches=2),
            ),
        ):
            changed = copy.deepcopy(self.cov)
            mutation(changed)
            with self.assertRaises(Rejected):
                final.coverage(canonical(changed), self.plan["modules"])
        for modules in ([], ["../escape.py"], ["mlsecops/final_evidence.py", "../escape.py"]):
            with self.assertRaises(Rejected):
                final.coverage(canonical(self.cov), modules)
        refs = self.index["governance"].copy()
        args = (
            refs,
            lambda ref: final.blob(self.state, ref, 64 * final.LIMIT),
            self.values,
            final.timestamp(now()),
            self.plan["image_packages"],
        )
        for mutate in (
            lambda r: r.update(status="inconclusive"),
            lambda r: r["policy"].update(allow_exceptions=True),
            lambda r: r["components"][0].update(status="fail"),
            lambda r: r["components"][0].update(diagnostic_only=True),
            lambda r: r["components"].pop(),
            lambda r: r.update(vulnerability_count=10),
            lambda r: r["go_detection_controls"][next(iter(r["go_detection_controls"]))].update(
                status="inconclusive"
            ),
            lambda r: r["components"][0].update(report_digest=self.placeholder),
        ):
            changed = copy.deepcopy(self.audit)
            mutate(changed)
            refs["image_audit"] = self.put(changed)
            with self.subTest(mutate=mutate), self.assertRaises(Rejected):
                final.checked_at("images", final.images, *args)

    def test_m22_review_is_candidate_bound_and_requires_two_distinct_challenges(self):
        self.build()
        report = copy.deepcopy(self.reports["M22"])
        refs = report["artifact_hashes"]

        def read(ref):
            return final.blob(self.state, ref)

        observed = final.release_policy.checked(
            decode(read(refs["review_observations"])), "m22-observations", self.keys["approver"]
        )
        good = copy.deepcopy(observed)
        for mutate in (
            lambda o: o["outcomes"].pop(),
            lambda o: o["outcomes"][1].update(run_id=o["outcomes"][0]["run_id"]),
            lambda o: o["outcomes"][0]["metrics"].update(status="fail"),
            lambda o: o.update(intake_sha256="0" * 64),
        ):
            observed = copy.deepcopy(good)
            mutate(observed)
            refs["review_observations"] = self.put(
                sign(observed, "m22-observations", self.release.bundle.materials.key)
            )
            with self.assertRaises(Rejected):
                final.challenges(report, read, self.keys["approver"], self.plan["reviewer_key"])
        report = copy.deepcopy(self.reports["M22"])
        report["input_digests"]["candidate_reference"] = "0" * 64
        with self.assertRaises(Rejected):
            final.challenges(report, read, self.keys["approver"], self.plan["reviewer_key"])

    def test_clean_source_redaction_bounded_reads_and_untrusted_exception_text(self):
        self.build()
        with patch.object(final, "command", return_value="dirty"):
            self.assertIn("checkout-changed", " ".join(self.run_report()["residual_risks"]))
        for raw in (b"", b"\xff", b"https://" + b"user:password" + b"@example.invalid"):
            with self.assertRaises((Rejected, UnicodeError)):
                final.evidence_text(raw)
        with self.assertRaisesRegex(final.Invalid, "invalid-material"):
            final.checked_at("safe", lambda: (_ for _ in ()).throw(ValueError("sensitive-value")))
        with self.assertRaisesRegex(final.Missing, "safe/material-missing"):
            final.checked_at("safe", final.pinned, self.state / "missing", digest(b"x"))
        p = self.state / "bounded"
        p.write_bytes(b"x" * 20)
        with self.assertRaises(Rejected):
            final.pinned(p, digest(b"x" * 20), 10)
        with self.assertRaises(Rejected):
            final.blob(self.state, "../outside")
        with self.assertRaises(Rejected):
            final.timestamp("2020-01-01")
        with patch.object(final, "frozen", side_effect=KeyError("sensitive-value")):
            report = self.run_report()
        self.assertEqual(report["status"], "fail")
        self.assertNotIn("sensitive-value", str(report))

    def test_existing_delivery_summary_matches_published_reports_without_authorizing(self):
        self.build()
        os.environ.pop("M18_INDEX_SHA256")
        os.environ.pop("M18_PLAN_SHA256")
        gates = ("M02", "M03", "M06", "M07", "M08", "M09", "M16", "M17")
        receipt = dict(
            candidate={
                k: self.values[k]
                for k in (
                    "candidate_reference",
                    "evaluation_reference",
                    "source_revision",
                    "source_fingerprint",
                    "image_id",
                    "qualified_candidate_model",
                    "qualified_candidate_subject",
                    "proposal_reference",
                )
            },
            reports={g: self.index["reports"][g] for g in gates},
            proposal_packet=self.freeze["evidence/release-native.json"],
            release_ready=False,
        )
        os.environ["M18_DELIVERY_SHA256"] = self.pinfile(
            "evidence/delivery-candidate.json", receipt
        )
        for g in gates:
            self.pinfile(
                "evidence/" + g + ".json",
                {**self.reports[g], "report_sha256": receipt["reports"][g]},
            )
        r = self.run_report()
        self.assertEqual(
            (r["status"], r["exit_code"], r["metrics"]["verified_gates"]), ("inconclusive", 2, 0)
        )
        self.assertEqual(r["diagnostics"]["receipt_matched"], list(gates))
        self.assertEqual(len(r["diagnostics"]["missing_receipts"]), 14)
        self.assertIs(r["production_authorized"], False)
        self.pinfile(
            "evidence/M08.json", {**self.reports["M08"], "report_sha256": self.placeholder}
        )
        (self.state / "evidence/M09.json").unlink()
        r = self.run_report()
        self.assertEqual(r["status"], "fail")
        self.assertEqual(r["diagnostics"]["unavailable"], ["M08", "M09"])
        receipt["release_ready"] = True
        os.environ["M18_DELIVERY_SHA256"] = self.pinfile(
            "evidence/delivery-candidate.json", receipt
        )
        self.assertIn("delivery-mode", " ".join(self.run_report()["residual_risks"]))


if __name__ == "__main__":
    unittest.main()
