import copy
import tempfile
import unittest
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path

from mlsecops import audit_lineage, canary_evaluation, canary_journal, serving_context, signing
from mlsecops import canary_native_evidence as evidence
from mlsecops.candidate_serving_reader import KIND
from mlsecops.contracts import Rejected, canonical, digest, write_json
from mlsecops.load_golden import Golden
from scripts.load_golden_qualification import expected


def response(golden, identifier):
    return dict(
        schema_version=1,
        bundle_sha256=golden.bundle,
        model_sha256=golden.model,
        request_id=identifier,
        predictions=[dict(decision="score", reason=None, score=golden.score)],
    )


class Native(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.state = Path(folder.name)
        start = "2026-01-01T00:00:00+00:00"
        self.wall = 1767225600
        root = signing.create_key(self.state / "key.pem")
        first = Golden.from_expected(expected())
        second = Golden(first.body, "3" * 64, "4" * 64, 0.25)
        self.golden = dict(stable=first, candidate=second)
        src = dict(source_revision="1" * 40, source_fingerprint="2" * 64)
        self.stable = dict(
            model_sha256=first.model,
            subject_sha256=first.bundle,
            sequence=1,
            request_sha256="9" * 64,
            proposal_reference="8" * 64,
        )
        self.candidate = dict(
            model_sha256=second.model,
            subject_sha256=second.bundle,
            proposal_reference="7" * 64,
            image_id="sha256:" + "f" * 64,
            permit_sha256="6" * 64,
            trust_root=root,
            candidate_reference="5" * 64,
            evaluation_reference="4" * 64,
            **src,
        )
        c = self.candidate
        campaign = "a" * 32
        self.directory = self.state / "evidence" / ("canary-native-" + campaign)
        self.directory.mkdir(parents=True)
        self.metadata = dict(model_digest=second.model, image_id=c["image_id"], **src)
        self.lineage = dict(
            **src,
            source_sha256="d" * 64,
            source_approval_sha256="3" * 64,
            dataset_sha256="2" * 64,
            lineage_sha256="1" * 64,
            run_sha256=digest(canonical(self.metadata)),
            evaluation_sha256=c["evaluation_reference"],
        )
        self.demo = dict(
            candidate=dict(candidate_reference=c["candidate_reference"], metadata=self.metadata),
            evaluation_reference=c["evaluation_reference"],
            dataset=dict(
                dataset_reference=self.lineage["dataset_sha256"],
                source_approval_digest=self.lineage["source_approval_sha256"],
            ),
            evaluation=dict(
                candidate_reference=c["candidate_reference"],
                dataset_reference=self.lineage["dataset_sha256"],
            ),
        )
        write_json(self.state / "storage-demo.json", self.demo)
        self.permit = dict(
            schema_version=1,
            purpose=KIND,
            campaign_id=campaign,
            environment="local-cpu",
            proposal_sha256=c["proposal_reference"],
            subject_sha256=second.bundle,
            model_sha256=second.model,
            **src,
            image_id=c["image_id"],
            issued_at=self.wall + 1,
            expires_at=self.wall + 45,
        )
        c["permit_sha256"] = digest(canonical(self.permit))
        self.sidecar = dict(
            permit=signing.sign(self.permit, KIND, self.state / "key.pem"),
            lineage=self.lineage,
            storage_demo_sha256=digest((self.state / "storage-demo.json").read_bytes()),
        )
        self.seal_source()
        self.contexts = dict(
            stable=asdict(
                serving_context.ReleaseContext(
                    self.stable["request_sha256"], first.bundle, first.model
                )
            ),
            candidate=asdict(
                serving_context.QualificationTrace(
                    c["permit_sha256"],
                    c["proposal_reference"],
                    second.bundle,
                    second.model,
                    audit_lineage.Lineage(**self.lineage),
                )
            ),
        )
        proposal = dict(
            status="pass",
            release_ready=False,
            source_dirty=False,
            finished_at=start,
            source={**src, "image_id": c["image_id"]},
            **{k: c[k] for k in ("proposal_reference", "model_sha256", "subject_sha256")},
        )
        file = self.directory.parent / "release-native.json"
        write_json(file, proposal)
        self.inputs = dict(
            source=src,
            runner=dict(GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1"),
            methods="2" * 64,
            proposal_pin=digest(file.read_bytes()),
        )
        payload = dict(
            schema_version=1,
            version=1,
            environment="local-cpu",
            issued_at=self.wall + 2,
            expires_at=self.wall + 1000,
            promotion_policy_sha256=c["permit_sha256"],
            revoked_artifacts=[],
            revoked_keys=[],
        )
        proof = dict(
            root=root,
            before=signing.sign(payload, "trust-policy", self.state / "key.pem"),
            after=signing.sign(
                {
                    **payload,
                    "issued_at": self.wall + 15,
                    "version": 2,
                    "revoked_artifacts": [second.model],
                },
                "trust-policy",
                self.state / "key.pem",
            ),
        )
        stages = []
        self.lines = defaultdict(list)
        for n, percent in enumerate((0, 10, 50, 100)):
            rows = []
            for i in range(100):
                role = "candidate" if (i + 1) * percent // 100 > i * percent // 100 else "stable"
                gold = self.golden[role]
                j = n * 100 + i + 1
                identifier = f"{j:032x}"
                self.exchange(role, identifier, 200)
                rows.append(
                    dict(
                        index=i,
                        start_ns=j * 10,
                        end_ns=j * 10 + 2,
                        status=200,
                        target=role,
                        outcome="ok",
                        response=dict(
                            model_sha256=gold.model,
                            bundle_sha256=gold.bundle,
                            risk_score=gold.score,
                            request_id=identifier,
                        ),
                    )
                )
            stages.append(
                dict(
                    schema_version=1,
                    candidate_percent=percent,
                    payload_sha256=digest(first.body),
                    rows=rows,
                )
            )
        self.stages = stages
        results = canary_evaluation.evaluate(stages, stable_golden=first, candidate_golden=second)
        tid = "b" * 32
        data = self.directory.parent / ("canary-" + tid) / "traffic.json"
        write_json(data, stages)
        samples = []
        for i, (role, status) in enumerate(
            (("candidate", 200), ("candidate", 503), ("stable", 200))
        ):
            identifier = f"{401 + i:032x}"
            self.exchange(role, identifier, status)
            reply = (
                response(self.golden[role], identifier)
                if status == 200
                else dict(
                    schema_version=1, request_id=identifier, error=dict(code="model_unavailable")
                )
            )
            samples.append(
                dict(start_ns=5000 + i * 10, end_ns=5002 + i * 10, status=status, reply=reply)
            )
        self.record = dict(
            schema_version=1,
            campaign="a" * 32,
            started_at=start,
            finished_at="2026-01-01T00:01:00+00:00",
            source=src,
            methods=self.inputs["methods"],
            runner=self.inputs["runner"],
            proposal_sha256=self.inputs["proposal_pin"],
            candidate=c,
            stable=self.stable,
            goldens={k: dict(body=g.body.decode(), score=g.score) for k, g in self.golden.items()},
            traffic=dict(
                campaign=tid,
                primary_sha256=digest(data.read_bytes()),
                stable=first.binding(),
                candidate=second.binding(),
                **results,
            ),
            recovery=dict(
                start_ns=4100,
                committed_ns=4200,
                observed_at_ns=(self.wall + 20) * 10**9 + 123,
                denial_admissions=dict(before=161, after=162),
                trust=proof,
                candidate=samples[:2],
                restored=samples[2],
            ),
            journals={},
        )
        for role in self.lines:
            self.reseal(role)

    def exchange(self, role, identifier, status):
        records = self.lines[role]
        for stage in (
            "request_started",
            "response_intended",
            "response_started",
            "response_completed",
        ):
            effective = None if stage == "request_started" else status
            event = dict(
                schema_version=2,
                principal_id="e" * 32,
                request_id=identifier,
                route="predict",
                stage=stage,
                status=effective,
                context=self.contexts[role] if effective == 200 else None,
            )
            records.append(
                dict(
                    schema_version=1,
                    sequence=len(records) + 1,
                    recorded_at_ns=(self.wall + (16 if int(identifier, 16) > 400 else 5)) * 10**9
                    + len(records)
                    + 1,
                    event=event,
                )
            )

    def reseal(self, role):
        content = b"".join(canonical(r) + b"\n" for r in self.lines[role])
        (self.directory / (role + ".jsonl")).write_bytes(content)
        self.record["journals"][role] = digest(content)

    def verify(self):
        return evidence.replay(self.state, self.record, **self.inputs)

    def seal_source(self):
        path = self.directory / "candidate-source.json"
        write_json(path, self.sidecar)
        self.candidate["source_evidence_sha256"] = digest(path.read_bytes())

    def test_source_report_refuses_swapped_candidate_or_evaluation_even_in_resealed_primary(self):
        for field in ("candidate_reference", "evaluation_reference"):
            original = self.candidate[field]
            self.candidate[field] = "f" * 64
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.verify()
            self.candidate[field] = original
        with (self.state / "storage-demo.json").open("ab") as stream:
            stream.write(b" ")
        with self.assertRaises(Rejected):
            self.verify()

    def test_resealed_sidecar_must_contain_original_signed_campaign_permit(self):
        for kind, changes in (
            (KIND, {"campaign_id": "b" * 32}),
            (KIND, {"proposal_sha256": "c" * 64}),
            ("release-approval", {}),
            (KIND, {"issued_at": self.wall + 10}),
        ):
            self.sidecar["permit"] = signing.sign(
                {**self.permit, **changes}, kind, self.state / "key.pem"
            )
            self.seal_source()
            with self.subTest(kind=kind, changes=changes), self.assertRaises(Rejected):
                self.verify()

    def test_observation_requires_current_authority_and_cross_clock_anchor(self):
        for observed in (
            True,
            0,
            (self.wall - 1) * 10**9,
            (self.wall + 61) * 10**9,
            (self.wall + 45) * 10**9,
            (self.wall + 14) * 10**9,
            (self.wall + 16) * 10**9,
        ):
            self.record["recovery"]["observed_at_ns"] = observed
            with self.subTest(observed=observed), self.assertRaises(Rejected):
                self.verify()

    def test_resealed_success_context_needs_full_actual_lineage(self):
        self.contexts["candidate"]["lineage"]["source_sha256"] = "0" * 64
        self.reseal("candidate")
        with self.assertRaises(Rejected):
            self.verify()

    def test_signed_trust_transition_must_explain_only_the_candidate_model_denial(self):
        proof = self.record["recovery"]["trust"]
        for field, value in (
            ("revoked_artifacts", [self.golden["candidate"].model, "f" * 64]),
            ("revoked_keys", ["e" * 64]),
            ("promotion_policy_sha256", "0" * 64),
            ("issued_at", self.wall + 30),
            ("expires_at", self.wall + 19),
        ):
            payload = signing.verify(proof["after"], "trust-policy", proof["root"])
            envelope = proof["after"]
            proof["after"] = signing.sign(
                {**payload, field: value}, "trust-policy", self.state / "key.pem"
            )
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.verify()
            proof["after"] = envelope

    def test_trust_cannot_postdate_the_successful_candidate_traffic(self):
        proof = self.record["recovery"]["trust"]
        initial = signing.verify(proof["before"], "trust-policy", proof["root"])
        proof["before"] = signing.sign(
            {**initial, "issued_at": self.wall + 10}, "trust-policy", self.state / "key.pem"
        )
        with self.assertRaises(Rejected):
            self.verify()

    def test_expired_permit_and_foreign_root_fail_with_valid_envelope_structure(self):
        key = self.state / "unrelated.pem"
        signing.create_key(key)
        self.sidecar["permit"] = signing.sign(self.permit, KIND, key)
        self.seal_source()
        with self.assertRaises(Rejected):
            self.verify()
        self.sidecar["permit"] = signing.sign(self.permit, KIND, self.state / "key.pem")
        self.seal_source()
        # The serving reader rounds its permit clock UP. In the last fractional
        # second expiry alone can fence the candidate.
        self.record["recovery"]["observed_at_ns"] = (self.wall + 44) * 10**9 + 1
        with self.assertRaises(Rejected):
            self.verify()
        self.record["recovery"]["observed_at_ns"] = (self.wall + 44) * 10**9
        self.assertEqual(self.verify()["requests"], 400)

    def test_last_stage_must_have_observed_a_valid_B_response_before_the_fault(self):
        # Re-signing the trust update with an issuance second before the final
        # candidate response is inconsistent with a post-stage revocation.
        proof = self.record["recovery"]["trust"]
        document = signing.verify(proof["after"], "trust-policy", proof["root"])
        proof["after"] = signing.sign(
            {**document, "issued_at": self.wall + 4}, "trust-policy", self.state / "key.pem"
        )
        with self.assertRaises(Rejected):
            self.verify()

    def test_admissions_require_replayed_candidate_attempts_and_exact_terminal_delta(self):
        for counts in ((-1, 0), (161, 160), (161, 163), (160, 161), (True, 1), (161, 162.0)):
            self.record["recovery"]["denial_admissions"] = dict(
                zip(("before", "after"), counts, strict=True)
            )
            with self.subTest(counts=counts), self.assertRaises(Rejected):
                self.verify()
        self.record["recovery"]["denial_admissions"] = dict(before=161, after=161)
        with self.assertRaises(Rejected):
            self.verify()
        del self.lines["candidate"][-4:]
        self.reseal("candidate")
        self.assertEqual(self.verify()["audit_completed"]["candidate"], 161)

    def test_primary_readback_binds_all_400_responses_and_fault(self):
        report = self.verify()
        self.assertEqual(
            (report["requests"], report["audit_completed"]), (400, dict(stable=241, candidate=162))
        )
        self.assertEqual(report["route_recovery_seconds"], 922 / 1e9)
        self.assertEqual(report["release_subject"], self.candidate["subject_sha256"])

    def test_rehashed_journal_with_foreign_stable_selection_is_rejected(self):
        self.contexts["stable"]["selection_sha256"] = "f" * 64
        self.reseal("stable")
        with self.assertRaises(Rejected):
            self.verify()

    def test_corrupt_or_rebound_capture_is_rejected(self):
        original = copy.deepcopy(self.record)
        for mutate in (
            lambda r: r.update(source={}),
            lambda r: r.update(finished_at="2025-12-01T00:00:00+00:00"),
            lambda r: r["candidate"].update(model_sha256="e" * 64),
            lambda r: r["traffic"].update(primary_sha256="f" * 64),
            lambda r: r["traffic"].update(decision="hold"),
            lambda r: r["recovery"].update(start_ns=1000),
            lambda r: r["recovery"]["restored"].update(end_ns=130_000_000_000),
            lambda r: r["recovery"]["candidate"][-1]["reply"].update(error={"code": "unavailable"}),
            lambda r: r["recovery"]["candidate"][0].update(status=503),
            lambda r: r["recovery"].update(committed_ns=6000),
            lambda r: r["recovery"]["trust"].update(after=r["recovery"]["trust"]["before"]),
        ):
            self.record = copy.deepcopy(original)
            mutate(self.record)
            with self.assertRaises(Rejected):
                self.verify()

    def test_journal_refuses_extra_missing_duplicate_and_unobserved_response(self):
        raw = (self.directory / "stable.jsonl").read_bytes()
        rows = [row for s in self.stages for row in s["rows"] if row["target"] == "stable"]
        extra = [self.record["recovery"]["restored"]]
        opts = dict(
            subject=self.stable["subject_sha256"],
            model=self.stable["model_sha256"],
            authority=dict(selection_sha256=self.stable["request_sha256"]),
        )
        for attempts, tail in (
            (rows[1:], extra),
            (rows + [rows[0]], extra),
            (rows, extra * 2),
            ([*rows, dict(status=0)], extra),
            ([*rows, dict(status=429)], extra),
            (rows, [{**extra[0], "status": 503}]),
        ):
            with self.assertRaises(Rejected):
                canary_journal.reconcile(raw, attempts, tail, **opts)
