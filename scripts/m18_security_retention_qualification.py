"""CAS assembly with genuine candidate signatures; no native services.

Source-section composition is independently exercised with its signed fixture.
Assembly fixtures mock only source composition and checkout identity.
"""

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, decode, digest, write_json
from scripts import m18_security_retention as retention
from scripts import security_gate_candidate_qualification as candidate_fixtures
from scripts import security_gate_sources_qualification as source_fixtures

ROOT = Path(__file__).resolve().parents[1]


class RetentionContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        candidate_fixtures.CandidateGate.setUpClass()
        cls.addClassCleanup(candidate_fixtures.CandidateGate.doClassCleanups)

    def setUp(self):
        self.fixture = candidate_fixtures.CandidateGate()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.state = self.fixture.state.resolve()
        self.source = {key: self.fixture.candidate[key] for key in retention.SOURCE_FIELDS}
        self.methods = self.fixture.out.public["method_materials"]
        self.owner = dict(GITHUB_RUN_ID="12345", GITHUB_RUN_ATTEMPT="2")
        self.enterContext(patch.object(retention.final, "clean"))
        self.enterContext(patch.object(retention.gate, "source_state", return_value=self.source))
        self.enterContext(patch.object(retention.gate, "materials", return_value=self.methods))
        self.enterContext(
            patch.object(
                retention.gate, "confirm_cleanup", side_effect=AssertionError("no infrastructure")
            )
        )
        self.enterContext(
            patch.object(retention.gate, "hosted", side_effect=AssertionError("no capture"))
        )
        self.values = dict(
            **self.fixture.candidate,
            model=self.fixture.candidate["model_sha256"],
            release_subject=self.fixture.proposal["subject_sha256"],
            proposal_reference=self.fixture.proposal["proposal_reference"],
            policy="1" * 64,
        )
        self.pins = dict(proposal=self.fixture.proposal_sha)
        manifest = dict(
            schema_version=1,
            source=dict(
                source=self.source["source_revision"],
                fingerprint=self.source["source_fingerprint"],
                methods_sha256=digest(canonical(self.methods)),
            ),
        )
        hashes = {}

        def source_file(name):
            pin = self.put(name, {"fixture": name})
            hashes[name] = pin
            return pin

        manifest["intake"] = dict(
            primary_file_sha256=source_file("evidence/security-source-private.json"),
            binding_sha256=source_file("evidence/security-source-private.bindings.json"),
            primary_sha256="2" * 64,
        )
        raw = canonical({"fixture": "identity"})
        pin = digest(raw)
        path = "security-identity-primary/" + pin + ".json"
        (self.state / path).parent.mkdir(parents=True)
        (self.state / path).write_bytes(raw)
        hashes[path] = pin
        manifest["identity"] = dict(
            primary_sha256=pin,
            binding_sha256=source_file("security-identity-primary/" + pin + ".bindings.json"),
        )
        manifest["trust"] = dict(
            run_id="3" * 32,
            primary_sha256=source_file("evidence/trust-service-" + "3" * 32 + ".primary.json"),
            binding_sha256=source_file("evidence/trust-service-" + "3" * 32 + ".binding.json"),
        )
        manifest["sequence"] = dict(
            primary_sha256=source_file("evidence/security-sequence-private.json")
        )
        self.source_result = dict(
            cases=["intake:controlled-case"],
            routes={kind: 0 for kind in retention.sources.KINDS},
            sequence_notice_seconds={"ingest-hole": 1, "heartbeat-head-only": 1},
            heartbeat_notice_seconds=1,
            artifact_hashes=hashes,
        )
        self.enterContext(
            patch.object(retention, "replay_sources", return_value=self.source_result)
        )
        self.stages = {}
        for stage, binding in (
            ("sources", manifest),
            ("inventory", self.fixture.inventory_pin),
            ("outage", self.fixture.outage_pin),
        ):
            packet = dict(
                schema_version=1,
                stage=stage,
                owner=self.owner.copy(),
                source=self.source,
                methods=digest(canonical(self.methods)),
                binding=binding,
                started_at="2026-11-14T07:15:00+00:00",
                finished_at="2026-11-14T07:15:00+00:00",
            )
            self.stages[stage] = packet
            self.pins[stage] = self.put("evidence/M23-" + stage + ".json", packet)
        owner_files = {}
        for name in retention.m23_delivery.OWNER_FILES:
            raw = (self.state / "kubernetes-security" / name).read_bytes()
            target = self.state / "M23-retired-serving/kubernetes-security" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            owner_files[name] = digest(raw)
        transition = dict(
            schema_version=1,
            inputs=dict(
                **{
                    k: self.values[k]
                    for k in (
                        *retention.SOURCE_FIELDS,
                        "image_id",
                        "candidate_reference",
                        "evaluation_reference",
                        "model_sha256",
                        "release_subject",
                        "proposal_reference",
                    )
                },
                policy_digest=self.values["policy"],
                files={retention.candidate.PROPOSAL: self.pins["proposal"]},
            ),
            transition={},
            outage_delivery="4" * 64,
            owner_files=owner_files,
        )
        self.pins["transition"] = self.put(retention.TRANSITION, transition)
        self.pins["workspace"] = digest((self.state / "workspace.json").read_bytes())
        evidence = retention.gate.reconcile(self.source_result, self.fixture.replay(), self.source)
        evidence["artifact_hashes"].update(
            method_materials=digest(canonical(self.methods)),
            **{"stage-" + stage: self.pins[stage] for stage in retention.gate.STAGES},
        )
        self.report = dict(
            schema_version=1,
            gate="M23",
            status="pass",
            profile="local-cpu",
            started_at="2026-11-14T07:15:00+00:00",
            finished_at="2026-11-14T07:20:00+00:00",
            policy_digest=self.values["policy"],
            source_revision=self.source["source_revision"],
            source_dirty=False,
            redaction_version=1,
            exit_code=0,
            residual_risks=retention.gate.LIMITATIONS,
            **{k: evidence[k] for k in ("input_digests", "artifact_hashes", "cases")},
            metrics=dict(checks=evidence["checks"], **evidence["metrics"]),
        )
        self.pins["report"] = self.put("evidence/M23.json", self.report)
        self.expected_cases = digest(canonical(sorted(case["id"] for case in self.report["cases"])))

    def put(self, name, document):
        write_json(self.state / name, document)
        return digest((self.state / name).read_bytes())

    def collect(self, **changes):
        args = dict(
            values=self.values, pins=self.pins, owner=self.owner, expected_cases=self.expected_cases
        )
        return retention.collect(ROOT, self.state, **(args | changes))

    def replay(self, index_pin, **changes):
        args = dict(
            index_pin=index_pin,
            values=self.values,
            pins=self.pins,
            owner=self.owner,
            expected_cases=self.expected_cases,
        )
        return retention.replay(ROOT, self.state, **(args | changes))

    def test_every_original_report_artifact_has_exact_M18_preimage(self):
        before = (self.state / "evidence/M23.json").read_bytes()
        result = self.collect()
        self.assertEqual(result["artifact_count"], 20)
        self.assertIs(result["release_ready"], False)
        self.assertEqual(retention.final.blob(self.state, self.pins["report"]), before)
        self.assertEqual((self.state / "evidence/M23.json").read_bytes(), before)
        for pin in self.report["artifact_hashes"].values():
            self.assertEqual(digest(retention.final.blob(self.state, pin)), pin)
        raw = (self.state / retention.candidate.INVENTORY_PRIMARY).read_bytes()
        self.assertEqual(
            retention.final.blob(self.state, self.fixture.inventory_pin["primary_sha256"]), raw[:-1]
        )
        self.assertEqual(retention.final.blob(self.state, digest(raw)), raw)
        self.assertEqual(self.replay(result["index_sha256"])["report_sha256"], self.pins["report"])

    def test_replay_after_original_files_and_owners_removed(self):
        result = self.collect()
        index = decode(retention.final.blob(self.state, result["index_sha256"]))
        for name in index["files"]:
            path = self.state / name
            if path.is_file():
                path.unlink()
        for name in retention.m23_delivery.OWNER_FILES:
            (self.state / "M23-retired-serving/kubernetes-security" / name).unlink()
        self.assertEqual(self.replay(result["index_sha256"])["artifact_count"], 20)

    def test_repeat_collection_does_not_rewrite_objects(self):
        first = self.collect()
        before = {
            p.name: p.stat().st_mtime_ns for p in (self.state / "evidence/M18-objects").iterdir()
        }
        with patch.object(retention.final, "retain", side_effect=AssertionError("rewritten")):
            self.assertEqual(self.collect(), first)
        self.assertEqual(
            before,
            {p.name: p.stat().st_mtime_ns for p in (self.state / "evidence/M18-objects").iterdir()},
        )

    def test_missing_or_corrupt_original_fails_before_any_CAS_write(self):
        for name in (
            "evidence/M23-sources.json",
            retention.candidate.INVENTORY_PRIMARY,
            retention.candidate.outage.PRIVATE,
            "evidence/security-outage/" + "1" * 32 + "/recovery.json",
            "M23-retired-serving/kubernetes-security/materials/registry.json",
        ):
            path = self.state / name
            raw = path.read_bytes()
            for corrupt in (False, True):
                if corrupt:
                    path.write_bytes(b"{}\n")
                else:
                    path.unlink()
                with (
                    self.subTest(name=name, corrupt=corrupt),
                    self.assertRaises((Rejected, OSError)),
                ):
                    self.collect()
                self.assertFalse((self.state / "evidence/M18-objects").exists())
                path.write_bytes(raw)

    def test_corrupt_existing_object_is_not_repaired(self):
        self.collect()
        path = self.state / "evidence/M18-objects" / self.pins["report"]
        path.write_bytes(b"corrupted")
        with (
            patch.object(retention.final, "retain", side_effect=AssertionError("rewritten")),
            self.assertRaises(Rejected),
        ):
            self.collect()
        self.assertEqual(path.read_bytes(), b"corrupted")

    def test_each_retained_object_missing_or_corrupt_blocks_replay(self):
        result = self.collect()
        for path in list((self.state / "evidence/M18-objects").iterdir()):
            raw = path.read_bytes()
            for corrupt in (False, True):
                if corrupt:
                    path.write_bytes(b"corrupted")
                else:
                    path.unlink()
                with self.subTest(pin=path.name, corrupt=corrupt), self.assertRaises(Rejected):
                    self.replay(result["index_sha256"])
                path.write_bytes(raw)

    def test_wrong_candidate_model_evaluation_subject_source_and_proposal(self):
        retained = self.collect()
        for field in (
            "candidate_reference",
            "evaluation_reference",
            "model_sha256",
            "release_subject",
            "source_fingerprint",
            "proposal_reference",
            "source_revision",
            "policy",
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.collect(
                    values=self.values | {field: "0" * (40 if field == "source_revision" else 64)}
                )
            with self.subTest(replay_field=field), self.assertRaises(Rejected):
                self.replay(
                    retained["index_sha256"],
                    values=self.values | {field: "0" * (40 if field == "source_revision" else 64)},
                )
        with self.assertRaises(Rejected):
            self.collect(pins=self.pins | {"proposal": "0" * 64})

    def test_report_projection_and_resealed_summary_rejected(self):
        original = (self.state / "evidence/M23.json").read_bytes()
        for change in (
            lambda r: r.update(report_sha256=self.pins["report"]),
            lambda r: r.update(status="inconclusive", exit_code=2),
            lambda r: r.update(exit_code=False),
            lambda r: r.update(source_dirty=0),
            lambda r: r.update(schema_version=True),
            lambda r: r["cases"][0].update(actual=1),
            lambda r: r["metrics"].update(checks=True),
            lambda r: r["artifact_hashes"].update(unresolved="0" * 64),
        ):
            report = decode(original)
            change(report)
            pin = self.put("evidence/M23.json", report)
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.collect(pins=self.pins | {"report": pin})

    def test_owner_case_inventory_and_every_explicit_pin_required(self):
        for key in retention.PIN_FIELDS:
            pins = self.pins.copy()
            pins.pop(key)
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.collect(pins=pins)
        for owner in (
            self.owner | {"GITHUB_RUN_ATTEMPT": "3"},
            self.owner | {"GITHUB_RUN_ID": "01"},
            self.owner | {"GITHUB_RUN_ID": True},
            self.owner | {"extra": "1"},
        ):
            with self.subTest(owner=owner), self.assertRaises(Rejected):
                self.collect(owner=owner)
        with self.assertRaises(Rejected):
            self.collect(expected_cases="0" * 64)

    def test_resealed_index_cannot_add_paths_replace_capture_or_schema(self):
        result = self.collect()
        index = decode(retention.final.blob(self.state, result["index_sha256"]))
        for change in (
            lambda p: p.update(schema_version=True),
            lambda p: p.update(extra="private"),
            lambda p: p["pins"].update(report="0" * 64),
            lambda p: p["owner"].update(GITHUB_RUN_ATTEMPT="3"),
            lambda p: p.update(expected_cases="0" * 64),
            lambda p: p["files"].update({"../secret.pem": self.pins["report"]}),
        ):
            changed = copy.deepcopy(index)
            change(changed)
            pin = retention.final.retain(self.state, canonical(changed) + b"\n")
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.replay(pin)

    def test_inventory_canonical_alias_requires_original_LF_file(self):
        path = self.state / retention.candidate.INVENTORY_PRIMARY
        path.write_bytes(path.read_bytes()[:-1])
        with self.assertRaises(Rejected):
            self.collect()
        self.assertFalse((self.state / "evidence/M18-objects").exists())

    def test_resealed_signed_corruption_reaches_and_fails_ordinary_verifier(self):
        path = self.state / retention.candidate.INVENTORY_PRIMARY
        packet = decode(path.read_bytes())
        packet["bundle"]["collector"]["records"][0]["receipt"]["signatures"][0]["sig"] = "invalid"
        write_json(path, packet)
        primary_pin = digest(canonical(packet))
        public = decode((self.state / retention.candidate.INVENTORY_PUBLIC).read_bytes())
        public["primary_sha256"] = primary_pin
        public_pin = self.put(retention.candidate.INVENTORY_PUBLIC, public)
        stage = copy.deepcopy(self.stages["inventory"])
        stage["binding"].update(primary_sha256=primary_pin, public_sha256=public_pin)
        self.pins["inventory"] = self.put("evidence/M23-inventory.json", stage)
        self.report["artifact_hashes"].update(
            {
                "candidate-inventory-primary_sha256": primary_pin,
                "candidate-inventory-public_sha256": public_pin,
                "stage-inventory": self.pins["inventory"],
            }
        )
        self.pins["report"] = self.put("evidence/M23.json", self.report)
        with (
            patch.object(
                retention.candidate, "replay", wraps=retention.candidate.replay
            ) as ordinary,
            self.assertRaises(Rejected),
        ):
            self.collect()
        ordinary.assert_called_once()
        self.assertFalse((self.state / "evidence/M18-objects").exists())

    def test_no_native_limit_can_silently_exceed_M18_object_limit(self):
        with patch.object(retention.final, "LIMIT", 1), self.assertRaises(Rejected):
            self.collect()
        self.assertFalse((self.state / "evidence/M18-objects").exists())

    def test_store_readback_rejects_failed_material_write(self):
        def bad_store(state, raw):
            pin = digest(raw)
            target = state / "evidence/M18-objects" / pin
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"incomplete")
            return pin

        with (
            patch.object(retention.final, "retain", side_effect=bad_store),
            self.assertRaises(Rejected),
        ):
            self.collect()


class OriginalSourceVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source_fixtures.GateSources.setUpClass()
        cls.addClassCleanup(source_fixtures.GateSources.doClassCleanups)

    def test_section_verifiers_equal_ordinary_replay_with_real_signatures(self):
        fixture = source_fixtures.GateSources
        source = dict(
            source_revision=fixture.source["source"],
            source_fingerprint=fixture.source["fingerprint"],
        )
        with patch.object(retention.gate, "source_state", return_value=source):
            expected = retention.sources.replay(fixture.root, fixture.state, fixture.manifest)
            actual = retention.replay_sources(fixture.root, fixture.state, fixture.manifest)
        self.assertEqual(actual, expected)

    def test_pre_run_source_inventory_equals_one_and_multi_window_ordinary_replay(self):
        # Compute before opening any report/capture. No tested result enters the pin.
        frozen_cases = retention.case_inventory(ROOT)
        fixture = source_fixtures.GateSources
        source = retention.sources.replay(fixture.root, fixture.state, fixture.manifest)
        candidate_fixtures.CandidateGate.setUpClass()
        self.addCleanup(candidate_fixtures.CandidateGate.doClassCleanups)
        candidate = candidate_fixtures.CandidateGate()
        candidate.setUp()
        self.addCleanup(candidate.doCleanups)
        for multiple in (False, True):
            if multiple:
                candidate.multiple_windows()
            result = candidate.replay()
            cases = source["cases"] + result["cases"]
            with self.subTest(multiple=multiple):
                self.assertEqual(len(cases), len(set(cases)))
                self.assertEqual(frozen_cases, digest(canonical(sorted(cases))))
                self.assertEqual(frozen_cases, retention.case_inventory(ROOT))

    def test_case_inventory_rejects_foreign_checkout_and_colliding_source_criteria(self):
        with self.assertRaises(Rejected):
            retention.case_inventory(ROOT / "foreign")
        with (
            patch.object(
                retention.candidate,
                "OUTAGE_FINAL_CASES",
                (retention.candidate.OUTAGE_PHASE_CASES[0],),
            ),
            self.assertRaises(Rejected),
        ):
            retention.case_inventory(ROOT)


if __name__ == "__main__":
    unittest.main()
