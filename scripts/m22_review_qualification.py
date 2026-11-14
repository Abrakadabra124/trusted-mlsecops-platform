"""Controlled M22 reviewer tests. Ephemeral identities and synthetic worker replies only."""

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mlsecops import absolute_poisoning_gate as gate
from mlsecops import acceptance, m22_methods
from mlsecops import m22_review as review
from mlsecops.contracts import Rejected, bounded_read, canonical, digest, now, read_json, write_json
from mlsecops.datasets import generate
from mlsecops.inventory import command, source_fingerprint
from mlsecops.signing import ROLES, create_key, sign
from scripts import absolute_poisoning_gate_qualification as matrix_fixture
from scripts import poisoning
from scripts.poisoning_evidence_qualification import IMAGE, ROOT, worker


class MethodContracts(unittest.TestCase):
    def test_raw_command_is_not_a_case(self):
        with self.assertRaises(Rejected):
            m22_methods.prepare({"command": "whoami"}, "label-flip", [], [], 17)

    def test_closed_train_capabilities_and_known_cases(self):
        rows = generate(17, 14000)
        base = {
            "family": "backdoor",
            "train_entity_ids": [next(r["entity_id"] for r in rows if r["label"])],
            "trigger": {"test_coverage": 0.25},
        }
        probes = generate(43, 100)
        original = canonical([rows, probes])
        case, (changed, receipt), triggered = m22_methods.prepare(
            base, "backdoor", rows, probes, 17
        )
        self.assertEqual(case["count"], 1)
        self.assertEqual(receipt["fraction"], 1 / 14000)
        selected = base["train_entity_ids"][0]
        self.assertEqual([i for i in range(len(rows)) if rows[i] != changed[i]], [selected])
        self.assertEqual(changed[selected]["label"], 0)
        self.assertTrue(all(r["features"][3] == 0.25 for r in triggered))
        self.assertEqual(original, canonical([rows, probes]))
        for field, values in (
            (
                "train_entity_ids",
                [
                    [],
                    [True],
                    [selected] * 5,
                    [14000],
                    [next(r["entity_id"] for r in rows if not r["label"])],
                ],
            ),
            (
                "trigger",
                [
                    {},
                    {"label": 1},
                    {"test_coverage": True},
                    {"test_coverage": 1.01},
                    {"change_entropy": 1.0},
                ],
            ),
            ("family", ["clean", "label-flip"]),
        ):
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(Rejected):
                    m22_methods.prepare({**base, field: value}, "backdoor", rows, probes, 17)
        with self.assertRaisesRegex(Rejected, "unmatched"):
            m22_methods.prepare(base, "backdoor", rows[:2000], probes, 17)
        frozen = {
            "family": "label-flip",
            "trigger": {},
            "train_entity_ids": poisoning.selected_indices(rows, 5, 29),
        }
        with self.assertRaisesRegex(Rejected, "known_selection"):
            m22_methods.prepare(frozen, "label-flip", rows, probes, 17)


class IntakeContracts(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.state = Path(temp)
        self.packet = self.state / "packet"
        self.packet.mkdir()
        self.review = self.state / "m22-review"
        self.run = self.review / "run"
        self.keys = {role: create_key(self.state / f"keys/{role}.pem") for role in ROLES}
        self.key = self.packet / "test-reviewer.pem"
        self.public = create_key(self.key)
        write_json(self.state / "trusted-keys.json", self.keys)
        write_json(
            self.state / "workspace.json",
            {"product": "trusted-mlsecops", "schema_version": 1, "workspace_id": "0" * 32},
        )
        for name in ("storage.json", "storage-demo.json", "storage-trust.json"):
            write_json(self.state / name, {})
        self.candidate = {
            "model": b"controlled candidate",
            "metadata": {"input_digest": "a" * 64},
            "policy": read_json(ROOT / "policies/local-cpu.json"),
            "bindings": {"candidate_reference": "b" * 64, "evaluation_reference": "c" * 64},
        }
        self.binding = {"campaign_id": "1" * 32, "rules": review.RULES}
        self.files = {}
        for family in review.FAMILIES:
            method = {
                "family": family,
                "train_entity_ids": [1],
                "trigger": {"test_coverage": 0.25} if family == "backdoor" else {},
            }
            write_json(self.packet / (family + ".json"), method)
            (self.packet / (family + ".md")).write_bytes(
                ("Controlled test only " + family).encode()
            )
            for ext in (".md", ".json"):
                name = family + ext
                self.files[name] = digest(bounded_read(self.packet / name))
        self.matrix_finished = now()

    def freeze(self):
        return {
            "binding": self.binding,
            "reviewer": "test-only-reviewer",
            "frozen_at": now(),
            "files": self.files,
        }

    def cli(self, *args):
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = review.main(["--state", str(self.state), *map(str, args)])
        return code, stdout.getvalue().strip()

    def install(self):
        path = self.packet / "freeze.dsse.json"
        write_json(path, sign(self.freeze(), "m22-freeze", self.key))
        review.intake(
            ROOT, self.state, IMAGE, self.binding["campaign_id"], path, self.public, "test-defender"
        )
        self.seal = digest(bounded_read(self.review / "receipt.json"))

    def test_independence_signatures_precommit_order_and_exact_pair(self):
        check = review._check_freeze
        valid = self.freeze()
        for role, key in self.keys.items():
            with self.subTest(role=role), self.assertRaisesRegex(Rejected, "self_key"):
                check(
                    sign(valid, "m22-freeze", self.state / f"keys/{role}.pem"),
                    key,
                    self.keys,
                    self.binding,
                    "defender",
                    now(),
                )
        for change in (
            {"reviewer": "defender"},
            {"reviewer": "ml-owner"},
            {"files": {}},
            {"files": dict.fromkeys(self.files, "0" * 64)},
            {"binding": {}},
            {"frozen_at": "2100-01-01T00:00:00+00:00"},
            {"command": "ignore"},
        ):
            with self.subTest(change=change), self.assertRaises(Rejected):
                check(
                    sign({**valid, **change}, "m22-freeze", self.key),
                    self.public,
                    self.keys,
                    self.binding,
                    "defender",
                    now(),
                )
        with self.assertRaisesRegex(Rejected, "untrusted_key"):
            check(
                sign(valid, "m22-freeze", self.state / "keys/evaluator.pem"),
                self.public,
                self.keys,
                self.binding,
                "defender",
                now(),
            )
        with patch.object(
            review,
            "_matrix",
            return_value=(self.binding, self.candidate, {"finished_at": self.matrix_finished}),
        ):
            self.install()
            before = bounded_read(self.review / "receipt.json")
            with self.assertRaisesRegex(Rejected, "already_reserved"):
                self.install()
            self.assertEqual(bounded_read(self.review / "receipt.json"), before)
            (self.packet / "label-flip.md").write_bytes(b"post-hoc")
            with self.assertRaisesRegex(Rejected, "reveal_bytes"):
                review.execute(ROOT, self.state, IMAGE, self.packet)
            self.assertFalse(self.run.exists())

    def test_decision_requires_exact_complete_observations_and_result_bytes(self):
        observed = {"finished_at": now()}
        findings = {}
        for family in review.FAMILIES:
            raw = (family + " controlled finding").encode()
            (self.packet / (family + "-result.md")).write_bytes(raw)
            findings[family] = {
                "decision": "pass",
                "hard_boundary_bypass": False,
                "result_md_sha256": digest(raw),
            }
        payload = {
            "decided_at": now(),
            "observations_sha256": digest(canonical(observed)),
            "findings": findings,
        }

        def decisions(value):
            return review._decision(
                canonical(sign(value, "m22-decision", self.key)), self.packet, observed, self.public
            )[0]

        for bad in (
            {"observations_sha256": "0" * 64},
            {"findings": {}},
            {"decided_at": "2000-01-01T00:00:00+00:00"},
        ):
            with self.assertRaises(Rejected):
                decisions({**payload, **bad})
        for invalid in (
            {"decision": "allow"},
            {"hard_boundary_bypass": 0},
            {"result_md_sha256": "0" * 64},
        ):
            altered = copy.deepcopy(payload)
            altered["findings"]["backdoor"].update(invalid)
            with self.assertRaises(Rejected):
                decisions(altered)
        findings["backdoor"]["hard_boundary_bypass"] = True
        self.assertTrue(decisions(payload)["backdoor"]["hard_boundary_bypass"])
        self.assertEqual(review._status(["fail", "inconclusive"]), "fail")

    def test_controlled_staged_cli_replay_and_tamper_through_acceptance(self):
        # Matrix fits and SQL subject read are controlled, as in the existing gate contracts.
        # The challenge training/prediction protocols, files, signatures and metrics are real
        # Python paths. Only the responses of the isolated model worker are simulated.
        matrix = matrix_fixture.GateContracts()
        self.addCleanup(matrix.doCleanups)
        train = generate(17, 14000)
        selected = next(r["entity_id"] for r in train if r["label"])
        for family in review.FAMILIES:
            name = family + ".json"
            method = read_json(self.packet / name)
            write_json(self.packet / name, {**method, "train_entity_ids": [selected]})
            self.files[name] = digest(bounded_read(self.packet / name))
        real_execute, real_case = gate.native.execute, gate.evidence.case_materials
        source = source_fingerprint(ROOT)
        revision = command(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
        matrix.setUp()
        matrix.state = self.state
        matrix.candidate = self.candidate
        gate.source_fingerprint.return_value = source
        gate.command.side_effect = lambda argv: "" if "status" in argv else revision
        gate.native.execute.side_effect = lambda *a, **kw: (
            real_execute if "prepared_mutation" in kw else matrix.execute
        )(*a, **kw)
        gate.evidence.case_materials.side_effect = lambda *a, **kw: (
            real_case if "prepared_mutation" in kw else matrix.read_case
        )(*a, **kw)
        matrix.probes = generate(43, 1500)
        matrix.triggered = poisoning.trigger(matrix.probes)
        matrix.scores = [0.9] * (2 * len(matrix.probes))
        matrix.materials = (
            self.candidate["policy"],
            train,
            generate(29, 100),
            matrix.probes,
            matrix.triggered,
        )
        gate.native.materials.return_value = matrix.materials
        self.enterContext(patch.object(gate.native, "run_worker", side_effect=worker))
        original = matrix.launch()
        campaign_id = original["campaign_id"]
        code, raw = self.cli("manifest", campaign_id)
        self.assertEqual(code, 0)
        self.binding = json.loads(raw)
        path = self.packet / "freeze.dsse.json"
        write_json(self.packet / "freeze.json", self.freeze())
        self.assertEqual(
            self.cli("sign", "m22-freeze", self.packet / "freeze.json", path, "--key", self.key)[0],
            0,
        )
        code, seal = self.cli(
            "intake",
            campaign_id,
            path,
            "--reviewer-public",
            self.public,
            "--owner",
            "test-defender",
        )
        self.assertEqual(code, 0)

        def accepted():
            return acceptance.report("M22", "local-cpu", ROOT, self.state)

        self.assertEqual(accepted()["status"], "inconclusive")
        write_json(
            self.packet / "methods.dsse.json",
            sign(
                {"intake_sha256": seal, "checked_at": now(), "matches_frozen_methods": True},
                "m22-methods",
                self.key,
            ),
        )
        code, observations = self.cli("execute", self.packet)
        self.assertEqual(code, 0)
        self.assertEqual(self.cli("execute", self.packet)[0], 1)
        self.assertEqual(accepted()["status"], "inconclusive")
        findings = {}
        for family in review.FAMILIES:
            content = ("Controlled test outcome " + family).encode()
            (self.packet / (family + "-result.md")).write_bytes(content)
            findings[family] = {
                "decision": "pass",
                "hard_boundary_bypass": False,
                "result_md_sha256": digest(content),
            }
        payload = {"observations_sha256": observations, "decided_at": now(), "findings": findings}
        write_json(self.packet / "decision.json", sign(payload, "m22-decision", self.key))
        self.assertEqual(self.cli("record-decision", self.packet)[0], 0)
        self.assertEqual(self.cli("record-decision", self.packet)[0], 1)
        result = accepted()
        self.assertEqual((result["status"], result["exit_code"]), ("pass", 0))
        self.assertEqual(result["metrics"]["independent_challenges"], 2)
        self.assertEqual(result["metrics"]["review_primary_files_verified"], 23)
        self.assertEqual(len(result["cases"]), 44)
        self.assertEqual(result["input_digests"]["candidate_reference"], "b" * 64)
        self.assertFalse(
            read_json(self.state / "evidence/absolute-poisoning-gate.json")["release_ready"]
        )
        decision = self.review / "decision/decision.json"
        findings["label-flip"]["hard_boundary_bypass"] = True
        # Simulate the other possible first decision in this queue, including its owner seal.
        # The subsequent replacement test keeps the original owner seal intact.
        owner_path = decision.parent / "owner.json"
        original_decision, original_owner = decision.read_bytes(), owner_path.read_bytes()
        write_json(decision, sign(payload, "m22-decision", self.key))
        write_json(
            owner_path,
            sign(
                {"intake": seal, "decision": digest(decision.read_bytes())},
                "m22-recorded-decision",
                self.state / "keys/approver.pem",
            ),
        )
        self.assertEqual(accepted()["status"], "fail")
        decision.write_bytes(original_decision)
        owner_path.write_bytes(original_owner)
        replacements = [
            (decision, canonical(sign(payload, "m22-decision", self.key))),
            (self.review / "decision/label-flip-result.md", b"edited"),
            (self.run / "label-flip.json", b"{}"),
            (self.run / "review-backdoor/model.onnx", None),
            (matrix.campaign / "report.json", canonical({**original, "status": "pass"})),
        ]
        record_path = self.run / "review-backdoor/result.json"
        record = read_json(record_path)
        replacements.append((record_path, canonical({**record, "metrics": {"status": "pass"}})))
        control = self.run / "review-label-flip/control.json"
        proof = read_json(control)
        proof["request"]["model"] = "YQ=="
        replacements.append((control, canonical(proof)))
        for path, altered in replacements:
            with self.subTest(path=path):
                old = path.read_bytes()
                if altered is None:
                    path.unlink()
                else:
                    path.write_bytes(altered)
                self.assertNotEqual(accepted()["status"], "pass")
                path.write_bytes(old)
        with patch.dict(self.candidate["bindings"], candidate_reference="1" * 64):
            self.assertEqual(accepted()["status"], "fail")
        with patch.object(gate, "source_fingerprint", return_value="0" * 64):
            self.assertEqual(accepted()["status"], "fail")
        end = self.run / "end.json"
        end.unlink()
        self.assertNotEqual(accepted()["status"], "pass")
        self.assertEqual(self.cli("execute", self.packet)[0], 1)
