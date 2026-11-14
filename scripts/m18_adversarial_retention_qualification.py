"""Content-retention contracts using simulated packets, never native attack evidence."""

import copy
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mlsecops import final_evidence as final
from mlsecops.contracts import Rejected, canonical, digest, now, write_json
from scripts import m18_adversarial_retention as retention

ROOT = Path(__file__).resolve().parents[1]


class AdversarialRetentionContracts(unittest.TestCase):
    def setUp(self):
        self.state = Path(self.enterContext(TemporaryDirectory()))

    def build(self, gate):
        name = retention.NAMES[gate]
        self.campaign = self.state / name / ("c" * 32)
        names = retention.material_names(gate)
        self.campaign.mkdir(parents=True)
        native = {"campaign_id": "c" * 32, "artifact_hashes": {}}
        for filename in sorted(names - {"report.json"}):
            path = self.campaign / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(canonical({"fixture": filename}) + b"\n")
            native["artifact_hashes"][filename] = digest(path.read_bytes())
        write_json(self.campaign / "report.json", native)
        write_json(self.state / f"evidence/{name}.json", native)
        manifest = {n: digest((self.campaign / n).read_bytes()) for n in names}
        binding = canonical({"fixture": "original worker prediction receipt"}) + b"\n"
        (self.campaign / "candidate-binding.json").write_bytes(binding)
        contracts = retention.contract_manifest(ROOT, gate)
        refs = {
            "campaign": digest(
                (self.campaign / "report.json").read_bytes() if gate == "M08" else canonical(native)
            ),
            "primary_materials": digest(canonical(manifest)),
            "contracts": digest(canonical(contracts)),
            "candidate_binding": digest(binding),
        }
        values = {
            key: digest(key.encode())
            for key in ("policy", "source_fingerprint", *final.BINDINGS[gate].split())
        }
        values["source_revision"] = "a" * 40
        inputs = {key: values[key] for key in ("source_fingerprint", *final.BINDINGS[gate].split())}
        if gate == "M08":
            inputs["source"] = values["source_fingerprint"]
        inputs.update({k: digest(k.encode()) for k in final.OTHER_INPUTS[gate].split()})
        cases = [{"id": k, "status": "pass"} for k in sorted(retention.case_inventory(ROOT, gate))]
        packet = dict(
            status="pass",
            campaign_id="c" * 32,
            cases=cases,
            input_digests=inputs,
            artifact_hashes=refs,
        )
        primary = f"evidence/{name}-gate.json"
        write_json(self.state / primary, packet)
        refs = dict(refs, **{final.PRIMARY[gate]: digest((self.state / primary).read_bytes())})
        report = dict(
            schema_version=1,
            gate=gate,
            profile="local-cpu",
            source_revision=values["source_revision"],
            policy_digest=values["policy"],
            redaction_version=1,
            status="pass",
            exit_code=0,
            source_dirty=False,
            started_at=now(),
            finished_at=now(),
            residual_risks=["Simulated retention fixture only"],
            input_digests=inputs,
            cases=cases,
            metrics={"checks": len(cases)},
            artifact_hashes=refs,
        )
        path = self.state / f"evidence/{gate}.json"
        write_json(path, report)
        return values, report, digest(path.read_bytes())

    def test_missing_primary_fails_without_creating_an_archive(self):
        for gate in retention.NAMES:
            with self.subTest(gate=gate):
                values, _, pin = self.build(gate)
                (self.campaign / "train.json").unlink()
                with self.assertRaises((Rejected, OSError)):
                    retention.retain(ROOT, self.state, values, gate, pin)
                self.assertFalse((self.state / "evidence/M18-objects").exists())

    def test_byte_mutation_and_wrong_external_pin_are_rejected(self):
        for gate in retention.NAMES:
            with self.subTest(gate=gate):
                values, _, pin = self.build(gate)
                path = self.campaign / "train.json"
                path.write_bytes(path.read_bytes() + b"\n")
                with self.assertRaises(Rejected):
                    retention.retain(ROOT, self.state, values, gate, pin)
                with self.assertRaises(Rejected):
                    retention.retain(ROOT, self.state, values, gate, "f" * 64)

    def test_offline_replay_survives_deleted_originals_and_detects_archive_corruption(self):
        for gate in retention.NAMES:
            with self.subTest(gate=gate):
                values, report, pin = self.build(gate)
                result = retention.retain(ROOT, self.state, values, gate, pin)
                self.assertEqual(result["primary_files"], 251 if gate == "M08" else 28)
                shutil.rmtree(self.campaign)
                (self.state / f"evidence/{retention.NAMES[gate]}.json").unlink()
                (self.state / f"evidence/{retention.NAMES[gate]}-gate.json").unlink()
                self.assertEqual(retention.verify(ROOT, self.state, values, gate, pin), result)
                path = (
                    self.state
                    / "evidence/M18-objects"
                    / report["artifact_hashes"]["candidate_binding"]
                )
                path.write_bytes(b"changed")
                with self.assertRaises(Rejected):
                    retention.verify(ROOT, self.state, values, gate, pin)

    def test_resealed_different_candidate_and_incomplete_cases_fail(self):
        for gate in retention.NAMES:
            values, report, pin = self.build(gate)
            retention.retain(ROOT, self.state, values, gate, pin)
            for field in (
                "candidate_reference",
                "evaluation_reference",
                "model_digest",
                "candidate_training_input",
            ):
                with self.subTest(gate=gate, field=field):
                    changed = copy.deepcopy(report)
                    changed["input_digests"][field] = "f" * 64
                    path = self.state / f"evidence/{gate}.json"
                    write_json(path, changed)
                    with self.assertRaises(Rejected):
                        retention.verify(ROOT, self.state, values, gate, digest(path.read_bytes()))
            changed = copy.deepcopy(report)
            changed["cases"].pop()
            changed["metrics"]["checks"] -= 1
            write_json(path, changed)
            with self.assertRaises(Rejected):
                retention.verify(ROOT, self.state, values, gate, digest(path.read_bytes()))

    def test_resealed_missing_or_traversing_manifest_does_not_read_outside_campaign(self):
        values, report, _ = self.build("M09")
        path = self.state / "evidence/robustness.json"
        from mlsecops.contracts import read_json

        native = read_json(path)
        native["artifact_hashes"]["../outside.json"] = native["artifact_hashes"].pop("train.json")
        write_json(path, native)
        report["artifact_hashes"]["campaign"] = digest(canonical(native))
        report["artifact_hashes"]["primary_materials"] = digest(
            canonical(native["artifact_hashes"])
        )
        acceptance = self.state / "evidence/M09.json"
        write_json(acceptance, report)
        with self.assertRaises(Rejected):
            retention.retain(ROOT, self.state, values, "M09", digest(acceptance.read_bytes()))

    def test_contract_preimages_equal_existing_producer_digests(self):
        from mlsecops import poisoning_gate, robustness_gate

        for gate, producer in (("M08", poisoning_gate), ("M09", robustness_gate)):
            self.assertEqual(
                digest(canonical(retention.contract_manifest(ROOT, gate))),
                producer.contract_materials(ROOT),
            )


if __name__ == "__main__":
    unittest.main()
