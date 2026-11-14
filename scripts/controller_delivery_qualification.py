import copy
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mlsecops import signing, storage_restore
from mlsecops.contracts import Rejected, bounded_read, canonical, digest, read_json, write_json
from mlsecops.controller_delivery import HISTORY, check_pair
from scripts.controller_delivery import reconcile


class PairBinding(unittest.TestCase):
    def setUp(self):
        self.metadata = {"model_digest": "model", "run_id": "run"}
        self.candidate = {"metadata": self.metadata, "candidate_reference": "candidate"}
        self.evaluation = {
            "candidate_reference": "candidate",
            "dataset_reference": "data",
            "report": self.metadata.copy(),
        }
        self.controller = {
            "publisher": {"result": self.candidate},
            "scorer": {"result": {"evaluation": self.evaluation, "evaluation_reference": "eval"}},
        }

    def check(self, controller):
        check_pair(controller, "candidate", "eval", "data", self.metadata, self.evaluation)

    def test_original_pair(self):
        self.check(self.controller)

    def test_same_model_different_subject_or_signature(self):
        for role, field, value in (
            ("publisher", "candidate_reference", "other"),
            ("publisher", "metadata", {**self.metadata, "run_id": "other"}),
            ("scorer", "evaluation_reference", "other"),
            ("scorer", "evaluation", {**self.evaluation, "dataset_reference": "other"}),
        ):
            with self.subTest(field=field), self.assertRaises(Rejected):
                changed = copy.deepcopy(self.controller)
                changed[role]["result"][field] = value
                self.check(changed)


class Replay(unittest.TestCase):
    def setUp(self):
        self.state = Path(self.enterContext(TemporaryDirectory()))
        self.e = self.state / "evidence"
        key = self.state / "trust.pem"
        public = {"trust": signing.create_key(key)}
        write_json(self.state / "trusted-keys.json", public)
        self.source = dict(source_revision="a" * 40, source_fingerprint="s", image_id="image")
        meta = self.source | dict(
            model_digest="model", policy_digest="policy", input_digest="input"
        )
        demo = dict(
            candidate=dict(candidate_reference="cand", metadata=meta),
            dataset=dict(dataset_reference="dataset"),
            evaluation_reference="evaluation",
            evaluation={"signed": "payload"},
        )
        proposal = dict(
            source=self.source,
            status="pass",
            release_ready=False,
            source_dirty=False,
            model_sha256="model",
            subject_sha256="subject",
            proposal_reference="proposal",
        )
        write_json(self.state / "storage-demo.json", demo)
        write_json(self.e / "release-native.json", proposal)
        self.pins = dict(
            demo_pin=digest(bounded_read(self.state / "storage-demo.json")),
            proposal_pin=digest(bounded_read(self.e / "release-native.json")),
            keys_pin=digest(canonical(public)),
            revision=self.source["source_revision"],
        )
        write_json(self.e / "authority-qualification.json", {"status": "pass"})
        authority = digest(bounded_read(self.e / "authority-qualification.json"))
        subject = dict(
            candidate_reference="cand",
            evaluation_reference="evaluation",
            dataset_reference="dataset",
            metadata_sha256=digest(canonical(meta)),
            evaluation_sha256=digest(canonical(demo["evaluation"])),
            authority_report=authority,
        )
        self.receipt = signing.sign({"subject": subject}, "controller-history-transfer", key)
        write_json(self.e / "controller-history-transfer.json", self.receipt)
        for gate in ("M03", "M04", "M05", "M07", "M20"):
            inputs = dict(
                candidate_reference="cand",
                evaluation_reference="evaluation",
                source_fingerprint="s",
                worker_image="image",
                image_id="image",
                dataset_reference="dataset",
                model_digest="model",
                model="model",
                model_sha256="model",
                training_request="input",
                subject_sha256="subject",
                proposal_reference="proposal",
                proposal_packet=self.pins["proposal_pin"],
            )
            write_json(
                self.e / (gate + ".json"),
                dict(
                    gate=gate,
                    profile="local-cpu",
                    source_revision="a" * 40,
                    source_dirty=False,
                    status="pass",
                    exit_code=0,
                    policy_digest="policy",
                    input_digests=inputs,
                    artifact_hashes=dict(
                        signed_evaluation="evaluation",
                        authority=authority,
                        authority_qualification=authority,
                    ),
                ),
            )

    def test_signed_owner_and_five_gates(self):
        self.assertEqual(
            set(reconcile(self.state, **self.pins)), {"M03", "M04", "M05", "M07", "M20"}
        )

    def test_foreign_key_modified_receipt_or_rebound_report(self):
        with self.assertRaises(Rejected):
            reconcile(self.state, **(self.pins | {"keys_pin": "0" * 64}))
        path = self.e / "controller-history-transfer.json"
        write_json(path, self.receipt | {"signatures": []})
        with self.assertRaises(Rejected):
            reconcile(self.state, **self.pins)
        write_json(path, self.receipt)
        for gate in ("M04", "M05", "M20"):
            path = self.e / (gate + ".json")
            original = read_json(path)
            altered = copy.deepcopy(original)
            altered["input_digests"]["evaluation_reference"] = "another-signed-run"
            write_json(path, altered)
            with self.subTest(gate=gate), self.assertRaises(Rejected):
                reconcile(self.state, **self.pins)
            write_json(path, original)

    def test_only_candidate_and_evaluation_table_data(self):
        lines = [f"{n}; 1 2 TABLE DATA ml {table} ml_owner" for n, table in enumerate(HISTORY)]
        good = "\n".join(lines).encode()
        storage_restore.validate_toc(good, data_tables=HISTORY)
        for bad in (
            good.splitlines()[0],
            good + b"\n" + good,
            good + b"\n4; 1 2 TABLE DATA ml releases ml_owner",
        ):
            with self.assertRaises(Rejected):
                storage_restore.validate_toc(bad, data_tables=HISTORY)
