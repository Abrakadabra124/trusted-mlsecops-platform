import copy
import unittest
from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from mlsecops import controller_delivery as delivery
from mlsecops import signing, storage_restore
from mlsecops.contracts import Rejected, bounded_read, canonical, digest, read_json, write_json
from mlsecops.controller_delivery import HISTORY, check_pair
from scripts import controller_serving_handoff as handoff
from scripts.controller_delivery import BASE7, PARENT11, combine, reconcile


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


class Transfer(unittest.TestCase):
    def setUp(self):
        self.state = Path(self.enterContext(TemporaryDirectory()))
        key = self.state / "keys/trust.pem"
        self.public = {"trust": signing.create_key(key)}
        self.owner = dict(workspace_id="owner", container_id="container", name="owned-host")
        self.migration = dict(volume_uid="volume", receipt_digest="signed-migration")
        self.baseline = {name: {"rows": 0} for name in HISTORY} | {"holdout": {"rows": 1}}
        self.tables = {name: {"rows": 2} for name in HISTORY} | {"holdout": {"rows": 1}}
        self.subject = {"candidate_reference": "candidate", "evaluation_reference": "evaluation"}
        self.ensure = Mock()
        self.enterContext(
            patch.object(
                delivery.kube_storage_migration, "exclusive", return_value=nullcontext(self.ensure)
            )
        )
        self.validate = self.enterContext(
            patch.object(delivery.kube_storage, "validate", return_value={"volume_uid": "volume"})
        )
        self.freeze = self.enterContext(patch.object(delivery.kube_storage_migration, "freeze"))
        self.ledger = self.enterContext(
            patch.object(delivery.kube_storage_migration, "ledger", return_value=self.tables)
        )
        self.enterContext(
            patch.object(delivery.kube_storage_migration, "connection_limit", return_value=0)
        )
        self.dump = self.enterContext(
            patch.object(delivery.kube_storage, "execute", return_value=b"PGDMPfixture")
        )
        self.host = self.enterContext(
            patch.object(delivery.storage_bootstrap, "validate", return_value=self.owner)
        )
        self.host_ledger = self.enterContext(
            patch.object(
                delivery.storage_restore, "ledger", side_effect=[self.baseline, self.tables]
            )
        )
        toc = b"1; 1 2 TABLE DATA ml candidates ml_owner\n2; 1 3 TABLE DATA ml evaluations ml_owner"
        self.restore = self.enterContext(
            patch.object(delivery, "binary_command", side_effect=[toc, b""])
        )

    def run_transfer(self):
        delivery.restore_history(
            self.state, self.owner, self.migration, self.baseline, self.public, self.subject
        )

    def test_transfer_is_fenced_signed_and_atomic(self):
        self.run_transfer()
        self.freeze.assert_called_once()
        self.assertEqual(self.restore.call_count, 2)
        self.assertIn("--single-transaction", self.restore.call_args.args[0])
        self.assertIn("--exit-on-error", self.restore.call_args.args[0])
        receipt = read_json(self.state / "evidence/controller-history-transfer.json")
        payload = signing.verify(receipt, "controller-history-transfer", self.public["trust"])
        self.assertEqual(payload["subject"], self.subject)
        self.assertEqual(payload["archive_sha256"], digest(b"PGDMPfixture"))
        self.assertEqual(payload["after"], self.tables)

    def test_occupied_destination_never_freezes_or_imports(self):
        self.baseline["candidates"]["rows"] = 1
        with self.assertRaisesRegex(Rejected, "empty_destination"):
            self.run_transfer()
        self.freeze.assert_not_called()
        self.restore.assert_not_called()

    def test_foreign_volume_never_freezes(self):
        self.validate.return_value = {"volume_uid": "foreign"}
        with self.assertRaisesRegex(Rejected, "volume_changed"):
            self.run_transfer()
        self.freeze.assert_not_called()

    def test_changed_private_dataset_never_imports(self):
        self.tables["holdout"]["rows"] = 2
        with self.assertRaisesRegex(Rejected, "dataset_changed"):
            self.run_transfer()
        self.restore.assert_not_called()

    def test_changed_owner_never_imports(self):
        self.host.return_value = self.owner | {"container_id": "foreign"}
        with self.assertRaisesRegex(Rejected, "host_changed"):
            self.run_transfer()
        self.restore.assert_not_called()

    def test_changed_host_ledger_never_imports(self):
        self.host_ledger.side_effect = [self.tables]
        with self.assertRaisesRegex(Rejected, "host_changed"):
            self.run_transfer()
        self.restore.assert_not_called()

    def test_unsigned_receipt_never_imports(self):
        with patch.object(delivery, "read_json", return_value={"signatures": []}):
            with self.assertRaises(Rejected):
                self.run_transfer()
        self.restore.assert_not_called()

    def test_partial_import_never_passes(self):
        self.restore.side_effect = [
            b"1; 1 2 TABLE DATA ml candidates ml_owner\n2; 1 3 TABLE DATA ml evaluations ml_owner",
            Rejected("restore_interrupted"),
        ]
        with self.assertRaisesRegex(Rejected, "restore_interrupted"):
            self.run_transfer()
        self.freeze.assert_called_once()
        self.assertEqual(self.host_ledger.call_count, 1)

    def test_final_ledger_or_fence_change_refuses(self):
        self.host_ledger.side_effect = [self.baseline, self.baseline]
        with self.assertRaisesRegex(Rejected, "final_ledgers"):
            self.run_transfer()


class ExplicitSetAndHandoff(unittest.TestCase):
    def test_no_partial_or_auto_selected_parent(self):
        scoped = {k: k for k in ("M03", "M04", "M05", "M07", "M20")}
        for profile, gates in (("base7", BASE7), ("parent11", PARENT11)):
            original = {g: g for g in gates}
            summary = {"release_ready": False, "reports": original}
            result = combine(summary, scoped, profile)
            self.assertEqual(set(result["reports"]), gates | set(scoped))
            for gate in gates:
                with self.subTest(gate=gate), self.assertRaises(Rejected):
                    combine(
                        summary | {"reports": {k: v for k, v in original.items() if k != gate}},
                        scoped,
                        profile,
                    )
            for changed in (
                summary | {"release_ready": True},
                summary | {"reports": original | {"M03": "other"}},
                summary | {"reports": original | {"M99": "unexpected"}},
            ):
                with self.assertRaises(Rejected):
                    combine(changed, scoped, profile)
        with self.assertRaises(Rejected):
            combine({"release_ready": False, "reports": {g: g for g in BASE7}}, scoped, "parent11")

    def test_sole_history_or_changed_timestamp_blocks_disposal(self):
        old = {t: {"rows": 0} for t in handoff.storage_schema.TABLES}
        old["evaluations"] = {"rows": 1}
        new = old | {"evaluations": {"rows": 2}}
        with (
            patch.object(handoff.kube_storage, "admin", return_value=b'{"id":"one"}'),
            patch.object(
                handoff.storage_bootstrap, "admin", return_value=b'{"id":"one","new":"two"}'
            ) as host,
        ):
            handoff.preserved_history(None, {"name": "host"}, old, new)
            host.return_value = b'{"id":"other"}'
            with self.assertRaisesRegex(Rejected, "history_missing"):
                handoff.preserved_history(None, {"name": "host"}, old, new)

    def test_foreign_or_shared_node_denied(self):
        node = {
            "Name": "/" + handoff.cluster.NODE,
            "Id": "id",
            "Mounts": [{"Type": "volume", "Name": "old"}],
            "Config": {
                "Labels": {
                    "io.x-k8s.kind.cluster": handoff.cluster.NAME,
                    "io.x-k8s.kind.role": "control-plane",
                }
            },
        }
        with (
            patch.object(
                handoff.cluster, "validate_cluster", return_value={"namespace_uid": "uid"}
            ),
            patch.object(handoff.storage_bootstrap, "inspect", return_value=node),
            patch.object(
                handoff, "command", side_effect=[handoff.cluster.NODE, "id\nother"]
            ) as cmd,
        ):
            with self.assertRaisesRegex(Rejected, "shared_node_volume"):
                handoff.owned_node(None)
            node["Config"]["Labels"]["io.x-k8s.kind.cluster"] = "foreign"
            cmd.side_effect = [handoff.cluster.NODE]
            with self.assertRaisesRegex(Rejected, "kind_ownership"):
                handoff.owned_node(None)
