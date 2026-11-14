"""Independent phase and cross-report contracts for the shared source campaign."""

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest, write_json
from scripts import serving_campaign as campaign


class SharedCampaignTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.sql = {"workspace_id": "owner", "container_id": "original"}
        write_json(self.state / "storage.json", self.sql)
        self.pin = digest(canonical(self.sql) + b"\n")
        (self.state / "kubeconfig").write_bytes(b"owned-config")
        self.node = {"container": "old-node", "namespace": "a", "volumes": ["old-volume"]}

    def test_transition_requires_owned_source_and_actual_absence(self):
        with (
            patch.object(campaign.storage_bootstrap, "validate", return_value=self.sql),
            patch.object(
                campaign.cluster,
                "validate_cluster",
                return_value={"workspace_id": "owner", "namespace_uid": "a"},
            ),
            patch.object(campaign.kube_storage, "validate", return_value={"volume_uid": "v"}),
            patch.object(campaign, "owned_node", return_value=self.node),
            patch.object(campaign, "command", return_value=campaign.cluster.NAME),
            patch.object(campaign.cluster, "bootstrap") as create,
        ):
            for pin in (self.pin, "0" * 64):
                with self.subTest(pin=pin), self.assertRaises(Rejected):
                    campaign.transition(self.state, self.state / "retired", pin)
            create.assert_not_called()

    def transition_mocks(self, commands):
        self.enterContext(
            patch.object(campaign.storage_bootstrap, "validate", return_value=self.sql)
        )
        self.enterContext(patch.object(campaign, "owned_node", return_value=self.node))
        self.enterContext(
            patch.object(
                campaign,
                "identity",
                side_effect=[dict(namespace="a", volume="v"), dict(namespace="b", volume="w")],
            )
        )
        command = self.enterContext(patch.object(campaign, "command", side_effect=commands))
        create = self.enterContext(patch.object(campaign.cluster, "bootstrap"))
        storage = self.enterContext(patch.object(campaign.kube_storage, "bootstrap"))
        return command, create, storage

    def test_transition_refuses_existing_archive_before_destructive_command(self):
        retired = self.state / "retired"
        retired.mkdir()
        command, create, _ = self.transition_mocks([])
        with self.assertRaises(Rejected):
            campaign.transition(self.state, retired, self.pin)
        command.assert_not_called()
        create.assert_not_called()
        with self.assertRaises(Rejected):
            campaign.transition(self.state, self.state / "serving", self.pin)

    def test_transition_preserves_private_evidence_and_config_until_absence_confirmed(self):
        evidence = self.state / "evidence"
        evidence.mkdir()
        (evidence / "retained.json").write_bytes(b"retained")
        (self.state / "serving").mkdir()
        (self.state / "serving" / "owner.json").write_bytes(b"old")
        command, create, storage = self.transition_mocks(["", "", "", ""])
        retired = self.state / "retired"
        result = campaign.transition(self.state, retired, self.pin)
        self.assertEqual(result["source_sql"], self.pin)
        self.assertEqual((retired / "kubeconfig").read_bytes(), b"owned-config")
        self.assertEqual((retired / "serving/owner.json").read_bytes(), b"old")
        self.assertEqual((evidence / "retained.json").read_bytes(), b"retained")
        self.assertEqual(
            Path(command.call_args_list[0].args[0][-1]), (retired / "teardown-kubeconfig").resolve()
        )
        create.assert_called_once_with(self.state)
        storage.assert_called_once_with(self.state)

    def test_surviving_node_or_volume_blocks_archive_and_bootstrap(self):
        for commands in (["", "", "old-node"], ["", "", "", "old-volume"]):
            with (
                self.subTest(commands=commands),
                unittest.mock.patch.object(
                    campaign, "identity", return_value=dict(namespace="a", volume="v")
                ),
                patch.object(campaign, "owned_node", return_value=self.node),
                patch.object(campaign, "command", side_effect=commands),
                patch.object(campaign.cluster, "bootstrap") as create,
            ):
                retired = self.state / ("retired" + str(len(commands)))
                with self.assertRaises(Rejected):
                    campaign.transition(self.state, retired, self.pin)
                create.assert_not_called()
                self.assertTrue((self.state / "kubeconfig").is_file())

    def test_two_boundaries_cannot_reuse_cluster_or_volume_or_break_chain(self):
        nodes = [
            dict(namespace=digest(bytes([i])), volume=digest(bytes([10 + i]))) for i in range(3)
        ]
        steps = [dict(before=nodes[i], after=nodes[i + 1], source_sql=self.pin) for i in range(2)]
        self.assertEqual(campaign.chain(steps, self.pin), nodes)
        for step, side, key, changed in (
            (0, "after", "volume", nodes[0]["volume"]),
            (1, "before", "namespace", nodes[0]["namespace"]),
            (1, "after", "volume", nodes[0]["volume"]),
        ):
            altered = copy.deepcopy(steps)
            altered[step][side][key] = changed
            with self.assertRaises(Rejected):
                campaign.chain(altered, self.pin)
        with self.assertRaises(Rejected):
            campaign.chain(steps, "0" * 64)

    def test_source_join_checks_all_declared_inputs_and_exact_outcomes(self):
        inputs = {"source": "a" * 64, "data_lock": "b" * 64, "source_fingerprint": "c" * 64}
        values = dict(inputs, source_revision="d" * 40)
        report = dict(
            gate="M02",
            source_revision=values["source_revision"],
            source_dirty=False,
            exit_code=0,
            status="pass",
            input_digests=inputs,
            cases=[dict(id="negative", status="pass", expected="reject", actual="invalid_source")],
        )
        campaign.bind_report("M02", report, values)
        for key in inputs:
            with self.subTest(key=key), self.assertRaises(Rejected):
                campaign.bind_report(
                    "M02", dict(report, input_digests=dict(inputs, **{key: "e" * 64})), values
                )
        with self.assertRaises(Rejected):
            campaign.bind_report(
                "M02", dict(report, cases=[dict(report["cases"][0], actual="skipped")]), values
            )
