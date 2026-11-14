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

    def test_transition_requires_owned_source_and_actual_absence(self):
        with (
            patch.object(campaign.storage_bootstrap, "validate", return_value=self.sql),
            patch.object(
                campaign.cluster,
                "validate_cluster",
                return_value={"workspace_id": "owner", "namespace_uid": "a"},
            ),
            patch.object(campaign.kube_storage, "validate", return_value={"volume_uid": "v"}),
            patch.object(campaign, "command", return_value=campaign.cluster.NAME),
            patch.object(campaign.cluster, "bootstrap") as create,
        ):
            for pin in (self.pin, "0" * 64):
                with self.subTest(pin=pin), self.assertRaises(Rejected):
                    campaign.transition(self.state, self.state / "retired", pin)
            create.assert_not_called()

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
