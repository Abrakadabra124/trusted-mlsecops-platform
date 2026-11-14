"""Reconcile the gate files from one proposal and refuse mixed attempts or candidates."""

import io
import os
import runpy
import sys
import unittest
from contextlib import chdir, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mlsecops.contracts import Rejected, bounded_read, decode, digest, write_json
from scripts.delivery_candidate import reconcile


class Delivery(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(TemporaryDirectory())
        self.enterContext(chdir(directory))
        self.root = Path(".runtime")
        self.dir = self.root / "evidence"

        def h(label):
            return digest(label.encode())

        self.source = dict(
            source_fingerprint=h("tree"), source_revision="c" * 40, image_id="sha256:" + h("image")
        )
        self.proposal = dict(
            source=self.source,
            status="pass",
            release_ready=False,
            source_dirty=False,
            model_sha256=h("model"),
            subject_sha256=h("subject"),
            proposal_reference=h("proposal"),
        )
        demo = dict(
            candidate=dict(
                candidate_reference=h("candidate"),
                metadata=dict(
                    model_digest=h("model"), policy_digest=h("policy"), input_digest=h("training")
                ),
            ),
            evaluation_reference=h("evaluation"),
        )
        demo["dataset"] = dict(dataset_reference=h("dataset"))
        self.original = self.dir / "release-native.json"
        self.demo = self.root / "storage-demo.json"
        write_json(self.original, self.proposal)
        write_json(self.demo, demo)
        pin = digest(bounded_read(self.original))
        self.env = dict(
            GITHUB_SHA=self.source["source_revision"],
            M17_PROPOSAL_SHA256=pin,
            M17_DEMO_SHA256=digest(bounded_read(self.demo)),
        )
        self.enterContext(patch.dict(os.environ, self.env))
        self.reports = {}
        write_json(Path("data.lock"), dict(output=dict(sha256=h("data"))))
        lock = digest(bounded_read(Path("data.lock")))
        for gate in ("M02", "M03", "M06", "M07", "M08", "M09", "M16", "M17"):
            common = dict(
                candidate_reference=h("candidate"),
                evaluation_reference=h("evaluation"),
                source_fingerprint=h("tree"),
            )
            result = dict(
                gate=gate,
                profile="local-cpu",
                source_dirty=False,
                source_revision=self.source["source_revision"],
                status="pass",
                exit_code=0,
                policy_digest=h("policy"),
            )
            if gate in ("M16", "M17"):
                result.update(release_ready=False, artifact_hashes=dict(proposal_packet=pin))
                inputs = dict(
                    **self.source,
                    qualified_candidate_model=h("model"),
                    qualified_candidate_subject=h("subject"),
                    proposal_reference=h("proposal"),
                )
            elif gate == "M02":
                common = dict(source_fingerprint=h("tree"))
                inputs = dict(data_lock=lock, source=h("data"))
            elif gate == "M03":
                inputs = dict(
                    data_lock=lock,
                    source=h("data"),
                    worker_image=self.source["image_id"],
                    dataset_reference=h("dataset"),
                )
            elif gate == "M06":
                inputs = dict(
                    frozen_demo=self.env["M17_DEMO_SHA256"],
                    worker_image=self.source["image_id"],
                    dataset_reference=h("dataset"),
                    model_digest=h("model"),
                    candidate_training_input=h("training"),
                )
            elif gate == "M07":
                inputs = dict(
                    data_lock=lock,
                    dataset_source=h("data"),
                    model=h("model"),
                    training_request=h("training"),
                    worker_image=self.source["image_id"],
                    dataset_reference=h("dataset"),
                )
            else:
                inputs = {
                    "image" if gate == "M08" else "image_id": self.source["image_id"],
                    "candidate_training_input": h("training"),
                    "model_digest": h("model"),
                }
            result["input_digests"] = common | inputs
            self.reports[gate] = result
            write_json(self.path(gate), result)

    def path(self, gate):
        return self.dir / (gate + ".json")

    def run_cli(self):
        with redirect_stdout(io.StringIO()) as out, patch.dict(sys.modules):
            sys.modules.pop("scripts.delivery_candidate", None)
            runpy.run_module("scripts.delivery_candidate", run_name="__main__")
        return decode(out.getvalue().encode())

    def test_cli_hashes_all_original_bytes(self):
        direct = reconcile(
            self.root,
            demo_pin=self.env["M17_DEMO_SHA256"],
            proposal_pin=self.env["M17_PROPOSAL_SHA256"],
            revision=self.source["source_revision"],
        )
        result = self.run_cli()
        self.assertEqual(result, direct)
        self.assertIs(result["release_ready"], False)
        self.assertEqual(
            result["reports"], {g: digest(bounded_read(self.path(g))) for g in self.reports}
        )
        self.assertEqual(result["proposal_packet"], self.env["M17_PROPOSAL_SHA256"])

    def test_mixed_inputs_and_incomplete_gates_refuse(self):
        for gate, result in self.reports.items():
            inputs = result["input_digests"]
            for key in inputs:
                with self.subTest(gate=gate, key=key), patch.dict(inputs, {key: "foreign"}):
                    write_json(self.path(gate), result)
                    with self.assertRaisesRegex(Rejected, "candidate_mismatch"):
                        self.run_cli()
            for change in (
                dict(exit_code=False),
                dict(status="inconclusive"),
                dict(source_dirty=True),
                dict(policy_digest="other"),
            ):
                with self.subTest(gate=gate, change=change), patch.dict(result, change):
                    write_json(self.path(gate), result)
                    with self.assertRaisesRegex(Rejected, "candidate_mismatch"):
                        self.run_cli()
            if gate in ("M16", "M17"):
                with patch.dict(result["artifact_hashes"], proposal_packet="9" * 64):
                    write_json(self.path(gate), result)
                    with self.assertRaisesRegex(Rejected, "recovery_proposal_mismatch"):
                        self.run_cli()
            write_json(self.path(gate), result)

    def test_changed_originals_or_foreign_revision_refuse(self):
        for key in ("M17_DEMO_SHA256", "M17_PROPOSAL_SHA256", "GITHUB_SHA"):
            with (
                self.subTest(key=key),
                patch.dict(os.environ, {key: "9" * 64}),
                self.assertRaises(Rejected),
            ):
                self.run_cli()
        self.proposal["model_sha256"] = "9" * 64
        write_json(self.original, self.proposal)
        with (
            patch.dict(os.environ, M17_PROPOSAL_SHA256=digest(bounded_read(self.original))),
            self.assertRaisesRegex(Rejected, "original_proposal_mismatch"),
        ):
            self.run_cli()

    def test_missing_report_does_not_emit_a_summary(self):
        self.path("M08").unlink()
        with self.assertRaisesRegex(Rejected, "artifact_unavailable"):
            self.run_cli()
