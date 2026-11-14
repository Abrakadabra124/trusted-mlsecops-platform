"""Source preparation with real signed dataset bytes and isolated storage transports."""

import unittest
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mlsecops import datasets, signing, storage, storage_pipeline
from mlsecops.contracts import canonical, digest, read_json, write_json
from scripts import inventory_fleet_materials as materials


class SourcePreparation(unittest.TestCase):
    def test_hosted_entry_rejects_unowned_runner_before_storage_access(self):
        import os
        import runpy
        import sys

        from mlsecops.contracts import Rejected

        with (
            patch.dict(os.environ, GITHUB_ACTIONS="false"),
            patch.object(sys, "argv", [materials.__file__]),
            self.assertRaisesRegex(Rejected, "trust_hosted_runner_required"),
        ):
            runpy.run_path(materials.__file__, run_name="__main__")

    def test_owner_pins_the_three_reports_with_the_original_demo_still_current(self):
        with ExitStack() as stack:
            root = Path(stack.enter_context(TemporaryDirectory()))
            state = root / ".runtime"
            current = dict(dataset=dict(dataset_reference="original"))
            write_json(state / "storage-demo.json", current)
            write_json(state / "storage-trust.json", {"test": True})
            write_json(root / "policies/local-cpu.json", {})
            stack.enter_context(patch.object(materials.rollout, "hosted"))
            stack.enter_context(
                patch.object(
                    materials, "independent_source", return_value=dict(dataset_reference="separate")
                )
            )

            def train(_, ref, *args, previous_half_sample):
                self.assertEqual(previous_half_sample, ref == "original")
                return dict(candidate_reference=digest(ref.encode()))

            stack.enter_context(patch.object(storage_pipeline, "train", side_effect=train))
            stack.enter_context(
                patch.object(
                    storage_pipeline, "evaluate", return_value={"evaluation_reference": "measured"}
                )
            )

            def qualify(_, state, image, *, demo_file="storage-demo.json", sequence=1):
                demo = read_json(state / demo_file)
                expected = 2 if demo_file == "storage-demo.json" else 1
                self.assertEqual(sequence, expected)
                if sequence == 1:
                    self.assertEqual(demo["evaluation_reference"], "measured")
                return dict(model_sha256=digest(canonical(demo)), sequence=sequence)

            stack.enter_context(
                patch.object(materials.release_native, "qualify", side_effect=qualify)
            )
            result = materials.prepare(root, state)
            self.assertEqual(set(result["reports"]), {"previous", "current", "independent"})
            self.assertEqual(
                result["reports"]["current"], read_json(state / "evidence/release-native.json")
            )
            self.assertEqual(
                signing.create_key(state / materials.KEY), result["qualification_root"]
            )
            self.assertEqual(current, read_json(state / "storage-demo.json"))

    def test_independent_signed_rows_enter_the_normal_storage_reader(self):
        root = Path(__file__).resolve().parents[1]
        policy = read_json(root / "policies/local-cpu.json")
        with TemporaryDirectory() as temp:
            state = Path(temp)
            (state / "approved").mkdir()
            (state / "source").mkdir()
            public = signing.create_key(state / "keys/curator.pem")
            write_json(state / "trusted-keys.json", dict(curator=public))
            approval = datasets.source_approval(state, policy, create=True)
            objects = {}

            def put(client, table, content):
                self.assertIn(client.name, ("ingestor", "curator"))
                objects[(table, digest(content))] = content
                return digest(content)

            with (
                patch.object(storage, "put", side_effect=put),
                patch.object(
                    storage, "get", side_effect=lambda client, table, pin: objects[table, pin]
                ),
            ):
                result = materials.independent_source(root, state, policy)
                splits, manifest, statement = materials.storage_dataset.read_dataset(
                    state / "storage-clients/publisher",
                    result["dataset_reference"],
                    policy,
                    public,
                    digest(canonical(approval)),
                    ("train", "validation", "holdout"),
                )
            lock = read_json(state / "source/M19-independent/stream.lock")
            self.assertNotEqual(
                lock["source_sha256"], read_json(root / "data.lock")["output"]["sha256"]
            )
            self.assertEqual(lock["source_sha256"], statement["quarantine_object"])
            self.assertEqual(
                [len(splits[n]) for n in ("train", "validation", "holdout")], policy["split_counts"]
            )
            self.assertEqual(
                min(row["entity_id"] for split in splits.values() for row in split), policy["rows"]
            )
            self.assertEqual(result["dataset_id"], digest(canonical(manifest)))

    def test_previous_training_view_binds_actual_rows_to_full_parent_digest(self):
        splits = {"train": list(range(8)), "validation": [9]}
        parent = digest(canonical(splits["train"]))
        manifest = {"objects": {"train.json": {"sha256": parent}}}
        trust = dict(curator="curator", source_approval_digest=parent)
        for previous in (True, False):
            selected = splits["train"][::2] if previous else splits["train"]

            def train(dataset, lineage, rows, *args):
                self.assertEqual(rows, {"train": selected, "validation": [9]})
                return {"execution": {}}, b"model", []

            with (
                patch.object(
                    materials.storage_dataset,
                    "read_dataset",
                    return_value=(splits, manifest, dict(dataset_id=parent, lineage_id=parent)),
                ),
                patch.object(storage_pipeline, "load_candidate"),
                patch.object(storage_pipeline, "train_verified_dataset", side_effect=train),
                patch.object(storage, "put", side_effect=lambda client, table, raw: digest(raw)),
            ):
                result = storage_pipeline.train(
                    "publisher", parent, {}, "image", trust, previous_half_sample=previous
                )
            expected = (
                dict(
                    training_view=dict(
                        method="even-index-train-rows",
                        parent_sha256=parent,
                        rows=4,
                        sha256=digest(canonical(selected)),
                    )
                )
                if previous
                else {}
            )
            self.assertEqual(result["metadata"]["execution"], expected)
        self.assertEqual(splits["train"], list(range(8)))
