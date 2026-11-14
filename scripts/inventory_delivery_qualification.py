"""Reuse the owner's original delivery release; both additional branches remain disposable."""

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mlsecops import inventory_fleet, signing, storage_bootstrap, storage_pki
from mlsecops import inventory_gate as gate
from mlsecops.contracts import Rejected, bounded_read, canonical, digest, read_json, write_json
from scripts import canary_candidate_native_qualification as fixtures
from scripts import inventory_fleet_materials as materials


class ExistingSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.ActualCandidate.setUpClass()
        cls.addClassCleanup(fixtures.ActualCandidate.doClassCleanups)

    def setUp(self):
        self.fx = fx = fixtures.ActualCandidate()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        self.root, self.state = fx.root, fx.state
        files = (
            "storage-demo.json",
            "storage-trust.json",
            "trusted-keys.json",
            "evidence/release-native.json",
        )
        self.paths = {n: self.state / n for n in files}
        self.keys = read_json(self.paths["trusted-keys.json"]) | {
            k: fx.context["trust"][k] for k in ("curator", "evaluator")
        }
        write_json(self.paths["trusted-keys.json"], self.keys)
        demo = read_json(self.paths["storage-demo.json"])
        demo["dataset"].update(
            {k: demo["candidate"]["metadata"][k] for k in ("dataset_id", "lineage_id")}
        )
        write_json(self.paths["storage-demo.json"], demo)
        self.env = dict(
            M19_DEMO_SHA256=digest(bounded_read(self.paths["storage-demo.json"])),
            M19_PROPOSAL_SHA256=fx.pin,
            M19_KEYS_SHA256=digest(canonical(self.keys)),
            M19_TRUST_SHA256=digest(bounded_read(self.paths["storage-trust.json"])),
            M19_WORKSPACE_ID="a" * 32,
            GITHUB_RUN_ID="17",
            GITHUB_RUN_ATTEMPT="2",
            GITHUB_SHA=fx.source["source_revision"],
        )
        self.enterContext(patch.dict(os.environ, self.env))
        self.owner = dict(
            source={k: v for k, v in fx.source.items() if k != "image_id"},
            runner={k: self.env[k] for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")},
            proposal_pin=fx.pin,
            methods="a" * 64,
        )
        fx.marker.return_value = dict(container_id="b" * 64, workspace_id="a" * 32, port=15439)
        self.enterContext(
            patch.object(
                gate.storage_bootstrap, "inspect", return_value={"State": {"Running": True}}
            )
        )
        self.enterContext(patch.object(materials.rollout, "hosted"))
        self.enterContext(
            patch.object(materials.rollout, "capture_inputs", return_value=self.owner)
        )
        self.enterContext(
            patch.object(
                materials, "resolve_image", return_value=fx.source["image_id"], create=True
            )
        )
        self.enterContext(patch.object(materials, "check_clients", create=True))
        self.extra = self.enterContext(
            patch.object(
                materials,
                "scenarios",
                return_value={
                    "previous": dict(model_sha256="a" * 64),
                    "independent": dict(model_sha256="b" * 64),
                },
                create=True,
            )
        )
        self.enterContext(
            patch.object(
                materials.release_native,
                "qualify",
                side_effect=AssertionError("current was republished"),
            )
        )

    def test_existing_source_stays_byte_identical_and_signed_sequence_one_is_reused(self):
        paths = {p: (bounded_read(p), p.stat().st_mtime_ns) for p in self.paths.values()}
        result = materials.existing(self.root, self.state)
        self.assertEqual(result["reports"]["current"], self.fx.report)
        self.assertEqual(set(result["reports"]), {"previous", "current", "independent"})
        self.assertEqual(result["delivery"], gate.inputs(self.root, self.state)[2]["delivery"])
        self.assertEqual({p: (bounded_read(p), p.stat().st_mtime_ns) for p in paths}, paths)
        self.extra.assert_called_once()
        self.fx.load.assert_called_once()

    def test_current_sequence_one_replays_only_with_its_verified_expected_sequence(self):
        from scripts import inventory_fleet_native as native

        signing.create_key(self.state / materials.KEY)
        context, golden, pin, item = native.prepare(
            self.state,
            self.state / "storage-clients/serving",
            self.fx.report,
            self.fx.context["policy"],
            self.keys,
            self.fx.campaign,
            self.fx.source,
            self.fx.features,
        )
        public = signing.create_key(self.state / materials.KEY)
        args = (
            item,
            self.fx.report,
            self.keys,
            public,
            self.fx.campaign,
            self.owner["source"],
            context["policy"],
            int(native.time.time()),
            "current",
        )
        binding, trace, observed = inventory_fleet.source(*args, current_sequence=1)
        self.assertEqual(observed, golden)
        self.assertEqual(binding["permit_sha256"], pin)
        self.assertEqual(trace["source_revision"], self.owner["source"]["source_revision"])
        with self.assertRaises(Rejected):
            inventory_fleet.source(*args)

    def test_failed_training_still_checks_all_original_files(self):
        self.extra.side_effect = RuntimeError("controlled failure")
        before = {n: bounded_read(p) for n, p in self.paths.items()}
        with self.assertRaisesRegex(RuntimeError, "controlled failure"):
            materials.existing(self.root, self.state)
        self.assertEqual(before, {n: bounded_read(p) for n, p in self.paths.items()})

    def test_stopped_source_and_expired_original_refuse_before_writes(self):
        with (
            patch.object(
                gate.storage_bootstrap, "inspect", return_value={"State": {"Running": False}}
            ),
            self.assertRaises(Rejected),
        ):
            materials.existing(self.root, self.state)
        with (
            patch.object(materials.time, "time", return_value=self.fx.fixture.bundle.clock + 1801),
            self.assertRaises(Rejected),
        ):
            materials.existing(self.root, self.state)
        self.extra.assert_not_called()

    def test_source_policy_mutation_is_detected(self):
        path = self.state / (
            "release-proposals/" + self.fx.report["campaign_id"] + "/policy-envelope.json"
        )

        def changed(*args, **kwargs):
            with path.open("ab") as f:
                f.write(b"\n")
            return {
                "previous": dict(model_sha256="a" * 64),
                "independent": dict(model_sha256="b" * 64),
            }

        self.extra.side_effect = changed
        with self.assertRaises(Rejected):
            materials.existing(self.root, self.state)

    def test_shared_source_cannot_fall_back_to_unpinned_legacy_mode(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(FileNotFoundError):
            materials.existing(self.root, self.state)

    def test_existing_cli_publishes_newline_correct_fleet_pin(self):
        output = self.root / "output"
        with patch.dict(os.environ, GITHUB_OUTPUT=str(output)):
            materials.main(self.root, ["--existing"])
        self.assertEqual(
            output.read_text().strip(),
            "sha256=" + digest(bounded_read(self.state / materials.FILE)),
        )

    def test_foreign_or_missing_pin_refused_before_scenario_writes(self):
        for k, v in (
            ("M19_PROPOSAL_SHA256", "0" * 64),
            ("M19_DEMO_SHA256", "0" * 64),
            ("M19_KEYS_SHA256", digest(bounded_read(self.paths["trusted-keys.json"]))),
            ("M19_TRUST_SHA256", "0" * 64),
            ("M19_TRUST_SHA256", ""),
            ("M19_WORKSPACE_ID", "0" * 32),
            ("GITHUB_SHA", "0" * 40),
        ):
            with (
                self.subTest(k=k, v=v),
                patch.dict(os.environ, {k: v}),
                self.assertRaises((Rejected, FileNotFoundError)),
            ):
                materials.existing(self.root, self.state)
        self.extra.assert_not_called()

    def test_even_owner_pinned_cross_candidate_demo_is_refused_before_writes(self):
        demo = read_json(self.paths["storage-demo.json"])
        demo["evaluation_reference"] = "0" * 64
        write_json(self.paths["storage-demo.json"], demo)
        with (
            patch.dict(
                os.environ, M19_DEMO_SHA256=digest(bounded_read(self.paths["storage-demo.json"]))
            ),
            self.assertRaises(Rejected),
        ):
            materials.existing(self.root, self.state)
        self.extra.assert_not_called()

    def test_changes_during_preparation_are_refused_at_finish(self):
        def changed(*args, **kw):
            with self.paths["storage-trust.json"].open("ab") as f:
                f.write(b"\n")
            return {
                "previous": dict(model_sha256="a" * 64),
                "independent": dict(model_sha256="b" * 64),
            }

        self.extra.side_effect = changed
        with self.assertRaises(Rejected):
            materials.existing(self.root, self.state)
        self.extra.assert_called_once()


class ClientOwnership(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        write_json(
            self.state / "workspace.json",
            dict(product="trusted-mlsecops", schema_version=1, workspace_id="a" * 32),
        )
        storage_pki.initialize(self.state)
        storage_bootstrap.export_clients(self.state, 15439)

    def test_all_roles_are_bound_to_owners_endpoint_certificates_and_keys(self):
        original = materials.check_clients(self.state, dict(port=15439))
        self.assertEqual(set(original), set(storage_pki.ROLES))
        with self.assertRaises(Rejected):
            materials.check_clients(self.state, dict(port=15440))
        path = self.state / "storage-clients/scorer/client.key"
        raw = path.read_bytes()
        path.write_bytes((self.state / "storage-pki/ml_curator.key").read_bytes())
        with self.assertRaises(Rejected):
            materials.check_clients(self.state, dict(port=15439))
        path.write_bytes(raw)
        config = self.state / "storage-clients/scorer/connection.json"
        settings = read_json(config)
        write_json(config, {**settings, "role": "publisher"})
        with self.assertRaises(Rejected):
            materials.check_clients(self.state, dict(port=15439))
        write_json(config, settings)
        self.assertEqual(materials.check_clients(self.state, dict(port=15439)), original)
