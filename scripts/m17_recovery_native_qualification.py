"""Controlled native orchestration with real owner pins, signed backup and both offline replays."""

import copy
import io
import os
import runpy
import sys
import unittest
from contextlib import contextmanager, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import call, patch
from uuid import UUID

from mlsecops import (
    daily_backup,
    model,
    prediction_protocol,
    signing,
    storage_bootstrap,
    storage_pki,
)
from mlsecops.contracts import (
    Rejected,
    bounded_read,
    canonical,
    decode,
    digest,
    read_json,
    write_json,
)
from scripts import daily_backup_systemd_native as timer
from scripts import m17_recovery_native as native
from scripts import release_authorization_qualification as release_fixtures
from scripts import restore_negative_native as negative
from scripts import restore_negative_qualification as negative_fixtures
from scripts.artifact_intake_fixture import receipt as intake_receipt


class RecoveryNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Both fixtures use controlled local signers. The approvals fixture drives
        # the normal authorization, reader, engine and prediction validation.
        negative_fixtures.SharedSnapshot.setUpClass()
        cls.addClassCleanup(negative_fixtures.SharedSnapshot.doClassCleanups)
        cls.shared = negative_fixtures.SharedSnapshot
        release_fixtures.ReleaseAuthorizationContracts.setUpClass()
        cls.addClassCleanup(release_fixtures.ReleaseAuthorizationContracts.tearDownClass)
        cls.fx = release_fixtures.ReleaseAuthorizationContracts()
        cls.fx.setUp()
        cls.addClassCleanup(cls.fx.doCleanups)
        bundle = cls.fx.bundle
        candidate = bundle.materials.fixture
        model_id = cls.shared.expected_model
        candidate.model = signing.decode64(cls.shared.record["objects"][model_id])
        runtime, scan = model.session(candidate.model)
        cls.features = [cls.shared.record["features"][0]] * 1000
        cls.scores = model.predict(runtime, cls.features)
        cls.predictions = {}
        for name in ("original", "restored"):
            batch = prediction_protocol.PredictionBatch(candidate.model, cls.features)
            scores = model.predict(runtime, cls.features)
            reply = prediction_protocol.response(batch.request, scores, scan)
            observed, _, proof = batch.consume(reply)
            cls.predictions[name] = dict(scores=observed.tolist(), prediction_receipt=proof)
        image = cls.shared.image
        candidate.expected["image_id"] = image
        candidate.metadata.update(image_id=image, execution={"image_id": image})
        candidate.metadata["model_digest"] = candidate.record["model_object"] = candidate.put(
            "candidates", candidate.model
        )
        report = candidate.bound["report"]
        report["prediction_protocol"]["model_digest"] = model_id
        report.update(
            model_digest=model_id,
            scan=scan,
            image_id=image,
            prediction_execution={"image_id": image},
            intake=intake_receipt(candidate.model, image, scan),
        )
        bundle.arguments["expected_serving_image"] = image
        candidate.metadata["validation_probability_digest"] = digest(canonical(cls.scores))
        candidate.record["scores_object"] = candidate.metadata["validation_probability_digest"]
        candidate.rebound_candidate()
        bundle.materials.context.update(
            candidate_reference=candidate.candidate_ref,
            evaluation_reference=candidate.evaluation_ref,
        )
        bundle.capsule = bundle.materials.create()
        cls.package = bundle.create()
        cls.checked = bundle.check(cls.package)

    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory())).resolve()
        self.state = self.root / ".runtime"
        self.target = self.state / native.TARGET
        self.campaign = self.shared.campaign
        self.approval = copy.deepcopy(self.shared.record)
        fx = self.fx
        c = fx.bundle.materials.fixture
        self.policy = c.policy
        self.public = dict(
            **c.public, approver=fx.bundle.materials.public, trust=fx.authorities.public["root"]
        )
        self.demo = dict(
            dataset=dict(
                dataset_reference=c.dataset_ref,
                source_approval_digest=c.trust["source_approval_digest"],
            ),
            candidate=dict(candidate_reference=c.candidate_ref, metadata=c.metadata),
            evaluation_reference=c.evaluation_ref,
        )
        self.report = dict(
            scope="release-proposal-and-authorization-denial-not-full-M10",
            status="pass",
            source_dirty=False,
            release_ready=False,
            source=c.expected,
            proposal_reference=digest(canonical(self.package["envelope"])),
            model_sha256=digest(c.model),
            subject_sha256=self.checked["subject_sha256"],
            campaign_id=self.checked["manifest"]["release_id"],
            policy_sha256=fx.policy_hash,
        )
        self.demo_file = self.state / "storage-demo.json"
        self.report_file = self.state / "evidence/release-native.json"
        self.method = self.root / ".github/workflows/storage-recovery.yml"
        for name in (
            "Dockerfile",
            "uv.lock",
            "data.lock",
            ".python-version",
            "pyproject.toml",
            "infra/systemd/mlsecops-daily-backup.timer",
            "infra/systemd/mlsecops-daily-backup.service",
            ".github/workflows/storage-recovery.yml",
            "scripts/controlled.py",
        ):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n")
        for path, obj in (
            (self.root / "policies/local-cpu.json", self.policy),
            (self.demo_file, self.demo),
            (self.report_file, self.report),
            (self.state / "trusted-keys.json", self.public),
            (self.target / "recovered-public-keys.json", self.public),
            (
                self.state
                / "release-proposals"
                / self.report["campaign_id"]
                / "policy-envelope.json",
                fx.policy_envelope,
            ),
        ):
            write_json(path, obj)
        self.output = self.root / "output"
        self.enterContext(
            patch.dict(
                os.environ,
                dict(
                    GITHUB_RUN_ID="403",
                    GITHUB_RUN_ATTEMPT="2",
                    RUNNER_TEMP=str(self.root),
                    GITHUB_OUTPUT=str(self.output),
                    M17_KEYS_SHA256=digest(canonical(self.public)),
                    M17_PROPOSAL_SHA256=digest(bounded_read(self.report_file)),
                    M17_DEMO_SHA256=digest(bounded_read(self.demo_file)),
                ),
            )
        )
        self.vault = self.root / ("m17-owner-" + self.campaign)
        self.revision = "f" * 40
        self.repo = self.stub(
            native, "command", side_effect=lambda a: "" if "status" in a else self.revision
        )
        self.stub(native, "__file__", new=str(self.root / "scripts/m17_recovery_native.py"))
        self.stub(native, "hosted")
        self.stub(native.uuid, "uuid4", return_value=UUID(hex=self.campaign))
        self.markers = {
            p: {**self.approval[k], "port": port}
            for p, k, port in ((self.state, "source", 15439), (self.target, "target", 15440))
        }
        self.running = {}
        for p, marker in self.markers.items():
            self.running[marker["container_id"]] = p == self.target
            write_json(p / "storage.json", marker)
        write_json(
            self.target / "workspace.json",
            dict(
                schema_version=1,
                product="trusted-mlsecops",
                workspace_id=self.markers[self.target]["workspace_id"],
            ),
        )
        storage_pki.initialize(self.target)
        storage_bootstrap.export_clients(self.target, 15440)
        self.validate = self.stub(
            storage_bootstrap, "validate", side_effect=lambda p: self.markers[p].copy()
        )
        self.inspect = self.stub(
            storage_bootstrap,
            "inspect",
            side_effect=lambda k, h: {"State": {"Running": self.running[h]}},
        )
        self.docker = self.stub(storage_bootstrap, "docker", side_effect=self.stop_container)
        self.make_primary()
        self.stub(native.load_clock, "sample", return_value=self.start)
        self.scheduler = self.stub(timer, "capture", side_effect=self.scheduled)
        self.seed = self.stub(negative, "seeded", side_effect=self.seeded)
        self.restore = self.stub(native.m17_restore_native, "capture", side_effect=self.restored)
        proposal = native.m17_restored_proposal
        self.stub(proposal, "hosted")
        self.stub(proposal, "validate", side_effect=lambda p: self.markers[p].copy())
        self.stub(proposal, "inspect", side_effect=self.inspect.side_effect)
        self.stub(proposal, "source", return_value=c.expected)
        self.stub(proposal.release_bundle, "load", return_value=self.package)
        self.enterContext(patch.object(daily_backup, "ROOT", self.root))

    def stub(self, obj, field, **kwargs):
        return self.enterContext(patch.object(obj, field, **kwargs))

    def make_primary(self):
        approval = self.approval
        self.verified = approval["healthy"]["verified_clock"]
        imported = datetime.fromisoformat(approval["restore"]["restored_at"])

        # The SQL restore and source stop precede the independently exercised HTTP probe.
        def anchor(instant):
            wall = (instant - datetime(1970, 1, 1, tzinfo=UTC)) // timedelta(microseconds=1) * 1000
            return dict(
                before_ns=wall,
                after_ns=wall,
                monotonic_ns=self.verified["monotonic_ns"] + wall - self.verified["before_ns"],
            )

        original = decode(signing.decode64(approval["backup_manifest"]["payload"]))
        event_time = datetime.fromtimestamp(
            max(float(row["epoch"]) for row in approval["events"]), UTC
        )
        # Place the export after the signed events, and before the first outer clock sample.
        # SharedSnapshot observes its real probe after its simulated import. Fit our
        # earlier anchors into that same subsecond slice rather than moving signed events.
        room = min(imported - event_time, timedelta(seconds=1))
        tick = room // 8
        point = imported - 5 * tick
        self.start = anchor(imported - 4 * tick)
        stopped = imported - tick
        self.rpo = (stopped - point).total_seconds()
        self.statement = dict(
            original,
            trusted_keys_digest=digest(canonical(self.public)),
            policy_digest=digest(canonical(self.policy)),
            recovery_point_at=point.isoformat(),
            started_at=(point - timedelta(seconds=1)).isoformat(),
            completed_at=point.isoformat(),
        )
        self.pin = digest(canonical(self.statement))
        self.archive = self.state / "backups" / self.pin
        env = signing.sign(self.statement, "storage-backup", self.fx.authorities.keys["root"])
        write_json(self.archive / "manifest.json", env)
        (self.archive / "data.dump").write_bytes(self.shared.archive_bytes)
        approval.update(
            backup_id=self.pin,
            backup_manifest=env,
            backup_public=self.public,
            backup_policy=self.policy,
        )
        approval["archive"]["backup_id"] = approval["restore"]["backup_id"] = self.pin
        c = self.fx.bundle.materials.fixture
        observ = dict(
            candidate_reference=c.candidate_ref,
            evaluation_reference=c.evaluation_ref,
            dataset_reference=c.dataset_ref,
            model_sha256=digest(c.model),
            image_id=self.shared.image,
            features_sha256=digest(canonical(self.features)),
            evaluated_scores=self.scores,
        )
        # Both branches represent independent captured worker replies for the same SQL model.
        self.sql = dict(
            schema_version=1,
            manifest=env,
            receipt={**approval["restore"], "reused": False},
            storage_demo=bounded_read(self.demo_file).decode(),
            source=self.markers[self.state],
            target=self.markers[self.target],
            started_at=(imported - 2 * tick).isoformat(),
            source_stopped_at=stopped.isoformat(),
            finished_at=imported.isoformat(),
            start_ns=anchor(imported - 2 * tick)["monotonic_ns"],
            finish_ns=anchor(imported)["monotonic_ns"],
        )
        for role in ("original", "restored"):
            self.sql[role] = dict(observ, **self.predictions[role])

    def stop_container(self, args):
        self.assertEqual(args[:-1], ["stop", "--time", "20"])
        self.assertTrue(self.running[args[-1]])
        self.running[args[-1]] = False

    @contextmanager
    def seeded(self, root, state, image, campaign, *, bind_candidate):
        self.assertTrue(callable(bind_candidate))
        self.assertEqual(
            (root, state, image, campaign), (self.root, self.state, native.IMAGE, self.campaign)
        )
        yield self

    def scheduled(self, root, state, owner_path, inventory):
        self.assertEqual(
            read_json(owner_path),
            dict(workspace_id=self.markers[state]["workspace_id"], trusted_keys=self.public),
        )
        receipt = dict(
            **{k: self.statement[k] for k in ("started_at", "completed_at", "recovery_point_at")},
            workspace_id=self.markers[state]["workspace_id"],
            source_revision=self.revision,
            backup_id=self.pin,
        )
        write_json(inventory, receipt)
        verified = daily_backup.execute("verify", state, owner_path, inventory)
        return verified, dict(
            inventory_sha256=digest(bounded_read(inventory)),
            backup_id=self.pin,
            runtime_units_removed=True,
            exit_status=0,
            trigger="controlled-on-active",
            daily_cadence_observed=False,
        )

    def restored(
        self, root, state, target, image, *, demo_pin, keys_pin, include_promotion, backup_pin
    ):
        self.assertEqual(
            (root, state, target, image, include_promotion, backup_pin),
            (self.root, self.state, self.target, native.IMAGE, True, self.pin),
        )
        self.assertEqual(
            (demo_pin, keys_pin), (os.environ["M17_DEMO_SHA256"], os.environ["M17_KEYS_SHA256"])
        )
        return copy.deepcopy(self.sql)

    def verify_restored(self, target, pin):
        self.assertEqual((target, pin), (self.target, self.pin))
        return copy.deepcopy(self.approval)

    def cli(self, action, expected=0):
        out = io.StringIO()
        with redirect_stdout(out), patch.object(sys, "argv", ["m17_recovery_native", action]):
            self.assertEqual(native.main(), expected, out.getvalue())
        return out.getvalue().splitlines()

    def captured(self):
        self.cli("capture")
        path = self.state / native.PACKET
        pin = digest(bounded_read(path))
        self.assertEqual(self.output.read_text().strip(), "sha256=" + pin)
        os.environ["M17_PRIMARY_SHA256"] = pin
        return read_json(path)

    def retain(self, record):
        path = self.state / native.PACKET
        write_json(path, record)
        os.environ["M17_PRIMARY_SHA256"] = digest(bounded_read(path))

    def test_cli_capture_stop_replay_includes_healthy_response_and_confirmed_stop(self):
        rec = self.captured()
        self.cli("stop")
        report = decode(self.cli("replay")[-1].encode())
        self.assertEqual(report["sql"]["backup_id"], self.pin)
        self.assertEqual(report["control"]["healthy_status"], 200)
        self.assertEqual(report["control"]["model_sha256"], self.shared.expected_model)
        self.assertEqual(report["control"]["model_sha256"], report["proposal"]["model_sha256"])
        self.assertEqual(report["control"]["model_sha256"], report["sql"]["model_sha256"])
        self.assertEqual(report["timing"]["rpo_seconds"], self.rpo)
        self.assertEqual(
            report["timing"]["rto_seconds"],
            (self.verified["monotonic_ns"] - self.start["monotonic_ns"]) / 1e9,
        )
        self.assertEqual(
            datetime.fromisoformat(report["started_at"]),
            datetime(1970, 1, 1, tzinfo=UTC)
            + timedelta(microseconds=rec["start"]["before_ns"] // 1000),
        )
        self.assertNotEqual(report["started_at"], rec["recovery"]["started_at"])
        self.assertFalse(report["proposal"]["release_ready"])

    def test_source_and_pin_preflight_before_seed_or_unit(self):
        for name in ("M17_DEMO_SHA256", "M17_PROPOSAL_SHA256", "M17_KEYS_SHA256"):
            with (
                self.subTest(name=name),
                patch.dict(os.environ, {name: "0" * 64}),
                self.assertRaises(Rejected),
            ):
                native.capture(self.root, self.state)
        self.repo.side_effect = lambda args: "dirty"
        with self.assertRaises(Rejected):
            native.capture(self.root, self.state)
        self.seed.assert_not_called()
        self.scheduler.assert_not_called()

    def test_changed_methods_after_probing_fail_capture_without_publishing(self):
        @contextmanager
        def drift(*args, **kwargs):
            with self.seeded(*args, **kwargs) as seed:
                yield seed
            self.method.write_text("changed method")

        self.seed.side_effect = drift
        self.cli("capture", 1)
        self.assertFalse(self.output.exists())
        self.assertFalse((self.state / native.PACKET).exists())

    def test_pin_mismatch_on_return_from_timer_refuses_before_restore(self):
        def bad(*args):
            inventory, schedule = self.scheduled(*args)
            return inventory, {**schedule, "inventory_sha256": "0" * 64}

        self.scheduler.side_effect = bad
        with self.assertRaises(Rejected):
            native.capture(self.root, self.state)
        self.restore.assert_not_called()

    def test_replay_requires_external_pins_and_stopped_owned_resources(self):
        record = self.captured()
        with self.assertRaises(Rejected):
            native.replay(self.root, self.state)
        self.cli("stop")
        with patch.dict(os.environ, M17_PRIMARY_SHA256="0" * 64), self.assertRaises(Rejected):
            native.replay(self.root, self.state)
        for directory in self.markers:
            with (
                patch.dict(self.markers[directory], network_id="9" * 64),
                self.assertRaises(Rejected),
            ):
                native.replay(self.root, self.state)
        for location in (
            self.vault / "owner.json",
            self.vault / "backup.json",
            self.archive / "data.dump",
        ):
            with self.subTest(location=location):
                content = bounded_read(location)
                location.write_bytes(b"{}\n")
                with self.assertRaises(Rejected):
                    native.replay(self.root, self.state)
                location.write_bytes(content)
        self.assertEqual(record["owner"]["runner"]["GITHUB_RUN_ATTEMPT"], "2")
        with patch.dict(os.environ, GITHUB_RUN_ATTEMPT="3"), self.assertRaises(Rejected):
            native.replay(self.root, self.state)

    def test_rehashed_cross_store_and_clock_substitutions_refuse(self):
        original = self.captured()
        self.cli("stop")
        for group, key, value in (
            ("approvals", "source", {**original["approvals"]["source"], "network_id": "9" * 64}),
            ("approvals", "target", {**original["approvals"]["target"], "volume": "other"}),
            ("approvals", "restore", {**original["approvals"]["restore"], "port": 15999}),
            ("approvals", "backup_public", {}),
            ("schedule", "runtime_units_removed", False),
            ("proposal", "subject_sha256", "9" * 64),
            ("recovery", "source_stopped_at", original["recovery"]["started_at"][:10]),
            ("start", "monotonic_ns", self.verified["monotonic_ns"] + 1),
        ):
            changed = copy.deepcopy(original)
            changed[group][key] = value
            self.retain(changed)
            with self.subTest(group=group, key=key), self.assertRaises(Rejected):
                native.replay(self.root, self.state)

    def test_stop_uses_validated_handles_only_and_confirms_stopped(self):
        self.cli("stop")
        handle = self.markers[self.target]["container_id"]
        self.docker.assert_called_once_with(["stop", "--time", "20", handle])
        (self.target / "storage.json").unlink()
        self.cli("stop")
        self.docker.assert_called_once()
        self.validate.side_effect = Rejected("foreign-owner")
        with self.assertRaisesRegex(Rejected, "foreign-owner"):
            native.stop(self.state)
        self.docker.assert_called_once()

    def test_foreign_target_still_stops_only_the_owned_source_in_finally(self):
        src = self.markers[self.state]["container_id"]
        dst = self.markers[self.target]["container_id"]
        self.running[src] = True

        def authorize(directory):
            if directory == self.target:
                raise Rejected("foreign-target")
            self.assertEqual(directory, self.state)
            return self.markers[directory].copy()

        self.validate.side_effect = authorize
        with self.assertRaisesRegex(Rejected, "foreign-target"):
            native.stop(self.state)
        self.docker.assert_called_once_with(["stop", "--time", "20", src])
        self.assertEqual(
            self.validate.call_args_list, [call(self.target), call(self.state), call(self.state)]
        )
        self.assertEqual(self.running, {src: False, dst: True})

    def test_replay_recomputes_same_archive_mutations_after_cleanup(self):
        packet = self.captured()
        self.cli("stop")
        packet["approvals"]["archive"]["cases"]["missing"]["archive_sha256"] = "8" * 64
        self.retain(packet)
        with self.assertRaises(Rejected):
            native.replay(self.root, self.state)

    def test_module_entrypoint_returns_bounded_failure_for_unknown_command(self):
        out = io.StringIO()
        # Execute the real script as __main__; an unknown operation has no side effects.
        path = Path(__file__).with_name("m17_recovery_native.py")
        with (
            patch.object(sys, "argv", [str(path), "unknown"]),
            redirect_stdout(out),
            self.assertRaises(SystemExit) as exit_code,
        ):
            runpy.run_path(str(path), run_name="__main__")
        self.assertEqual(exit_code.exception.code, 1)
        self.assertEqual(decode(out.getvalue().encode())["status"], "fail")

    def test_stop_unconfirmed_and_unknown_cli_have_bounded_failure(self):
        self.docker.side_effect = None
        self.cli("stop", 1)
        error = decode(self.cli("unknown", 1)[-1].encode())
        self.assertEqual(error["status"], "fail")
        self.assertEqual(set(error), {"site", "callers", "status"})
