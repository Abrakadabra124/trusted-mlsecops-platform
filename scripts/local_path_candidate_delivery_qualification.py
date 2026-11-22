"""Exercise the two producer checkpoints with a real tar and no daemon."""

import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts import local_path_candidate_delivery as delivery


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.run = self.root / "scan"
        self.run.mkdir()
        self.archive = self.run / "candidate.tar"
        config = canonical(
            {
                "os": "linux",
                "architecture": "amd64",
                "config": {},
                "rootfs": {"diff_ids": ["sha256:" + "a" * 64]},
            }
        )
        self.config = "sha256:" + digest(config)
        with tarfile.open(self.archive, "w") as tar:
            for name, data in (
                ("manifest.json", canonical([{"Config": "config.json"}])),
                ("config.json", config),
            ):
                item = tarfile.TarInfo(name)
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
        self.env = {
            "RUNNER_TEMP": str(self.root),
            "GITHUB_OUTPUT": str(self.root / "output"),
            "GITHUB_REPOSITORY": delivery.REPOSITORY,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_REF": delivery.REF,
            "GITHUB_REPOSITORY_ID": str(delivery.REPO_ID),
            "GITHUB_WORKFLOW_REF": delivery.REPOSITORY
            + "/"
            + delivery.WORKFLOW
            + "@"
            + delivery.REF,
            "GITHUB_JOB": "qualify",
            "GITHUB_WORKSPACE": str(Path.cwd()),
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "LIVE_OUTCOME": "success",
            "CLEANUP_OUTCOME": "success",
        }
        self.enterContext(patch.dict(os.environ, self.env, clear=False))
        self.enterContext(patch.object(delivery.platform, "system", return_value="Linux"))
        self.enterContext(patch.object(delivery.platform, "machine", return_value="x86_64"))
        self.git = self.enterContext(
            patch.object(delivery, "checked_recipe", return_value="b" * 64)
        )
        self.enterContext(
            patch.object(
                delivery.audit,
                "inspect_image",
                return_value={
                    "Id": self.config,
                    "Os": "linux",
                    "Architecture": "amd64",
                    "Config": {},
                    "RootFS": {"Layers": ["sha256:" + "a" * 64]},
                },
            )
        )
        self.report = {
            "status": "diagnostic-clear",
            "stock": {"config": delivery.STOCK[1]},
            "proposal": {"config": self.config},
            "binary_sha256": delivery.BINARY_SHA256,
            "stock_binary_sha256": delivery.STOCK_BINARY_SHA256,
        }
        self.live = {
            "schema_version": 1,
            "scope": "disposable-local-path-pvc",
            "status": "pass",
            "release_ready": False,
            "reason": None,
            "baseline_config_id": delivery.STOCK[1],
            "candidate_config_id": self.config,
            "restored_stock_config_id": delivery.STOCK[1],
            "candidate_runtime_digest": "sha256:" + "d" * 64,
            "deployment_uid": "b" * 36,
            "pvc_bound": True,
            "remount_verified": True,
            "pvc_deleted": True,
            "pv_deleted": True,
            "backing_directory_absent": True,
            "cleanup_verified": True,
        }
        self.raw = self.archive.read_bytes()
        self.archive_sha = digest(self.raw)

    def retain(self):
        return delivery.retain(self.run, self.report, self.archive_sha)

    def stage(self):
        self.retain()
        key, value = (self.root / "output").read_text().strip().split("=")
        self.assertEqual(key, "measurement_sha256")
        os.environ["MEASUREMENT_SHA256"] = value
        self.write_live(self.live)

    def write_live(self, live):
        raw = canonical(live) + b"\n"
        (self.root / "local-path-pvc.json").write_bytes(raw)
        os.environ["LIVE_REPORT_SHA256"] = digest(raw)

    def test_refuses_to_stage_without_clear_same_archive_and_hosted_run(self):
        for status in ("fail", "inconclusive"):
            with (
                self.subTest(status=status),
                patch.dict(self.report, status=status),
                self.assertRaises(Rejected),
            ):
                self.retain()
        for key, value in (
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_REPOSITORY", "other/repo"),
            ("GITHUB_REF", "refs/heads/main"),
            ("RUNNER_ENVIRONMENT", "self-hosted"),
        ):
            with (
                self.subTest(key=key),
                patch.dict(os.environ, {key: value}),
                self.assertRaises(Rejected),
            ):
                self.retain()
        with self.assertRaises(Rejected):
            delivery.retain(self.run, self.report, "0" * 64)
        with patch.dict(self.report, stock_binary_sha256="1" * 64), self.assertRaises(Rejected):
            self.retain()
        self.assertFalse((self.root / "local-path-measured").exists())

    def test_requires_live_report_and_separate_successful_cleanup(self):
        self.stage()
        for key, value in (
            ("CLEANUP_OUTCOME", "skipped"),
            ("LIVE_OUTCOME", "failure"),
            ("LIVE_REPORT_SHA256", "0" * 64),
            ("MEASUREMENT_SHA256", "f" * 64),
            ("GITHUB_SHA", "c" * 40),
            ("GITHUB_RUN_ID", "456"),
        ):
            with (
                self.subTest(key=key),
                patch.dict(os.environ, {key: value}),
                self.assertRaises(Rejected),
            ):
                delivery.prepare()
        for key, value in {
            "schema_version": True,
            "scope": "other",
            "status": "inconclusive",
            "reason": "fault",
            "release_ready": True,
            "baseline_config_id": self.config,
            "restored_stock_config_id": self.config,
            "candidate_config_id": delivery.STOCK[1],
            "candidate_runtime_digest": "tag",
            **dict.fromkeys(delivery.LIVE_CHECKS, 1),
        }.items():
            self.write_live({**self.live, key: value})
            with self.subTest(key=key), self.assertRaises(Rejected):
                delivery.prepare()
        self.assertFalse((self.root / "local-path-qualified").exists())

    def test_rechecks_retained_bytes_config_and_directory_members(self):
        self.stage()
        parent = self.root / "local-path-measured"
        path = parent / "candidate.tar"
        path.write_bytes(self.raw + b"trailing")
        with self.assertRaises(Rejected):
            delivery.prepare()
        path.write_bytes(self.raw)
        with (
            patch.object(delivery.audit, "identity", return_value=delivery.STOCK[1]),
            self.assertRaises(Rejected),
        ):
            delivery.prepare()
        extra = parent / "kubeconfig"
        extra.touch()
        with self.assertRaises(Rejected):
            delivery.prepare()
        extra.unlink()
        (self.root / "local-path-qualified").mkdir()
        with self.assertRaises((OSError, Rejected)):
            delivery.prepare()
        self.assertEqual(list((self.root / "local-path-qualified").iterdir()), [])

    def test_only_exact_original_archive_and_bounded_receipt(self):
        self.stage()
        delivery.prepare()
        target = self.root / "local-path-qualified"
        self.assertEqual(
            sorted(p.name for p in target.iterdir()), ["candidate.tar", "receipt.json"]
        )
        self.assertEqual((target / "candidate.tar").read_bytes(), self.raw)
        receipt = decode((target / "receipt.json").read_bytes(), 8192)
        self.assertEqual(receipt["archive_sha256"], self.archive_sha)
        self.assertEqual(receipt["config_id"], self.config)
        self.assertEqual(receipt["stock_config_id"], delivery.STOCK[1])
        self.assertEqual(receipt["live_report_sha256"], os.environ["LIVE_REPORT_SHA256"])
        self.assertEqual(receipt["measurement_sha256"], os.environ["MEASUREMENT_SHA256"])
        self.assertEqual(receipt["recipe_sha256"], "b" * 64)
        self.assertEqual(receipt["candidate_runtime_digest"], self.live["candidate_runtime_digest"])
