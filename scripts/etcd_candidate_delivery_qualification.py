"""Exercise the delivery receipt against small Docker save and scanner fixtures."""

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, digest
from scripts import etcd_candidate_delivery as delivery


class DeliveryReceipt(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.scans = self.work / "scans"
        self.scans.mkdir()
        self.recipe = b"FROM scratch\n"
        (self.work / "context").mkdir()
        (self.work / "context/Dockerfile").write_bytes(self.recipe)
        self.git = self.enterContext(
            patch.object(delivery.subprocess, "check_output", return_value=self.recipe)
        )
        layers = ["sha256:" + "1" * 64]
        config = json.dumps(
            {"os": "linux", "architecture": "amd64", "config": {}, "rootfs": {"diff_ids": layers}}
        ).encode()
        self.config_id = "sha256:" + digest(config)
        self.archive = self.scans / "candidate.tar"
        with tarfile.open(self.archive, "w") as archive:
            for name, data in (
                ("config.json", config),
                ("manifest.json", b'[{"Config":"config.json"}]'),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        self.inspect = {
            "Id": self.config_id,
            "Os": "linux",
            "Architecture": "amd64",
            "RootFS": {"Layers": layers},
            "Config": {},
        }
        self.report("inspect", [self.inspect])
        self.report("sbom", {"source": {"metadata": {"imageID": self.config_id}}})
        self.report("grype", {"source": {"target": {"imageID": self.config_id}}})
        (self.work / "first").mkdir()
        (self.work / "first/id").write_text(self.config_id + "\n")
        self.env = {
            "GITHUB_REPOSITORY": "Abrakadabra124/trusted-mlsecops-platform",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_REF": "refs/heads/qualify/r1-etcd-delivery",
            "ETCD_ARCHIVE_SHA256": digest(self.archive.read_bytes()),
            "ETCD_LIVE_CONFIG": self.config_id,
            "ETCD_RECIPE_SHA256": digest(self.recipe),
        }

    def report(self, name, value):
        (self.scans / f"candidate.{name}.json").write_text(json.dumps(value))

    def refused(self):
        with self.assertRaises(Rejected):
            delivery.prepare(self.work, self.env)
        self.assertFalse((self.scans / "receipt.json").exists())

    def test_exact_receipt_and_producer_log(self):
        with patch("builtins.print") as output:
            delivery.prepare(self.work, self.env)
        receipt = (self.scans / "receipt.json").read_bytes()
        self.assertEqual(
            json.loads(receipt),
            {
                "schema_version": 1,
                "repository": self.env["GITHUB_REPOSITORY"],
                "source_revision": self.env["GITHUB_SHA"],
                "run_id": 123,
                "run_attempt": 2,
                "archive_sha256": self.env["ETCD_ARCHIVE_SHA256"],
                "archive_size": self.archive.stat().st_size,
                "config_id": self.config_id,
                "recipe_sha256": digest(self.recipe),
            },
        )
        self.assertIn("receipt_sha256=" + digest(receipt), output.call_args.args[0])
        self.assertIn(
            "archive_sha256=" + digest(self.archive.read_bytes()), output.call_args.args[0]
        )
        self.assertEqual(
            self.git.call_args.args[0][-1], self.env["GITHUB_SHA"] + ":" + delivery.RECIPE
        )

    def test_archive_changed_after_scan_with_identical_config(self):
        with self.archive.open("ab") as stream:
            stream.write(b"changed")
        self.refused()

    def test_original_reports_and_live_identity_must_each_match(self):
        for report, key in (("sbom", "metadata"), ("grype", "target")):
            with self.subTest(report=report):
                self.report(report, {"source": {key: {"imageID": "sha256:" + "0" * 64}}})
                self.refused()
                self.report(report, {"source": {key: {"imageID": self.config_id}}})
        self.env["ETCD_LIVE_CONFIG"] = "sha256:" + "0" * 64
        self.refused()

    def test_archive_config_independent_of_all_reported_ids(self):
        other = "sha256:" + "b" * 64
        self.inspect["Id"] = other
        self.report("inspect", [self.inspect])
        self.report("sbom", {"source": {"metadata": {"imageID": other}}})
        self.report("grype", {"source": {"target": {"imageID": other}}})
        (self.work / "first/id").write_text(other)
        self.env["ETCD_LIVE_CONFIG"] = other
        self.refused()

    def test_recipe_pin_and_build_context_must_each_match_git_blob(self):
        self.git.return_value = b"other"
        self.refused()
        self.git.return_value = self.recipe
        (self.work / "context/Dockerfile").write_bytes(b"other")
        self.refused()

    def test_run_identity(self):
        for field, value in (
            ("GITHUB_REPOSITORY", "elsewhere/project"),
            ("GITHUB_REF", "refs/heads/main"),
            ("GITHUB_SHA", "a" * 39),
            ("GITHUB_RUN_ID", "1.5"),
            ("GITHUB_RUN_ATTEMPT", "0"),
        ):
            with self.subTest(field=field), patch.dict(self.env, {field: value}):
                self.refused()
