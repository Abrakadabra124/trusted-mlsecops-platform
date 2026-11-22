"""Controlled delivery of the same bytes scanned and used for the DNS rollout."""

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import coredns_candidate_delivery as delivery


class CoreDNSDelivery(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        recipe = b"FROM scratch\n"
        self.enterContext(patch.object(delivery.subprocess, "check_output", return_value=recipe))
        (self.root / "context").mkdir()
        (self.root / "context/Dockerfile").write_bytes(recipe)
        config = canonical(
            dict(os="linux", architecture="amd64", config={}, rootfs={"diff_ids": []})
        )
        self.config = "sha256:" + digest(config)
        self.archive = self.root / "candidate.tar"
        with tarfile.open(self.archive, "w") as tar:
            for name, content in (
                ("config.json", config),
                ("manifest.json", b'[{"Config":"config.json"}]'),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(content)
                tar.addfile(member, io.BytesIO(content))
        self.inspect = {
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {},
            "RootFS": {"Layers": []},
            "Id": self.config,
        }
        self.enterContext(patch.object(delivery.audit, "inspect_image", return_value=self.inspect))
        self.env = dict(
            GITHUB_REPOSITORY=delivery.REPOSITORY,
            GITHUB_SHA="1" * 40,
            GITHUB_REF=delivery.REF,
            GITHUB_RUN_ID="123",
            GITHUB_RUN_ATTEMPT="1",
            QUALIFIED_RECIPE_SHA256=digest(recipe),
            QUALIFIED_ARCHIVE_SHA256=digest(self.archive.read_bytes()),
            QUALIFIED_CONFIG=self.config,
            LIVE_CONFIG=self.config,
        )
        (self.root / "candidate.id").write_text(self.config)
        self.reports(self.config, self.config)

    def reports(self, syft, grype):
        (self.root / "candidate-sbom.json").write_bytes(
            canonical({"source": {"metadata": {"imageID": syft}}})
        )
        (self.root / "candidate-scan.json").write_bytes(
            canonical({"source": {"target": {"imageID": grype}}})
        )

    def test_exact_receipt_and_producer_log(self):
        with patch("builtins.print") as log:
            delivery.prepare(self.root, self.env)
        raw = (self.root / "receipt.json").read_bytes()
        self.assertEqual(
            json.loads(raw),
            dict(
                schema_version=1,
                repository=self.env["GITHUB_REPOSITORY"],
                source_revision=self.env["GITHUB_SHA"],
                run_id=123,
                run_attempt=1,
                config_id=self.config,
                archive_sha256=self.env["QUALIFIED_ARCHIVE_SHA256"],
                archive_size=self.archive.stat().st_size,
                recipe_sha256=self.env["QUALIFIED_RECIPE_SHA256"],
            ),
        )
        for value in ("coredns-qualified-123-1", digest(raw), self.env["QUALIFIED_ARCHIVE_SHA256"]):
            self.assertIn(value, log.call_args.args[0])

    def refused(self):
        with self.assertRaises(Rejected):
            delivery.prepare(self.root, self.env)
        self.assertFalse((self.root / "receipt.json").exists())

    def test_changed_bytes_with_same_config(self):
        with self.archive.open("ab") as stream:
            stream.write(b"changed after qualification")
        self.refused()

    def test_each_image_identity_must_match(self):
        other = "sha256:" + "a" * 64
        for syft, grype in ((other, self.config), (self.config, other)):
            self.reports(syft, grype)
            self.refused()
        self.reports(other, other)
        self.inspect["Id"] = other
        (self.root / "candidate.id").write_text(other)
        with patch.dict(self.env, LIVE_CONFIG=other, QUALIFIED_CONFIG=other):
            self.refused()

    def test_scope_live_identity_and_recipe(self):
        for key, value in (
            ("GITHUB_REF", "refs/heads/main"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_RUN_ID", "1.0"),
            ("GITHUB_SHA", "bad"),
            ("GITHUB_REPOSITORY", "other/repo"),
            ("LIVE_CONFIG", "sha256:" + "f" * 64),
            ("QUALIFIED_RECIPE_SHA256", "0" * 64),
        ):
            with self.subTest(key=key), patch.dict(self.env, {key: value}):
                self.refused()
        (self.root / "context/Dockerfile").write_bytes(b"changed")
        self.refused()
