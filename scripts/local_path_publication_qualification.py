"""Offline authority, byte identity and schema separation tests for local-path."""

import io
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from mlsecops.contracts import Rejected, canonical, digest
from scripts import local_path_publication as local
from scripts.coredns_publication import PUBLISHER as coredns
from scripts.etcd_publication import PUBLISHER as etcd
from scripts.qualified_publication import REPOSITORY


def tar_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for path, data in files:
            member = tarfile.TarInfo(path)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return stream.getvalue()


class LocalPathPublicationTests(unittest.TestCase):
    def setUp(self):
        self.pub = local.PUBLISHER
        self.env = dict(
            GITHUB_REPOSITORY=REPOSITORY,
            GITHUB_REPOSITORY_ID="1407811916",
            GITHUB_REF="refs/heads/main",
            GITHUB_EVENT_NAME="workflow_dispatch",
            QUALIFIED_RUN_ID="45048228181",
        )
        self.art = dict(
            id=14764617515,
            name="local-path-qualified-45048228181-1",
            digest=self.pub.ZIP_DIGEST,
            size_in_bytes=109089777,
            expired=False,
            workflow_run=dict(
                id=self.pub.RUN_ID,
                repository_id=1407811916,
                head_repository_id=1407811916,
                head_branch=self.pub.BRANCH,
                head_sha=self.pub.EXPECTED_SOURCE,
            ),
        )

    def test_preflight_rejects_wrong_authority_before_io(self):
        for key, val in (
            ("QUALIFIED_RUN_ID", "45046593772"),
            ("GITHUB_REF", "refs/heads/dev"),
            ("GITHUB_EVENT_NAME", "push"),
            ("GITHUB_REPOSITORY_ID", "22"),
        ):
            with (
                self.subTest(key=key),
                patch.object(self.pub, "body") as body,
                self.assertRaises(Rejected),
            ):
                self.pub.preflight({**self.env, key: val})
            body.assert_not_called()

    def test_exact_archive_and_only_one_asset(self):
        def select(*assets):
            return self.pub.select_artifact(
                dict(total_count=len(assets), artifacts=assets), self.pub.RUN_ID
            )

        self.assertEqual(select(self.art), self.art)
        for key, val in (
            ("id", 1),
            ("size_in_bytes", 7),
            ("digest", "sha256:" + "b" * 64),
            ("name", "local-path-qualified-45048228181-2"),
            ("expired", True),
        ):
            with self.subTest(key=key), self.assertRaises(Rejected):
                select({**self.art, key: val})
        with self.assertRaises(Rejected):
            select(self.art, {**self.art, "name": "other"})

    def test_job_steps_include_post_cleanup_and_every_step_succeeded(self):
        steps = [dict(name=s, status="completed", conclusion="success") for s in self.pub.STEPS]
        job = dict(
            id=self.pub.JOB_ID,
            name="qualify",
            run_id=self.pub.RUN_ID,
            run_attempt=1,
            head_branch=self.pub.BRANCH,
            head_sha=self.pub.EXPECTED_SOURCE,
            status="completed",
            conclusion="success",
            steps=steps,
        )

        def verify(**changes):
            self.pub.verify_jobs(dict(total_count=1, jobs=[{**job, **changes}]), self.pub.RUN_ID)

        verify()
        for changes in (
            dict(id=1),
            dict(run_attempt=2),
            dict(steps=steps[:-2]),
            dict(steps=steps[::-1]),
            dict(steps=steps + [steps[-1]]),
            dict(steps=[*steps[:-1], {**steps[-1], "conclusion": "skipped"}]),
        ):
            with self.subTest(changes=list(changes)), self.assertRaises(Rejected):
                verify(**changes)

    def test_real_receipt_byte_pin_precedes_parsing_and_v1_publishers_reject_it(self):
        raw = canonical(self.pub.expected_receipt()) + b"\n"
        self.assertEqual(
            digest(raw), "355a417a232f82206a217230a6903e151d54b5ca6b03576874eaaeb8501a67bd"
        )
        size = self.pub.ARCHIVE_SIZE
        self.assertEqual(
            self.pub.validate_receipt(raw, self.pub.RUN_ID, size), self.pub.expected_receipt()
        )
        with patch.object(
            local, "decode", side_effect=AssertionError("parsed before verification")
        ):
            with self.assertRaisesRegex(Rejected, "receipt_digest"):
                self.pub.validate_receipt(raw + b" ", self.pub.RUN_ID, size)
        for legacy in (etcd, coredns):
            with self.assertRaises(Rejected):
                legacy.validate_receipt(raw, self.pub.RUN_ID, size)
        with self.assertRaises(Rejected):
            self.pub.validate_receipt(raw, self.pub.RUN_ID, size + 1)

    def test_v2_rejects_any_substituted_missing_or_extra_field_even_with_matching_byte_pin(self):
        original = self.pub.expected_receipt()
        for key, val in original.items():
            for changed in (
                {k: v for k, v in original.items() if k != key},
                {
                    **original,
                    key: (True if key == "run_attempt" else 1 if val is True else "foreign"),
                },
            ):
                raw = canonical(changed) + b"\n"
                with (
                    self.subTest(key=key),
                    patch.object(self.pub, "RECEIPT_SHA256", digest(raw)),
                    self.assertRaises(Rejected),
                ):
                    self.pub.validate_receipt(raw, self.pub.RUN_ID, self.pub.ARCHIVE_SIZE)
        raw = canonical({**original, "extra": "x"})
        with patch.object(self.pub, "RECEIPT_SHA256", digest(raw)), self.assertRaises(Rejected):
            self.pub.validate_receipt(raw, self.pub.RUN_ID, self.pub.ARCHIVE_SIZE)

    def test_zip_and_tar_digest_precede_docker_and_registry(self):
        temp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = temp / "test.zip"
        blobs = []
        witnesses = []
        for content in (b"stock ELF fixture", b"patched ELF fixture"):
            layer = tar_bytes([(self.pub.BINARY, content)])
            blobs.append(("blobs/sha256/" + digest(layer), layer))
            witnesses.append((digest(layer), len(content), digest(content)))
        self.enterContext(patch.object(self.pub, "ELF_LAYERS", witnesses))
        data = tar_bytes(blobs)
        with (
            patch.object(self.pub, "ARCHIVE_SIZE", len(data)),
            patch.object(self.pub, "ARCHIVE_SHA256", digest(data)),
        ):
            raw = canonical(self.pub.expected_receipt()) + b"\n"
            for label, tar, receipt in (
                ("ok", data, raw),
                ("tar", data[:-1] + b"X", raw),
                ("receipt", data, raw + b" "),
                ("elf", data, raw),
            ):
                with zipfile.ZipFile(path, "w") as z:
                    z.writestr("candidate.tar", tar)
                    z.writestr("receipt.json", receipt)
                blob = path.read_bytes()
                art = {**self.art, "digest": "sha256:" + digest(blob), "size_in_bytes": len(blob)}
                with (
                    patch.object(self.pub, "RECEIPT_SHA256", digest(raw)),
                    patch.object(self.pub, "ZIP_DIGEST", art["digest"]),
                    patch.object(self.pub, "ZIP_SIZE", len(blob)),
                ):
                    if label == "ok":
                        self.pub.unpack(path, art, self.pub.RUN_ID, temp / label)
                        self.assertEqual((temp / label).read_bytes(), data)
                    elif label == "elf":
                        with (
                            patch.object(
                                self.pub,
                                "ELF_LAYERS",
                                [(witnesses[1][0], witnesses[1][1], "0" * 64)],
                            ),
                            self.assertRaisesRegex(Rejected, "elf_digest"),
                        ):
                            self.pub.unpack(path, art, self.pub.RUN_ID, temp / label)
                    else:
                        with self.assertRaises(Rejected):
                            self.pub.unpack(path, art, self.pub.RUN_ID, temp / label)

    def test_anonymous_pull_checks_actual_layer_responses(self):
        content = b"compressed layer"
        layers = [{"digest": "sha256:" + digest(content), "size": len(content)}]
        raw = canonical({"layers": layers})
        manifest = "sha256:" + digest(raw)
        self.assertTrue(self.pub.REQUIRE_PUBLIC)
        for body in (content, content[:-1], content + b"x", b"x" * len(content), None):
            with (
                self.subTest(body=body),
                patch.object(self.pub, "registry_auth", return_value="anonymous") as grant,
                patch.object(self.pub, "readback") as readback,
                patch.object(self.pub, "body", return_value=raw),
                patch.object(self.pub, "open_url") as fetch,
            ):
                if body is None:
                    fetch.side_effect = HTTPError("https://ghcr.io", 403, "forbidden", {}, None)
                    self.assertEqual(
                        self.pub.anonymous_readback("tag", manifest, self.pub.CONFIG), "blocked"
                    )
                else:
                    fetch.return_value = io.BytesIO(body)
                    if body == content:
                        self.assertEqual(
                            self.pub.anonymous_readback("tag", manifest, self.pub.CONFIG),
                            "verified",
                        )
                    else:
                        with self.assertRaises(Rejected):
                            self.pub.anonymous_readback("tag", manifest, self.pub.CONFIG)
                grant.assert_called_once_with()
                readback.assert_called_once_with("tag", manifest, self.pub.CONFIG, "anonymous")
                fetch.assert_called_once_with(
                    self.pub.V2 + "/blobs/" + layers[0]["digest"],
                    "anonymous",
                    "application/octet-stream",
                )

    def test_preflight_cli_cannot_publish_and_requires_both_source_files(self):
        with (
            patch.dict(os.environ, self.env, clear=True),
            patch.object(self.pub, "evidence", return_value=self.art) as evidence,
            patch.object(self.pub, "main") as publish,
            patch.object(self.pub, "body", side_effect=[b"workflow", b"recipe"]) as get,
            patch.object(self.pub, "WORKFLOW_SHA256", digest(b"workflow")),
        ):
            with self.assertRaisesRegex(Rejected, "source_file_mismatch"):
                local.main(["--preflight"])
            self.assertEqual(len(get.call_args_list), 2)
            evidence.assert_called_once_with(self.pub.RUN_ID, None)
            publish.assert_not_called()

    def test_only_stock_entrypoint_in_the_measured_config(self):
        details = dict(
            Id=self.pub.CONFIG,
            Os="linux",
            Architecture="amd64",
            Config={"Entrypoint": ["/bin/sh", "-c", "/" + self.pub.BINARY], "User": "0"},
        )
        self.pub.verify_image(details)
        for change in (
            dict(Id=self.pub.STOCK_CONFIG),
            dict(Architecture="arm64"),
            dict(Config={**details["Config"], "Entrypoint": ["/bin/sh"]}),
        ):
            with self.assertRaises(Rejected):
                self.pub.verify_image({**details, **change})
