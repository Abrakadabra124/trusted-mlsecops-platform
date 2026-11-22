import hashlib
import io
import os
import runpy
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from mlsecops.contracts import Rejected, canonical
from scripts import etcd_publication
from scripts import qualified_publication as shared


class PublicationContractCases:
    """Run the same transport, substitution and archive tests for either fixed publisher."""

    def setUp(self):
        self.rev = "a" * 40
        self.enterContext(patch.object(self.pub, "EXPECTED_SOURCE", self.rev))
        self.run_id = 1234
        self.repo = {"id": 1407811916, "full_name": shared.REPOSITORY, "private": False}
        self.run = {
            "repository": self.repo,
            "head_repository": self.repo,
            "id": self.run_id,
            "workflow_id": 74,
            "path": self.pub.WORKFLOW,
            "head_branch": self.pub.BRANCH,
            "head_sha": self.rev,
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
            "event": "push",
        }
        self.steps = [
            {"name": name, "status": "completed", "conclusion": "success"}
            for name in self.pub.STEPS
        ]
        self.job = {
            "name": self.pub.JOB_NAME,
            "run_attempt": 1,
            "head_branch": self.pub.BRANCH,
            "run_id": self.run_id,
            "head_sha": self.rev,
            "status": "completed",
            "conclusion": "success",
            "steps": self.steps,
        }
        self.art = {
            "id": 71,
            "name": self.asset,
            "expired": False,
            "size_in_bytes": 500,
            "digest": "sha256:" + "c" * 64,
            "workflow_run": {
                "id": self.run_id,
                "repository_id": self.repo["id"],
                "head_repository_id": self.repo["id"],
                "head_sha": self.rev,
                "head_branch": self.pub.BRANCH,
            },
        }
        self.config = "sha256:" + "d" * 64
        self.tar = b"test-only-archive"
        self.receipt = {
            "schema_version": 1,
            "repository": shared.REPOSITORY,
            "source_revision": self.rev,
            "run_id": self.run_id,
            "run_attempt": 1,
            "archive_size": len(self.tar),
            "archive_sha256": hashlib.sha256(self.tar).hexdigest(),
            "config_id": self.config,
            "recipe_sha256": self.pub.RECIPE,
        }
        self.temp = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_only_fixed_main_dispatch_and_nonzero_source(self):
        env = {
            "GITHUB_REPOSITORY": shared.REPOSITORY,
            "GITHUB_REPOSITORY_ID": str(shared.REPO_ID),
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
        }
        self.assertEqual(self.pub.dispatch(env, "1234"), 1234)
        for text in ("", "0", "01234", "-1", "1.1", "12\n", "abc", "пј‘пј’"):
            with self.subTest(text=text), self.assertRaises(Rejected):
                self.pub.dispatch(env, text)
        for key in env:
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.pub.dispatch({**env, key: "other"}, "1234")
        with patch.object(self.pub, "EXPECTED_SOURCE", "0" * 40), self.assertRaises(Rejected):
            self.pub.dispatch(env, "1234")

    def test_trusted_run_and_exact_successful_job(self):
        self.pub.verify_run(self.run, self.run_id)
        self.pub.verify_jobs({"total_count": 1, "jobs": [self.job]}, self.run_id)
        for key, value in (
            ("id", 4321),
            ("head_branch", "main"),
            ("head_sha", "f" * 40),
            ("event", "workflow_dispatch"),
            ("run_attempt", 2),
            ("run_attempt", True),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("path", ".github/workflows/evil.yml"),
            ("head_repository", {**self.repo, "id": 77}),
            ("repository", {**self.repo, "private": True}),
        ):
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.pub.verify_run({**self.run, key: value}, self.run_id)
        for job in (
            {**self.job, "name": "other"},
            {**self.job, "run_id": 1},
            {**self.job, "steps": self.steps[:-1]},
            {**self.job, "steps": [*self.steps, self.steps[-1]]},
            {**self.job, "steps": [*self.steps[:-1], {**self.steps[-1], "conclusion": "skipped"}]},
        ):
            with self.assertRaises(Rejected):
                self.pub.verify_jobs({"total_count": 1, "jobs": [job]}, self.run_id)

    def test_attempt_specific_api_job_workflow_and_artifact(self):
        path = f"/actions/runs/{self.run_id}"
        docs = {
            path: self.run,
            "/actions/workflows/74": {"id": 74, "path": self.pub.WORKFLOW},
            path + "/attempts/1/jobs?per_page=100": {"total_count": 1, "jobs": [self.job]},
            path + "/artifacts?per_page=100": {"total_count": 1, "artifacts": [self.art]},
        }

        def get(url, auth):
            self.assertEqual(auth, "test grant")
            return canonical(docs[url.removeprefix(shared.API)])

        with patch.object(self.pub, "body", side_effect=get):
            self.assertEqual(self.pub.evidence(self.run_id, "test grant"), self.art)
            for key, bad in (
                ("head_branch", "foreign"),
                ("run_attempt", 2),
                ("steps", self.steps[::-1]),
                ("steps", self.steps[:-2]),
            ):
                with patch.dict(self.job, {key: bad}), self.assertRaises(Rejected):
                    self.pub.evidence(self.run_id, "test grant")
            docs["/actions/workflows/74"]["path"] = ".github/workflows/wrong.yml"
            with self.assertRaisesRegex(Rejected, "workflow_invalid"):
                self.pub.evidence(self.run_id, "test grant")

    def test_cli_reports_private_publication_and_sanitizes_failures(self):
        env = {
            "GITHUB_REPOSITORY": shared.REPOSITORY,
            "GITHUB_REPOSITORY_ID": str(shared.REPO_ID),
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "QUALIFIED_RUN_ID": str(self.run_id),
            "GITHUB_TOKEN": "sensitive-test-value",
            "RUNNER_TEMP": str(self.temp),
            "GITHUB_ACTOR": "actor",
        }
        for access in ("blocked", "verified"):
            with (
                patch.dict(os.environ, env),
                redirect_stdout(io.StringIO()) as out,
                patch.object(
                    self.pub,
                    "publish",
                    return_value={"published": True, "anonymous_adoption": access},
                ) as send,
            ):
                self.assertEqual(self.pub.main(), int(access == "blocked" and self.public_required))
                self.assertEqual(
                    send.call_args.args[:3], (self.run_id, "sensitive-test-value", "actor")
                )
                self.assertNotIn("sensitive-test-value", out.getvalue())
                self.assertEqual(
                    "Anonymous adoption blocked" in out.getvalue(), access == "blocked"
                )
        for error in (
            HTTPError("https://storage.example/?sensitive-test-value", 403, "", {}, io.BytesIO()),
            OSError("sensitive-test-value"),
            Rejected("etcd_publication_run_invalid"),
        ):
            with (
                patch.dict(os.environ, env),
                redirect_stdout(io.StringIO()) as out,
                patch.object(self.pub, "publish", side_effect=error),
            ):
                self.assertEqual(self.pub.main(), 1)
                self.assertNotIn("sensitive-test-value", out.getvalue())
        with (
            patch.dict(os.environ, {**env, "GITHUB_REF": "refs/heads/foreign"}),
            redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as stopped,
        ):
            runpy.run_path(self.module.__file__, run_name="__main__")
        self.assertEqual(stopped.exception.code, 1)

    def test_transport_and_stream_bounds(self):
        with patch.object(shared, "build_opener") as opener:
            opener.return_value.open.return_value = io.BytesIO(b"ok")
            self.assertEqual(self.pub.body("https://api.github.com/test", "Bearer value"), b"ok")
            request = opener.return_value.open.call_args.args[0]
            redirect = shared.HTTPSRedirect(self.pub.require)
            next_req = redirect.redirect_request(
                request, None, 302, "", {}, "https://storage.example/file"
            )
            self.assertIsNone(next_req.get_header("Authorization"))
            self.pub.open_url("https://ghcr.io/token")
            self.assertIsNone(
                opener.return_value.open.call_args.args[0].get_header("Authorization")
            )
            with self.assertRaises(Rejected):
                redirect.redirect_request(request, None, 302, "", {}, "http://storage.example/file")
        for name, content, size in (("short", b"1", 2), ("long", b"12", 1)):
            with self.assertRaises(Rejected):
                self.pub.copy_exact(io.BytesIO(content), self.temp / name, size)
        with patch.object(self.pub, "body", return_value=canonical({"token": "fake"})) as get:
            self.assertEqual(self.pub.registry_auth("Basic test"), "Bearer fake")
            self.assertIn("pull%2Cpush", get.call_args.args[0])
            self.assertEqual(self.pub.registry_auth(), "Bearer fake")
            self.assertNotIn("push", get.call_args.args[0])
            self.assertIsNone(get.call_args.args[1])

    def test_artifact_id_and_source_binding(self):
        def check(arts):
            return self.pub.select_artifact(
                {"total_count": len(arts), "artifacts": arts}, self.run_id
            )

        self.assertEqual(check([self.art]), self.art)
        for change in (
            {"name": "other"},
            {"digest": None},
            {"expired": True},
            {"size_in_bytes": shared.LIMIT + 1},
            {"workflow_run": {**self.art["workflow_run"], "head_repository_id": 3}},
            {"workflow_run": {**self.art["workflow_run"], "head_sha": "0" * 40}},
        ):
            with self.assertRaises(Rejected):
                check([{**self.art, **change}])
        with self.assertRaises(Rejected):
            check([self.art, self.art])

    def unpack(self, receipt=None, extra=None, symlink=False, corrupt_digest=False):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as z:
            ent = zipfile.ZipInfo("candidate.tar")
            ent.external_attr = (0o120777 if symlink else 0o100644) << 16
            z.writestr(ent, self.tar)
            z.writestr("receipt.json", canonical(self.receipt if receipt is None else receipt))
            if extra:
                z.writestr(extra, b"x")
        path = self.temp / "artifact.zip"
        path.write_bytes(data.getvalue())
        art = {
            **self.art,
            "size_in_bytes": path.stat().st_size,
            "digest": "sha256:" + hashlib.sha256(data.getvalue()).hexdigest(),
        }
        if corrupt_digest:
            art["digest"] = "sha256:" + "0" * 64
        return self.pub.unpack(path, art, self.run_id, self.temp / "candidate.tar")

    def test_archive_receipt_and_config(self):
        self.assertEqual(self.unpack(), self.receipt)
        self.assertEqual((self.temp / "candidate.tar").read_bytes(), self.tar)

    def test_invalid_members_digest_and_receipt_fail_closed(self):
        for params in (
            {"extra": "../escape"},
            {"extra": "other"},
            {"symlink": True},
            {"corrupt_digest": True},
        ):
            with self.subTest(params=params), self.assertRaises(Rejected):
                self.unpack(**params)
        for key, value in (
            ("source_revision", "b" * 40),
            ("run_id", False),
            ("run_attempt", True),
            ("schema_version", 1.0),
            ("recipe_sha256", "f" * 64),
            ("archive_size", 1),
            ("archive_sha256", "0" * 64),
            ("config_id", "sha256:bad"),
            ("extra", 0),
        ):
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.unpack({**self.receipt, key: value})

    def test_tag_lookup_allows_only_registry_confirmed_absence(self):
        def error(status, code):
            return HTTPError(
                "https://ghcr.io",
                status,
                "",
                {},
                io.BytesIO(canonical({"errors": [{"code": code}]})),
            )

        for code in ("MANIFEST_UNKNOWN", "NAME_UNKNOWN"):
            with patch.object(self.pub, "body", side_effect=error(404, code)):
                self.pub.require_absent("tag", "Bearer test")
        for status, code in (
            (401, "UNAUTHORIZED"),
            (403, "DENIED"),
            (500, "UNKNOWN"),
            (404, "DENIED"),
        ):
            with (
                patch.object(self.pub, "body", side_effect=error(status, code)),
                self.assertRaises((HTTPError, Rejected)),
            ):
                self.pub.require_absent("tag", "Bearer test")
        with (
            patch.object(self.pub, "body", return_value=b"manifest"),
            self.assertRaisesRegex(Rejected, "tag_exists"),
        ):
            self.pub.require_absent("tag", "Bearer test")

    def test_native_readback_checks_actual_bytes_by_tag_digest_and_config(self):
        config = canonical({"os": "linux", "architecture": "amd64"})
        cfg = "sha256:" + shared.digest(config)
        m = canonical({"schemaVersion": 2, "config": {"digest": cfg, "size": len(config)}})
        d = "sha256:" + shared.digest(m)
        with patch.object(self.pub, "body", side_effect=[m, m, config]) as get:
            self.pub.readback("tag", d, cfg, "Bearer test")
            self.assertEqual(
                [c.args[0] for c in get.call_args_list],
                [
                    self.pub.V2 + "/manifests/tag",
                    self.pub.V2 + "/manifests/" + d,
                    self.pub.V2 + "/blobs/" + cfg,
                ],
            )
        for responses, expected in (
            ([b"x"], cfg),
            ([m, b"x"], cfg),
            ([m, m], "sha256:" + "f" * 64),
            ([m, m, b"x" * len(config)], cfg),
        ):
            with patch.object(self.pub, "body", side_effect=responses), self.assertRaises(Rejected):
                self.pub.readback("tag", d, expected, "Bearer test")

    def test_separate_anonymous_readback_does_not_mask_verification_errors(self):
        with patch.object(self.pub, "registry_auth", return_value="anonymous") as auth:
            with patch.object(self.pub, "readback") as read:
                self.assertEqual(
                    self.pub.anonymous_readback("tag", "manifest", "config"), "verified"
                )
                auth.assert_called_once_with()
                read.assert_called_once_with("tag", "manifest", "config", "anonymous")
            for code in (401, 403, 404, 503):
                error = HTTPError("https://ghcr.io", code, "", {}, io.BytesIO())
                with patch.object(self.pub, "readback", side_effect=error):
                    if code == 503:
                        with self.assertRaises(HTTPError):
                            self.pub.anonymous_readback("tag", "manifest", "config")
                    else:
                        self.assertEqual(
                            self.pub.anonymous_readback("tag", "manifest", "config"), "blocked"
                        )
            with (
                patch.object(self.pub, "readback", side_effect=Rejected("bad_digest")),
                self.assertRaises(Rejected),
            ):
                self.pub.anonymous_readback("tag", "manifest", "config")

    def test_publish_only_by_verified_loaded_id_and_never_run_image(self):
        image_config = self.image_config()
        cfg = {
            "os": "linux",
            "architecture": "amd64",
            "rootfs": {"diff_ids": []},
            "config": image_config,
        }
        cfg_id = "sha256:" + shared.digest(canonical(cfg))
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as t:
            for n, b in (
                ("manifest.json", canonical([{"Config": "config.json"}])),
                ("config.json", canonical(cfg)),
            ):
                info = tarfile.TarInfo(n)
                info.size = len(b)
                t.addfile(info, io.BytesIO(b))
        self.tar = archive.getvalue()
        self.receipt.update(
            config_id=cfg_id, archive_size=len(self.tar), archive_sha256=shared.digest(self.tar)
        )
        recipe = b"test recipe"
        workflow = b"test workflow"
        self.receipt["recipe_sha256"] = shared.digest(recipe)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("candidate.tar", self.tar)
            z.writestr("receipt.json", canonical(self.receipt))
        zip_data = buf.getvalue()
        art = {
            **self.art,
            "digest": "sha256:" + shared.digest(zip_data),
            "size_in_bytes": len(zip_data),
        }
        tag = self.tag_prefix + self.rev
        manifest = "sha256:" + "e" * 64
        details = {
            "Id": cfg_id,
            "Architecture": "amd64",
            "Os": "linux",
            "RootFS": {"Layers": []},
            "Config": image_config,
        }

        def docker(args, **kwargs):
            cmd = args[3:]
            self.assertNotIn("token-example", args)
            if cmd[:2] == ["image", "inspect"]:
                output = canonical([details])
            elif cmd[0] == "push":
                self.assertEqual(
                    cmd, ["push", "--platform", "linux/amd64", self.pub.REGISTRY + ":" + tag]
                )
                output = f"{tag}: digest: {manifest} size: 358\n".encode()
            elif cmd[0] == "tag":
                self.assertEqual(cmd, ["tag", cfg_id, self.pub.REGISTRY + ":" + tag])
                output = b""
            else:
                self.assertIn(cmd[0], {"login", "load"})
                output = b""
            return subprocess.CompletedProcess(args, 0, stdout=output)

        for fault in (
            "",
            "config",
            "archive",
            "tag",
            "changed_evidence",
            "workflow_pin",
            "recipe_pin",
        ):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as dest:
                observed = dict(art)
                if fault == "changed_evidence":
                    observed["id"] += 1
                details["Id"] = "invalid" if fault == "config" else cfg_id
                details["RootFS"]["Layers"] = ["wrong"] if fault == "archive" else []
                with (
                    patch.object(self.pub, "evidence", side_effect=[art, observed]),
                    patch.object(
                        self.pub,
                        "body",
                        side_effect=[
                            b"wrong" if fault == "workflow_pin" else workflow,
                            b"wrong" if fault == "recipe_pin" else recipe,
                        ],
                    ) as get,
                    patch.object(self.pub, "WORKFLOW_SHA256", shared.digest(workflow)),
                    patch.object(self.pub, "RECIPE", shared.digest(recipe)),
                    patch.object(self.pub, "open_url", return_value=io.BytesIO(zip_data)),
                    patch.object(self.pub, "registry_auth", return_value="test grant"),
                    patch.object(
                        self.pub,
                        "require_absent",
                        side_effect=Rejected("tag_exists") if fault == "tag" else None,
                    ),
                    patch.object(self.pub, "readback") as read,
                    patch.object(self.pub, "anonymous_readback", return_value="blocked"),
                    patch.object(shared.subprocess, "run", side_effect=docker) as calls,
                ):
                    if fault:
                        with self.assertRaises(Rejected):
                            self.pub.publish(self.run_id, "token-example", "actor", Path(dest))
                        self.assertNotIn("push", [c.args[0][3] for c in calls.call_args_list])
                    else:
                        result = self.pub.publish(self.run_id, "token-example", "actor", Path(dest))
                        self.assertTrue(result["published"])
                        self.assertFalse(result["release_ready"])
                        self.assertEqual(result["anonymous_adoption"], "blocked")
                        self.assertEqual(result["reference"], self.pub.REGISTRY + "@" + manifest)
                        read.assert_called_once_with(tag, manifest, cfg_id, "test grant")
                        self.assertEqual(
                            get.call_args_list[0].args[0],
                            f"{shared.API}/contents/{self.pub.WORKFLOW}?ref={self.rev}",
                        )


class EtcdPublicationTests(PublicationContractCases, unittest.TestCase):
    module = etcd_publication
    pub = etcd_publication.PUBLISHER
    asset = "etcd-qualified-1234-1"
    tag_prefix = "3.6.17-xcrypto-v0.59.0-r1-"
    public_required = False

    @staticmethod
    def image_config():
        labels = {
            "org.opencontainers.image.source": "https://github.com/" + shared.REPOSITORY,
            "org.opencontainers.image.version": "3.6.17",
            "org.trusted-mlsecops-platform.etcd.patch": "x-crypto-v0.59.0-r1",
            "org.trusted-mlsecops-platform.etcd.upstream-revision": "0689586e360e2c6b46f95ad5634c25d5fa1683db",
        }
        return {"Labels": labels}

    def test_pinned_etcd_profile_and_labels(self):
        self.assertEqual(
            etcd_publication.EtcdPublisher.EXPECTED_SOURCE,
            "13ef78c65cf212706b1bbb4495a33ef6437d1fc2",
        )
        self.assertEqual(
            self.pub.WORKFLOW_SHA256,
            "d17df170a0e8f7e39b8444c0bb4b5b4a04082355e25904be403ec55441e6ec6e",
        )
        self.assertEqual(
            self.pub.RECIPE, "2c2ef58b4f8eeb484d24c0bb1d55b91d9d26fd2e49a1185153bbe8511a2f5f2d"
        )
        self.assertEqual(self.pub.JOB_NAME, "qualify")
        labels = self.image_config()["Labels"]
        for key in labels:
            with self.subTest(key=key), self.assertRaisesRegex(Rejected, "image_labels_invalid"):
                self.pub.verify_image({"Config": {"Labels": {**labels, key: "substitution"}}})
