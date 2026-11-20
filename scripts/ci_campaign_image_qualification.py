"""Campaign workflow, role and artifact boundaries with in-memory GitHub and Docker."""

import io
import json
import os
import runpy
import shutil
import sys
import unittest
from contextlib import contextmanager, redirect_stdout
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, canonical
from scripts import ci_campaign_image as campaign
from scripts import ci_source_image as core
from scripts import ci_source_image_native as native
from scripts import ci_source_image_native_qualification as hosted
from scripts import ci_source_image_qualification as images

BRANCH = "qualify/candidate-cross-job"
WORKFLOW = ".github/workflows/candidate-cross-job.yml"
REF = "refs/heads/" + BRANCH


class CampaignImageTests(unittest.TestCase):
    def setUp(self):
        self.fixture = hosted.DriverTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.enterContext(patch("socket.socket", side_effect=AssertionError("no network")))
        self.enterContext(
            patch("subprocess.Popen", side_effect=AssertionError("no infrastructure"))
        )

    @contextmanager
    def job(self, name, *, image_core=None):
        row = hosted.artifact()
        row["workflow_run"]["head_branch"] = BRANCH
        api = hosted.API([row])
        api.run.update(
            head_branch=BRANCH, path=WORKFLOW, event="workflow_dispatch", status="in_progress"
        )
        with (
            self.fixture.execution(name, api=api, core=image_core) as values,
            patch.object(campaign.platform, "system", return_value="Linux"),
            patch.object(campaign.platform, "machine", return_value="x86_64"),
            patch.object(
                campaign.platform,
                "freedesktop_os_release",
                return_value={"ID": "ubuntu", "VERSION_ID": "24.04"},
            ),
        ):
            os.environ.update(
                GITHUB_REF=REF,
                GITHUB_EVENT_NAME="workflow_dispatch",
                GITHUB_WORKFLOW_REF=f"{hosted.REPO}/{WORKFLOW}@{REF}",
            )
            yield values

    def test_wrong_role_cannot_read_metadata_prepare_workspace_or_change_image(self):
        for action, job in (
            ("build", "producer"),
            ("receive", "image"),
            ("precheck", "contracts"),
            ("local-cleanup", "image_cleanup"),
            ("cleanup", "shared"),
            ("foreign", "image"),
        ):
            with self.subTest(action=action, job=job), self.job(job) as (root, _, api, engine):
                with self.assertRaises(Rejected):
                    campaign.execute(action)
                self.assertFalse(api.calls)
                self.assertFalse((root / native.DIRECTORY).exists())
                engine.prepare.assert_not_called()
                engine.cleanup.assert_not_called()

    def test_qualification_push_other_branch_dirty_checkout_and_wrong_workflow_sha_refuse_build(
        self,
    ):
        with self.job("image") as (_, output, api, engine):
            for changes in (
                dict(GITHUB_EVENT_NAME="push"),
                dict(GITHUB_REF=hosted.ENV["GITHUB_REF"]),
                dict(GITHUB_REPOSITORY_ID="1"),
                dict(GITHUB_SHA="d" * 40),
                dict(GITHUB_WORKFLOW_SHA="e" * 40),
                dict(GITHUB_WORKFLOW_REF=hosted.ENV["GITHUB_WORKFLOW_REF"]),
            ):
                with (
                    self.subTest(changes=changes),
                    patch.dict(os.environ, changes),
                    self.assertRaises(Rejected),
                ):
                    campaign.execute("build")
            with (
                patch.object(native, "command", side_effect=[hosted.SHA, " M Dockerfile"]),
                self.assertRaises(Rejected),
            ):
                campaign.execute("build")
            self.assertEqual(api.calls, [])
            self.assertEqual(output.read_text(), "")
            engine.prepare.assert_not_called()

    def test_guard_refuses_foreign_repo_completed_run_and_stale_attempt_before_owner_creation(self):
        with self.job("image") as (root, _, api, engine):
            for obj, changes in (
                (api.repo, {"fork": True}),
                (api.repo, {"private": True}),
                (api.repo, {"id": 7}),
                (api.run, {"run_attempt": 2}),
                (api.run, {"status": "completed"}),
                (api.run, {"event": "push"}),
                (api.run, {"path": hosted.WORKFLOW}),
                (api.run, {"head_branch": hosted.BRANCH}),
                (api.run["head_repository"], {"id": 8}),
            ):
                with (
                    self.subTest(changes=changes),
                    patch.dict(obj, changes),
                    self.assertRaises(Rejected),
                ):
                    campaign.execute("build")
            engine.prepare.assert_not_called()
            self.assertFalse(native.owner_path(root, os.environ).exists())

    def test_host_labels_cannot_override_actual_platform(self):
        with self.job("image") as (_, _, api, engine):
            for attribute, result in (
                ("system", "Windows"),
                ("machine", "aarch64"),
                ("freedesktop_os_release", {"ID": "ubuntu", "VERSION_ID": "22.04"}),
            ):
                with (
                    self.subTest(attribute=attribute),
                    patch.object(campaign.platform, attribute, return_value=result),
                    self.assertRaises(Rejected),
                ):
                    campaign.execute("build")
            self.assertFalse(api.calls)
            engine.prepare.assert_not_called()

    def test_build_writes_only_closed_receipt_and_cleanup_uses_external_owner(self):
        with self.job("image") as (root, output, _, engine):
            value = campaign.execute("build")
            self.assertTrue(value["image_prepared"])
            self.assertIs(value["release_ready"], False)
            self.assertEqual(
                output.read_bytes().splitlines(), [b"receipt=" + canonical(hosted.RECEIPT)]
            )
            owner = native.owner_record(root, os.environ, create=False)
            engine.prepare.assert_called_once_with(root, root / native.DIRECTORY, owner=owner)
            with self.assertRaises(FileExistsError):
                campaign.execute("build")
            campaign.execute("local-cleanup")
            engine.cleanup.assert_called_once_with(root / native.DIRECTORY, owner=owner)

    def test_receiver_refuses_other_workflows_artifact_or_other_attempt_before_download(self):
        with self.job("shared") as (root, _, api, engine):
            for obj, changes in (
                (api.rows[0]["workflow_run"], {"head_branch": hosted.BRANCH}),
                (api.rows[0], {"name": "source-image-12345-2"}),
                (api.rows[0], {"size_in_bytes": native.ZIP_LIMIT + 1}),
            ):
                with (
                    self.subTest(changes=changes),
                    patch.dict(obj, changes),
                    self.assertRaises(Rejected),
                ):
                    campaign.execute("precheck")
            self.assertFalse(native.owner_path(root, os.environ).exists())
            engine.workspace_create.assert_not_called()

    def test_each_reader_uses_its_own_precheck_then_verifies_archive_and_tag(self):
        data = images.ImageTests()
        data.setUp()
        self.addCleanup(data.doCleanups)
        data.packed()
        for name in ("producer", "shared", "serving"):
            with self.subTest(job=name), self.job(name, image_core=core) as (root, output, _, _):
                os.environ["SOURCE_IMAGE_RECEIPT"] = canonical(data.receipt).decode()
                self.assertTrue(campaign.execute("precheck")["artifact_checked"])
                directory = root / native.DIRECTORY
                shutil.copyfile(data.directory / "image.tar.gz", directory / "image.tar.gz")
                calls = []

                def command(args, timeout=30):
                    calls.append(args)
                    if args[1] == "info":
                        return json.dumps(dict(OSType="linux", Driver="overlay2"))
                    if args[1:3] == ["image", "inspect"]:
                        return json.dumps([data.inspected()])
                    return ""

                with (
                    patch.object(core, "source_contract", return_value=data.expected()),
                    patch.object(core, "command", command),
                    patch.object(core, "execute", data.probe),
                ):
                    self.assertTrue(campaign.execute("receive")["image_received"])
                self.assertIn(["docker", "image", "tag", data.identifier, core.IMAGE], calls)
                self.assertIn(["docker", "image", "inspect", core.IMAGE], calls)
                self.assertFalse(directory.exists())
                with self.assertRaises(Rejected):
                    campaign.execute("receive")
                self.assertEqual(campaign.execute("local-cleanup")["files_removed"], 0)
                self.assertEqual(output.read_text(), "")

    def test_approved_precheck_cannot_be_reused_for_another_reader_or_artifact_branch(self):
        with self.job("producer") as (_, _, api, engine):
            campaign.execute("precheck")
            with patch.dict(os.environ, GITHUB_JOB="serving"), self.assertRaises(Rejected):
                campaign.execute("receive")
            with (
                patch.dict(api.rows[0]["workflow_run"], head_branch=hosted.BRANCH),
                self.assertRaises(Rejected),
            ):
                campaign.execute("receive")
            engine.receive.assert_not_called()
            engine.cleanup.assert_not_called()

    def test_remote_cleanup_validates_campaign_branch_before_exact_id_delete_and_absence(self):
        with self.job("image_cleanup") as (_, _, api, _):
            with (
                patch.dict(api.rows[0]["workflow_run"], head_branch=hosted.BRANCH),
                self.assertRaises(Rejected),
            ):
                campaign.execute("cleanup")
            self.assertFalse(any(c[0] == "DELETE" for c in api.calls))
            self.assertEqual(campaign.execute("cleanup")["artifacts_deleted"], 1)
            self.assertIn(("GET", f"repos/{hosted.REPO}/actions/artifacts/901", True), api.calls)
            self.assertEqual(campaign.execute("cleanup")["artifacts_deleted"], 0)

    def test_cli_projects_only_closed_output_on_refusal(self):
        output = io.StringIO()
        with (
            redirect_stdout(output),
            patch.object(sys, "argv", ["image", "private-argument"]),
            self.assertRaises(SystemExit) as exited,
        ):
            runpy.run_path(campaign.__file__, run_name="__main__")
        self.assertEqual(exited.exception.code, 1)
        value = json.loads(output.getvalue())
        self.assertEqual(
            value, dict(status="inconclusive", scope="campaign-source-image", release_ready=False)
        )
        with (
            patch.object(campaign, "execute", Mock(return_value={"status": "pass"})),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(campaign.main(["build"]), 0)


if __name__ == "__main__":
    unittest.main()
