"""Controlled hosted-driver refusals; no Docker, network or private input."""

import copy
import importlib
import importlib.util
import io
import json
import os
import runpy
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, canonical

SHA = "a" * 40
FP = "b" * 64
REPO = "Abrakadabra124/trusted-mlsecops-platform"
REPO_ID = 1407811916
BRANCH = "qualify/source-image-transfer"
WORKFLOW = ".github/workflows/source-image-transfer.yml"
ENV = dict(
    GITHUB_ACTIONS="true",
    RUNNER_ENVIRONMENT="github-hosted",
    RUNNER_OS="Linux",
    RUNNER_ARCH="X64",
    ImageOS="ubuntu24",
    GITHUB_REPOSITORY=REPO,
    GITHUB_REPOSITORY_ID=str(REPO_ID),
    GITHUB_REF="refs/heads/" + BRANCH,
    GITHUB_EVENT_NAME="push",
    GITHUB_WORKFLOW_REF=f"{REPO}/{WORKFLOW}@refs/heads/{BRANCH}",
    GITHUB_WORKFLOW_SHA=SHA,
    GITHUB_SHA=SHA,
    GITHUB_RUN_ID="12345",
    GITHUB_RUN_ATTEMPT="1",
    GITHUB_JOB="producer",
)
RECEIPT = dict(
    schema_version=1,
    source_revision=SHA,
    source_fingerprint=FP,
    image_id="sha256:" + "c" * 64,
    archive_sha256="d" * 64,
    archive_bytes=4096,
    tar_sha256="e" * 64,
    tar_bytes=10240,
)


def artifact():
    return dict(
        id=901,
        name="source-image-12345-1",
        size_in_bytes=8192,
        expired=False,
        workflow_run=dict(
            id=12345,
            repository_id=REPO_ID,
            head_repository_id=REPO_ID,
            head_sha=SHA,
            head_branch=BRANCH,
        ),
    )


class API:
    def __init__(self, rows=None):
        self.repo = dict(
            id=REPO_ID,
            full_name=REPO,
            private=False,
            fork=False,
            visibility="public",
            owner={"login": "Abrakadabra124"},
        )
        self.run = dict(
            id=12345,
            run_attempt=1,
            head_sha=SHA,
            head_branch=BRANCH,
            event="push",
            path=WORKFLOW,
            repository=copy.deepcopy(self.repo),
            head_repository=copy.deepcopy(self.repo),
        )
        self.commit = {"sha": SHA}
        self.rows = copy.deepcopy(rows or [])
        self.calls = []
        self.keep = False
        self.delete_error = False
        self.absence = None
        self.listing = None
        self.record = None

    def __call__(self, method, path, *, absent=False):
        self.calls.append((method, path, absent))
        if path == "repos/" + REPO:
            return copy.deepcopy(self.repo)
        if path == f"repos/{REPO}/commits/{SHA}":
            return copy.deepcopy(self.commit)
        if path == f"repos/{REPO}/actions/runs/12345":
            return copy.deepcopy(self.run)
        if path == f"repos/{REPO}/actions/runs/12345/artifacts?per_page=100":
            return copy.deepcopy(
                self.listing
                if self.listing is not None
                else dict(
                    total_count=len(self.rows),
                    artifacts=self.rows,
                )
            )
        if path.startswith(f"repos/{REPO}/actions/artifacts/"):
            identifier = int(path.rsplit("/", 1)[1])
            found = next((r for r in self.rows if r["id"] == identifier), None)
            if method == "DELETE":
                if self.delete_error:
                    raise Rejected("TEST_SECRET_DELETE")
                if not self.keep:
                    self.rows = [r for r in self.rows if r["id"] != identifier]
                return {}
            if found is None:
                if absent:
                    return self.absence
                raise Rejected("missing_artifact")
            return copy.deepcopy(self.record if self.record is not None else found)
        raise AssertionError("unexpected API request")


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("scripts.ci_source_image_native"))
        self.driver = importlib.import_module("scripts.ci_source_image_native")

    def guard(self, api=None, env=None, **changes):
        args = dict(head=SHA, dirty=False, platform="linux") | changes
        return self.driver.guard(API() if api is None else api, ENV if env is None else env, **args)

    @contextmanager
    def execution(self, action="producer", api=None, core=None):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory).resolve() / "checkout"
            root.mkdir()
            temporary = root.parent / "runner-temp"
            temporary.mkdir()
            output = root / "output"
            output.touch()
            env = ENV | dict(
                GITHUB_OUTPUT=str(output),
                SOURCE_IMAGE_RECEIPT=canonical(RECEIPT).decode(),
                SOURCE_IMAGE_ARTIFACT_ID="901",
                GITHUB_JOB=action,
                RUNNER_TEMP=str(temporary),
            )
            core = core or SimpleNamespace(
                prepare=Mock(return_value=copy.deepcopy(RECEIPT)),
                receive=Mock(return_value=copy.deepcopy(RECEIPT)),
                cleanup=Mock(return_value=1),
                workspace_create=Mock(),
            )
            api = API([artifact()]) if api is None else api
            # Windows normalizes real environment keys to uppercase; model Linux exactly.
            stack.enter_context(patch.object(self.driver.os, "environ", env))
            stack.enter_context(patch.object(self.driver.Path, "cwd", return_value=root))
            stack.enter_context(patch.object(self.driver.sys, "platform", "linux"))
            stack.enter_context(
                patch.object(
                    self.driver, "command", side_effect=lambda args: "" if "status" in args else SHA
                )
            )
            stack.enter_context(patch.object(self.driver, "request", api))
            stack.enter_context(patch.object(self.driver, "image_core", return_value=core))
            yield root, output, api, core

    def test_environment_and_source_fail_before_api(self):
        for key in ENV:
            if key == "GITHUB_JOB":
                continue
            with self.subTest(key=key):
                api = Mock(side_effect=AssertionError("early API"))
                with self.assertRaises(Rejected):
                    self.guard(api, ENV | {key: "foreign"})
                api.assert_not_called()
        for changes in (
            dict(dirty=True),
            dict(dirty=0),
            dict(platform="win32"),
            dict(head="A" * 40),
            dict(head="1" * 40),
            dict(head=None),
        ):
            with self.assertRaises(Rejected):
                self.guard(**changes)

    def test_public_identity_and_workflow_run(self):
        self.assertEqual(self.guard(), (12345, 1))
        api = API()
        api.run["event"] = "workflow_dispatch"
        self.assertEqual(
            self.guard(api, ENV | {"GITHUB_EVENT_NAME": "workflow_dispatch"}), (12345, 1)
        )
        for field, bad in (
            ("id", 2),
            ("id", True),
            ("full_name", "foreign/repo"),
            ("private", True),
            ("private", 0),
            ("fork", True),
            ("fork", 0),
            ("visibility", "private"),
            ("owner", {}),
            ("owner", None),
        ):
            api = API()
            api.repo[field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(Rejected):
                self.guard(api)
        for field in ("id", "run_attempt", "head_sha", "head_branch", "event", "path"):
            api = API()
            api.run[field] = "foreign"
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.guard(api)
        for field in ("repository", "head_repository"):
            for bad in (
                None,
                {},
                {"id": True},
                API().repo | {"private": True},
                API().repo | {"fork": True},
                API().repo | {"full_name": "renamed"},
            ):
                api = API()
                api.run[field] = bad
                with self.assertRaises(Rejected):
                    self.guard(api)
        for field in ("repo", "run", "commit"):
            api = API()
            setattr(api, field, [])
            with self.assertRaises(Rejected):
                self.guard(api)
        api = API()
        api.commit = {"sha": "0" * 40}
        with self.assertRaises(Rejected):
            self.guard(api)

    def test_numbers_and_closed_receipts(self):
        self.assertEqual(self.driver.number("9007199254740991"), 2**53 - 1)
        for value in (None, 1, True, "0", "01", "-1", "1\n", "9007199254740992"):
            with self.assertRaises(Rejected):
                self.driver.number(value)
        self.assertEqual(self.driver.receipt(RECEIPT, ENV), RECEIPT)
        for bad in (None, [], {}, RECEIPT | {"secret": "TEST_SECRET"}):
            with self.assertRaises(Rejected):
                self.driver.receipt(bad, ENV)
        for key, bad in (
            ("schema_version", True),
            ("schema_version", 2),
            ("source_revision", "f" * 40),
            ("source_fingerprint", "B" * 64),
            ("image_id", "c" * 64),
            ("archive_sha256", 0),
            ("tar_sha256", "0" * 63),
            ("archive_bytes", True),
            ("archive_bytes", 0),
            ("archive_bytes", 384 * 1024**2 + 1),
            ("tar_bytes", 2 * 1024**3 + 1),
            ("tar_bytes", -1),
        ):
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.driver.receipt(RECEIPT | {key: bad}, ENV)

    def test_artifact_identity_and_size_before_download(self):
        api = API([artifact()])
        self.assertEqual(self.driver.artifact_check(api, ENV, 901), artifact())
        for key, bad in (
            ("id", True),
            ("id", 0),
            ("id", 2**53),
            ("name", "source-image-12345-2"),
            ("expired", True),
            ("expired", 0),
            ("size_in_bytes", True),
            ("size_in_bytes", 0),
            ("size_in_bytes", 385 * 1024**2 + 1),
            ("workflow_run", None),
        ):
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.driver.artifact_valid(artifact() | {key: bad}, ENV)
        for key in artifact()["workflow_run"]:
            item = artifact()
            item["workflow_run"][key] = "foreign"
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.driver.artifact_valid(item, ENV)
        with self.assertRaises(Rejected):
            self.driver.artifact_valid(None, ENV)
        api.record = artifact() | {"id": 902}
        with self.assertRaises(Rejected):
            self.driver.artifact_check(api, ENV, 901)

    def test_cleanup_validates_entire_listing_before_delete(self):
        invalid = artifact() | {"id": 902, "name": "foreign"}
        for listing in (
            None,
            [],
            {},
            {"total_count": True, "artifacts": [artifact()]},
            {"total_count": 2, "artifacts": [artifact()]},
            {"total_count": 101, "artifacts": [artifact()]},
            {"total_count": 2, "artifacts": [artifact(), invalid]},
            {"total_count": 1, "artifacts": [invalid]},
            {"total_count": 0, "artifacts": {}},
        ):
            api = API()
            api.listing = [] if listing is None else listing
            with self.subTest(listing=listing), self.assertRaises(Rejected):
                self.driver.cleanup(api, ENV, lambda: self.guard(api))
            self.assertFalse(any(c[0] == "DELETE" for c in api.calls))
        api = API([artifact()])
        api.record = artifact() | {"size_in_bytes": 9999}
        with self.assertRaises(Rejected):
            self.driver.cleanup(api, ENV, lambda: self.guard(api))
        self.assertFalse(any(c[0] == "DELETE" for c in api.calls))

    def test_cleanup_requires_404_and_accessible_empty_list(self):
        for mode in ("keep", "delete_error", "absence"):
            api = API([artifact()])
            setattr(api, mode, {} if mode == "absence" else True)
            with self.subTest(mode=mode), self.assertRaises(Rejected):
                self.driver.cleanup(api, ENV, lambda: self.guard(api))
        api = API([artifact()])

        def changed_authority():
            api.repo["private"] = True
            return self.guard(api)

        with self.assertRaises(Rejected):
            self.driver.cleanup(api, ENV, changed_authority)
        self.assertFalse(any(c[0] == "DELETE" for c in api.calls))
        api = API([artifact()])
        self.assertEqual(self.driver.cleanup(api, ENV, lambda: self.guard(api)), 1)
        self.assertIn(("GET", f"repos/{REPO}/actions/artifacts/901", True), api.calls)
        self.assertEqual(self.driver.cleanup(api, ENV, lambda: self.guard(api)), 0)
        for after in (
            {},
            {"total_count": False, "artifacts": []},
            {"total_count": 1, "artifacts": [artifact()]},
        ):
            api = API([artifact()])

            def mutate_after_delete():
                if not api.rows:
                    api.listing = after
                return self.guard(api)

            with self.assertRaises(Rejected):
                self.driver.cleanup(api, ENV, mutate_after_delete)

    def test_wrong_job_and_invalid_cli_do_not_run_commands_or_leak(self):
        for action in (
            "producer",
            "receiver",
            "precheck",
            "cleanup",
            "producer-cleanup",
            "receiver-cleanup",
            "foreign",
        ):
            with (
                patch.dict(os.environ, ENV | {"GITHUB_JOB": "foreign"}, clear=True),
                patch.object(self.driver, "command") as command,
                patch.object(self.driver, "request") as api,
            ):
                with self.assertRaises(Rejected):
                    self.driver.execute(action)
                command.assert_not_called()
                api.assert_not_called()
        for args in ([], ["TEST_SECRET"], ["producer", "TEST_SECRET"]):
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(self.driver.main(args), 1)
            self.assertNotIn("TEST_SECRET", stdout.getvalue() + stderr.getvalue())
            self.assertFalse(json.loads(stdout.getvalue())["release_ready"])

    def test_producer_outputs_exact_public_receipt_and_rechecks_authority(self):
        with self.execution() as (root, output, api, core):
            result = self.driver.execute("producer")
            self.assertEqual(json.loads(output.read_text().split("=", 1)[1]), RECEIPT)
            self.assertEqual(len(output.read_text().splitlines()), 1)
            self.assertFalse(result["release_ready"])
            owner = self.driver.owner_record(root, os.environ, create=False)
            core.prepare.assert_called_once_with(root, root / self.driver.DIRECTORY, owner=owner)
            self.assertNotIn(owner, output.read_text())

            def revoke(*args, **kwargs):
                api.repo["private"] = True
                return RECEIPT

            core.prepare.side_effect = revoke
            output.write_text("")
            self.driver.owner_path(root, os.environ).unlink()
            with self.assertRaises(Rejected):
                self.driver.execute("producer")
            self.assertEqual(output.read_text(), "")

    def test_receiver_requires_producer_receipt_and_never_reissues_pins(self):
        with self.execution("receiver") as (root, output, api, core):
            self.assertTrue(self.driver.execute("precheck")["artifact_checked"])
            owner = self.driver.owner_record(root, os.environ, create=False)
            core.workspace_create.assert_called_once_with(root / self.driver.DIRECTORY, owner)
            self.assertTrue(self.driver.execute("receiver")["image_received"])
            core.receive.assert_called_once_with(
                root, root / self.driver.DIRECTORY, RECEIPT, owner=owner
            )
            self.assertEqual(output.read_text(), "")
            core.cleanup.assert_called_once()
            for bad in ("", "{}", "x" * 4097, '{"schema_version":1,"schema_version":1}'):
                core.receive.reset_mock()
                with (
                    patch.dict(os.environ, {"SOURCE_IMAGE_RECEIPT": bad}),
                    self.assertRaises(Rejected),
                ):
                    self.driver.execute("receiver")
                core.receive.assert_not_called()
            core.receive.return_value = RECEIPT | {"image_id": "sha256:" + "f" * 64}
            with self.assertRaises(Rejected):
                self.driver.execute("receiver")
            self.assertGreater(core.cleanup.call_count, 1)

    def test_local_cleanup_and_remote_cleanup_have_separate_roles(self):
        for job in ("producer", "receiver"):
            with self.execution(job) as (root, _, api, core):
                owner = self.driver.owner_record(root, os.environ, create=True)
                self.assertEqual(self.driver.execute(job + "-cleanup")["files_removed"], 1)
                core.cleanup.assert_called_once_with(root / self.driver.DIRECTORY, owner=owner)
                self.assertFalse(any(c[0] == "DELETE" for c in api.calls))
        with self.execution("cleanup") as (_, _, api, core):
            self.assertEqual(self.driver.execute("cleanup")["artifacts_deleted"], 1)
            core.cleanup.assert_not_called()

    def test_cli_sanitizes_failure_and_interrupt(self):
        for error in (RuntimeError("TEST_SECRET"), KeyboardInterrupt("TEST_SECRET")):
            output = io.StringIO()
            with patch.object(self.driver, "execute", side_effect=error), redirect_stdout(output):
                self.assertEqual(self.driver.main(["producer"]), 1)
            self.assertNotIn("TEST_SECRET", output.getvalue())
        output = io.StringIO()
        with (
            patch.object(self.driver, "execute", return_value={"status": "pass"}),
            patch.object(sys, "argv", ["driver", "cleanup"]),
            redirect_stdout(output),
        ):
            self.assertEqual(self.driver.main(), 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "pass")

    def test_core_import_is_real_and_only_lazy(self):
        core = importlib.import_module("scripts.ci_source_image")
        self.assertIs(self.driver.image_core(), core)
        self.assertEqual(core.ARCHIVE_LIMIT, self.driver.ARCHIVE_LIMIT)
        self.assertEqual(core.TAR_LIMIT, self.driver.TAR_LIMIT)
        self.assertEqual(core.IMAGE, "trusted-mlsecops:dev")

    def test_local_cleanup_requires_external_owner_before_touching_existing_directory(self):
        with self.execution() as (root, _, _, core):
            self.assertEqual(self.driver.execute("producer-cleanup")["files_removed"], 0)
            core.cleanup.assert_not_called()
            directory = root / self.driver.DIRECTORY
            directory.mkdir(parents=True)
            sentinel = directory / "image.tar"
            sentinel.write_bytes(b"foreign")
            with self.assertRaises(Rejected):
                self.driver.execute("producer-cleanup")
            self.assertEqual(sentinel.read_bytes(), b"foreign")
            core.cleanup.assert_not_called()

    def test_owner_record_is_fresh_closed_external_and_bound_to_job(self):
        with self.execution() as (root, _, _, _):
            owner = self.driver.owner_record(root, os.environ, create=True)
            self.assertRegex(owner, r"^[a-f0-9]{64}$")
            self.assertEqual(self.driver.owner_record(root, os.environ, create=False), owner)
            path = self.driver.owner_path(root, os.environ)
            self.assertFalse(path.is_relative_to(root))
            with self.assertRaises((Rejected, FileExistsError)):
                self.driver.owner_record(root, os.environ, create=True)
            original = json.loads(path.read_text())
            for key in original:
                path.write_bytes(canonical(original | {key: "foreign"}))
                with self.subTest(key=key), self.assertRaises(Rejected):
                    self.driver.owner_record(root, os.environ, create=False)
            path.write_bytes(canonical(original | {"extra": True}))
            with self.assertRaises(Rejected):
                self.driver.owner_record(root, os.environ, create=False)
            for bad in (b"[]", b"x" * 4097):
                path.write_bytes(bad)
                with self.assertRaises(Rejected):
                    self.driver.owner_record(root, os.environ, create=False)
            for bad in (str(root), str(root / ".runtime"), "relative"):
                with patch.dict(os.environ, {"RUNNER_TEMP": bad}), self.assertRaises(Rejected):
                    self.driver.owner_path(root, os.environ)

    def test_receiver_cannot_load_without_trusted_precheck_owner(self):
        with self.execution("receiver") as (_, _, _, core):
            with self.assertRaises(Rejected):
                self.driver.execute("receiver")
            core.receive.assert_not_called()
            core.cleanup.assert_not_called()

    def test_owner_record_hardlinks_cannot_authorize_cleanup(self):
        with self.execution() as (root, _, _, core):
            self.driver.owner_record(root, os.environ, create=True)
            path = self.driver.owner_path(root, os.environ)
            os.link(path, path.with_suffix(".alias"))
            with self.assertRaises(Rejected):
                self.driver.execute("producer-cleanup")
            core.cleanup.assert_not_called()
            self.assertTrue(path.exists())

    def test_precheck_failure_never_creates_download_workspace(self):
        for kind in ("receipt", "artifact"):
            with self.execution("receiver") as (root, _, api, core):
                if kind == "receipt":
                    os.environ["SOURCE_IMAGE_RECEIPT"] = "{}"
                else:
                    api.rows[0]["workflow_run"]["id"] = 54321
                with self.assertRaises(Rejected):
                    self.driver.execute("precheck")
                self.assertFalse(self.driver.owner_path(root, os.environ).exists())
                core.workspace_create.assert_not_called()

    def test_receiver_authority_change_or_failure_cleans_only_owned_workspace(self):
        for revoked in (False, True):
            with self.execution("receiver") as (root, _, api, core):
                self.driver.execute("precheck")
                owner = self.driver.owner_record(root, os.environ, create=False)

                def receiving(*args, **kwargs):
                    if revoked:
                        api.run["head_repository"]["id"] = 123
                        return RECEIPT
                    raise Rejected("TEST_SECRET_CORE_FAILURE")

                core.receive.side_effect = receiving
                with self.assertRaises(Rejected):
                    self.driver.execute("receiver")
                core.cleanup.assert_called_once_with(root / self.driver.DIRECTORY, owner=owner)

    def test_cleanup_detects_changed_artifact_and_inaccessible_postdelete_list(self):
        api = API([artifact()])

        def changed_artifact():
            api.record = artifact() | {"size_in_bytes": 7777}

        with self.assertRaises(Rejected):
            self.driver.cleanup(api, ENV, changed_artifact)
        self.assertFalse(any(c[0] == "DELETE" for c in api.calls))
        api = API([artifact()])

        def inaccessible(method, path, **kwargs):
            if not api.rows and "/artifacts?" in path:
                raise Rejected("access_denied_not_empty")
            return api(method, path, **kwargs)

        with self.assertRaises(Rejected):
            self.driver.cleanup(inaccessible, ENV, lambda: self.guard(api))

    def test_entrypoint_refusal_is_machine_readable_without_secret_output(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(sys, "argv", ["driver", "TEST_SECRET"]),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as error,
        ):
            runpy.run_path(self.driver.__file__, run_name="__main__")
        self.assertEqual(error.exception.code, 1)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "inconclusive")
        self.assertNotIn("TEST_SECRET", stdout.getvalue() + stderr.getvalue())

    def test_real_core_precheck_and_idempotent_owned_cleanup_without_docker(self):
        core = importlib.import_module("scripts.ci_source_image")
        with self.execution("receiver", core=core) as (root, _, _, _):
            with patch.object(core, "command", side_effect=AssertionError("unexpected command")):
                self.driver.execute("precheck")
                directory = root / self.driver.DIRECTORY
                owner = self.driver.owner_record(root, os.environ, create=False)
                core.workspace_check(directory, owner)
                self.assertEqual({p.name for p in directory.iterdir()}, {"owner.json"})
                self.assertEqual(self.driver.execute("receiver-cleanup")["files_removed"], 1)
                self.assertFalse(directory.exists())
                self.assertEqual(self.driver.execute("receiver-cleanup")["files_removed"], 0)

    def test_real_core_preserves_foreign_directory_after_failed_precheck(self):
        core = importlib.import_module("scripts.ci_source_image")
        with self.execution("receiver", core=core) as (root, _, _, _):
            directory = root / self.driver.DIRECTORY
            core.workspace_create(directory, "f" * 64)
            sentinel = directory / "image.tar"
            sentinel.write_bytes(b"foreign")
            with self.assertRaises(Rejected):
                self.driver.execute("precheck")
            with self.assertRaises(Rejected):
                self.driver.execute("receiver-cleanup")
            self.assertEqual(sentinel.read_bytes(), b"foreign")
            core.workspace_check(directory, "f" * 64)


if __name__ == "__main__":
    unittest.main()
