"""Exercise the receiver entry point with synthetic authority, jobs and store."""

import base64
import io
import os
import runpy
import sys
import tempfile
import unittest
from contextlib import ExitStack, nullcontext, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, canonical, decode
from scripts import ci_primary_job as job

RUN = dict(
    repository="Abrakadabra124/trusted-mlsecops-platform",
    run_id=123,
    run_attempt=2,
    producer_job="producer",
)
SHA = "a" * 40
SOURCE = dict(source_revision=SHA, source_fingerprint="b" * 64, image_id="sha256:" + "c" * 64)
OWNER = dict(freeze_pin="1" * 64, freeze={"proposal": "2" * 64}, expected=SOURCE, run_owner=RUN)
ORIGIN = dict(workspace_id="3" * 32, container_id="4" * 64, offline_pin="5" * 64)
KEY = b"K" * 32
PRODUCER = base64.b64encode(b"P" * 32).decode()
RECEIVER = base64.b64encode(b"R" * 32).decode()
PACKET = b"MLSPRIMARY\x01encrypted-fixture"
RELEASE = dict(
    repository_id=1465012664, release_id=62, name="ci-primary-123-2", target_commitish="d" * 40
)
REF = "refs/heads/qualify/candidate-cross-job"
WORKFLOW = ".github/workflows/candidate-cross-job.yml"


class PrimaryJobTests(unittest.TestCase):
    def setUp(self):
        self.temp = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.root = self.temp / "repo"
        self.root.mkdir(mode=0o700)
        self.trust = self.temp / "original.pem"
        self.trust.write_bytes(b"synthetic")
        self.trust.chmod(0o600)
        self.env = dict(
            GITHUB_ACTIONS="true",
            RUNNER_ENVIRONMENT="github-hosted",
            RUNNER_OS="Linux",
            RUNNER_ARCH="X64",
            ImageOS="ubuntu24",
            GITHUB_WORKSPACE=str(self.root),
            GITHUB_REPOSITORY=RUN["repository"],
            GITHUB_REPOSITORY_ID="1407811916",
            GITHUB_EVENT_NAME="workflow_dispatch",
            GITHUB_REF=REF,
            GITHUB_JOB="shared",
            GITHUB_WORKFLOW_REF=f"{RUN['repository']}/{WORKFLOW}@{REF}",
            GITHUB_WORKFLOW_SHA=SHA,
            GITHUB_SHA=SHA,
            GITHUB_RUN_ID="123",
            GITHUB_RUN_ATTEMPT="2",
        )
        self.enterContext(patch.object(os, "environ", self.env))
        self.enterContext(patch.object(Path, "cwd", return_value=self.root))
        self.enterContext(patch.object(job.platform, "system", return_value="Linux"))
        self.enterContext(patch.object(job.platform, "machine", return_value="x86_64"))
        self.enterContext(
            patch.object(
                job.platform,
                "freedesktop_os_release",
                return_value={"ID": "ubuntu", "VERSION_ID": "24.04"},
            )
        )
        self.real_admission = job.native.authorize
        self.guard = self.enterContext(patch.object(job.native, "authorize", return_value=(123, 2)))
        self.source = self.enterContext(
            patch.object(job.guard, "checkout_source", return_value=SOURCE)
        )
        self.final_guard = self.enterContext(patch.object(job.guard, "authorize"))
        self.public = self.enterContext(patch.object(job, "PublicClient"))
        self.private = self.enterContext(patch.object(job, "PrivateClient"))
        self.result = dict(
            arguments=OWNER | {"extra": "private-evidence"},
            origin=ORIGIN,
            replay={"raw": "sensitive"},
            destination=Path("private"),
        )
        self.shared = self.enterContext(patch.object(job.shared, "run", side_effect=self.run_job))
        self.serving = self.enterContext(patch.object(job.serving, "run", side_effect=self.run_job))
        self.handoff = SimpleNamespace(seal=Mock(return_value=(PACKET, RECEIVER)), replay=Mock())
        self.store = SimpleNamespace(put=Mock(), get_unverified=Mock(return_value=PACKET))
        self.enterContext(
            patch.dict(
                sys.modules,
                {
                    "scripts.ci_primary_handoff": self.handoff,
                    "scripts.ci_primary_store": self.store,
                },
            )
        )

    def run_job(self, *args, **kwargs):
        self.assertEqual(args, (self.root,))
        self.assertEqual(
            kwargs,
            dict(
                source_api=self.public.return_value,
                api=self.private.return_value,
                trust_key_path=self.trust,
                key=KEY,
                trusted_public=PRODUCER,
                run_owner=RUN,
                source=SOURCE,
            ),
        )
        self.assertFalse(any(k.startswith("CANDIDATE_") for k in os.environ))
        self.assertNotIn("UNRELATED_SECRET", os.environ)
        print("sensitive")
        os.write(2, b"sensitive")
        return self.result

    def invoke(self, command, *, changes=None):
        supplied = dict(
            CANDIDATE_PUBLIC_TOKEN="public",
            CANDIDATE_TRANSFER_KEY=base64.b64encode(KEY).decode(),
            UNRELATED_SECRET="private-fixture",
        )
        if command == "capture":
            supplied.update(
                CANDIDATE_STORE_READ="read",
                CANDIDATE_TRUST_FILE=str(self.trust),
                CANDIDATE_PRODUCER_PUBLIC=PRODUCER,
            )
        else:
            supplied.update(
                CANDIDATE_STORE_WRITE="write",
                CANDIDATE_PRIMARY_RELEASE=canonical(RELEASE).decode(),
                CANDIDATE_RECEIVER_PUBLIC=RECEIVER,
            )
        supplied.update(changes or {})
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(self.env, supplied), redirect_stdout(out), redirect_stderr(err):
            code = job.main([command])
        self.assertEqual(err.getvalue(), "")
        return code, out.getvalue()

    def capture(self, role="shared"):
        self.env["GITHUB_JOB"] = role
        self.assertEqual(
            self.invoke("capture"), (0, f"primary_capture=pass\nreceiver_public={RECEIVER}\n")
        )
        (self.shared if role == "shared" else self.serving).assert_called_once()
        self.handoff.seal.assert_called_once_with(
            self.root, self.result, role=role, key=KEY, run_owner=RUN, source=SOURCE
        )
        self.public.assert_called_once_with("public")
        self.private.assert_called_once_with("read", write=False)
        self.store.put.assert_not_called()
        folder = self.root / ".runtime" / ("ci-primary-" + role)
        self.assertEqual(sorted(p.name for p in folder.iterdir()), ["context.json", "packet.bin"])
        self.assertEqual((folder / "packet.bin").read_bytes(), PACKET)
        self.assertEqual(
            decode((folder / "context.json").read_bytes()),
            dict(owner=OWNER, origin=ORIGIN, receiver_public=RECEIVER),
        )
        return folder

    def test_shared_capture_then_distinct_publish_verifies_before_writing(self):
        self.capture()
        self.serving.assert_not_called()
        calls = Mock()
        calls.attach_mock(self.handoff.replay, "replay")
        calls.attach_mock(self.final_guard, "guard")
        calls.attach_mock(self.store.put, "put")
        self.assertEqual(self.invoke("publish"), (0, "primary_publish=pass\n"))
        self.assertEqual([c[0] for c in calls.mock_calls], ["replay", "guard", "put"])
        self.handoff.replay.assert_called_once_with(
            self.root,
            PACKET,
            role="shared",
            key=KEY,
            run_owner=RUN,
            source=SOURCE,
            trusted_public=RECEIVER,
            owner=OWNER,
            origin=ORIGIN,
        )
        self.store.put.assert_called_once_with(
            self.private.return_value,
            PACKET,
            role="shared",
            run_owner=RUN,
            source=SOURCE,
            release=RELEASE,
        )
        self.private.assert_called_with("write", write=True)
        self.shared.assert_called_once()

    def test_serving_capture_is_immutable_and_role_scoped(self):
        destination = self.root / ".runtime/ci-primary-serving"
        # Also exercise the contracts fallback on hosts without directory descriptors.
        with patch.object(job, "_parent", return_value=nullcontext((destination, {}))):
            folder = self.capture("serving")
        self.shared.assert_not_called()
        self.assertEqual(self.invoke("capture")[0], 1)
        self.serving.assert_called_once()
        self.assertEqual((folder / "packet.bin").read_bytes(), PACKET)
        self.env["GITHUB_JOB"] = "shared"
        self.assertEqual(self.invoke("publish")[0], 1)
        self.store.put.assert_not_called()

    def test_early_admission_refuses_before_source_or_workspace(self):
        for changes in (
            dict(GITHUB_JOB="producer"),
            dict(GITHUB_REF="refs/heads/main"),
            dict(RUNNER_ENVIRONMENT="self-hosted"),
            dict(GITHUB_RUN_ATTEMPT="02"),
            dict(GITHUB_EVENT_NAME="push"),
        ):
            with self.subTest(changes=changes):
                self.assertEqual(self.invoke("capture", changes=changes)[0], 1)
        with patch.object(job.platform, "machine", return_value="aarch64"):
            self.assertEqual(self.invoke("publish")[0], 1)
        self.guard.assert_not_called()
        self.source.assert_not_called()
        self.guard.side_effect = Rejected("sensitive")
        self.assertEqual(self.invoke("capture"), (1, "primary_job=refused\n"))
        self.source.assert_not_called()
        self.shared.assert_not_called()
        self.assertFalse((self.root / ".runtime").exists())

    def test_capture_requires_explicit_separate_inputs_and_external_trust(self):
        for changes in (
            dict(CANDIDATE_STORE_WRITE="wrong-phase"),
            dict(CANDIDATE_TRANSFER_KEY="eA=="),
            dict(CANDIDATE_PRODUCER_PUBLIC="not-base64"),
            dict(CANDIDATE_TRUST_FILE="relative"),
            dict(CANDIDATE_TRUST_FILE=str(self.root / "original.pem")),
            dict(CANDIDATE_PUBLIC_TOKEN="", GITHUB_TOKEN="broad"),
            dict(CANDIDATE_STORE_READ="", GH_TOKEN="broad"),
            dict(CANDIDATE_STORE_READ="public"),
        ):
            with self.subTest(fields=list(changes)):
                self.assertEqual(
                    self.invoke("capture", changes=changes), (1, "primary_job=refused\n")
                )
        self.shared.assert_not_called()
        self.assertEqual(self.invoke("unknown")[0], 1)

    def test_publish_requires_independent_key_complete_replay_and_current_guard(self):
        self.capture()
        for changes in (
            dict(CANDIDATE_RECEIVER_PUBLIC=PRODUCER),
            dict(CANDIDATE_PRIMARY_RELEASE="{}"),
            dict(CANDIDATE_STORE_READ="wrong-phase"),
        ):
            self.assertEqual(self.invoke("publish", changes=changes)[0], 1)
        self.handoff.replay.assert_not_called()
        self.handoff.replay.side_effect = ValueError("sensitive")
        self.assertEqual(self.invoke("publish"), (1, "primary_job=refused\n"))
        self.handoff.replay.side_effect = None
        self.final_guard.side_effect = Rejected("sensitive")
        self.assertEqual(self.invoke("publish")[0], 1)
        self.store.put.assert_not_called()

    def test_failed_staging_leaves_no_published_capture(self):
        with patch.object(job, "atomic_write", side_effect=[None, OSError("private-detail")]):
            self.assertEqual(self.invoke("capture"), (1, "primary_job=refused\n"))
        self.assertEqual(list((self.root / ".runtime").iterdir()), [])
        self.assertEqual(self.invoke("publish")[0], 1)
        self.store.put.assert_not_called()

    def test_missing_directory_sync_ack_never_prints_a_capture_key(self):
        folder = self.root / ".runtime/ci-primary-shared"
        pinned = 12345678
        rename, sync = os.rename, os.fsync

        def rename_at(source, target, *, dst_dir_fd):
            self.assertEqual((target, dst_dir_fd), (folder.name, pinned))
            rename(source, folder)

        def fsync(fd):
            if fd == pinned:
                raise OSError("private detail")
            sync(fd)

        with (
            patch.object(
                job, "_parent", return_value=nullcontext((folder.name, {"dir_fd": pinned}))
            ),
            patch.object(os, "rename", rename_at),
            patch.object(os, "fsync", fsync),
        ):
            self.assertEqual(self.invoke("capture"), (1, "primary_job=refused\n"))
        self.assertEqual((folder / "packet.bin").read_bytes(), PACKET)
        self.store.put.assert_not_called()

    def test_cli_entrypoint_refuses_arguments_without_starting_a_job(self):
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["ci_primary_job", "capture", "serving"]),
            redirect_stdout(output),
            self.assertRaises(SystemExit) as exit_status,
        ):
            runpy.run_path(job.__file__, run_name="__main__")
        self.assertEqual(exit_status.exception.code, 1)
        self.assertEqual(output.getvalue(), "primary_job=refused\n")
        self.guard.assert_not_called()

    def test_actual_public_admission_precedes_local_image_and_receiver(self):
        self.guard.side_effect = self.real_admission
        self.enterContext(patch.object(job.native, "sys", SimpleNamespace(platform="linux")))
        git = self.enterContext(patch.object(job.native, "command", side_effect=[SHA, ""]))
        repo = dict(id=1407811916, full_name=RUN["repository"], private=False, fork=False)
        self.public.return_value.side_effect = [
            repo | {"visibility": "public", "owner": {"login": "Abrakadabra124"}},
            {"sha": SHA},
            dict(
                id=123,
                run_attempt=2,
                head_sha=SHA,
                head_branch="qualify/candidate-cross-job",
                event="workflow_dispatch",
                path=WORKFLOW,
                status="completed",
                repository=repo,
                head_repository=repo,
            ),
        ]
        self.assertEqual(self.invoke("capture"), (1, "primary_job=refused\n"))
        self.assertEqual(git.call_count, 2)
        base = "repos/" + RUN["repository"]
        self.assertEqual(
            [c.args for c in self.public.return_value.call_args_list],
            [("GET", base), ("GET", base + "/commits/" + SHA), ("GET", base + "/actions/runs/123")],
        )
        self.source.assert_not_called()
        self.shared.assert_not_called()
        self.assertFalse((self.root / ".runtime").exists())

    def test_internal_output_on_inherited_fds_and_exception_stays_private(self):
        def noisy_failure(*args, **kwargs):
            os.write(1, b"private evidence")
            os.write(2, b"private error")
            raise OSError("private failure")

        self.shared.side_effect = noisy_failure
        with tempfile.TemporaryFile(dir=self.temp) as log:
            with ExitStack() as restore:
                for fd in (1, 2):
                    saved = os.dup(fd)
                    restore.callback(os.close, saved)
                    restore.callback(os.dup2, saved, fd)
                    os.dup2(log.fileno(), fd)
                self.assertEqual(self.invoke("capture"), (1, "primary_job=refused\n"))
            log.seek(0)
            self.assertEqual(log.read(), b"")
        self.handoff.seal.assert_not_called()

    def test_untrusted_parent_and_nonprivate_context_are_refused(self):
        # Exercise the POSIX ownership rules even when the test runner is Windows.
        path = Mock()
        posix = SimpleNamespace(name="posix", geteuid=lambda: 1000)
        with patch.object(job, "os", posix):
            for uid, mode, private in (
                (999, 0o40700, False),
                (1000, 0o40775, False),
                (1000, 0o40755, True),
                (1000, 0o120777, False),
            ):
                path.lstat.return_value = SimpleNamespace(st_uid=uid, st_mode=mode)
                with self.subTest(mode=mode, uid=uid), self.assertRaises(Rejected):
                    job._directory(path, private=private)
            path.lstat.return_value = SimpleNamespace(st_uid=1000, st_mode=0o40700)
            job._directory(path, private=True)
        with patch.object(job, "os", SimpleNamespace(name="nt")):
            job._directory(path, private=True)

    def test_source_revision_or_workspace_drift_never_reaches_receiver(self):
        self.source.return_value = SOURCE | {"source_revision": "d" * 40}
        self.assertEqual(self.invoke("capture")[0], 1)
        self.assertEqual(self.invoke("capture", changes={"GITHUB_WORKSPACE": str(self.temp)})[0], 1)
        self.shared.assert_not_called()
        self.assertFalse((self.root / ".runtime").exists())

    def test_remote_reader_passes_bytes_and_only_external_authority_to_replay(self):
        args = dict(role="serving", run_owner=RUN, source=SOURCE)
        authority = dict(key=KEY, trusted_public=RECEIVER, owner=OWNER, origin=ORIGIN)
        api = object()
        value = job.replay_remote(self.root, api=api, release=RELEASE, **args, **authority)
        self.store.get_unverified.assert_called_once_with(api, release=RELEASE, **args)
        self.handoff.replay.assert_called_once_with(self.root, PACKET, **args, **authority)
        self.assertIs(value, self.handoff.replay.return_value)
