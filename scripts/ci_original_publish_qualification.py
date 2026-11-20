"""Publisher contract on a synthetic prepared workspace and in-memory journal."""

import io
import os
import runpy
import stat
import sys
import unittest
from contextlib import chdir, redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, digest, write_json
from scripts import ci_campaign_control_qualification as control
from scripts import ci_campaign_journal_qualification as journal
from scripts import ci_original_publish as cli
from scripts import ci_private_assets_qualification as working

ORIGIN = journal.PIN | {"release_id": 701, "name": "ci-origin-31-2"}


class PrivateAPI:
    """Separate working and journal releases on one synthetic private API."""

    def __init__(self):
        self.working = working.StoreAPI()
        self.journal = journal.JournalAPI()
        self.working.sibling = [self.journal.release]

    def backend(self, path):
        if (
            "/releases/700" in path
            or "/releases/assets/" in path
            and int(path.rsplit("/", 1)[-1]) in self.journal.data
        ):
            return self.journal
        return self.working

    def json(self, method, path, **kwargs):
        return self.backend(path).json(method, path, **kwargs)

    def upload(self, path, name, data):
        return self.backend(path).upload(path, name, data)

    def download(self, path, limit):
        return self.backend(path).download(path, limit)


class PublisherTests(unittest.TestCase):
    def setUp(self):
        fx = self.fx = control.CampaignControlTests()
        self.addCleanup(fx.doCleanups)
        fx.setUp()
        self.temp = Path(self.enterContext(TemporaryDirectory())).resolve()
        self.root = self.temp / "repo"
        state = self.state = self.root / ".runtime"
        tools = state / "bin"
        tools.mkdir(parents=True, mode=0o700)
        for name in cli.install_ci_tools.TOOLS:
            path = tools / name
            path.write_bytes(b"fixture")
            path.chmod(0o755)
        self.enterContext(chdir(self.root))
        private = self.temp / "signer"
        private.mkdir(mode=0o700)
        self.signer = private / "fixture.pem"
        self.public = signing.create_key(self.signer)
        self.image = dict(
            fx.source,
            schema_version=1,
            archive_sha256="0" * 64,
            tar_sha256="1" * 64,
            archive_bytes=100,
            tar_bytes=200,
        )
        self.env = dict(
            GITHUB_JOB="producer",
            GITHUB_WORKSPACE=str(self.root),
            RUNNER_TEMP=str(self.temp),
            GITHUB_REPOSITORY=fx.run["repository"],
            GITHUB_RUN_ID="31",
            GITHUB_RUN_ATTEMPT="2",
            GITHUB_SHA=fx.source["source_revision"],
            PATH=os.defpath,
            CANDIDATE_PUBLIC_TOKEN="public-test",
            CANDIDATE_STORE_WRITE="private-test",
            CANDIDATE_TRANSFER_KEY=signing.encode64(control.KEY),
            SOURCE_IMAGE_RECEIPT=canonical(self.image).decode(),
            CANDIDATE_JOURNAL_RELEASE=canonical(journal.PIN).decode(),
            CANDIDATE_ORIGIN_RELEASE=canonical(ORIGIN).decode(),
            CANDIDATE_JOURNAL_PUBLIC=self.public,
            CANDIDATE_JOURNAL_KEY_FILE=str(self.signer),
            GITHUB_OUTPUT="invalid-public-output",
        )
        self.enterContext(patch.dict(os.environ, self.env, clear=True))
        cli.image.owner_record(self.root, os.environ, create=True)
        marker = self.marker = dict(
            workspace_id=fx.origin["workspace_id"], container_id=fx.origin["container_id"]
        )
        current = dict(
            workspace=marker["workspace_id"],
            container=marker["container_id"],
            revision=fx.source["source_revision"],
            fingerprint=fx.source["source_fingerprint"],
            run="31",
            attempt="2",
            keys="9" * 64,
        )
        self.enterContext(patch.object(cli.controller_intake, "owner", return_value=current))
        write_json(state / cli.controller_intake.START, dict(owner=current))
        start = digest((state / cli.controller_intake.START).read_bytes())
        write_json(
            state / "evidence/ci-producer-inputs.json",
            dict(workspace=marker["workspace_id"], start=start),
        )
        write_json(
            state / "evidence/storage-bootstrap.json",
            dict(status="ready", container_id=marker["container_id"]),
        )
        refs = {k: k for k in ("dataset_reference", "candidate_reference", "evaluation_reference")}
        write_json(
            state / cli.controller_intake.CAPTURE,
            dict(subject=refs, start=start, release_ready=False),
        )
        write_json(
            state / "storage-demo.json",
            dict(
                candidate={"candidate_reference": refs["candidate_reference"]},
                dataset={"dataset_reference": refs["dataset_reference"]},
                evaluation_reference=refs["evaluation_reference"],
            ),
        )
        cluster = cli.campaign.cluster_owner
        location = state / cluster.WITNESS
        write_json(
            location / "workspace.json",
            dict(product="trusted-mlsecops", schema_version=1, workspace_id=marker["workspace_id"]),
        )
        self.witness_path = location / cluster.recovery.RECORD
        self.witness = dict(
            workspace_id=marker["workspace_id"],
            run_owner=fx.run,
            source=fx.source,
            baseline_empty=True,
            sql=None,
            cluster=dict(observed=True, containers={"old": "original"}),
            cleanup=dict(sql=True, cluster=True),
        )
        write_json(self.witness_path, self.witness)
        self.api = PrivateAPI()
        self.copies = {}
        self.copy = Mock(side_effect=self.copy_originals)
        self.enterContext(
            patch.dict(
                sys.modules, {"scripts.ci_origin_backup": SimpleNamespace(copy_originals=self.copy)}
            )
        )
        self.public_api = Mock()
        self.enterContext(patch.object(working, "TAG", "ci-candidate-31-2"))
        self.enterContext(patch.object(working, "REF", "refs/tags/ci-candidate-31-2"))
        self.authorize = self.enterContext(patch.object(cli.campaign.guard, "authorize"))
        self.validate = self.enterContext(
            patch.object(cli.campaign.storage_bootstrap, "validate", return_value=marker)
        )
        self.enterContext(
            patch.object(
                cli.campaign.storage_bootstrap, "inspect", return_value={"State": {"Running": True}}
            )
        )
        self.cluster = self.enterContext(patch.object(cluster, "cleanup"))
        self.stop = self.enterContext(patch.object(cli.campaign.recovery, "stop_owned"))
        self.offline = self.enterContext(
            patch.object(cli.campaign.receipt, "offline_pin", return_value=fx.origin["offline_pin"])
        )
        self.prepare = self.enterContext(
            patch.object(cli.campaign.producer, "prepare", side_effect=self.prepared)
        )
        self.fresh = self.enterContext(
            patch.object(
                cli.campaign.bridge,
                "_fresh",
                return_value=(
                    dict(
                        proposal_issued_at=control.NOW - 10,
                        captured_at=control.NOW - 10,
                        proposal_expires_at=control.NOW + 1600,
                    ),
                    control.NOW,
                ),
            )
        )

    def copy_originals(self, api, *, release, checkpoint, run_owner, source, key):
        self.assertEqual(
            (api, release, run_owner, source, key),
            (self.api, ORIGIN, self.fx.run, self.fx.source, control.KEY),
        )
        self.assertEqual(len(api.journal.uploads), 8)
        pins = checkpoint["storage"]["assets"]
        self.assertEqual(set(pins), set(cli.store.LIMITS))
        for stem, pin in pins.items():
            self.assertNotIn(stem, self.copies)
            self.copies[stem] = cli.store._read(api, stem, pin)
            self.assertEqual(digest(self.copies[stem]), pin["sha256"])

    def prepared(self, root, state, *, key):
        self.assertEqual((root, state, key), (self.root, self.state, control.KEY))
        self.assertEqual(os.environ["PATH"].split(os.pathsep)[0], str(state / "bin"))
        self.assertFalse(any(k.startswith("CANDIDATE_") for k in os.environ))
        self.assertEqual(os.environ["GITHUB_OUTPUT"], os.devnull)
        self.cluster.assert_called_once_with(state)
        self.assertFalse(self.api.working.mutations or self.api.journal.uploads)
        print("private synthetic observation")
        os.write(2, b"private child diagnostic\n")
        return dict(owner=self.fx.owner, reports=self.fx.reports, sealed=self.fx.packets)

    def publish(self, **changes):
        args = dict(
            api=self.api,
            source_api=self.public_api,
            key=control.KEY,
            image_receipt=self.image,
            key_path=self.signer,
            trusted_public=self.public,
            descriptor=journal.PIN,
            origin_release=ORIGIN,
        )
        return cli.publish(self.root, **(args | changes))

    def invoke(self):
        with (
            patch.object(cli, "PrivateClient", return_value=self.api) as writer,
            patch.object(cli, "PublicClient", return_value=self.public_api) as public,
            redirect_stdout(io.StringIO()) as out,
            redirect_stderr(io.StringIO()) as err,
        ):
            code = cli.main(["publish"])
        public.assert_called_once_with("public-test")
        writer.assert_called_once_with("private-test", write=True)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(os.environ["PATH"], os.defpath)
        return code, out.getvalue().splitlines()

    def test_cli_real_five_assets_eight_checkpoints_and_closed_readback(self):
        with patch.object(cli.journal, "recover", wraps=cli.journal.recover) as recovered:
            code, lines = self.invoke()
        self.assertEqual(code, 0)
        self.assertEqual(len(lines), 2)
        public = cli.journal._public(lines[1].removeprefix("producer_public="))
        self.assertEqual(lines, ["original_publish=pass", "producer_public=" + public])
        self.assertEqual(len(self.api.working.contents), 5)
        self.assertEqual(len(self.api.journal.uploads), 8)
        self.assertEqual(len(self.copies), 5)
        self.copy.assert_called_once()
        # Five working readbacks, five backup sources, one final live control.
        self.assertEqual(len(self.api.working.downloads), 11)
        self.assertEqual(self.api.working.downloads[-1], (104, len(self.copies[cli.store.CONTROL])))
        tip = recovered.call_args.kwargs["expected_tip"]
        self.assertEqual(
            tip, dict(step=8, asset_id=1007, sha256=digest(self.api.journal.data[1007]))
        )
        self.assertEqual(
            self.authorize.call_args_list[0].kwargs,
            dict(
                source_api=self.public_api,
                job="producer",
                run_owner=self.fx.run,
                source=self.fx.source,
            ),
        )
        with self.assertRaises(FileExistsError):
            self.publish()
        self.prepare.assert_called_once()
        self.cluster.assert_called_once()
        self.stop.assert_called_once()
        self.copy.assert_called_once()

    def test_late_publish_error_is_preserved_even_with_all_eight_checkpoints(self):
        original = Rejected("private late window refusal")
        self.fresh.side_effect = original
        with patch.object(cli.journal, "recover") as recover, self.assertRaises(Rejected) as caught:
            self.publish()
        self.assertIs(caught.exception, original)
        self.assertEqual(len(self.api.journal.uploads), 8)
        recover.assert_not_called()
        self.copy.assert_not_called()
        self.assertEqual(self.cluster.call_count, 2)
        self.assertEqual(self.stop.call_count, 2)
        self.assertEqual(self.offline.call_count, 3)

    def test_cli_readback_failure_releases_no_key_or_private_diagnostics(self):
        with patch.object(
            cli.journal, "recover", side_effect=RuntimeError("private journal details")
        ):
            self.assertEqual(self.invoke(), (1, ["original_publish=refused"]))
        self.assertEqual(len(self.api.journal.uploads), 8)
        self.assertEqual(self.stop.call_count, 2)

    def test_foreign_owner_after_failure_is_never_cleaned_by_name(self):
        def changed(*args, **kwargs):
            write_json(self.witness_path, self.witness | {"source": {}})
            self.validate.return_value = self.marker | {"container_id": "0" * 64}
            raise KeyboardInterrupt()

        self.prepare.side_effect = changed
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.publish()
        self.assertEqual(
            caught.exception.__notes__,
            ["producer_cluster_cleanup_unconfirmed", "producer_sql_cleanup_unconfirmed"],
        )
        self.cluster.assert_called_once()
        self.stop.assert_not_called()
        self.assertEqual(self.api.journal.uploads, [])

    def test_malformed_inputs_and_foreign_workspace_fail_before_claim_or_mutation(self):
        for changes in (
            dict(key=b"x"),
            dict(trusted_public=signing.encode64(bytes(32))),
            dict(descriptor=journal.PIN | {"name": "foreign"}),
            dict(origin_release=ORIGIN | {"release_id": journal.PIN["release_id"]}),
            dict(origin_release=ORIGIN | {"name": "ci-origin-31-1"}),
            dict(key_path=self.root / "private.pem"),
            dict(image_receipt=self.image | {"source_revision": "0" * 40}),
        ):
            with self.subTest(fields=list(changes)), self.assertRaises((ValueError, OSError)):
                self.publish(**changes)
        self.validate.return_value = self.marker | {"container_id": "0" * 64}
        with self.assertRaises(Rejected):
            self.publish()
        self.prepare.assert_not_called()
        self.cluster.assert_not_called()
        self.stop.assert_not_called()
        self.assertFalse(self.api.working.mutations or self.api.journal.uploads)
        self.assertFalse((self.state / "ci-original-publish-claim").exists())

    def test_unexpected_tool_cannot_shadow_host_commands(self):
        (self.state / "bin/git").touch()
        with self.assertRaises(Rejected):
            self.publish()
        self.prepare.assert_not_called()
        self.assertFalse(self.api.journal.uploads)

    def test_alias_of_working_release_is_rejected_before_backup(self):
        with self.assertRaises(Rejected):
            self.publish(origin_release=ORIGIN | {"release_id": 71})
        self.assertEqual(len(self.api.journal.uploads), 8)
        self.copy.assert_not_called()

    def test_backup_readback_refusal_withholds_key(self):
        self.copy.side_effect = Rejected("private retained byte mismatch")
        self.assertEqual(self.invoke(), (1, ["original_publish=refused"]))
        self.assertEqual(len(self.api.working.downloads), 5)
        self.assertEqual(self.stop.call_count, 2)

    def advance_after_copy(self, seconds):
        def slow_copy(*args, **kwargs):
            self.copy_originals(*args, **kwargs)
            self.enterContext(patch("time.time", return_value=control.NOW + seconds))
            self.enterContext(patch("time.time_ns", return_value=(control.NOW + seconds) * 10**9))

        self.copy.side_effect = slow_copy

    def test_closed_historical_journal_cannot_admit_expired_live_control(self):
        self.advance_after_copy(1600)
        with self.assertRaisesRegex(Rejected, "ci_transfer_time"):
            self.publish()
        self.assertEqual(len(self.copies), 5)
        self.assertEqual(len(self.api.working.downloads), 11)

    def test_last_packet_has_only_599_seconds_after_backup(self):
        packet = self.fx.packets["validation-serving"]
        packet["context"].update(issued_at=control.NOW - 300, expires_at=control.NOW + 1500)
        packet["envelope"] = control.ci_transfer.seal(
            b"private controlled plaintext: validation-serving",
            key=control.KEY,
            context=packet["context"],
        )
        packet["ciphertext_sha256"] = digest(packet["envelope"])
        self.fresh.return_value[0].update(
            proposal_issued_at=control.NOW - 301, captured_at=control.NOW - 301
        )
        self.advance_after_copy(901)
        self.assertEqual(self.invoke(), (1, ["original_publish=refused"]))
        self.assertEqual(len(self.api.working.downloads), 11)

    def test_exactly_600_seconds_after_readback_is_sufficient(self):
        self.advance_after_copy(1000)
        self.assertEqual(self.invoke()[0], 0)
        self.assertEqual(len(self.api.working.downloads), 11)

    def test_run_superseded_during_copy_cannot_expose_producer_key(self):
        def authorize(*args, **kwargs):
            if self.copies:
                self.assertEqual(len(self.api.working.downloads), 11)
                raise Rejected("run superseded")

        self.authorize.side_effect = authorize
        self.assertEqual(self.invoke(), (1, ["original_publish=refused"]))
        self.assertEqual(len(self.copies), 5)

    def test_reconciliation_rejects_changed_tip_checkpoint_returned_receipt_or_issuer(self):
        closed = journal.workflow_checkpoints(self.public)[-1]
        tip = dict(step=8, asset_id=1007, sha256="a" * 64)
        result = dict(complete=True, tip=tip, checkpoint=closed)
        args = dict(
            public=self.public,
            storage=closed["storage"],
            last=canonical(closed),
            tip=tip,
            recovered=result,
        )
        self.assertEqual(cli._confirmed(**args), closed)
        for changes in (
            dict(recovered=result | {"complete": 1}),
            dict(recovered=result | {"tip": tip | {"asset_id": 1008}}),
            dict(recovered=result | {"checkpoint": closed | {"extra": True}}),
            dict(storage=closed["storage"] | {"repository_id": True}),
            dict(public=signing.encode64(bytes(32))),
        ):
            with self.subTest(field=next(iter(changes))), self.assertRaises(Rejected):
                cli._confirmed(**(args | changes))

    def test_public_admission_and_prior_proposal_refuse_before_private_release(self):
        with (
            patch.object(self.authorize, "side_effect", Rejected("not admitted")),
            self.assertRaises(Rejected),
        ):
            self.publish()
        (self.state / cli.campaign.producer.CLAIM).mkdir()
        with self.assertRaises(Rejected):
            self.publish()
        self.cluster.assert_not_called()
        self.prepare.assert_not_called()
        self.assertFalse(self.api.journal.uploads or self.api.working.mutations)

    def test_foreign_controller_start_blocks_original_freeze(self):
        write_json(self.state / cli.controller_intake.START, {"owner": {"container": "foreign"}})
        with self.assertRaises(Rejected):
            self.publish()
        self.prepare.assert_not_called()
        self.stop.assert_not_called()

    def test_malformed_cli_environment_is_quiet_before_preparation(self):
        for changes in (
            dict(CANDIDATE_PUBLIC_TOKEN=""),
            dict(CANDIDATE_STORE_READ="extra"),
            dict(CANDIDATE_TRANSFER_KEY="***"),
            dict(SOURCE_IMAGE_RECEIPT="{}"),
            dict(CANDIDATE_JOURNAL_RELEASE="[]"),
            dict(GITHUB_JOB="serving"),
        ):
            with (
                self.subTest(field=next(iter(changes))),
                patch.dict(os.environ, changes),
                redirect_stdout(io.StringIO()) as out,
                redirect_stderr(io.StringIO()) as err,
            ):
                self.assertEqual(cli.main(["publish"]), 1)
                self.assertEqual(
                    (out.getvalue(), err.getvalue()), ("original_publish=refused\n", "")
                )
        self.prepare.assert_not_called()

    def test_invalid_command_has_only_fixed_refusal(self):
        with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli.main(["prepare"]), 1)
        self.assertEqual((out.getvalue(), err.getvalue()), ("original_publish=refused\n", ""))

    def test_module_entry_point_requires_explicit_publish(self):
        with (
            patch.object(sys, "argv", [cli.__file__]),
            redirect_stdout(io.StringIO()) as out,
            self.assertRaises(SystemExit) as exit_status,
        ):
            runpy.run_path(cli.__file__, run_name="__main__")
        self.assertEqual(
            (exit_status.exception.code, out.getvalue()), (1, "original_publish=refused\n")
        )

    def test_portable_checks_reject_extra_tool_and_in_checkout_signer_without_posix_metadata(self):
        tool_dir = self.state / "bin"
        platform = SimpleNamespace(
            name="nt", access=os.access, X_OK=os.X_OK, environ=os.environ, pathsep=os.pathsep
        )
        with patch.object(cli, "os", platform):
            self.assertEqual(cli._signer(self.root, self.signer), self.signer)
            cli._tools(self.state)
            self.assertEqual(os.environ["PATH"].split(os.pathsep)[0], str(tool_dir))
            unexpected = tool_dir / "unexpected"
            unexpected.touch()
            with self.assertRaises(Rejected):
                cli._tools(self.state)
            with self.assertRaises(Rejected):
                cli._signer(self.root, unexpected)

    def test_signer_ancestry_and_tool_permissions_with_posix_metadata(self):
        # Exercise the hosted permission policy even on a Windows development host.
        with patch.object(cli, "os", wraps=os) as host:
            uid = getattr(os, "geteuid", lambda: 0)()
            host.name, host.geteuid, host.pathsep = "posix", lambda: uid, os.pathsep
            host.environ = os.environ
            signer = Mock()
            signer.is_absolute.return_value = True
            signer.resolve.return_value = signer
            signer.is_relative_to.return_value = False
            signer.lstat.return_value = SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_uid=uid
            )
            signer.parent.lstat.return_value = SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o700, st_uid=uid
            )
            ancestor = Mock()
            signer.parent.parents = (ancestor,)
            with patch.object(cli, "Path", return_value=signer):
                for owner, mode in ((uid, 0o755), (0, 0o1777)):
                    ancestor.stat.return_value = SimpleNamespace(st_uid=owner, st_mode=mode)
                    self.assertIs(cli._signer(self.root, self.signer), signer)
                for owner, mode in ((uid, 0o777), (uid + 1, 0o755)):
                    ancestor.stat.return_value = SimpleNamespace(st_uid=owner, st_mode=mode)
                    with self.assertRaises(Rejected):
                        cli._signer(self.root, self.signer)
            folder = Mock()
            folder.lstat.return_value = signer.parent.lstat.return_value
            files = []
            for name in cli.install_ci_tools.TOOLS:
                file = Mock()
                file.name = name
                file.lstat.return_value = SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o755, st_uid=uid, st_nlink=1
                )
                files.append(file)
            folder.iterdir.return_value = files
            host.access.return_value = True
            with patch.object(cli, "safe_child", return_value=folder):
                cli._tools(self.state)
                files[0].lstat.return_value.st_mode |= 0o020
                with self.assertRaises(Rejected):
                    cli._tools(self.state)
