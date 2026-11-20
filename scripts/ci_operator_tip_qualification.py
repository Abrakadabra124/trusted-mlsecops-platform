"""Operator retention against a real signed synthetic journal and a pinned origin."""

import io
import os
import runpy
import sys
import unittest
from contextlib import nullcontext, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mlsecops import signing
from mlsecops.contracts import Rejected, atomic_write, canonical
from scripts import ci_campaign_journal as journal
from scripts import ci_campaign_journal_qualification as fixture
from scripts import ci_operator_tip as operator
from scripts import ci_tip_witness as witness


class OperatorTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(self.enterContext(TemporaryDirectory())).resolve()
        self.folder = self.base / "accepted"
        self.signer = self.base / "journal.pem"
        public = signing.create_key(self.signer)
        self.key = bytes(range(32))
        self.api = fixture.JournalAPI()
        self.context = dict(
            journal_release=fixture.PIN,
            origin_release=fixture.PIN | {"release_id": 701, "name": "ci-origin-123-1"},
            run_owner=fixture.OWNER,
            source=fixture.SOURCE,
            trusted_public=public,
        )
        append = journal.publisher(
            self.api,
            journal=fixture.PIN,
            run_owner=fixture.OWNER,
            source=fixture.SOURCE,
            trusted_public=public,
            key=self.key,
            key_path=self.signer,
        )
        for closed in fixture.workflow_checkpoints(signing.create_key(self.base / "issuer.pem")):
            self.tip = append(closed)
        self.raw = witness.seal(self.tip, key=self.key, key_path=self.signer, **self.context)
        self.get = self.enterContext(
            patch.object(operator.backup, "get_witness", return_value=self.raw)
        )

    def capture(self):
        return operator.capture(self.folder, api=self.api, key=self.key, **self.context)

    def test_retry_preserves_original_pin_and_offline_read_survives_loss_of_both_stores(self):
        self.assertEqual(self.capture(), self.tip)
        path = self.folder / "journal-tip.bin"
        before = path.stat()
        self.assertEqual(self.capture(), self.tip)
        self.assertEqual(before.st_mtime_ns, path.stat().st_mtime_ns)
        self.assertEqual(path.read_bytes(), self.raw)
        self.get.side_effect = AssertionError("unexpected remote read")
        self.api.data.clear()
        self.assertEqual(operator.read_pin(self.folder, key=self.key, **self.context), self.tip)
        with self.assertRaises(Rejected):
            operator.read_pin(self.folder, key=bytes(32), **self.context)

    def test_untrusted_witness_or_truncated_chain_leaves_no_pin(self):
        self.get.return_value = self.raw[:-1]
        with self.assertRaises(Rejected):
            self.capture()
        self.assertFalse(self.folder.exists())
        self.get.return_value = self.raw
        self.api.rows.pop()
        with self.assertRaises(Rejected):
            self.capture()
        self.assertFalse(self.folder.exists())

    def test_existing_foreign_or_corrupt_folder_is_never_overwritten(self):
        self.folder.mkdir(mode=0o700)
        path = self.folder / "journal-tip.bin"
        with self.assertRaises(Rejected):
            self.capture()
        atomic_write(path, b"bad", mode=0o600)
        with self.assertRaises(Rejected):
            self.capture()
        self.assertEqual(path.read_bytes(), b"bad")
        atomic_write(path, self.raw)
        (self.folder / "extra").touch()
        with self.assertRaises(Rejected):
            self.capture()

    def test_name_only_platform_publication(self):
        with patch.object(operator, "_parent", return_value=nullcontext((self.folder, {}))):
            self.assertEqual(self.capture(), self.tip)

    def test_conflicting_and_successful_publication_races(self):
        rename = os.rename

        def race(src, dst, **options):
            self.folder.mkdir(mode=0o700)
            atomic_write(self.folder / "journal-tip.bin", self.raw)
            raise FileExistsError

        with patch.object(operator.os, "rename", side_effect=race):
            self.assertEqual(self.capture(), self.tip)
        rename(self.folder, self.base / "first")
        with patch.object(operator.os, "rename", side_effect=PermissionError):
            with self.assertRaises((Rejected, OSError)):
                self.capture()
        self.assertFalse(self.folder.exists())

    def test_private_config_cli_and_public_result(self):
        config = self.base / "receipt.json"
        atomic_write(config, canonical(self.context))
        env = dict(
            CANDIDATE_TIP_CONFIG=str(config),
            CANDIDATE_TIP_DIRECTORY=str(self.folder),
            CANDIDATE_TRANSFER_KEY=signing.encode64(self.key),
            CANDIDATE_STORE_READ="fixture",
        )

        def invoke(environ, args):
            out = io.StringIO()
            with patch.dict(os.environ, environ, clear=True), redirect_stdout(out):
                status = operator.main(args)
            return status, out.getvalue().strip()

        root = Path(operator.__file__).resolve().parents[1]
        with (
            patch.object(
                operator.native, "command", side_effect=[fixture.SOURCE["source_revision"], ""]
            ),
            patch.object(operator, "Client", return_value=self.api) as client,
        ):
            self.assertEqual(invoke(env, ["pin"]), (0, "operator_tip=pass"))
        client.assert_called_once_with("fixture", write=False)
        for bad in (
            env | {"CANDIDATE_STORE_WRITE": ""},
            env | {"GITHUB_ACTIONS": "true"},
            env | {"CANDIDATE_TIP_CONFIG": str(root / "README.md")},
        ):
            self.assertEqual(invoke(bad, ["pin"]), (1, "operator_tip=refused"))
        with patch.object(
            operator.native, "command", side_effect=[fixture.SOURCE["source_revision"], "dirty"]
        ):
            self.assertEqual(invoke(env, ["pin"]), (1, "operator_tip=refused"))
        with patch.object(sys, "argv", ["operator_tip", "wrong"]), redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                runpy.run_path(str(operator.__file__), run_name="__main__")
        self.assertEqual(cm.exception.code, 1)

    def test_unsafe_path_and_changed_pin_rejected(self):
        root = Path(operator.__file__).resolve().parents[1]
        other = self.base / "another-checkout"
        other.mkdir(mode=0o700)
        (other / ".git").touch()
        for folder in (root / "unsafe-output", Path("relative"), other / "output"):
            with self.assertRaises(Rejected):
                operator.read_pin(folder, key=self.key, **self.context)
        self.capture()
        with patch.object(operator, "_stamp", side_effect=[1, 2]):
            with self.assertRaises(Rejected):
                operator.read_pin(self.folder, key=self.key, **self.context)
