"""Private signing-file permissions, failure and identity contracts."""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import key_files, signing
from mlsecops.contracts import Rejected
from scripts import key_files_native


class SigningFileContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.key = self.root / "keys" / "test.pem"

    def test_creation_does_not_depend_on_late_path_chmod(self):
        with patch.object(Path, "chmod", side_effect=RuntimeError("late chmod unavailable")):
            public = signing.create_key(self.key)
        self.assertEqual(signing.create_key(self.key), public)
        signed = signing.sign({"test": True}, "test", self.key)
        self.assertEqual(signing.verify(signed, "test", public), {"test": True})

    def test_non_posix_dispatch_keeps_regular_file_checks_without_claiming_acl_validation(self):
        signing.create_key(self.key)
        with patch.object(key_files, "Path", return_value=self.key), patch.object(os, "name", "nt"):
            self.assertEqual(key_files.read(self.key), self.key.read_bytes())
            metadata = SimpleNamespace(st_mode=stat.S_IFCHR, st_nlink=1)
            with self.assertRaisesRegex(Rejected, "signing_key_file_identity"):
                key_files.validate(metadata)

    @unittest.skipUnless(os.name == "posix", "POSIX creation-time permissions require Linux")
    def test_private_permissions_exist_before_first_secret_write_with_umask_022(self):
        original_open = os.open
        observed = []

        def opened(path, flags, mode=0o777, **kwargs):
            descriptor = original_open(path, flags, mode, **kwargs)
            if flags & os.O_CREAT:
                metadata = os.fstat(descriptor)
                observed.append((stat.S_IMODE(metadata.st_mode), metadata.st_size))
            return descriptor

        old_mask = os.umask(0o022)
        try:
            with patch.object(os, "open", side_effect=opened):
                signing.create_key(self.key)
        finally:
            os.umask(old_mask)
        self.assertEqual(observed, [(0o600, 0)])
        self.assertEqual(stat.S_IMODE(self.key.parent.stat().st_mode), 0o700)

    @unittest.skipUnless(os.name == "posix", "POSIX existing-file mode check")
    def test_existing_broad_key_is_refused_without_repair_or_replacement(self):
        signing.create_key(self.key)
        before = self.key.read_bytes()
        self.key.chmod(0o644)
        for action in (signing.create_key, signing.load_key):
            with self.assertRaises(Rejected):
                action(self.key)
            self.assertEqual(self.key.read_bytes(), before)
            self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o644)

    def test_hardlinked_key_is_refused(self):
        signing.create_key(self.key)
        alias = self.root / "hardlink.pem"
        os.link(self.key, alias)
        for action in (signing.create_key, signing.load_key):
            with self.assertRaises(Rejected):
                action(alias)

    def test_special_device_never_reaches_pem_parser(self):
        device = "NUL" if os.name == "nt" else "/dev/null"
        with patch.object(signing.serialization, "load_pem_private_key") as parser:
            with self.assertRaises(Rejected):
                signing.load_key(device)
            parser.assert_not_called()

    def test_exclusive_creation_preserves_existing_bytes(self):
        self.key.parent.mkdir()
        with key_files.opened(self.key, create=True) as stream:
            stream.write(b"synthetic canary")
        with self.assertRaisesRegex(Rejected, "signing_key_file_unavailable"):
            with key_files.opened(self.key, create=True):
                self.fail("must not replace")
        self.assertEqual(key_files.read(self.key), b"synthetic canary")

    def test_interrupted_creation_closes_descriptor_and_keeps_private_file(self):
        self.key.parent.mkdir()
        with self.assertRaisesRegex(RuntimeError, "interrupted"):
            with key_files.opened(self.key, create=True) as stream:
                descriptor = stream.fileno()
                raise RuntimeError("interrupted")
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        self.assertEqual(self.key.read_bytes(), b"")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600)
        with self.assertRaises(Rejected):
            signing.create_key(self.key)
        self.assertEqual(self.key.read_bytes(), b"")

    def test_interrupted_partial_write_is_private_and_never_regenerated(self):
        self.key.parent.mkdir()
        with self.assertRaisesRegex(RuntimeError, "interrupted"):
            with key_files.opened(self.key, create=True) as stream:
                stream.write(b"partial-synthetic-canary")
                raise RuntimeError("interrupted")
        self.assertEqual(self.key.read_bytes(), b"partial-synthetic-canary")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600)
        with self.assertRaises(Rejected):
            signing.create_key(self.key)
        self.assertEqual(self.key.read_bytes(), b"partial-synthetic-canary")

    def test_native_canary_refuses_local_or_self_hosted_execution(self):
        for system, actions, runner in (
            ("nt", "true", "github-hosted"),
            ("posix", "false", "github-hosted"),
            ("posix", "true", "self-hosted"),
        ):
            with (
                self.subTest(system=system, actions=actions, runner=runner),
                patch.object(os, "name", system),
                patch.dict(os.environ, GITHUB_ACTIONS=actions, RUNNER_ENVIRONMENT=runner),
                patch.object(key_files_native, "foreign_read") as read,
            ):
                with self.assertRaisesRegex(Rejected, "requires_disposable_hosted_linux"):
                    key_files_native.qualify()
                read.assert_not_called()

    def test_canary_reader_has_bounded_fixed_command_and_never_masks_execution_failure(self):
        with patch.object(
            subprocess,
            "run",
            return_value=SimpleNamespace(stdout=b'{"status":"permission-denied"}', stderr=b""),
        ) as run:
            self.assertEqual(
                key_files_native.foreign_read(self.key), {"status": "permission-denied"}
            )
            args = run.call_args.args[0]
            self.assertEqual(args[:6], ["sudo", "-n", "-u", "nobody", "/usr/bin/python3", "-c"])
            self.assertEqual(args[-1], str(self.key))
            self.assertEqual(
                run.call_args.kwargs, {"capture_output": True, "check": True, "timeout": 10}
            )
        for effect in (
            subprocess.TimeoutExpired("canary", 10),
            subprocess.CalledProcessError(1, "canary"),
        ):
            with patch.object(subprocess, "run", side_effect=effect):
                with self.assertRaises(type(effect)):
                    key_files_native.foreign_read(self.key)
        with patch.object(subprocess, "run", return_value=SimpleNamespace(stderr=b"unexpected")):
            with self.assertRaisesRegex(Rejected, "key_canary_unexpected_stderr"):
                key_files_native.foreign_read(self.key)

    def test_size_mutation_and_permission_changes_fail_before_parser(self):
        signing.create_key(self.key)
        metadata = self.key.stat()
        fields = (
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        for field in ("st_nlink", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"):
            after = SimpleNamespace(**{name: getattr(metadata, name) for name in fields})
            setattr(after, field, getattr(after, field) + 1)
            with (
                self.subTest(field=field),
                patch.object(os, "fstat", side_effect=[metadata, metadata, after]),
                patch.object(signing.serialization, "load_pem_private_key") as parser,
            ):
                with self.assertRaises(Rejected):
                    signing.load_key(self.key)
                parser.assert_not_called()
        self.key.write_bytes(b"x" * 4097)
        with self.assertRaisesRegex(Rejected, "signing_key_file_size"):
            key_files.read(self.key)
        self.key.write_bytes(b"x" * 4096)
        self.assertEqual(len(key_files.read(self.key)), 4096)

    def test_posix_wrong_owner_or_broad_permissions_rejected_on_descriptor(self):
        for owner, mode in ((2, 0o600), (1, 0o644), (1, 0o620)):
            metadata = SimpleNamespace(st_mode=stat.S_IFREG | mode, st_nlink=1, st_uid=owner)
            with (
                patch.object(os, "name", "posix"),
                patch.object(os, "geteuid", return_value=1, create=True),
            ):
                with self.assertRaisesRegex(Rejected, "signing_key_file_permissions"):
                    key_files.validate(metadata)

    def test_missing_or_linked_paths_fail_without_changing_existing_files(self):
        with self.assertRaisesRegex(Rejected, "signing_key_file_unavailable"):
            key_files.read(self.key)
        for results in ([True], [False, True]):
            with patch.object(Path, "is_symlink", side_effect=results):
                with self.assertRaisesRegex(Rejected, "symlink_key"):
                    with key_files.opened(self.key):
                        self.fail("must not enter")

    @unittest.skipUnless(os.name == "posix", "Linux no-follow and FIFO probes")
    def test_symlink_after_path_check_and_fifo_are_rejected_without_blocking(self):
        signing.create_key(self.key)
        alias = self.root / "link.pem"
        alias.symlink_to(self.key)
        with patch.object(Path, "is_symlink", return_value=False):
            with self.assertRaisesRegex(Rejected, "signing_key_file_unavailable"):
                key_files.read(alias)
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(Rejected, "signing_key_file_identity"):
            key_files.read(fifo)


if __name__ == "__main__":
    unittest.main()
