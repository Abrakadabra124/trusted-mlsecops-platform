"""Durable one-use epochs: no reset or recovery by silently deleting state."""

import io
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mlsecops import monitoring_state as state
from mlsecops.contracts import Rejected, decode


class StateContracts(unittest.TestCase):
    def test_configuration_rejects_relative_paths_invalid_pins_roles_and_epochs(self):
        base = [str(Path.cwd() / ".runtime/epochs"), "a" * 64, "producer", "b" * 32, "c" * 64]
        for index, value in (
            (0, "relative"),
            (0, None),
            (1, "bad"),
            (2, "trainer"),
            (3, "bad"),
            (4, False),
        ):
            arguments = list(base)
            arguments[index] = value
            with self.subTest(index=index), self.assertRaises(Rejected):
                state.Guard(*arguments)

    @unittest.skipUnless(os.name == "posix", "Linux durable directory handles required")
    def test_claim_is_durable_role_scoped_and_never_released_on_clean_shutdown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "epochs"
            pin = state.initialize(str(root))
            guard = state.Guard(str(root), pin, "producer", "a" * 32, "b" * 64)
            receipt = guard.claim()
            self.assertFalse(receipt["history_unavailable"])
            self.assertEqual(receipt["previous_epochs"], 0)
            with self.assertRaises(Rejected):
                guard.claim()
            with self.assertRaises(Rejected):
                state.Guard(str(root), pin, "producer", "a" * 32, "c" * 64).claim()
            self.assertFalse(
                state.Guard(str(root), pin, "sink", "a" * 32, "b" * 64).claim()[
                    "history_unavailable"
                ]
            )
            replacement = state.Guard(str(root), pin, "producer", "d" * 32, "b" * 64).claim()
            self.assertTrue(replacement["history_unavailable"])
            self.assertEqual(replacement["previous_epochs"], 1)
            with self.assertRaises(Rejected):
                state.initialize(str(root))

    @unittest.skipUnless(os.name == "posix", "Linux durable directory handles required")
    def test_missing_pin_changed_identity_bad_permissions_links_and_partial_marker_fail_closed(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "epochs"
            guard = state.Guard(str(root), "a" * 64, "producer", "b" * 32, "c" * 64)
            with self.assertRaises(Rejected):
                guard.claim()
            pin = state.initialize(str(root))
            with self.assertRaises(Rejected):
                guard.claim()
            guard = state.Guard(str(root), pin, "producer", "b" * 32, "c" * 64)
            # An empty marker left by a crash is still consumed, not a free epoch.
            marker = root / ("producer-" + "b" * 32)
            marker.touch(mode=0o600)
            with self.assertRaises(Rejected):
                guard.claim()
            self.assertTrue(
                state.Guard(str(root), pin, "producer", "d" * 32, "c" * 64).claim()[
                    "history_unavailable"
                ]
            )
            root.chmod(0o755)
            with self.assertRaises(Rejected):
                guard.claim()
            root.chmod(0o700)
            marker.chmod(0o644)
            with self.assertRaises(Rejected):
                state.Guard(str(root), pin, "producer", "e" * 32, "c" * 64).claim()
            marker.chmod(0o600)
            linked = Path(temporary) / "linked"
            linked.symlink_to(root, target_is_directory=True)
            with self.assertRaises(Rejected):
                state.Guard(str(linked), pin, "producer", "e" * 32, "c" * 64).claim()
            (root / "unexpected").touch(mode=0o600)
            with self.assertRaises(Rejected):
                state.Guard(str(root), pin, "producer", "e" * 32, "c" * 64).claim()

    def test_unsupported_host_does_not_attempt_filesystem_mutation(self):
        path = str(Path.cwd() / ".runtime/epochs")
        with patch.object(state.os, "name", "nt"), patch.object(state.os, "open") as opening:
            with self.assertRaises(Rejected):
                state.initialize(path)
            opening.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "Linux durable directory handles required")
    def test_abrupt_process_exit_preserves_claim_and_concurrent_admission_is_exclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = str(Path(temporary) / "epochs")
            pin = state.initialize(root)
            code = "import os,sys;from mlsecops.monitoring_state import Guard;Guard(sys.argv[1],sys.argv[2],'producer','a'*32,'b'*64).claim();os._exit(0)"
            child = subprocess.run(
                [sys.executable, "-c", code, root, pin], capture_output=True, timeout=10
            )
            self.assertEqual(child.returncode, 0)
            self.assertEqual((child.stdout, child.stderr), (b"", b""))
            with self.assertRaises(Rejected):
                state.Guard(root, pin, "producer", "a" * 32, "b" * 64).claim()
            import fcntl

            with state.directory(root) as locked:
                fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(Rejected):
                    state.Guard(root, pin, "producer", "c" * 32, "b" * 64).claim()
            self.assertTrue(
                state.Guard(root, pin, "producer", "c" * 32, "b" * 64).claim()[
                    "history_unavailable"
                ]
            )

    @unittest.skipUnless(os.name == "posix", "Linux durable directory handles required")
    def test_short_write_interruption_full_registry_and_changed_identity_are_not_reset(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "epochs"
            pin = state.initialize(str(root))
            write = os.write
            with patch.object(state.os, "write", side_effect=lambda fd, data: write(fd, data[:2])):
                state.Guard(str(root), pin, "producer", "a" * 32, "b" * 64).claim()
            with patch.object(state, "MAX_CLAIMS", 1), self.assertRaises(Rejected):
                state.Guard(str(root), pin, "producer", "c" * 32, "b" * 64).claim()
            with patch.object(state.os, "write", return_value=0), self.assertRaises(Rejected):
                state.Guard(str(root), pin, "producer", "c" * 32, "b" * 64).claim()
            with self.assertRaises(Rejected):
                state.Guard(str(root), pin, "producer", "c" * 32, "b" * 64).claim()
            with (
                patch.object(state.os, "fsync", side_effect=OSError("PRIVATE")),
                self.assertRaises(Rejected),
            ):
                state.Guard(str(root), pin, "producer", "d" * 32, "b" * 64).claim()
            with self.assertRaises(Rejected):
                state.Guard(str(root), pin, "producer", "d" * 32, "b" * 64).claim()
            (root / "identity").write_bytes(b"bad")
            with self.assertRaises(Rejected):
                state.Guard(str(root), pin, "producer", "e" * 32, "b" * 64).claim()

    @unittest.skipUnless(os.name == "posix", "Linux ownership semantics required")
    def test_private_file_checks_owner_type_permissions_and_links(self):
        for field, value in (
            ("st_mode", 0o40700),
            ("st_uid", os.getuid() + 1),
            ("st_nlink", 2),
            ("st_mode", 0o100644),
        ):
            metadata = {"st_mode": 0o100600, "st_uid": os.getuid(), "st_nlink": 1}
            metadata[field] = value
            with self.subTest(field=field), self.assertRaises(Rejected):
                state.private(SimpleNamespace(**metadata))

    def test_provision_cli_and_errors_never_print_private_input(self):
        with (
            patch.object(state, "enforce_privacy"),
            patch.object(state, "initialize", return_value="a" * 64),
            patch.object(sys, "stdout", io.StringIO()) as output,
        ):
            self.assertEqual(state.main(["--directory", "PRIVATE"]), 0)
            self.assertEqual(decode(output.getvalue())["state_sha256"], "a" * 64)
            self.assertNotIn("PRIVATE", output.getvalue())
        for failure, code in ((OSError("PRIVATE"), 1), (KeyboardInterrupt(), 130)):
            with (
                patch.object(state, "enforce_privacy", side_effect=failure),
                patch.object(sys, "stderr", io.StringIO()) as output,
            ):
                self.assertEqual(state.main([]), code)
                self.assertEqual(output.getvalue(), "monitoring_state_rejected\n")
        with (
            patch("mlsecops.process_privacy.enforce", side_effect=Rejected("PRIVATE")),
            patch.object(sys, "stderr", io.StringIO()),
            self.assertRaises(SystemExit) as stopped,
        ):
            runpy.run_path(state.__file__, run_name="__main__")
        self.assertEqual(stopped.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
