import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops import recovery_lock
from mlsecops.contracts import Rejected
from mlsecops.recovery_lock import target_lock


class RecoveryLockContracts(unittest.TestCase):
    def test_platform_adapters_and_failure_release(self):
        windows = SimpleNamespace(locking=Mock(), LK_NBLCK=1, LK_UNLCK=0)
        posix = SimpleNamespace(flock=Mock(), LOCK_EX=2, LOCK_NB=4, LOCK_UN=8)
        for platform, module, adapter in (("win32", "msvcrt", windows), ("linux", "fcntl", posix)):
            with (
                patch.object(recovery_lock.sys, "platform", platform),
                patch.dict(sys.modules, {module: adapter}),
            ):
                recovery_lock.set_lock(99, True)
                recovery_lock.set_lock(99, False)
        self.assertEqual(windows.locking.call_args_list[0].args, (99, 1, 1))
        self.assertEqual(posix.flock.call_args_list[0].args, (99, 6))
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            with patch.object(recovery_lock, "set_lock", side_effect=OSError("controlled-busy")):
                with self.assertRaisesRegex(Rejected, "restore_target_busy"):
                    with target_lock(target):
                        self.fail("Must not enter")
            with self.assertRaisesRegex(Rejected, "controlled-body-failure"):
                with target_lock(target):
                    raise Rejected("controlled-body-failure")
            with target_lock(target):
                self.assertFalse(target.exists())

    def test_process_exit_without_context_cleanup_does_not_leave_live_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            program = "from pathlib import Path; from mlsecops.recovery_lock import target_lock; import os,sys\nwith target_lock(Path(sys.argv[1])): os._exit(0)"
            completed = subprocess.run(
                [sys.executable, "-c", program, str(target)], capture_output=True, timeout=10
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with target_lock(target):
                self.assertFalse(target.exists())

    def test_second_process_cannot_enter_same_target_and_lock_releases(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            program = "from pathlib import Path; from mlsecops.recovery_lock import target_lock; from mlsecops.contracts import Rejected; import sys\ntry:\n with target_lock(Path(sys.argv[1])): print('acquired')\nexcept Rejected as error:\n print(str(error)); raise SystemExit(2)"
            with target_lock(target):
                blocked = subprocess.run(
                    [sys.executable, "-c", program, str(target)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(blocked.returncode, 2, blocked.stderr)
                self.assertEqual(blocked.stdout.strip(), "restore_target_busy")
                self.assertFalse(target.exists())
            acquired = subprocess.run(
                [sys.executable, "-c", program, str(target)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(acquired.returncode, 0, acquired.stderr)
            self.assertEqual(acquired.stdout.strip(), "acquired")


if __name__ == "__main__":
    unittest.main()
