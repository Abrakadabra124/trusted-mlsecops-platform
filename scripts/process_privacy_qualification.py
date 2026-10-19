import ctypes
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mlsecops import process_privacy
from mlsecops.contracts import Rejected, canonical


class ProcessPrivacyContracts(unittest.TestCase):
    def test_guard_sets_and_reads_back_both_kernel_controls(self):
        resource = Mock(RLIMIT_CORE=4, getrlimit=Mock(return_value=(0, 0)))
        prctl = Mock(side_effect=[0, 0])
        with (
            patch.object(process_privacy.sys, "platform", "linux"),
            patch.object(process_privacy.importlib, "import_module", return_value=resource),
            patch.object(ctypes, "CDLL", return_value=Mock(prctl=prctl)) as library,
        ):
            self.assertIsNone(process_privacy.enforce())
        library.assert_called_once_with(None, use_errno=True)
        resource.setrlimit.assert_called_once_with(4, (0, 0))
        resource.getrlimit.assert_called_once_with(4)
        self.assertEqual(prctl.call_args_list[0].args, (4, 0, 0, 0, 0))
        self.assertEqual(prctl.call_args_list[1].args, (3, 0, 0, 0, 0))
        self.assertEqual(prctl.restype, ctypes.c_int)
        self.assertEqual(prctl.argtypes, [ctypes.c_int, *([ctypes.c_ulong] * 4)])

    def test_guard_fails_closed_on_unavailable_or_unconfirmed_controls(self):
        for fault in (
            "platform",
            "resource",
            "library",
            "set-dump",
            "get-dump",
            "set-limit",
            "get-limit",
        ):
            with self.subTest(fault=fault):
                resource = Mock(RLIMIT_CORE=4, getrlimit=Mock(return_value=(0, 0)))
                if fault == "set-limit":
                    resource.setrlimit.side_effect = OSError("synthetic-private-policy")
                if fault == "get-limit":
                    resource.getrlimit.return_value = (0, -1)
                prctl = Mock(
                    side_effect=[-1 if fault == "set-dump" else 0, 1 if fault == "get-dump" else 0]
                )
                with (
                    patch.object(
                        process_privacy.sys, "platform", "win32" if fault == "platform" else "linux"
                    ),
                    patch.object(
                        process_privacy.importlib,
                        "import_module",
                        side_effect=ImportError("synthetic-private-policy")
                        if fault == "resource"
                        else None,
                        return_value=resource,
                    ),
                    patch.object(
                        ctypes,
                        "CDLL",
                        side_effect=OSError("synthetic-private-policy")
                        if fault == "library"
                        else None,
                        return_value=Mock(prctl=prctl),
                    ),
                ):
                    with self.assertRaisesRegex(Rejected, "^worker_privacy_unavailable$"):
                        process_privacy.enforce()


@unittest.skipUnless(sys.platform == "linux", "actual prctl/rlimit require native Linux CI")
class NativeProcessPrivacyContracts(unittest.TestCase):
    def test_disposable_child_readback_and_abort_never_mark_a_core_dump(self):
        root = Path(__file__).resolve().parents[1]
        script = """
import ctypes, json, os, resource, signal, sys
sys.path.insert(0, sys.argv[1])
from mlsecops.process_privacy import enforce
libc = ctypes.CDLL(None)
libc.prctl.restype = ctypes.c_int
libc.prctl.argtypes = [ctypes.c_int, *([ctypes.c_ulong] * 4)]
before = libc.prctl(3, 0, 0, 0, 0)
enforce()
after = libc.prctl(3, 0, 0, 0, 0)
limits = resource.getrlimit(resource.RLIMIT_CORE)
child = os.fork()
if child == 0:
    os.kill(os.getpid(), signal.SIGABRT)
    os._exit(99)
_, status = os.waitpid(child, 0)
print(json.dumps({'before': before, 'after': after, 'limits': limits,
    'signal': os.WTERMSIG(status) if os.WIFSIGNALED(status) else None,
    'core_dumped': os.WCOREDUMP(status), 'files': len(os.listdir('.'))}))
"""
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [sys.executable, "-c", script, str(root)],
                cwd=temporary,
                capture_output=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(result.returncode, 0, "privacy_native_child_failed")
            self.assertEqual(result.stderr, b"", "privacy_native_child_stderr")
            observed = json.loads(result.stdout)
            self.assertEqual(observed["before"], 1, "privacy_baseline_inconclusive")
            self.assertEqual(observed["after"], 0)
            self.assertEqual(observed["limits"], [0, 0])
            self.assertEqual(observed["signal"], 6)
            self.assertFalse(observed["core_dumped"])
            self.assertEqual(observed["files"], 0)
        print(
            canonical(
                {
                    "scope": "worker-kernel-privacy-component-not-full-M13",
                    "status": "pass",
                    "dumpable": observed["after"],
                    "core_limits": observed["limits"],
                    "abort_signal": observed["signal"],
                    "core_dumped": observed["core_dumped"],
                    "owned_files": observed["files"],
                    "release_ready": False,
                }
            ).decode()
        )


if __name__ == "__main__":
    unittest.main()
