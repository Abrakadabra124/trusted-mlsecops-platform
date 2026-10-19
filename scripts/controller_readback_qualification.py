import ctypes
import json
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from mlsecops import controller, process_privacy
from mlsecops.contracts import Rejected


class ReadbackContracts(unittest.TestCase):
    def test_snapshot_observes_without_mutating_unsafe_state(self):
        for dumpable, limits in ((0, (0, 0)), (1, (1024, -1)), (2, (-1, -1))):
            resource = Mock(RLIMIT_CORE=4, getrlimit=Mock(return_value=limits))
            prctl = Mock(return_value=dumpable)
            with (
                patch.object(process_privacy.sys, "platform", "linux"),
                patch.object(process_privacy.importlib, "import_module", return_value=resource),
                patch.object(ctypes, "CDLL", return_value=Mock(prctl=prctl)),
            ):
                self.assertEqual(
                    process_privacy.readback(), {"dumpable": dumpable, "core_limits": list(limits)}
                )
            prctl.assert_called_once_with(3, 0, 0, 0, 0)
            resource.setrlimit.assert_not_called()

    def test_snapshot_unavailable_never_claims_secure_state(self):
        for fault in ("platform", "library", "dumpable", "limits"):
            resource = Mock(RLIMIT_CORE=4, getrlimit=Mock(return_value=(0, 0)))
            if fault == "limits":
                resource.getrlimit.side_effect = OSError("private-resource")
            with (
                patch.object(
                    process_privacy.sys, "platform", "win32" if fault == "platform" else "linux"
                ),
                patch.object(process_privacy.importlib, "import_module", return_value=resource),
                patch.object(
                    ctypes,
                    "CDLL",
                    side_effect=OSError("private-library") if fault == "library" else None,
                    return_value=Mock(prctl=Mock(return_value=-1 if fault == "dumpable" else 0)),
                ),
            ):
                with self.assertRaisesRegex(Rejected, "^process_privacy_readback_unavailable$"):
                    process_privacy.readback()
            resource.setrlimit.assert_not_called()

    def test_process_state_enforces_only_explicit_privacy_requirement(self):
        for observation in (
            {"dumpable": 0, "core_limits": [0, 0]},
            {"dumpable": 1, "core_limits": [0, 0]},
            {"dumpable": 0, "core_limits": [0, -1]},
        ):
            with (
                patch.dict(
                    sys.modules,
                    {"resource": Mock(getrusage=Mock(return_value=Mock(ru_maxrss=100)))},
                ),
                patch.object(controller, "sys", Mock(modules={})),
                patch.object(controller.os, "geteuid", create=True, return_value=65532),
                patch.object(controller.Path, "is_file", return_value=True),
                patch.object(controller.Path, "exists", return_value=False),
                patch.object(
                    controller, "privacy_readback", create=True, return_value=observation
                ) as readback,
            ):
                self.assertNotIn("privacy", controller.process_state("scorer"))
                readback.assert_not_called()
                if observation == {"dumpable": 0, "core_limits": [0, 0]}:
                    self.assertEqual(
                        controller.process_state("scorer", require_privacy=True)["privacy"],
                        observation,
                    )
                else:
                    with self.assertRaisesRegex(Rejected, "^controller_process_privacy_mismatch$"):
                        controller.process_state("scorer", require_privacy=True)


@unittest.skipUnless(sys.platform == "linux", "native controller privacy requires Linux CI")
class NativeControllerPrivacyContracts(unittest.TestCase):
    def test_every_cli_protects_its_own_process_before_private_work(self):
        from scripts.controller_privacy_qualification import ENTRYPOINTS

        script = """
import importlib, io, json, sys
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch
from mlsecops.process_privacy import readback
from mlsecops.contracts import Rejected
module = importlib.import_module(sys.argv[1])
operation, arguments = sys.argv[2], json.loads(sys.argv[3])
sys.argv = ['controlled', *arguments]
observed = {}
def action(*args, **kwargs):
    observed.update(readback())
    raise Rejected('controlled-stop')
with patch.object(module, operation, side_effect=action), patch.object(module, 'read_json', create=True, return_value={}):
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        code = module.main()
print(json.dumps({'process': observed, 'exit': code}))
"""
        for module, arguments, operation, _diagnostic in ENTRYPOINTS:
            with self.subTest(module=module.__name__):
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        script,
                        module.__name__,
                        operation,
                        json.dumps(arguments),
                    ],
                    capture_output=True,
                    timeout=20,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, "native_cli_probe_failed")
                self.assertEqual(result.stderr, b"", "native_cli_probe_diagnostic")
                self.assertEqual(
                    json.loads(result.stdout),
                    {"process": {"dumpable": 0, "core_limits": [0, 0]}, "exit": 1},
                )

    def test_changed_dumpability_is_observed_without_repair(self):
        script = """
import ctypes, json
from mlsecops.process_privacy import enforce, readback
enforce()
library = ctypes.CDLL(None)
library.prctl.restype = ctypes.c_int
library.prctl.argtypes = [ctypes.c_int, *([ctypes.c_ulong] * 4)]
assert library.prctl(4, 1, 0, 0, 0) == 0
first, second = readback(), readback()
print(json.dumps([first, second]))
"""
        result = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, timeout=15, check=False
        )
        self.assertEqual(result.returncode, 0, "native_readback_probe_failed")
        self.assertEqual(result.stderr, b"")
        self.assertEqual(json.loads(result.stdout), [{"dumpable": 1, "core_limits": [0, 0]}] * 2)


if __name__ == "__main__":
    unittest.main()
