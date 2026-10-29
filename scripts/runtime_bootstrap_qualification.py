import io
import os
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from mlsecops import runtime_bootstrap as target
from mlsecops import serving_worker
from mlsecops.contracts import Rejected

WARNING = (
    b"2026-10-29 14:49:53.514843361 [W:onnxruntime:Default, "
    b"device_discovery.cc:146 GetPciBusId] Skipping pci_bus_id for PCI path at "
    b'"/sys/devices/platform/test-device" because filename "test-device" '
    b"did not match expected pattern of [0-9a-f]+:[0-9a-f]+:[0-9a-f]+[.][0-9a-f]+\n"
)


class DiagnosticTests(unittest.TestCase):
    def test_only_complete_exact_pci_metadata_warning_is_accepted(self):
        for content in (b"", WARNING, WARNING * 2, b"\x1b[0;93m" + WARNING[:-1] + b"\x1b[m\n"):
            with self.subTest(content=content[:5]):
                target.validate_diagnostics(content)

    def test_unknown_error_truncation_oversize_and_control_characters_reject(self):
        for content in (
            b"\n",
            b"PRIVATE-CANARY\n",
            WARNING.rstrip(),
            WARNING + b"error\n",
            WARNING.replace(b"[W:", b"[E:"),
            WARNING.replace(b"GetPciBusId", b"Other"),
            WARNING.replace(b"/sys/devices/", b"/private/"),
            WARNING.replace(b"test-device", b"test\x00device"),
            b"\x1b[0;93m" + WARNING,
            WARNING + b"x" * target.LIMIT,
            b"x" * target.LIMIT,
            b"x" * (target.LIMIT + 1),
        ):
            with (
                self.subTest(content=content[:5]),
                self.assertRaisesRegex(Rejected, "^runtime_bootstrap_rejected$"),
            ):
                target.validate_diagnostics(content)

    def test_wrong_platform_or_version_and_preimported_runtime_reject(self):
        with patch.object(target.sys, "platform", "win32"), self.assertRaises(Rejected):
            target.initialize()
        with (
            patch.object(target.sys, "platform", "linux"),
            patch.dict(sys.modules, {"onnxruntime": Mock()}),
            self.assertRaises(Rejected),
        ):
            target.initialize()
        with patch.object(target.sys, "platform", "linux"), patch.dict(sys.modules):
            sys.modules.pop("onnxruntime", None)
            with (
                patch.object(target.importlib.metadata, "version", return_value="foreign"),
                self.assertRaises(Rejected),
            ):
                target.initialize()


class NativeCaptureTests(unittest.TestCase):
    """Run on Linux CI only: real fd2, memfd and RLIMIT_FSIZE, no services."""

    def run_import(self, content=b"", failure=None, configure=None):
        import resource

        original = target.importlib.import_module
        runtime = Mock()
        before_limits = resource.getrlimit(resource.RLIMIT_FSIZE)
        before_fd = os.fstat(2)
        before_fds = set(os.listdir("/proc/self/fd"))

        def importing(name):
            if name != "onnxruntime":
                return original(name)
            os.write(2, content)
            if failure:
                raise failure
            return runtime

        try:
            with (
                patch.dict(sys.modules),
                patch.object(target.importlib, "import_module", side_effect=importing),
            ):
                sys.modules.pop("onnxruntime", None)
                if configure:
                    with configure():
                        target.initialize()
                else:
                    target.initialize()
        finally:
            self.assertEqual(resource.getrlimit(resource.RLIMIT_FSIZE), before_limits)
            self.assertEqual(
                (os.fstat(2).st_dev, os.fstat(2).st_ino), (before_fd.st_dev, before_fd.st_ino)
            )
            self.assertEqual(set(os.listdir("/proc/self/fd")), before_fds)
        return runtime

    def test_native_write_is_captured_and_error_logger_set(self):
        for content in (b"", WARNING, b"\x1b[0;93m" + WARNING[:-1] + b"\x1b[m\n"):
            runtime = self.run_import(content)
            runtime.set_default_logger_severity.assert_called_once_with(3)

    def test_unknown_diagnostics_reject_and_restore_descriptors(self):
        with self.assertRaisesRegex(Rejected, "^runtime_bootstrap_rejected$"):
            self.run_import(WARNING + b"PRIVATE-CANARY\n")

    def test_failed_import_restores_descriptors_and_limits(self):
        with self.assertRaisesRegex(Rejected, "^runtime_bootstrap_rejected$"):
            self.run_import(WARNING, failure=ImportError("PRIVATE-CANARY"))

    def test_native_overflow_is_bounded_and_rejected(self):
        for size in (target.LIMIT, target.LIMIT + 100000):
            with self.subTest(size=size), self.assertRaises(Rejected):
                self.run_import(b"x" * size)

    def test_existing_smaller_limit_is_not_increased(self):
        import resource

        before = resource.getrlimit(resource.RLIMIT_FSIZE)
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024, before[1]))
            with self.assertRaises(Rejected):
                self.run_import()
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE, before)

    def test_existing_finite_adequate_limit_is_restored(self):
        import resource

        before = resource.getrlimit(resource.RLIMIT_FSIZE)
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (8192, before[1]))
            self.run_import(WARNING)
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE, before)

    def test_capture_setup_failures_release_owned_descriptors(self):
        import resource

        for owner, name in (
            (os, "memfd_create"),
            (os, "dup"),
            (os, "dup2"),
            (resource, "setrlimit"),
        ):
            with self.subTest(name=name), self.assertRaises(Rejected):
                self.run_import(
                    configure=lambda: patch.object(
                        owner, name, side_effect=OSError("PRIVATE-CANARY")
                    )
                )

    def test_restore_failure_never_proceeds_as_success(self):
        original = os.dup2
        calls = []

        def restore_then_fail(source, destination):
            result = original(source, destination)
            calls.append(result)
            if len(calls) == 2:
                raise OSError("PRIVATE-CANARY")
            return result

        with self.assertRaises(Rejected):
            self.run_import(
                configure=lambda: patch.object(os, "dup2", side_effect=restore_then_fail)
            )

    def test_real_fresh_cpu_import_and_stderr_after_initialization(self):
        source = """
import os
from mlsecops.runtime_bootstrap import initialize
initialize()
import onnxruntime as ort
assert "CPUExecutionProvider" in ort.get_available_providers()
os.write(2, b"after-initialization\\n")
"""
        result = subprocess.run(
            [sys.executable, "-c", source], capture_output=True, timeout=30, check=False
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"after-initialization\n")


class BootstrapBoundaryTests(unittest.TestCase):
    def test_import_failure_prevents_reading_model_and_emits_only_finite_code(self):
        with (
            patch.object(serving_worker, "enforce_privacy"),
            patch.object(serving_worker.signal, "alarm", create=True),
            patch.object(
                serving_worker,
                "initialize_runtime",
                create=True,
                side_effect=Rejected("PRIVATE-IMPORT-CANARY"),
            ) as initialize,
            patch.object(serving_worker, "serve", return_value=0) as serve,
            patch.object(serving_worker.sys, "stderr", new_callable=io.StringIO) as diagnostic,
        ):
            self.assertEqual(serving_worker.main(), 1)
            initialize.assert_called_once_with()
            serve.assert_not_called()
            self.assertEqual(diagnostic.getvalue(), "serving_worker_rejected\n")

    def test_privacy_and_timeout_precede_runtime_import_and_model_read(self):
        events = []
        with (
            patch.object(
                serving_worker, "enforce_privacy", side_effect=lambda: events.append("privacy")
            ),
            patch.object(
                serving_worker.signal,
                "alarm",
                create=True,
                side_effect=lambda seconds: events.append(seconds),
            ),
            patch.object(
                serving_worker,
                "initialize_runtime",
                create=True,
                side_effect=lambda: events.append("import"),
            ),
            patch.object(
                serving_worker, "serve", side_effect=lambda *args: events.append("read") or 0
            ),
        ):
            self.assertEqual(serving_worker.main(), 0)
        self.assertEqual(events, ["privacy", 120, "import", "read"])
