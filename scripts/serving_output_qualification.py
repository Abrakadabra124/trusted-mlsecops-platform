import copy
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from mlsecops import worker_transport
from mlsecops.contracts import Rejected, canonical
from scripts import serving_output_probe as probe


def expected():
    return {
        "image_id": "sha256:" + "a" * 64,
        "source_revision": "b" * 40,
        "source_fingerprint": "c" * 64,
    }


def report():
    return {
        "schema_version": 1,
        "scope": "actual-candidate-serving-qualification-not-release-approval",
        "status": "pass",
        "release_ready": False,
        "full_M12": "inconclusive",
        "campaign_id": "d" * 32,
        "started_at": "2026-10-19T00:00:00+00:00",
        "finished_at": "2026-10-19T00:01:00+00:00",
        "source": expected(),
        "source_dirty": False,
        "cases": ["controlled-case"],
        **dict.fromkeys(
            (
                "proposal_reference",
                "subject_sha256",
                "model_sha256",
                "candidate_reference",
                "evaluation_reference",
                "qualification_permit_sha256",
                "reference_response_sha256",
            ),
            "e" * 64,
        ),
        "runtime": {
            "http_privacy": {
                "status": "pass",
                "request_cases": 12,
                "audit_events_confirmed": 36,
                "approved_metric_series": 69,
            },
            "http_correlation": {"status": "pass"},
            "public_audit_window": {"status": "pass"},
        },
        "limitations": ["controlled fixture, not native acceptance"],
    }


NEEDLES = tuple(("private-canary-" + str(index)).encode() for index in range(6))


def operation(observe):
    observe(NEEDLES)
    print("controlled-progress")
    return report()


class OutputObservationContracts(unittest.TestCase):
    def test_sealed_capture_discards_late_content_and_emits_only_constant_failure(self):
        capture = probe.LifecycleCapture()
        self.assertEqual(capture.write("before"), 6)
        capture.seal()
        with patch("scripts.serving_privacy_probe.os.write") as output:
            self.assertEqual(capture.write(""), 0)
            output.assert_not_called()
            self.assertEqual(capture.write("private-late-value"), 18)
            output.assert_called_once_with(2, b"serving_output_late_write\n")
        self.assertEqual(capture.getvalue(), "before")

    def test_canonical_transport_is_opt_in_and_rejects_invalid_mode_before_spawn(self):
        source = "import sys; sys.stdout.buffer.write(b'{}\\n')"
        captured = worker_transport.capture(
            [sys.executable, "-c", source], timeout=10, canonical_output=True
        )
        self.assertEqual(captured["output"], {})
        source = "import sys; sys.stdout.buffer.write(b' {} \\n')"
        self.assertEqual(
            worker_transport.capture([sys.executable, "-c", source], timeout=10)["output"], {}
        )
        with patch.object(worker_transport.subprocess, "Popen") as spawned:
            with self.assertRaisesRegex(Rejected, "worker_capture_mode"):
                worker_transport.capture([], canonical_output=1)
        spawned.assert_not_called()

    def test_late_cached_capture_handler_must_reach_outer_observer(self):
        source = """
import atexit, logging, sys
from mlsecops.contracts import canonical
from scripts.serving_output_probe import produce
from scripts.serving_output_qualification import operation
def late(observe):
    result = operation(observe)
    logger = logging.getLogger('late-cache')
    logger.addHandler(logging.StreamHandler(sys.stderr))
    logger.setLevel(logging.WARNING)
    atexit.register(lambda: logger.warning('private-canary-0'))
    return result
sys.stdout.buffer.write(canonical(produce(late)) + b'\\n')
"""
        with self.assertRaises(Rejected):
            captured = worker_transport.capture([sys.executable, "-c", source], timeout=10)
            probe.observe(captured, expected())

    def test_strict_wire_mode_rejects_invisible_added_stdout_bytes(self):
        source = "import os, sys; sys.stdout.buffer.write(b'{}\\n'); sys.stdout.flush(); os.write(1, b' \\t\\n')"
        with self.assertRaises(Rejected):
            worker_transport.capture(
                [sys.executable, "-c", source], timeout=10, canonical_output=True
            )

    def test_nested_http_capture_late_handler_cannot_hide_from_lifecycle_observer(self):
        source = """
import atexit, logging, sys
from mlsecops.contracts import canonical
from mlsecops.datasets import FEATURES
from scripts.serving_output_probe import produce
from scripts.serving_output_qualification import report
from scripts.serving_privacy_probe import exercise
from scripts.serving_privacy_qualification import PrivacyProbeContracts
def operation(observe):
    original = PrivacyProbeContracts().simulated_request()
    logger = logging.getLogger('nested-cache')
    logger.propagate = False
    logger.setLevel(logging.WARNING)
    def request(*arguments, **keywords):
        if not logger.handlers:
            logger.addHandler(logging.StreamHandler(sys.stderr))
        return original(*arguments, **keywords)
    for name in ('audit_status', 'audit_scan', 'privacy_credential'):
        setattr(request, name, getattr(original, name))
    body = {'schema_version': 1, 'instances': [dict.fromkeys(FEATURES, 0.5)]}
    result = report()
    result['runtime']['http_privacy'] = {
        **exercise(request, body, input_observer=observe),
        'approved_metric_series': 69,
    }
    if sys.argv[1] == 'after-http':
        logger.warning(request.privacy_credential)
    elif sys.argv[1] == 'atexit':
        atexit.register(lambda: logger.warning(request.privacy_credential))
    return result
sys.stdout.buffer.write(canonical(produce(operation)) + b'\\n')
"""
        for mode in ("clean", "after-http", "atexit"):
            with self.subTest(mode=mode):
                captured = worker_transport.capture(
                    [sys.executable, "-c", source, mode], timeout=15, canonical_output=True
                )
                self.assertEqual(captured["output"]["native"]["status"], "pass")
                if mode == "clean":
                    self.assertEqual(probe.observe(captured, expected())["status"], "pass")
                else:
                    self.assertEqual(
                        captured["diagnostics"]["bytes"], len(b"serving_output_late_write\n")
                    )
                    with self.assertRaisesRegex(Rejected, "serving_output_observation_invalid"):
                        probe.observe(captured, expected())

    def test_nested_captures_are_sealed_on_success_failure_and_cancellation(self):
        from mlsecops.datasets import FEATURES
        from scripts import serving_privacy_probe
        from scripts.serving_privacy_qualification import PrivacyProbeContracts

        body = {"schema_version": 1, "instances": [dict.fromkeys(FEATURES, 0.5)]}
        for failure in (None, RuntimeError("controlled"), KeyboardInterrupt()):
            captures = [probe.LifecycleCapture() for _index in range(3)]

            def metrics_check(*arguments):
                if failure is not None:
                    raise failure

            with (
                self.subTest(failure=type(failure).__name__),
                patch.object(serving_privacy_probe, "LifecycleCapture", side_effect=captures),
            ):
                request = PrivacyProbeContracts().simulated_request()
                if failure is None:
                    serving_privacy_probe.exercise(request, body, metrics_check=metrics_check)
                else:
                    with self.assertRaises(type(failure)):
                        serving_privacy_probe.exercise(request, body, metrics_check=metrics_check)
            for capture in captures:
                with patch.object(serving_privacy_probe.os, "write") as output:
                    self.assertTrue(capture.sealed)
                    capture.write(request.privacy_credential)
                    output.assert_called_once_with(2, b"serving_output_late_write\n")
                    self.assertNotIn(request.privacy_credential, capture.getvalue())

    def test_full_observation_requires_successful_parent_transport_not_child_claim(self):
        child = probe.produce(operation)
        self.assertEqual(child["observation"]["status"], "inconclusive")
        envelope = {
            "schema_version": 1,
            "output": child,
            "diagnostics": {
                "bytes": 0,
                "gpu_discovery_warning": False,
                "raw_output_retained": False,
            },
        }
        result = probe.observe(envelope, expected())
        self.assertEqual(result["runtime"]["output_privacy"]["status"], "pass")
        self.assertTrue(result["runtime"]["output_privacy"]["fd_lifecycle_complete"])
        self.assertEqual(result["runtime"]["output_privacy"]["canary_count"], 6)
        self.assertFalse(result["release_ready"])
        self.assertEqual(result["cases"], ["controlled-case", "full-lifecycle-output-privacy"])
        for needle in NEEDLES:
            self.assertNotIn(needle, canonical(result))
        self.assertNotIn("output_privacy", child["native"]["runtime"])

    def test_report_publication_uses_exact_scanned_snapshot_not_mutable_producer_object(self):
        mutable = report()
        snapshot = canonical(mutable)
        original = probe.LifecycleCapture.getvalue

        def operation(observe):
            observe(NEEDLES)
            return mutable

        def after_serialization(capture):
            mutable["limitations"].append(NEEDLES[0].decode())
            return original(capture)

        with patch.object(probe.LifecycleCapture, "getvalue", after_serialization):
            child = probe.produce(operation)
        self.assertTrue(NEEDLES[0] in canonical(mutable), "mutation control did not execute")
        self.assertTrue(
            canonical(child["native"]) == snapshot, "published report differs from scanned bytes"
        )
        mutable["runtime"].clear()
        envelope = {
            "schema_version": 1,
            "output": child,
            "diagnostics": {
                "bytes": 0,
                "gpu_discovery_warning": False,
                "raw_output_retained": False,
            },
        }
        accepted = probe.observe(envelope, expected())
        self.assertEqual(accepted["status"], "pass")
        self.assertFalse(NEEDLES[0] in canonical(accepted), "private input escaped snapshot")

    def test_python_and_report_canaries_overflow_missing_or_repeated_observer_fail(self):
        for mode in ("stdout", "stderr", "report", "overflow", "missing", "repeated", "invalid"):

            def faulty(observe):
                if mode != "missing":
                    observe(NEEDLES if mode != "invalid" else ["private"])
                if mode == "repeated":
                    observe(NEEDLES)
                if mode in ("stdout", "stderr"):
                    print(NEEDLES[0].decode(), file=sys.stderr if mode == "stderr" else sys.stdout)
                if mode == "overflow":
                    print("x" * 65537)
                result = report()
                if mode == "report":
                    result["limitations"] = [NEEDLES[0].decode()]
                return result

            with self.subTest(mode=mode), self.assertRaises(Rejected):
                probe.produce(faulty)

    def test_unexpected_child_schema_status_source_or_diagnostics_never_pass(self):
        child = probe.produce(operation)
        base = {
            "schema_version": 1,
            "output": child,
            "diagnostics": {
                "bytes": 0,
                "gpu_discovery_warning": False,
                "raw_output_retained": False,
            },
        }
        variants = []
        for section, field, value in (
            ("diagnostics", "bytes", 1),
            ("diagnostics", "gpu_discovery_warning", True),
            ("output", "extra", "private"),
        ):
            changed = copy.deepcopy(base)
            changed[section][field] = value
            variants.append(changed)
        for field, value in (
            ("status", "pass"),
            ("canary_count", 0),
            ("canary_count", True),
            ("stdout_characters", -1),
            ("stderr_characters", 65537),
            ("extra", 1),
        ):
            changed = copy.deepcopy(base)
            changed["output"]["observation"][field] = value
            variants.append(changed)
        for field, value in (
            ("status", "fail"),
            ("source_dirty", True),
            ("release_ready", True),
            ("schema_version", True),
            ("scope", "release-approved"),
            ("source", {}),
            ("cases", []),
            ("extra", "private"),
        ):
            changed = copy.deepcopy(base)
            changed["output"]["native"][field] = value
            variants.append(changed)
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(Rejected):
                probe.observe(changed, expected())
        for section in ("http_privacy", "http_correlation", "public_audit_window"):
            changed = copy.deepcopy(base)
            changed["output"]["native"]["runtime"][section]["status"] = "inconclusive"
            with self.assertRaisesRegex(Rejected, "serving_output_components_incomplete"):
                probe.observe(changed, expected())

    def test_actual_fd_cached_log_subprocess_and_interpreter_exit_writes_cannot_escape(self):
        encoded = json.dumps(probe.produce(operation))
        for mode in ("valid", "stdout", "stderr", "cached-log", "subprocess", "atexit", "nonzero"):
            source = "import os, sys, logging, subprocess, atexit\n"
            source += "from contextlib import redirect_stdout, redirect_stderr\nimport io\n"
            source += "logger = logging.getLogger('cached'); logger.addHandler(logging.StreamHandler(sys.stderr)); logger.setLevel(logging.WARNING)\n"
            source += "with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):\n"
            source += {
                "valid": "    pass\n",
                "stdout": "    os.write(1, b'private-fd-canary')\n",
                "stderr": "    os.write(2, b'private-fd-canary')\n",
                "cached-log": "    logger.warning('private-fd-canary')\n",
                "subprocess": "    subprocess.run([sys.executable, '-c', \"import os; os.write(2, b'private-fd-canary')\"], check=True)\n",
                "atexit": "    atexit.register(lambda: os.write(2, b'private-fd-canary'))\n",
                "nonzero": "    sys.exit(7)\n",
            }[mode]
            source += "print(" + repr(encoded) + ")\n"
            with self.subTest(mode=mode):
                if mode == "valid":
                    observed = worker_transport.capture([sys.executable, "-c", source], timeout=10)
                    self.assertEqual(probe.observe(observed, expected())["status"], "pass")
                else:
                    with self.assertRaises(Rejected):
                        observed = worker_transport.capture(
                            [sys.executable, "-c", source], timeout=10
                        )
                        probe.observe(observed, expected())

    def test_failure_restores_python_streams_and_does_not_publish_raw_capture(self):
        output, diagnostic = io.StringIO(), io.StringIO()

        def failing(observe):
            observe(NEEDLES)
            print("private-canary-0")
            raise RuntimeError("controlled-error")

        with redirect_stdout(output), redirect_stderr(diagnostic):
            with self.assertRaisesRegex(RuntimeError, "controlled-error"):
                probe.produce(failing)
            print("restored")
        self.assertEqual(output.getvalue(), "restored\n")
        self.assertEqual(diagnostic.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
