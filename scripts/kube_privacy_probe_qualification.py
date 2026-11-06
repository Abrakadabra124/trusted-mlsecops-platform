import copy
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, decode, read_json, write_json
from scripts import kube_privacy_probe as probe
from scripts.serving_output_probe import produce


def envelope():
    value = produce(
        lambda observe: (
            observe(tuple(bytes([i]) for i in range(1, 10))),
            {
                "status": "pass",
                "release_ready": False,
            },
        )[1],
        canary_count=9,
    )
    return {
        "schema_version": 1,
        "output": value,
        "diagnostics": {"bytes": 0, "gpu_discovery_warning": False, "raw_output_retained": False},
    }


class PrivacyProbeEnvelopeContracts(unittest.TestCase):
    def test_parent_accepts_only_complete_empty_diagnostic_lifecycle(self):
        result = probe.finish(envelope())
        self.assertEqual(result["output_observation"]["canary_count"], 9)
        self.assertTrue(result["output_observation"]["fd_lifecycle_complete"])
        self.assertFalse(result["release_ready"])

    def test_native_stderr_missing_canary_overflow_and_false_ready_are_refused(self):
        good = envelope()
        for mutate in (
            lambda v: v["diagnostics"].update(bytes=1),
            lambda v: v["output"]["observation"].update(canary_count=6),
            lambda v: v["output"]["observation"].update(stdout_characters=65537),
            lambda v: v["output"]["observation"].update(stderr_characters=True),
            lambda v: v["output"]["native"].update(release_ready=True),
            lambda v: v["output"].update(native=[]),
            lambda v: v["output"].update(extra="private"),
        ):
            value = copy.deepcopy(good)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(Rejected):
                probe.finish(value)

    def test_capture_count_cannot_be_disabled_or_unbounded(self):
        for count in (0, 17, True, 1.5):
            with self.subTest(count=count), self.assertRaises(Rejected):
                produce(lambda observe: {}, canary_count=count)

    def test_parent_prints_only_validated_envelope_and_fixed_private_failure_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for failure in (False, True):
                write_json(root / "failure.json", {"phase": "worker"})
                with (
                    patch.object(probe, "DIRECTORY", root),
                    patch.object(probe, "enforce"),
                    patch.object(
                        probe.worker_transport,
                        "capture",
                        return_value=envelope(),
                        side_effect=Rejected("private-error") if failure else None,
                    ) as capture,
                    patch.object(probe.sys, "stdout", io.StringIO()) as output,
                ):
                    self.assertEqual(
                        probe.main(["--config", "config", "--request", "request"]), int(failure)
                    )
                result = decode(output.getvalue().encode())
                self.assertNotIn("private-error", output.getvalue())
                self.assertFalse(result["release_ready"])
                self.assertEqual(
                    capture.call_args.kwargs, {"timeout": 240, "canonical_output": True}
                )
                if failure:
                    self.assertEqual(result["phase"], "worker")
                else:
                    self.assertTrue(result["output_observation"]["fd_lifecycle_complete"])

    def test_child_output_capture_and_fixed_failure_side_channel(self):
        def qualify(config, request, observe):
            observe(tuple(f"canary-{i}".encode() for i in range(9)))
            return {"status": "pass", "release_ready": False}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for failure in (False, True):
                with (
                    patch.object(probe, "DIRECTORY", root),
                    patch.object(probe, "PHASE", "http"),
                    patch.object(probe, "enforce"),
                    patch.object(probe, "read_json", return_value={}),
                    patch.object(
                        probe,
                        "qualify",
                        side_effect=Rejected("private-error") if failure else qualify,
                    ),
                    patch.object(probe.sys, "stdout", io.StringIO()) as output,
                ):
                    self.assertEqual(
                        probe.main(["--config", "config", "--request", "request", "--child"]),
                        int(failure),
                    )
                self.assertNotIn("private-error", output.getvalue())
                result = decode(output.getvalue().encode())
                if failure:
                    self.assertEqual(read_json(root / "failure.json")["phase"], "http")
                    self.assertEqual(result["code"], "kubernetes_privacy_rejected")
                else:
                    self.assertEqual(result["observation"]["canary_count"], 9)


if __name__ == "__main__":
    unittest.main()
