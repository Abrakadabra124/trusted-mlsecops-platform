import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical
from scripts import kube_privacy_native as native


def report():
    return {
        "status": "pass",
        "release_ready": False,
        "source_dirty": False,
        "full_M13": "inconclusive",
        "source": {"source_revision": "a" * 40},
        "model_sha256": "b" * 64,
        "subject_sha256": "c" * 64,
        "actual_refusal": {"parent_refusal": "release_assurance_required"},
        "native": {
            "status": "pass",
            "release_ready": False,
            "scope": "actual-candidate-kubernetes-privacy-not-full-M13",
            "model_sha256": "b" * 64,
            "subject_sha256": "c" * 64,
            "output_observation": {
                "fd_lifecycle_complete": True,
                "native_stderr_bytes": 0,
                "canary_count": 9,
            },
            "operator_observation": {"service_windows": 2, "worker_terminal": True},
            "privacy": {
                "approved_metric_series": 69,
                "request_cases": 12,
                "audit_events_confirmed": 36,
            },
            "cases": [
                {"id": label, "status": "pass", "expected": True, "actual": True}
                for label in sorted(native.CASES)
            ],
            "audit": {
                "observed_responses": 30,
                "correlation": {"correlated_requests": 20, "events": 100},
                "packet_sha256": "private-canary",
            },
        },
        "private_url": "https://private-canary.invalid",
    }


class NativePrivacyProjectionContracts(unittest.TestCase):
    def test_projection_contains_finite_counts_not_private_graph_or_hashes(self):
        projected = native.projection(report())
        self.assertNotIn("private-canary", canonical(projected).decode())
        self.assertEqual(projected["checks"], 26)
        self.assertEqual(projected["full_M13"], "inconclusive")
        self.assertFalse(projected["release_ready"])

    def test_missing_cases_misbinding_fake_true_diagnostics_and_invalid_counts_refuse(self):
        mutations = (
            lambda v: v["native"]["cases"].pop(),
            lambda v: v["native"]["cases"][0].update(actual=1),
            lambda v: v["native"]["cases"].append(copy.deepcopy(v["native"]["cases"][0])),
            lambda v: v["native"].update(model_sha256="foreign"),
            lambda v: v["native"]["output_observation"].update(native_stderr_bytes=1),
            lambda v: v["native"]["operator_observation"].update(service_windows=1),
            lambda v: v["native"]["audit"].update(observed_responses="private-canary"),
            lambda v: v["native"]["audit"]["correlation"].update(events=True),
            lambda v: v["native"]["audit"]["correlation"].update(events=65537),
            lambda v: v["source"].update(source_revision="private-canary"),
            lambda v: v.update(release_ready=True),
        )
        for mutate in mutations:
            value = report()
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(Rejected):
                native.projection(value)

    def test_hosted_guard_prevents_preparation(self):
        with (
            patch.object(native, "hosted", side_effect=Rejected("hosted")),
            patch.object(native.kube_serving_native, "prepare") as prepare,
            self.assertRaises(Rejected),
        ):
            native.qualify(Path("."), Path(".runtime"), "image")
        prepare.assert_not_called()

    def test_current_source_and_actual_refusal_are_bound_before_publication(self):
        value = report()
        value["source"].update(source_fingerprint="f" * 64, image_id="sha256:" + "d" * 64)
        prepared = {
            **value["source"],
            "profile": {"image_id": value["source"]["image_id"]},
            "actual": value["actual_refusal"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for changed in (False, True):
                with (
                    patch.object(native, "hosted"),
                    patch.object(
                        native, "materials", side_effect=[{}, {"changed": "yes"} if changed else {}]
                    ),
                    patch.object(native, "command", return_value=""),
                    patch.object(native.kube_serving_native, "prepare", return_value=prepared),
                    patch.object(
                        native.kube_candidate_native, "qualify", return_value=copy.deepcopy(value)
                    ),
                ):
                    if changed:
                        with self.assertRaises(Rejected):
                            native.qualify(root, root, "image")
                    else:
                        result = native.qualify(root, root, "image")
                        self.assertEqual(result["status"], "pass")
                        self.assertTrue(
                            (root / "evidence/kubernetes-privacy-private.json").is_file()
                        )


if __name__ == "__main__":
    unittest.main()
