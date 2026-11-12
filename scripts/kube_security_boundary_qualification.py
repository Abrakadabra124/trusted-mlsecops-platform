"""Promoter-only fixed-source mounting and cleanup without Kubernetes."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected
from scripts import kube_privacy_bundle as bundle
from scripts import kube_security_boundary as boundary
from scripts.kube_serving_runtime_qualification import PROFILE


class BoundaryJobContracts(unittest.TestCase):
    def test_explicit_fixture_bundle_is_bounded_and_promoter_scoped(self):
        root = Path(__file__).resolve().parents[1]
        result = bundle.manifest(root, "proof", "a" * 32, entry="security_audit_boundary_probe")
        self.assertIn("security_audit_boundary_probe.py", result["data"])
        self.assertIn("promotion_qualification.py", result["data"])
        self.assertLess(sum(len(v.encode()) for v in result["data"].values()), bundle.MAX_BYTES)
        document, spec = boundary.materials(root, PROFILE, "a" * 32, "proof")
        self.assertEqual(document["metadata"]["namespace"], "ml-promoter")
        self.assertEqual(spec["serviceAccountName"], "promoter")
        self.assertEqual(
            spec["containers"][0]["command"],
            ["python", "-m", "scripts.security_audit_boundary_probe"],
        )
        mounts = {v["mountPath"] for v in spec["containers"][0]["volumeMounts"]}
        self.assertTrue({"/client", "/security", "/audit", "/app/scripts"} <= mounts)
        self.assertNotIn("/trust-client", mounts)

    def test_unowned_host_refused_before_any_read_or_create(self):
        with (
            patch.object(boundary, "hosted", side_effect=Rejected("unowned")),
            patch.object(boundary.audit_state, "validate") as validate,
            patch.object(boundary, "kubectl") as api,
            self.assertRaises(Rejected),
        ):
            boundary.invoke(Path("unused"), PROFILE)
        validate.assert_not_called()
        api.assert_not_called()

    def test_cleanup_is_attempted_when_creation_fails(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(boundary, "hosted"),
            patch.object(boundary.audit_state, "validate", return_value={"workspace_id": "a" * 32}),
            patch.object(boundary, "kubectl", side_effect=Rejected("create")),
            patch.object(boundary.kube_promotion, "cleanup") as cleanup,
            self.assertRaises(Rejected),
        ):
            boundary.invoke(Path(temporary), PROFILE)
        cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
