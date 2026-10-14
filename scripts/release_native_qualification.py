import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mlsecops.contracts import Rejected, digest, read_json, write_json
from mlsecops.signing import create_key
from scripts import release_bundle_qualification as fixtures
from scripts import release_native as native


class NativeReleaseContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.ReleaseBundleContracts.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.ReleaseBundleContracts.tearDownClass()

    def setUp(self):
        self.fixture = fixtures.ReleaseBundleContracts()
        self.fixture.setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name)
        self.root = self.state / "root"
        context = self.fixture.materials.context
        self.expected = context["expected"]
        write_json(self.root / "policies/local-cpu.json", context["policy"])
        (self.root / "uv.lock").write_bytes(self.fixture.lock)
        write_json(self.state / "storage-trust.json", context["trust"])
        write_json(
            self.state / "storage-demo.json",
            {
                "candidate": {"candidate_reference": context["candidate_reference"]},
                "evaluation_reference": context["evaluation_reference"],
            },
        )
        public = {
            "approver": self.fixture.materials.public,
            "evaluator": self.fixture.materials.fixture.public["evaluator"],
            "trust": create_key(self.state / "keys/trust.pem"),
        }
        write_json(self.state / "trusted-keys.json", public)
        for role, original in (
            ("approver", self.fixture.materials.key),
            ("evaluator", self.fixture.materials.fixture.directory / "evaluator.pem"),
        ):
            (self.state / f"keys/{role}.pem").write_bytes(original.read_bytes())
        self.published = {}

    def get(self, client, table, reference):
        if table == "releases":
            return self.published[reference]
        return self.fixture.materials.get(Path(client).name, table, reference)

    def put(self, client, table, content):
        self.assertEqual((Path(client).name, table), ("promoter", "releases"))
        self.published[digest(content)] = content
        return digest(content)

    def qualify(self, **changes):
        settings = {
            "validate": {"return_value": {"container_id": "controlled"}},
            "source_fingerprint": {"return_value": self.expected["source_fingerprint"]},
            "command": {
                "side_effect": lambda args: (
                    "" if args[-1] == "--porcelain" else self.expected["source_revision"]
                )
            },
            "resolve_image": {"return_value": self.expected["image_id"]},
            "metadata_snapshot": {"return_value": {"controlled": "unchanged"}},
            "release_snapshot": {"side_effect": lambda client: set(self.published)},
        }
        settings.update(changes)
        with contextlib.ExitStack() as stack:
            for name, values in settings.items():
                stack.enter_context(patch.object(native, name, **values))
            stack.enter_context(
                patch.object(native.material_bundle.storage, "get", side_effect=self.get)
            )
            stack.enter_context(
                patch.object(native.material_bundle.storage, "put", side_effect=self.put)
            )
            stack.enter_context(
                patch.object(
                    native.material_bundle.storage,
                    "connection_parameters",
                    side_effect=lambda client: {"user": "ml_" + Path(client).name},
                )
            )
            return native.qualify(self.root, self.state, "controlled")

    def test_real_signatures_complete_readback_and_actual_candidate_denied(self):
        report = self.qualify()
        self.assertEqual((report["status"], report["full_M10"]), ("pass", "inconclusive"))
        self.assertFalse(report["release_ready"])
        self.assertFalse(report["source_dirty"])
        self.assertEqual(
            (len(report["cases"]), report["objects"], report["documents"]), (10, 17, 6)
        )
        self.assertEqual(len(self.published), 17)
        stored = self.state / "release-proposals" / report["campaign_id"] / "report.json"
        self.assertEqual(read_json(stored), report)

    def test_authorization_bypass_or_wrong_reason_fails_qualification(self):
        for effect in (None, Rejected("unexpected")):
            with (
                patch.object(native.release_authorization, "verify", side_effect=effect),
                self.assertRaisesRegex(Rejected, "native_negative"),
            ):
                self.qualify()

    def test_input_metadata_and_object_set_changes_fail_closed(self):
        for changes, reason in (
            ({"metadata_snapshot": {"side_effect": [{}, {"changed": True}]}}, "metadata_changed"),
            ({"release_snapshot": {"return_value": set()}}, "object_set_mismatch"),
            (
                {
                    "source_fingerprint": {
                        "side_effect": [self.expected["source_fingerprint"], "other"]
                    }
                },
                "inputs_changed",
            ),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(Rejected, reason):
                self.qualify(**changes)

    def test_nondeterministic_reference_or_serving_readback_fails_closed(self):
        with (
            patch.object(native.release_bundle, "publish", side_effect=["a" * 64, "b" * 64]),
            self.assertRaisesRegex(Rejected, "idempotency_failed"),
        ):
            self.qualify()
        original = native.release_bundle.read

        def changed(client, reference, **arguments):
            result = original(client, reference, **arguments)
            if Path(client).name == "serving":
                result["model"] = b"changed"
            return result

        with (
            patch.object(native.release_bundle, "read", side_effect=changed),
            self.assertRaisesRegex(Rejected, "readback_mismatch"),
        ):
            self.qualify()

    def test_cli_preserves_private_report_and_sanitizes_failure(self):
        report = self.qualify()
        output = self.state / "evidence/release-native.json"
        for error in (None, Rejected("private-details"), OSError("private-path")):
            stdout, stderr = io.StringIO(), io.StringIO()
            with (
                patch.object(native.sys, "argv", ["native", "--state", str(self.state)]),
                patch.object(native, "validate"),
                patch.object(native, "qualify", return_value=report, side_effect=error),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(native.main(), 1 if error else 0)
            self.assertNotIn("private", stdout.getvalue() + stderr.getvalue())
            self.assertEqual(read_json(output)["status"], "fail" if error else "pass")
            self.assertNotIn("metadata_snapshot", stdout.getvalue())

    def test_cli_requires_ownership_before_writing_and_sanitizes_write_errors(self):
        output = self.state / "evidence/release-native.json"
        with (
            patch.object(native.sys, "argv", ["native", "--state", str(self.state)]),
            patch.object(native, "validate", side_effect=Rejected("foreign-runtime")),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(native.main(), 1)
        self.assertFalse(output.exists())
        with (
            patch.object(native.sys, "argv", ["native", "--state", str(self.state)]),
            patch.object(native, "validate"),
            patch.object(native, "write_json", side_effect=OSError("private-path")),
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            self.assertEqual(native.main(), 1)
        self.assertNotIn("private-path", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
